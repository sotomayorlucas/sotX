#!/usr/bin/env python3
"""
sotOS HTTPS Proxy -- bridges HTTP (guest) to HTTPS (internet).

The guest OS connects via plain HTTP to this proxy. The proxy
fetches the target URL over HTTPS and returns the response.

Supports GET, POST, HEAD, and PUT for full git smart protocol
(git clone/push over HTTPS uses POST for pack negotiation).

Usage:
    python scripts/https_proxy.py [--port PORT]

Guest usage (direct URL rewriting):
    busybox wget http://10.0.2.2:PORT/https://dl-cdn.alpinelinux.org/alpine/v3.19/...
    git clone http://10.0.2.2:PORT/https://github.com/user/repo.git

Guest usage (HTTP_PROXY mode -- preferred):
    Set in guest environment:
        http_proxy=http://10.0.2.2:PORT
        https_proxy=http://10.0.2.2:PORT
    Then use normal HTTPS URLs:
        git clone https://github.com/user/repo.git
        wget https://example.com/file.tar.gz

In HTTP_PROXY mode the proxy intercepts HTTP CONNECT requests
(used by clients for HTTPS through an HTTP proxy) and also
handles plain GET/POST with full URL (http://...) in the
request line (standard HTTP proxy behavior).
"""

import http.server
import ssl
import socket
import select
import urllib.request
import urllib.error
import sys
import argparse
import threading
import time

# Maximum response body to buffer (for non-streaming). 256 MB.
MAX_BODY = 256 * 1024 * 1024

# Streaming threshold: responses larger than this are streamed in chunks.
STREAM_THRESHOLD = 1 * 1024 * 1024  # 1 MB

class HTTPSProxyHandler(http.server.BaseHTTPRequestHandler):
    """Handle requests by proxying to the target HTTPS URL.

    Two modes:
    1. URL-in-path: GET /https://example.com/path  -> fetch https://example.com/path
    2. HTTP proxy:  GET http://example.com/path     -> fetch http://example.com/path
                    CONNECT example.com:443         -> TCP tunnel for TLS
    """

    # Increase default timeout for slow TLS handshakes under TCG
    timeout = 120

    def _get_target_url(self):
        """Extract target URL from the request path."""
        path = self.path

        # Mode 2: Full URL in request line (standard HTTP proxy)
        if path.startswith("http://") or path.startswith("https://"):
            return path

        # Mode 1: URL-in-path (legacy): /https://example.com/path
        target = path.lstrip("/")
        if target.startswith("http://") or target.startswith("https://"):
            return target

        return None

    def _proxy_request(self, method="GET", body=None):
        """Forward a request to the target URL."""
        target_url = self._get_target_url()
        if not target_url:
            self.send_error(400, f"Bad URL: {self.path}")
            return

        self.log_message("Proxying %s: %s (%s bytes body)",
                         method, target_url,
                         len(body) if body else 0)

        try:
            ctx = ssl.create_default_context()
            headers = {
                "User-Agent": self.headers.get("User-Agent", "sotOS-HTTPS-Proxy/2.0"),
            }
            # Forward important headers from the client
            for h in ("Content-Type", "Accept", "Accept-Encoding",
                       "Accept-Language", "Authorization", "Range",
                       "If-Modified-Since", "If-None-Match",
                       "Git-Protocol", "Cache-Control", "Pragma"):
                val = self.headers.get(h)
                if val:
                    headers[h] = val

            req = urllib.request.Request(target_url, data=body,
                                         headers=headers, method=method)
            resp = urllib.request.urlopen(req, context=ctx, timeout=60)

            # Read response
            data = resp.read(MAX_BODY)

            self.send_response(resp.status)
            # Forward all response headers
            for key, val in resp.headers.items():
                # Skip hop-by-hop headers
                if key.lower() in ("transfer-encoding", "connection",
                                    "keep-alive", "proxy-authenticate",
                                    "proxy-authorization", "te", "trailers",
                                    "upgrade"):
                    continue
                self.send_header(key, val)
            # Always set Content-Length (we've buffered the full response)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        except urllib.error.HTTPError as e:
            self.log_message("HTTP error: %d %s", e.code, e.reason)
            try:
                err_body = e.read()
            except Exception:
                err_body = b""
            self.send_response(e.code)
            for key, val in e.headers.items():
                if key.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(key, val)
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)
        except Exception as e:
            self.log_message("Proxy error: %s", str(e))
            self.send_error(502, str(e))

    def do_GET(self):
        self._proxy_request("GET")

    def do_HEAD(self):
        self._proxy_request("HEAD")

    def do_POST(self):
        # Read the request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None
        self._proxy_request("POST", body)

    def do_PUT(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None
        self._proxy_request("PUT", body)

    def do_CONNECT(self):
        """Handle CONNECT method for HTTPS tunneling.

        When a client sets http_proxy/https_proxy and requests an HTTPS URL,
        it sends: CONNECT github.com:443 HTTP/1.1
        We establish a TCP connection to the target and relay bytes both ways.
        """
        host_port = self.path
        try:
            host, port = host_port.rsplit(":", 1)
            port = int(port)
        except ValueError:
            self.send_error(400, f"Bad CONNECT target: {host_port}")
            return

        self.log_message("CONNECT tunnel to %s:%d", host, port)

        try:
            # Connect to the remote server
            remote = socket.create_connection((host, port), timeout=30)
        except Exception as e:
            self.send_error(502, f"Cannot connect to {host}:{port}: {e}")
            return

        # Tell the client the tunnel is established
        self.send_response(200, "Connection Established")
        self.end_headers()

        # Relay bytes between client and remote
        client_sock = self.connection
        client_sock.setblocking(False)
        remote.setblocking(False)

        try:
            while True:
                rlist, _, xlist = select.select(
                    [client_sock, remote], [], [client_sock, remote], 120)

                if xlist:
                    break

                if not rlist:
                    # Timeout -- close the tunnel
                    break

                for sock in rlist:
                    try:
                        data = sock.recv(65536)
                    except (BlockingIOError, ssl.SSLWantReadError):
                        continue
                    except Exception:
                        data = b""

                    if not data:
                        # Connection closed
                        remote.close()
                        return

                    if sock is client_sock:
                        remote.sendall(data)
                    else:
                        client_sock.sendall(data)
        except Exception:
            pass
        finally:
            try:
                remote.close()
            except Exception:
                pass

    def log_message(self, format, *args):
        ts = time.strftime("%H:%M:%S")
        sys.stderr.write(f"[proxy {ts}] {format % args}\n")


class ThreadedHTTPServer(http.server.HTTPServer):
    """HTTP server that handles each request in a new thread."""
    allow_reuse_address = True

    def process_request(self, request, client_address):
        t = threading.Thread(target=self._handle, args=(request, client_address))
        t.daemon = True
        t.start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def main():
    parser = argparse.ArgumentParser(description="sotOS HTTPS Proxy")
    parser.add_argument("--port", "-p", type=int, default=8080,
                        help="Port to listen on (default: 8080)")
    args = parser.parse_args()

    server = ThreadedHTTPServer(("0.0.0.0", args.port), HTTPSProxyHandler)
    print(f"sotOS HTTPS proxy listening on port {args.port}")
    print(f"")
    print(f"Mode 1 (URL rewriting):")
    print(f"  wget http://10.0.2.2:{args.port}/https://example.com/")
    print(f"")
    print(f"Mode 2 (HTTP proxy -- preferred for git/wget/curl):")
    print(f"  export http_proxy=http://10.0.2.2:{args.port}")
    print(f"  export https_proxy=http://10.0.2.2:{args.port}")
    print(f"  git clone https://github.com/user/repo.git")
    print(f"")
    print(f"Supports: GET, POST, HEAD, PUT, CONNECT (TLS tunnel)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
