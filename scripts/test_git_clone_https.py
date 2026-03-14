#!/usr/bin/env python3
"""Validation: git clone over HTTPS on sotOS.

Boots sotOS with a git+SSL sysroot disk, then attempts
`git clone https://github.com/octocat/Hello-World.git /tmp/test`.
QEMU SLIRP provides internet access via 10.0.2.x gateway,
DNS resolver at 10.0.2.3.

Requires disk built with git + SSL dependencies:
  python scripts/fetch_rootfs.py --apk git --apk pcre2 --apk curl \
    --apk nghttp2 --apk libcurl --apk ca-certificates --apk brotli-libs \
    --apk c-ares --apk libidn2 --apk libunistring --apk zstd-libs \
    --apk openssl --apk libssl3 --apk libcrypto3 --disk
"""

import sys, os, time, subprocess, threading, random

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
IMAGE = "target/sotos.img"
DISK = "target/disk.img"

# Timeouts
BOOT_TIMEOUT    = 90    # seconds to wait for shell prompt
GIT_VER_TIMEOUT = 15    # seconds for git --version
CLONE_TIMEOUT   = 600   # seconds for HTTPS clone (TLS + TCG is slow)

# ---------------------------------------------------------------------------
# QEMU session
# ---------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.output = bytearray()
        self.lock = threading.Lock()
    def start(self):
        self.proc = subprocess.Popen(
            [QEMU, "-accel", "tcg,tb-size=256",
             "-drive", f"format=raw,file={IMAGE}",
             "-drive", f"if=none,format=raw,file={DISK},id=disk0",
             "-device", "virtio-blk-pci,drive=disk0,disable-modern=on",
             "-serial", "stdio", "-display", "none", "-no-reboot", "-m", "512M",
             "-netdev", "user,id=net0",
             "-device", "virtio-net-pci,netdev=net0,disable-modern=on"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
    def _read_loop(self):
        while True:
            b = self.proc.stdout.read(1)
            if not b: break
            with self.lock:
                self.output.extend(b)
    def wait_for(self, text, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            with self.lock:
                if text.encode() in self.output: return True
            time.sleep(0.1)
        return False
    def wait_for_prompt(self, timeout=30):
        return self.wait_for("$ ", timeout)
    def get_output(self):
        with self.lock: return self.output.decode('utf-8', errors='replace')
    def send(self, cmd):
        for ch in cmd:
            self.proc.stdin.write(ch.encode())
            self.proc.stdin.flush()
            time.sleep(0.05)
        self.proc.stdin.write(b'\n')
        self.proc.stdin.flush()
    def clear(self):
        with self.lock: self.output.clear()
    def stop(self):
        try: self.proc.kill()
        except: pass

# ---------------------------------------------------------------------------
# Diagnostic analysis
# ---------------------------------------------------------------------------
def analyze_output(out):
    """Parse the clone output and print structured diagnostics."""
    checks = {
        "Cloning started":     any(k in out for k in ("Cloning", "cloning")),
        "DNS resolved":        any(k in out for k in ("Resolv", "resolv", "getaddrinfo")),
        "TCP connected":       any(k in out for k in ("Connected", "connected", "connect(")),
        "TLS handshake":       any(k in out for k in ("SSL", "TLS", "ssl", "tls",
                                                       "handshake", "certificate")),
        "Auth / 401":          "401" in out,
        "HTTP redirect":       any(k in out for k in ("301", "302", "redirect")),
        "Receiving objects":   any(k in out for k in ("Receiving", "receiving",
                                                       "Counting", "Compressing")),
        "Checkout done":       any(k in out for k in ("Checking out", "checking out",
                                                       "Resolving deltas")),
        "Fatal error":         "fatal:" in out,
        "SSL/TLS error":       any(k in out for k in ("SSL_ERROR", "SSL_connect",
                                                       "server certificate",
                                                       "unable to access")),
        "DNS error":           any(k in out for k in ("Could not resolve", "could not resolve",
                                                       "Name or service not known")),
        "Connection refused":  "Connection refused" in out,
        "Timeout":             "timed out" in out.lower(),
    }

    print("\n  Diagnostic analysis:")
    for label, hit in checks.items():
        marker = "YES" if hit else "no"
        print(f"    {label:24s}: {marker}")

    # Extract fatal lines
    fatal_lines = [l.strip() for l in out.split('\n') if 'fatal:' in l]
    if fatal_lines:
        print(f"\n  Fatal messages ({len(fatal_lines)}):")
        for fl in fatal_lines[:10]:
            print(f"    {fl[:200]}")

    # Extract error lines
    error_lines = [l.strip() for l in out.split('\n')
                   if ('error:' in l.lower() or 'Error' in l) and 'fatal:' not in l]
    if error_lines:
        print(f"\n  Error messages ({len(error_lines)}):")
        for el in error_lines[:10]:
            print(f"    {el[:200]}")

    return checks

# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------
def main():
    # Pre-flight: check required files
    print("=== Pre-flight checks ===")
    for path, desc in [(IMAGE, "kernel image"), (DISK, "sysroot disk")]:
        if not os.path.exists(path):
            print(f"  FAIL: {desc} not found at {path}")
            print(f"  Build with: just build && python scripts/fetch_rootfs.py --disk")
            return 1
        sz = os.path.getsize(path)
        print(f"  {desc}: {path} ({sz / (1024*1024):.1f} MB)")

    # Boot
    print("\n=== Boot sotOS ===")
    s = Session()
    s.start()
    print("  Waiting for LUCAS shell...")
    if not s.wait_for("$", BOOT_TIMEOUT):
        print(f"  FAIL: shell not ready after {BOOT_TIMEOUT}s")
        out = s.get_output()
        print(f"  --- Last 4000 chars of output ---")
        print(out[-4000:])
        save_output(out, "boot timeout — no shell prompt")
        s.stop()
        return 1
    print("  [OK] Shell prompt detected")

    time.sleep(1)

    # Step 1: Verify git binary
    print("\n=== Step 1: Check git binary ===")
    s.clear()
    s.send("/usr/bin/git --version")
    if s.wait_for("git version", GIT_VER_TIMEOUT):
        out = s.get_output()
        for line in out.strip().split('\n'):
            if 'git version' in line:
                print(f"  {line.strip()}")
                break
        print("  [OK] git binary works")
    else:
        print("  [FAIL] git not found or crashed")
        out = s.get_output()
        print(f"  --- Output ({len(out)} chars) last 3000 ---")
        print(out[-3000:])
        save_output(out, "git --version failed")
        s.stop()
        return 1

    time.sleep(0.5)

    # Step 2: git clone over HTTPS
    s.clear()
    clone_url = "https://github.com/octocat/Hello-World.git"
    clone_dest = f"/tmp/t{random.randint(1000,9999)}"
    print(f"\n=== Step 2: git clone {clone_url} ===")

    # Try with SSL_CERT_FILE first; if TLS fails the diagnostics will show it
    # and the user can retry with GIT_SSL_NO_VERIFY=1
    cmd = (f"HOME=/tmp "
           f"GIT_TRACE=2 "
           f"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt "
           f"/usr/bin/git clone {clone_url} {clone_dest}")
    print(f"  cmd: {cmd}")
    s.send(cmd)

    t0 = time.time()
    got_prompt = s.wait_for("$", CLONE_TIMEOUT)
    elapsed = time.time() - t0
    out = s.get_output()

    print(f"\n  Clone phase took {elapsed:.1f}s (timeout={CLONE_TIMEOUT}s)")
    print(f"  Shell returned: {'YES' if got_prompt else 'NO (timeout)'}")

    # Print full output
    print(f"\n  --- Clone output ({len(out)} bytes) ---")
    lines = out.strip().split('\n')
    for line in lines:
        print(f"  | {line[:200]}")
    print("  --- End ---")

    # Analyze
    checks = analyze_output(out)

    # Step 3: If clone may have succeeded, verify content
    has_fatal = checks.get("Fatal error", False)
    has_receiving = checks.get("Receiving objects", False)
    has_checkout = checks.get("Checkout done", False)

    if got_prompt and not has_fatal:
        s.clear()
        print(f"\n=== Step 3: Verify cloned content ===")
        s.send(f"ls {clone_dest}")
        if s.wait_for("README", 15):
            print("  [OK] README found in cloned repo")
            print("  ===================================")
            print("  [SUCCESS] HTTPS git clone worked!")
            print("  ===================================")
            save_output(out, "SUCCESS")
            s.stop()
            return 0
        else:
            ls_out = s.get_output()
            print(f"  README not found in ls output")
            print(f"  ls output: {ls_out[-500:]}")
    elif has_fatal:
        print(f"\n  Clone failed with fatal error (see diagnostics above)")
    else:
        print(f"\n  Clone did not complete within {CLONE_TIMEOUT}s")

    # Save diagnostics
    full_output = s.get_output()
    save_output(full_output, "clone failed or incomplete")
    s.stop()
    return 1

def save_output(output, status):
    """Save full session output to target/git_https_diag.txt for post-mortem."""
    diag_path = "target/git_https_diag.txt"
    try:
        os.makedirs("target", exist_ok=True)
        with open(diag_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"=== sotOS git clone HTTPS test ===\n")
            f.write(f"Status: {status}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Output length: {len(output)} chars\n")
            f.write(f"{'=' * 60}\n\n")
            if isinstance(output, bytes):
                f.write(output.decode('utf-8', errors='replace'))
            else:
                f.write(output)
        print(f"\n  Full output saved to {diag_path}")
    except Exception as e:
        print(f"\n  Warning: could not save diagnostics: {e}")

if __name__ == '__main__':
    sys.exit(main())
