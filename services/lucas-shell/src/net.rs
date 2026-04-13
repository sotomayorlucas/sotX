use crate::syscall::*;
use crate::util::*;

// ---------------------------------------------------------------------------
// Networking helpers
// ---------------------------------------------------------------------------

/// Print an IPv4 address in dotted-decimal.
fn print_ip(ip: u32) {
    let bytes = ip.to_be_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 { print(b"."); }
        print_u64(b as u64);
    }
}

/// Resolve a hostname to an IP address. Tries parse_ip first, then DNS.
pub fn resolve_host(host: &[u8]) -> Option<u32> {
    if let Some(ip) = parse_ip(host) {
        return Some(ip);
    }
    // Try DNS resolution.
    let ip = linux_dns_resolve(host.as_ptr(), host.len());
    if ip != 0 {
        Some(ip as u32)
    } else {
        None
    }
}

/// Parse an IPv4 dotted-decimal address. Returns big-endian u32.
fn parse_ip(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut val: u32 = 0;
    let mut has_digit = false;

    for &b in s {
        if b >= b'0' && b <= b'9' {
            val = val * 10 + (b - b'0') as u32;
            if val > 255 { return None; }
            has_digit = true;
        } else if b == b'.' {
            if !has_digit || octet_idx >= 3 { return None; }
            octets[octet_idx] = val as u8;
            octet_idx += 1;
            val = 0;
            has_digit = false;
        } else {
            return None;
        }
    }
    if !has_digit || octet_idx != 3 { return None; }
    octets[3] = val as u8;
    Some(u32::from_be_bytes(octets))
}

/// Build a sockaddr_in structure.
fn build_sockaddr(ip: u32, port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0] = 2; // AF_INET (low byte)
    sa[1] = 0;
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip.to_be_bytes());
    sa
}

// ---------------------------------------------------------------------------
// Network commands
// ---------------------------------------------------------------------------

pub fn cmd_resolve(name: &[u8]) {
    match resolve_host(name) {
        Some(ip) => {
            print(name);
            print(b" -> ");
            print_ip(ip);
            print(b"\n");
        }
        None => {
            print(b"resolve: cannot resolve ");
            print(name);
            print(b"\n");
        }
    }
}

pub fn cmd_ping(host: &[u8]) {
    let ip = match resolve_host(host) {
        Some(ip) => ip,
        None => {
            print(b"ping: cannot resolve host\n");
            return;
        }
    };

    print(b"PING ");
    print(host);
    print(b" (");
    print_ip(ip);
    print(b") 56 data bytes\n");

    let mut sent = 0u32;
    let mut received = 0u32;

    for seq in 0..4u64 {
        sent += 1;
        let result = linux_icmp_ping(ip as u64, seq);
        if result != 0 {
            received += 1;
            let ttl = (result >> 32) as u32;
            print(b"64 bytes from ");
            print_ip(ip);
            print(b": icmp_seq=");
            print_u64(seq);
            print(b" ttl=");
            print_u64(ttl as u64);
            print(b"\n");
        } else {
            print(b"Request timeout for icmp_seq ");
            print_u64(seq);
            print(b"\n");
        }
    }

    // Statistics.
    print(b"--- ");
    print(host);
    print(b" ping statistics ---\n");
    print_u64(sent as u64);
    print(b" packets transmitted, ");
    print_u64(received as u64);
    print(b" received");
    if sent > 0 {
        let loss = ((sent - received) * 100) / sent;
        print(b", ");
        print_u64(loss as u64);
        print(b"% packet loss");
    }
    print(b"\n");
}

pub fn cmd_traceroute(host: &[u8]) {
    let ip = match resolve_host(host) {
        Some(ip) => ip,
        None => {
            print(b"traceroute: cannot resolve host\n");
            return;
        }
    };

    print(b"traceroute to ");
    print(host);
    print(b" (");
    print_ip(ip);
    print(b"), 30 hops max\n");

    for ttl in 1..=30u64 {
        // Print TTL number with padding.
        if ttl < 10 { print(b" "); }
        print_u64(ttl);
        print(b"  ");

        let result = linux_traceroute_hop(ip as u64, ttl);
        if result == 0 {
            print(b"* * *\n");
        } else {
            let hop_ip = (result & 0xFFFFFFFF) as u32;
            let reached = (result >> 32) != 0;
            print_ip(hop_ip);
            print(b"\n");
            if reached {
                break;
            }
        }
    }
}

pub fn cmd_wget(args: &[u8]) {
    // Parse options: wget [-O file] [-q] <url>
    let mut output_file: &[u8] = b"";
    let mut quiet = false;
    let mut url: &[u8] = b"";

    let mut i = 0;
    while i < args.len() {
        while i < args.len() && args[i] == b' ' { i += 1; }
        if i >= args.len() { break; }

        if i + 2 <= args.len() && args[i] == b'-' && args[i + 1] == b'O' {
            // -O filename
            i += 2;
            while i < args.len() && args[i] == b' ' { i += 1; }
            let start = i;
            while i < args.len() && args[i] != b' ' { i += 1; }
            output_file = &args[start..i];
        } else if i + 2 <= args.len() && args[i] == b'-' && args[i + 1] == b'q' {
            quiet = true;
            i += 2;
        } else {
            let start = i;
            while i < args.len() && args[i] != b' ' { i += 1; }
            url = &args[start..i];
        }
    }

    if url.is_empty() {
        print(b"usage: wget [-O file] [-q] <url>\n");
        return;
    }

    // Check for https:// — TLS requires a full crypto handshake not yet implemented
    if starts_with(url, b"https://") {
        print(b"wget: HTTPS requires TLS (not yet implemented)\n");
        print(b"hint: use http:// or a plain HTTP mirror\n");
        return;
    }

    // Parse URL: http://host[:port]/path
    if !starts_with(url, b"http://") {
        print(b"wget: unsupported protocol (use http://)\n");
        return;
    }
    let after_scheme = &url[7..]; // skip "http://"

    // Find host and path.
    let mut host_end = after_scheme.len();
    let mut path_start = after_scheme.len();
    for j in 0..after_scheme.len() {
        if after_scheme[j] == b'/' {
            host_end = j;
            path_start = j;
            break;
        }
    }
    let host = &after_scheme[..host_end];
    let path = if path_start < after_scheme.len() {
        &after_scheme[path_start..]
    } else {
        b"/" as &[u8]
    };

    // Parse host:port.
    let mut port: u16 = 80;
    let mut hostname = host;
    for j in 0..host.len() {
        if host[j] == b':' {
            hostname = &host[..j];
            port = parse_u64_simple(&host[j + 1..]) as u16;
            break;
        }
    }

    // Resolve hostname (IP or DNS).
    let ip = match resolve_host(hostname) {
        Some(ip) => ip,
        None => {
            print(b"wget: cannot resolve '");
            print(hostname);
            print(b"'\n");
            return;
        }
    };

    if !quiet {
        print(b"Connecting to ");
        print(hostname);
        print(b" (");
        print_ip(ip);
        print(b"):");
        print_u64(port as u64);
        print(b"...\n");
    }

    // Create socket.
    let fd = linux_socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if fd < 0 {
        print(b"wget: socket failed\n");
        return;
    }

    // Connect.
    let sa = build_sockaddr(ip, port);
    if linux_connect(fd as u64, sa.as_ptr(), 16) < 0 {
        print(b"wget: connect failed\n");
        linux_close(fd as u64);
        return;
    }

    if !quiet {
        print(b"HTTP request sent: GET ");
        print(path);
        print(b"\n");
    }

    // Build HTTP GET request.
    let mut req = [0u8; 512];
    let mut pos = 0;
    let prefix = b"GET ";
    req[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let plen = path.len().min(200);
    req[pos..pos + plen].copy_from_slice(&path[..plen]);
    pos += plen;
    let suffix = b" HTTP/1.0\r\nHost: ";
    req[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos += suffix.len();
    let hlen = hostname.len().min(64);
    req[pos..pos + hlen].copy_from_slice(&hostname[..hlen]);
    pos += hlen;
    let ua = b"\r\nUser-Agent: sotX-wget/1.0\r\nConnection: close\r\n\r\n";
    req[pos..pos + ua.len()].copy_from_slice(ua);
    pos += ua.len();

    // Send request — may need multiple sends for larger requests.
    let mut sent_total: usize = 0;
    while sent_total < pos {
        let chunk = (pos - sent_total).min(40); // IPC inline limit
        let sent = linux_sendto(
            fd as u64,
            req[sent_total..].as_ptr(),
            chunk as u64,
            0,
        );
        if sent <= 0 {
            print(b"wget: send failed\n");
            linux_close(fd as u64);
            return;
        }
        sent_total += sent as usize;
    }

    // Read response in chunks, accumulate into a large buffer.
    let mut response = [0u8; 8192];
    let mut resp_len: usize = 0;
    let mut consecutive_empty = 0u32;

    loop {
        let mut buf = [0u8; 56]; // IPC inline limit per recv
        let n = linux_recvfrom(fd as u64, buf.as_mut_ptr(), buf.len() as u64, 0);
        if n <= 0 {
            consecutive_empty += 1;
            if consecutive_empty > 5 || n < 0 { break; }
            continue;
        }
        consecutive_empty = 0;
        let copy_len = (n as usize).min(response.len() - resp_len);
        if copy_len == 0 { break; } // buffer full
        response[resp_len..resp_len + copy_len].copy_from_slice(&buf[..copy_len]);
        resp_len += copy_len;
    }

    linux_close(fd as u64);

    if resp_len == 0 {
        print(b"wget: empty response\n");
        return;
    }

    // Find end of HTTP headers (\r\n\r\n).
    let mut header_end: usize = 0;
    let mut body_start: usize = 0;
    for j in 0..resp_len.saturating_sub(3) {
        if response[j] == b'\r' && response[j + 1] == b'\n'
            && response[j + 2] == b'\r' && response[j + 3] == b'\n'
        {
            header_end = j;
            body_start = j + 4;
            break;
        }
    }

    // Parse status line from headers.
    if !quiet && header_end > 0 {
        let mut status_end = 0;
        while status_end < header_end && response[status_end] != b'\r' {
            status_end += 1;
        }
        print(b"Response: ");
        linux_write(1, response[..status_end].as_ptr(), status_end);
        print(b"\n");

        let headers = &response[..header_end];
        if let Some(cl) = find_header_value(headers, b"Content-Length") {
            print(b"Length: ");
            print(cl);
            print(b" bytes\n");
        }
        if let Some(ct) = find_header_value(headers, b"Content-Type") {
            print(b"Type: ");
            print(ct);
            print(b"\n");
        }
    }

    // If no body found, just use the whole response.
    if body_start == 0 {
        body_start = 0;
    }

    let body = &response[body_start..resp_len];
    let body_len = body.len();

    // Output body to file or stdout.
    if !output_file.is_empty() {
        let mut path_buf = [0u8; 128];
        let fpath = null_terminate(output_file, &mut path_buf);
        let out_fd = linux_open(fpath, 0x41); // O_WRONLY | O_CREAT
        if out_fd < 0 {
            print(b"wget: cannot create file '");
            print(output_file);
            print(b"'\n");
            linux_write(1, body.as_ptr(), body_len);
            print(b"\n");
        } else {
            linux_write(out_fd as u64, body.as_ptr(), body_len);
            linux_close(out_fd as u64);
            if !quiet {
                print(b"Saved to '");
                print(output_file);
                print(b"' (");
                print_u64(body_len as u64);
                print(b" bytes)\n");
            }
        }
    } else {
        linux_write(1, body.as_ptr(), body_len);
        if body_len > 0 && body[body_len - 1] != b'\n' {
            print(b"\n");
        }
    }

    if !quiet {
        print_u64(resp_len as u64);
        print(b" bytes total received\n");
    }
}

/// Find the value of an HTTP header (case-insensitive search for name).
fn find_header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut i: usize = 0;
    while i + name.len() + 1 < headers.len() {
        if headers[i] == b'\n' || i == 0 {
            let start = if headers[i] == b'\n' { i + 1 } else { i };
            if start + name.len() + 1 < headers.len() {
                let mut matches = true;
                for k in 0..name.len() {
                    let a = headers[start + k];
                    let b = name[k];
                    if a != b && a != (b ^ 0x20) {
                        if !(a.is_ascii_alphabetic() && b.is_ascii_alphabetic()
                            && (a & 0xDF) == (b & 0xDF)) {
                            matches = false;
                            break;
                        }
                    }
                }
                if matches && headers[start + name.len()] == b':' {
                    let mut val_start = start + name.len() + 1;
                    while val_start < headers.len() && headers[val_start] == b' ' {
                        val_start += 1;
                    }
                    let mut val_end = val_start;
                    while val_end < headers.len() && headers[val_end] != b'\r' && headers[val_end] != b'\n' {
                        val_end += 1;
                    }
                    return Some(&headers[val_start..val_end]);
                }
            }
        }
        i += 1;
    }
    None
}
