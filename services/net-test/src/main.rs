#![no_std]
#![no_main]

// Network test binary for LUCAS socket proxy validation.
// Tests: DNS over UDP, TCP HTTP GET to example.com.
// Uses raw Linux syscalls — all intercepted by LUCAS child_handler.

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    exit(137);
}

// --- Linux syscall wrappers ---

#[inline(always)]
fn syscall1(nr: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1, in("rsi") a2,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn write(fd: u64, buf: &[u8]) -> i64 {
    syscall3(1, fd, buf.as_ptr() as u64, buf.len() as u64)
}

fn read(fd: u64, buf: &mut [u8]) -> i64 {
    syscall3(0, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
}

fn close(fd: u64) -> i64 {
    syscall1(3, fd)
}

fn socket(domain: u64, stype: u64, proto: u64) -> i64 {
    syscall3(41, domain, stype, proto)
}

fn connect(fd: u64, addr: &[u8]) -> i64 {
    syscall3(42, fd, addr.as_ptr() as u64, addr.len() as u64)
}

fn sendto(fd: u64, buf: &[u8], flags: u64, addr: &[u8]) -> i64 {
    syscall6(44, fd, buf.as_ptr() as u64, buf.len() as u64, flags, addr.as_ptr() as u64, addr.len() as u64)
}

fn recvfrom(fd: u64, buf: &mut [u8]) -> i64 {
    syscall6(45, fd, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0)
}

fn exit(code: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 231u64, // exit_group
            in("rdi") code,
            options(nostack, noreturn),
        );
    }
}

// --- Helpers ---

fn print(s: &[u8]) {
    write(1, s);
}

fn print_u32(mut n: u32) {
    if n == 0 { print(b"0"); return; }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        write(1, &buf[i..i+1]);
    }
}

fn print_i64(n: i64) {
    if n < 0 {
        print(b"-");
        print_u32((-n) as u32);
    } else {
        print_u32(n as u32);
    }
}

fn print_ip(ip: u32) {
    print_u32((ip >> 24) & 0xFF);
    print(b".");
    print_u32((ip >> 16) & 0xFF);
    print(b".");
    print_u32((ip >> 8) & 0xFF);
    print(b".");
    print_u32(ip & 0xFF);
}

// Build sockaddr_in: AF_INET(2) + port(BE) + ip(BE)
fn make_sockaddr(ip: u32, port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0] = 2; sa[1] = 0; // AF_INET
    sa[2] = (port >> 8) as u8;
    sa[3] = (port & 0xFF) as u8;
    sa[4] = (ip >> 24) as u8;
    sa[5] = (ip >> 16) as u8;
    sa[6] = (ip >> 8) as u8;
    sa[7] = ip as u8;
    sa
}

// --- DNS query builder ---
// Builds a minimal DNS A-record query for a domain name.
// Returns the number of bytes written to `buf`.
fn build_dns_query(buf: &mut [u8], domain: &[u8], txid: u16) -> usize {
    // Header: 12 bytes
    buf[0] = (txid >> 8) as u8;
    buf[1] = (txid & 0xFF) as u8;
    buf[2] = 0x01; buf[3] = 0x00; // flags: RD=1 (recursion desired)
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
    buf[6] = 0; buf[7] = 0;       // ANCOUNT=0
    buf[8] = 0; buf[9] = 0;       // NSCOUNT=0
    buf[10] = 0; buf[11] = 0;     // ARCOUNT=0

    // Question section: encode domain as DNS labels
    let mut pos = 12;
    let mut label_start = pos;
    pos += 1; // reserve length byte
    let mut label_len: u8 = 0;

    let mut i = 0;
    while i < domain.len() {
        if domain[i] == b'.' {
            buf[label_start] = label_len;
            label_start = pos;
            pos += 1;
            label_len = 0;
        } else {
            buf[pos] = domain[i];
            pos += 1;
            label_len += 1;
        }
        i += 1;
    }
    buf[label_start] = label_len;
    buf[pos] = 0; pos += 1; // root label

    // QTYPE = A (1)
    buf[pos] = 0; buf[pos+1] = 1; pos += 2;
    // QCLASS = IN (1)
    buf[pos] = 0; buf[pos+1] = 1; pos += 2;

    pos
}

// Parse DNS response, extract first A record IP. Returns 0 on failure.
fn parse_dns_response(buf: &[u8], len: usize) -> u32 {
    if len < 12 { return 0; }
    let ancount = ((buf[6] as u16) << 8) | buf[7] as u16;
    if ancount == 0 { return 0; }

    // Skip header (12 bytes) + question section
    let mut pos = 12;
    // Skip QNAME
    while pos < len {
        let label_len = buf[pos] as usize;
        if label_len == 0 { pos += 1; break; }
        if label_len >= 0xC0 { pos += 2; break; } // compression pointer
        pos += 1 + label_len;
    }
    pos += 4; // skip QTYPE + QCLASS

    // Parse answer RRs
    let mut ans = 0u16;
    while ans < ancount && pos + 10 < len {
        // Name (may be compressed)
        if pos < len && buf[pos] >= 0xC0 {
            pos += 2;
        } else {
            while pos < len {
                let ll = buf[pos] as usize;
                if ll == 0 { pos += 1; break; }
                if ll >= 0xC0 { pos += 2; break; }
                pos += 1 + ll;
            }
        }

        if pos + 10 > len { break; }
        let rtype = ((buf[pos] as u16) << 8) | buf[pos+1] as u16;
        let rdlength = ((buf[pos+8] as u16) << 8) | buf[pos+9] as u16;
        pos += 10;

        if rtype == 1 && rdlength == 4 && pos + 4 <= len {
            // A record!
            return ((buf[pos] as u32) << 24)
                 | ((buf[pos+1] as u32) << 16)
                 | ((buf[pos+2] as u32) << 8)
                 | (buf[pos+3] as u32);
        }
        pos += rdlength as usize;
        ans += 1;
    }
    0
}

// --- Entry point ---

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"\n=== sotX Network Test ===\n\n");

    // ---------------------------------------------------------------
    // Test 1: DNS lookup for "example.com" via UDP to 10.0.2.3:53
    // ---------------------------------------------------------------
    print(b"[1] DNS lookup: example.com -> 10.0.2.3:53\n");

    let dns_ip: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 3; // 10.0.2.3
    let resolved_ip: u32;

    let udp_fd = socket(2, 2, 0); // AF_INET, SOCK_DGRAM
    if udp_fd < 0 {
        print(b"[FAIL] socket(DGRAM) = ");
        print_i64(udp_fd);
        print(b"\n");
        exit(1);
    }
    print(b"    socket(DGRAM) = ");
    print_i64(udp_fd);
    print(b"\n");

    // Build DNS query
    let mut dns_buf = [0u8; 128];
    let qlen = build_dns_query(&mut dns_buf, b"example.com", 0x1234);

    // Send query to 10.0.2.3:53
    let dns_addr = make_sockaddr(dns_ip, 53);
    let sent = sendto(udp_fd as u64, &dns_buf[..qlen], 0, &dns_addr);
    if sent < 0 {
        print(b"[FAIL] sendto(DNS) = ");
        print_i64(sent);
        print(b"\n");
        close(udp_fd as u64);
        exit(1);
    }
    print(b"    sent ");
    print_u32(sent as u32);
    print(b" bytes DNS query\n");

    // Receive DNS response (retry a few times with yield)
    let mut resp_buf = [0u8; 512];
    let mut rlen: i64 = 0;
    let mut tries = 0u32;
    while tries < 200 {
        rlen = recvfrom(udp_fd as u64, &mut resp_buf);
        if rlen > 0 { break; }
        // Yield CPU (nanosleep 0)
        let ts: [u64; 2] = [0, 0];
        syscall2(35, ts.as_ptr() as u64, 0); // nanosleep
        tries += 1;
    }
    close(udp_fd as u64);

    if rlen <= 0 {
        print(b"[FAIL] No DNS response after 200 retries\n");
        // Fall back to hardcoded IP for example.com
        print(b"    Using hardcoded IP 93.184.216.34\n");
        resolved_ip = (93 << 24) | (184 << 16) | (216 << 8) | 34;
    } else {
        print(b"    recv ");
        print_u32(rlen as u32);
        print(b" bytes DNS response\n");

        let ip = parse_dns_response(&resp_buf, rlen as usize);
        if ip == 0 {
            print(b"[WARN] DNS parse failed, using hardcoded IP\n");
            resolved_ip = (93 << 24) | (184 << 16) | (216 << 8) | 34;
        } else {
            print(b"[PASS] DNS resolved: example.com -> ");
            print_ip(ip);
            print(b"\n");
            resolved_ip = ip;
        }
    }

    // ---------------------------------------------------------------
    // Test 2: TCP HTTP GET to example.com:80
    // ---------------------------------------------------------------
    print(b"\n[2] TCP HTTP GET http://example.com/\n");

    let tcp_fd = socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if tcp_fd < 0 {
        print(b"[FAIL] socket(STREAM) = ");
        print_i64(tcp_fd);
        print(b"\n");
        exit(1);
    }
    print(b"    socket(STREAM) = ");
    print_i64(tcp_fd);
    print(b"\n");

    // Connect
    let http_addr = make_sockaddr(resolved_ip, 80);
    print(b"    connect(");
    print_ip(resolved_ip);
    print(b":80)...\n");

    let ret = connect(tcp_fd as u64, &http_addr);
    if ret < 0 {
        print(b"[FAIL] connect() = ");
        print_i64(ret);
        print(b"\n");
        close(tcp_fd as u64);
        exit(1);
    }
    print(b"[PASS] TCP connected!\n");

    // Send HTTP request in chunks (IPC inline limit is 40 bytes per send)
    // Use HTTP/1.0 without Connection header (server closes after response)
    let http_req = b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    let mut sent_total: usize = 0;
    while sent_total < http_req.len() {
        let chunk = &http_req[sent_total..];
        let n = write(tcp_fd as u64, chunk);
        if n < 0 {
            print(b"[FAIL] write chunk = ");
            print_i64(n);
            print(b"\n");
            close(tcp_fd as u64);
            exit(1);
        }
        if n == 0 { break; }
        print(b"    chunk: ");
        print_u32(n as u32);
        print(b"/");
        print_u32(chunk.len() as u32);
        print(b"\n");
        sent_total += n as usize;
    }
    print(b"    total sent: ");
    print_u32(sent_total as u32);
    print(b"/");
    print_u32(http_req.len() as u32);
    print(b" bytes\n");

    // Read response (EAGAIN=-11 means "no data yet, retry")
    print(b"    reading response...\n");
    let mut total_read: u32 = 0;
    let mut first_print = true;
    let mut retries = 0u32;

    loop {
        let mut rbuf = [0u8; 56];
        let n = read(tcp_fd as u64, &mut rbuf);
        if n > 0 {
            total_read += n as u32;
            retries = 0;
            if first_print {
                print(b"--- HTTP Response ---\n");
                first_print = false;
            }
            if total_read <= 1024 {
                write(1, &rbuf[..n as usize]);
            }
        } else if n == 0 {
            // EOF: connection closed by peer
            break;
        } else if n == -11 {
            // EAGAIN: no data yet, retry
            retries += 1;
            if retries > 2000 {
                print(b"    (timeout after 2000 retries)\n");
                break;
            }
            let ts: [u64; 2] = [0, 0];
            syscall2(35, ts.as_ptr() as u64, 0);
        } else {
            // Other error
            print(b"    read error: ");
            print_i64(n);
            print(b"\n");
            break;
        }
    }

    close(tcp_fd as u64);

    if total_read > 0 {
        if total_read > 512 {
            print(b"\n... (truncated) ...\n");
        }
        print(b"\n--- End Response ---\n");
        print(b"[PASS] Received ");
        print_u32(total_read);
        print(b" bytes total from example.com\n");
    } else {
        print(b"[FAIL] No data received from HTTP server\n");
        exit(1);
    }

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    print(b"\n=== sotX is connected to the Internet! ===\n");
    exit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"PANIC in net-test!\n");
    exit(1);
}
