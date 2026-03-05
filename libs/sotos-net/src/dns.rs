//! Minimal DNS resolver — A-record queries only.
//!
//! Builds a standard DNS query for a hostname and parses the response
//! to extract the first A record (IPv4 address).

/// Build a DNS A-record query for `name` into `buf`.
/// Returns the total query length, or 0 on error.
pub fn build_query(name: &[u8], buf: &mut [u8]) -> usize {
    // DNS header: 12 bytes
    // Question: encoded name + 4 bytes (QTYPE + QCLASS)
    if name.is_empty() || buf.len() < 12 + name.len() + 6 {
        return 0;
    }

    // Transaction ID.
    buf[0] = 0xDE;
    buf[1] = 0xAD;
    // Flags: standard query, recursion desired.
    buf[2] = 0x01; // QR=0, Opcode=0, RD=1
    buf[3] = 0x00;
    // QDCOUNT = 1.
    buf[4] = 0x00;
    buf[5] = 0x01;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0.
    for i in 6..12 {
        buf[i] = 0;
    }

    // Encode domain name: "example.com" → \x07example\x03com\x00
    let mut pos = 12;
    let mut label_start = pos;
    pos += 1; // Skip length byte (filled later).

    for &b in name.iter() {
        if b == b'.' {
            let label_len = pos - label_start - 1;
            if label_len == 0 || label_len > 63 {
                return 0;
            }
            buf[label_start] = label_len as u8;
            label_start = pos;
            pos += 1;
        } else {
            if pos >= buf.len() {
                return 0;
            }
            buf[pos] = b;
            pos += 1;
        }
    }
    // Final label.
    let label_len = pos - label_start - 1;
    if label_len == 0 || label_len > 63 {
        return 0;
    }
    buf[label_start] = label_len as u8;

    // Null terminator for name.
    if pos >= buf.len() {
        return 0;
    }
    buf[pos] = 0;
    pos += 1;

    // QTYPE = A (1).
    if pos + 4 > buf.len() {
        return 0;
    }
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    // QCLASS = IN (1).
    buf[pos + 2] = 0x00;
    buf[pos + 3] = 0x01;
    pos += 4;

    pos
}

/// Parse a DNS response and extract the first A-record IP address.
/// Returns `Some(ip)` as a big-endian u32, or `None` if not found.
pub fn parse_response(data: &[u8]) -> Option<u32> {
    if data.len() < 12 {
        return None;
    }

    // Check this is a response (QR=1).
    if data[2] & 0x80 == 0 {
        return None;
    }

    // Check RCODE (lower 4 bits of byte 3) is 0 (no error).
    if data[3] & 0x0F != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if ancount == 0 {
        return None;
    }

    // Skip past the question section.
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(data, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return None;
        }
    }

    // Parse answer records.
    for _ in 0..ancount {
        pos = skip_name(data, pos)?;
        if pos + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        // TTL: 4 bytes.
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            return None;
        }

        if rtype == 1 && rdlength == 4 {
            // A record — 4-byte IPv4 address.
            let ip = u32::from_be_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            ]);
            return Some(ip);
        }

        pos += rdlength;
    }

    None
}

/// Skip a DNS name (handles compression pointers).
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    if pos >= data.len() {
        return None;
    }
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total.
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}
