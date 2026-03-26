use crate::syscall::*;

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

pub fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    &hay[..needle.len()] == needle
}

pub fn trim(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

pub fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a == b
}

/// Copy name into buf with NUL terminator. Returns pointer to buf.
pub fn null_terminate<'a>(name: &[u8], buf: &'a mut [u8]) -> *const u8 {
    let len = name.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&name[..len]);
    buf[len] = 0;
    buf.as_ptr()
}

/// Find the first space in a byte slice, returning the index or None.
pub fn find_space(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b' ' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse a decimal u64 from byte slice.
pub fn parse_u64_simple(s: &[u8]) -> u64 {
    let mut val: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        val = val * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    val
}

/// Find a byte in a slice.
pub fn find_byte(s: &[u8], b: u8) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b { return Some(i); }
        i += 1;
    }
    None
}

/// Find a substring in a byte slice.
pub fn find_substr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    if hay.len() < needle.len() { return None; }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle { return Some(i); }
        i += 1;
    }
    None
}

/// Check if `hay` contains `needle` as a substring.
pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if hay.len() < needle.len() { return false; }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

/// Find a pipe operator `|` outside of single/double quotes.
pub fn find_pipe_unquoted(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < s.len() {
        match s[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"'  if !in_single => in_double = !in_double,
            b'|'  if !in_single && !in_double => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Glob pattern match: supports leading `*suffix`, trailing `prefix*`, and exact match.
#[allow(dead_code)]
pub fn pattern_match(pattern: &[u8], text: &[u8]) -> bool {
    if eq(pattern, b"*") { return true; }
    if pattern.is_empty() { return text.is_empty(); }
    // "foo*" — starts with
    if pattern[pattern.len() - 1] == b'*' {
        let prefix = &pattern[..pattern.len() - 1];
        return starts_with(text, prefix);
    }
    // "*foo" — ends with
    if pattern[0] == b'*' {
        let suffix = &pattern[1..];
        return text.len() >= suffix.len() && &text[text.len() - suffix.len()..] == suffix;
    }
    // Exact match.
    eq(pattern, text)
}

/// Compare two byte slices lexicographically. Returns <0, 0, >0.
pub fn compare_bytes(a: &[u8], b: &[u8]) -> i32 {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        if a[i] != b[i] {
            return (a[i] as i32) - (b[i] as i32);
        }
    }
    (a.len() as i32) - (b.len() as i32)
}

/// Format a u64 right-aligned in a field of given width.
pub fn format_u64_right(n: u64, width: usize, buf: &mut [u8]) -> usize {
    let mut tmp = [0u8; 20];
    let mut len: usize = 0;
    let mut val = n;
    if val == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while val > 0 {
            tmp[len] = b'0' + (val % 10) as u8;
            val /= 10;
            len += 1;
        }
    }
    let padding = if width > len { width - len } else { 0 };
    let total = padding + len;
    if total > buf.len() { return 0; }
    for i in 0..padding { buf[i] = b' '; }
    for i in 0..len { buf[padding + i] = tmp[len - 1 - i]; }
    total
}

/// Convert u64 to decimal string in a fixed buffer.
pub fn u64_to_dec(mut val: u64, buf: &mut [u8; 10]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while val > 0 && i < 10 {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

/// Read from an open fd until EOF or buf full. Returns bytes read.
pub fn read_all(fd: u64, buf: &mut [u8]) -> usize {
    let mut total: usize = 0;
    loop {
        let n = linux_read(fd, buf[total..].as_mut_ptr(), buf.len() - total);
        if n <= 0 { break; }
        total += n as usize;
        if total >= buf.len() { break; }
    }
    total
}

/// Open file by name, read contents into buf, close. Returns bytes read or -1 on error.
pub fn slurp_file(name: &[u8], buf: &mut [u8]) -> i64 {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 { return -1; }
    let total = read_all(fd as u64, buf);
    linux_close(fd as u64);
    total as i64
}

/// Read a line of input (simple: no history/completion). Returns length.
pub fn read_simple_line(buf: &mut [u8]) -> usize {
    let mut pos: usize = 0;
    loop {
        let mut ch = [0u8; 1];
        let n = linux_read(0, ch.as_mut_ptr(), 1);
        if n <= 0 { continue; }
        match ch[0] {
            b'\r' | b'\n' => { print(b"\n"); return pos; }
            0x08 | 0x7F => {
                if pos > 0 { pos -= 1; print(b"\x08 \x08"); }
            }
            0x20..=0x7E => {
                if pos < buf.len() - 1 {
                    buf[pos] = ch[0];
                    pos += 1;
                    linux_write(1, &ch[0] as *const u8, 1);
                }
            }
            _ => {}
        }
    }
}

/// Open a virtual file (prefix + name), read and print response.
pub fn open_virtual_and_print(prefix: &[u8], name: &[u8], on_error: &[u8]) {
    let mut path_buf = [0u8; 64];
    let mut pos = prefix.len();
    path_buf[..pos].copy_from_slice(prefix);
    if !name.is_empty() {
        let n = name.len().min(path_buf.len() - pos - 1);
        path_buf[pos..pos + n].copy_from_slice(&name[..n]);
        pos += n;
    }
    path_buf[pos] = 0;
    let fd = linux_open(path_buf.as_ptr(), 0);
    if fd >= 0 {
        let mut buf = [0u8; 256];
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n > 0 { linux_write(1, buf.as_ptr(), n as usize); }
        linux_close(fd as u64);
    } else {
        print(on_error);
    }
}
