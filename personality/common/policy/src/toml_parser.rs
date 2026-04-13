//! Minimal policy file parser for sotX .policy files.
//!
//! Parses a subset of TOML sufficient for policy definitions:
//! - `[section]` headers
//! - `key = "string"` / `key = true` / `key = false` / `key = 123`
//! - `key = ["item1", "item2"]` (string arrays)
//! - `#` line comments
//!
//! No external dependencies -- pure `no_std` + `core`.

use crate::exec_policy::{CompromiseAction, ResolvedExecPolicy};

/// Errors from policy parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// An unknown section header was encountered.
    UnknownSection,
    /// An unknown key was encountered within a section.
    UnknownKey,
    /// A value could not be parsed (wrong type, malformed, etc.).
    InvalidValue,
    /// The input is too large or a field exceeds its buffer.
    Overflow,
}

/// Parse a .policy file into a `ResolvedExecPolicy`.
///
/// The input is a byte slice containing TOML-like text. Example:
///
/// ```text
/// [binary]
/// path = "/usr/sbin/nginx"
///
/// [domain_defaults]
/// network = false
/// max_capabilities = 32
///
/// [on_exec]
/// inherit = false
/// network = true
/// fs_read = ["/etc/nginx", "/var/www"]
/// fs_write = ["/var/log/nginx"]
/// max_memory = 32768
///
/// [on_compromise]
/// action = "migrate"
/// alert = true
/// ```
pub fn parse_policy(input: &[u8]) -> Result<ResolvedExecPolicy, ParseError> {
    let mut policy = ResolvedExecPolicy::default_restrictive();
    let mut section = Section::None;

    let mut pos = 0;
    while pos < input.len() {
        // Find end of current line.
        let line_end = find_newline(input, pos);
        let line = trim_bytes(&input[pos..line_end]);
        pos = skip_past_newline(input, line_end);

        // Skip empty lines and comments.
        if line.is_empty() || line[0] == b'#' {
            continue;
        }

        // Section header?
        if line[0] == b'[' {
            section = parse_section(line)?;
            continue;
        }

        // Key = value pair.
        let (key, value) = split_kv(line)?;

        match section {
            Section::None => {
                // Top-level keys not in a section are ignored.
            }
            Section::Binary => {
                // Binary identity fields -- informational, not stored in policy.
                match key {
                    b"path" | b"hash" => { /* accepted but not stored in ResolvedExecPolicy */ }
                    _ => return Err(ParseError::UnknownKey),
                }
            }
            Section::DomainDefaults => {
                apply_domain_defaults(&mut policy, key, value)?;
            }
            Section::OnExec => {
                apply_on_exec(&mut policy, key, value)?;
            }
            Section::OnCompromise => {
                apply_on_compromise(&mut policy, key, value)?;
            }
        }
    }

    Ok(policy)
}

// ── Internals ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Section {
    None,
    Binary,
    DomainDefaults,
    OnExec,
    OnCompromise,
}

fn parse_section(line: &[u8]) -> Result<Section, ParseError> {
    // Strip brackets: "[section_name]" -> "section_name"
    if line.len() < 3 || line[line.len() - 1] != b']' {
        return Err(ParseError::UnknownSection);
    }
    let name = trim_bytes(&line[1..line.len() - 1]);
    match name {
        b"binary" => Ok(Section::Binary),
        b"domain_defaults" => Ok(Section::DomainDefaults),
        b"on_exec" => Ok(Section::OnExec),
        b"on_compromise" => Ok(Section::OnCompromise),
        _ => Err(ParseError::UnknownSection),
    }
}

fn split_kv(line: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let eq_pos = match memchr_byte(b'=', line) {
        Some(p) => p,
        None => return Err(ParseError::InvalidValue),
    };
    let key = trim_bytes(&line[..eq_pos]);
    let value = trim_bytes(&line[eq_pos + 1..]);
    if key.is_empty() || value.is_empty() {
        return Err(ParseError::InvalidValue);
    }
    Ok((key, value))
}

fn apply_domain_defaults(
    policy: &mut ResolvedExecPolicy,
    key: &[u8],
    value: &[u8],
) -> Result<(), ParseError> {
    match key {
        b"network" => policy.network_allowed = parse_bool(value)?,
        b"fs_write" => policy.fs_write_allowed = parse_bool(value)?,
        b"max_capabilities" => policy.max_capabilities = parse_u32(value)?,
        b"max_child_domains" => policy.max_child_domains = parse_u32(value)?,
        b"max_memory" => policy.max_memory_pages = parse_u32(value)?,
        b"fs_read" => parse_path_array(value, &mut policy.fs_read_paths, &mut policy.fs_read_count)?,
        _ => return Err(ParseError::UnknownKey),
    }
    Ok(())
}

fn apply_on_exec(
    policy: &mut ResolvedExecPolicy,
    key: &[u8],
    value: &[u8],
) -> Result<(), ParseError> {
    match key {
        b"inherit" => { let _ = parse_bool(value)?; /* informational */ }
        b"network" => policy.network_allowed = parse_bool(value)?,
        b"fs_read" => parse_path_array(value, &mut policy.fs_read_paths, &mut policy.fs_read_count)?,
        b"fs_write" => {
            // Can be bool or array. Try array first.
            if !value.is_empty() && value[0] == b'[' {
                policy.fs_write_allowed = true;
                parse_path_array(value, &mut policy.fs_write_paths, &mut policy.fs_write_count)?;
            } else {
                policy.fs_write_allowed = parse_bool(value)?;
            }
        }
        b"listen_ports" => { /* accepted, not yet enforced */ }
        b"max_memory" => policy.max_memory_pages = parse_u32(value)?,
        b"max_capabilities" => policy.max_capabilities = parse_u32(value)?,
        b"max_child_domains" => policy.max_child_domains = parse_u32(value)?,
        b"ipc_targets" => parse_name_array(value, &mut policy.ipc_targets, &mut policy.ipc_target_count)?,
        _ => return Err(ParseError::UnknownKey),
    }
    Ok(())
}

fn apply_on_compromise(
    policy: &mut ResolvedExecPolicy,
    key: &[u8],
    value: &[u8],
) -> Result<(), ParseError> {
    match key {
        b"action" => {
            let s = parse_string(value)?;
            policy.on_compromise = match s {
                b"kill" => CompromiseAction::Kill,
                b"migrate" => CompromiseAction::MigrateToDeception,
                b"alert" => CompromiseAction::Alert,
                b"ignore" => CompromiseAction::Ignore,
                _ => return Err(ParseError::InvalidValue),
            };
        }
        b"alert" => { let _ = parse_bool(value)?; /* informational */ }
        _ => return Err(ParseError::UnknownKey),
    }
    Ok(())
}

// ── Value parsers ──────────────────────────────────────────────────

fn parse_bool(value: &[u8]) -> Result<bool, ParseError> {
    match value {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err(ParseError::InvalidValue),
    }
}

fn parse_u32(value: &[u8]) -> Result<u32, ParseError> {
    let mut result: u32 = 0;
    if value.is_empty() {
        return Err(ParseError::InvalidValue);
    }
    for &b in value {
        if b < b'0' || b > b'9' {
            return Err(ParseError::InvalidValue);
        }
        result = result.checked_mul(10).ok_or(ParseError::Overflow)?;
        result = result.checked_add((b - b'0') as u32).ok_or(ParseError::Overflow)?;
    }
    Ok(result)
}

/// Parse a quoted string value, returning the inner bytes (without quotes).
fn parse_string(value: &[u8]) -> Result<&[u8], ParseError> {
    if value.len() < 2 || value[0] != b'"' || value[value.len() - 1] != b'"' {
        return Err(ParseError::InvalidValue);
    }
    Ok(&value[1..value.len() - 1])
}

/// Parse `["item1", "item2"]` into a fixed-size array of byte buffers.
fn parse_array_into<const N: usize>(
    value: &[u8],
    slots: &mut [[u8; N]],
    count: &mut usize,
) -> Result<(), ParseError> {
    let items = parse_string_array(value)?;
    *count = 0;
    for item in &items {
        if let Some(s) = item {
            if *count >= slots.len() {
                return Err(ParseError::Overflow);
            }
            let len = if s.1 > N { N } else { s.1 };
            slots[*count] = [0u8; N];
            slots[*count][..len].copy_from_slice(&s.0[..len]);
            *count += 1;
        }
    }
    Ok(())
}

/// Alias: parse string array into 128-byte path slots.
fn parse_path_array(
    value: &[u8],
    paths: &mut [[u8; 128]],
    count: &mut usize,
) -> Result<(), ParseError> {
    parse_array_into(value, paths, count)
}

/// Alias: parse string array into 32-byte name slots.
fn parse_name_array(
    value: &[u8],
    names: &mut [[u8; 32]],
    count: &mut usize,
) -> Result<(), ParseError> {
    parse_array_into(value, names, count)
}

/// A parsed string copied into a fixed buffer, with its actual length.
struct ArrayItem([u8; 128], usize);

fn parse_string_array(value: &[u8]) -> Result<[Option<ArrayItem>; 16], ParseError> {
    const NONE: Option<ArrayItem> = None;
    let mut result = [NONE; 16];
    let mut idx = 0;

    if value.is_empty() || value[0] != b'[' || value[value.len() - 1] != b']' {
        return Err(ParseError::InvalidValue);
    }

    let inner = &value[1..value.len() - 1];
    let mut pos = 0;

    while pos < inner.len() {
        // Skip whitespace and commas.
        while pos < inner.len() && (inner[pos] == b' ' || inner[pos] == b',' || inner[pos] == b'\t') {
            pos += 1;
        }
        if pos >= inner.len() {
            break;
        }

        // Expect a quoted string.
        if inner[pos] != b'"' {
            return Err(ParseError::InvalidValue);
        }
        pos += 1; // skip opening quote

        let start = pos;
        while pos < inner.len() && inner[pos] != b'"' {
            pos += 1;
        }
        if pos >= inner.len() {
            return Err(ParseError::InvalidValue);
        }

        let len = pos - start;
        if idx >= 16 {
            return Err(ParseError::Overflow);
        }
        let mut buf = [0u8; 128];
        let copy_len = if len > 128 { 128 } else { len };
        buf[..copy_len].copy_from_slice(&inner[start..start + copy_len]);
        result[idx] = Some(ArrayItem(buf, copy_len));
        idx += 1;

        pos += 1; // skip closing quote
    }

    Ok(result)
}

// ── Byte helpers (no alloc) ────────────────────────────────────────

fn find_newline(input: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < input.len() && input[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_past_newline(input: &[u8], line_end: usize) -> usize {
    if line_end < input.len() {
        line_end + 1
    } else {
        input.len()
    }
}

fn trim_bytes(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && is_ws(s[start]) {
        start += 1;
    }
    let mut end = s.len();
    while end > start && is_ws(s[end - 1]) {
        end -= 1;
    }
    &s[start..end]
}

fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\r'
}

fn memchr_byte(needle: u8, haystack: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        // Empty input should yield default restrictive policy.
        let policy = parse_policy(b"").unwrap();
        assert!(!policy.network_allowed);
        assert!(!policy.fs_write_allowed);
    }

    #[test]
    fn parse_nginx_policy() {
        let input = br#"
[binary]
path = "/usr/sbin/nginx"
hash = "aabbccdd"

[domain_defaults]
network = false
max_capabilities = 32

[on_exec]
inherit = false
network = true
fs_read = ["/etc/nginx", "/var/www", "/usr/lib"]
fs_write = ["/var/log/nginx", "/var/run"]
max_memory = 32768

[on_compromise]
action = "migrate"
alert = true
"#;
        let policy = parse_policy(input).unwrap();
        assert!(policy.network_allowed); // on_exec overrides domain_defaults
        assert!(policy.fs_write_allowed);
        assert_eq!(policy.fs_read_count, 3);
        assert_eq!(policy.fs_write_count, 2);
        assert_eq!(policy.max_memory_pages, 32768);
        assert_eq!(policy.max_capabilities, 32);
        assert_eq!(policy.on_compromise, CompromiseAction::MigrateToDeception);
    }

    #[test]
    fn parse_restrictive_policy() {
        let input = br#"
[domain_defaults]
network = false
fs_write = false
max_capabilities = 8

[on_compromise]
action = "kill"
alert = true
"#;
        let policy = parse_policy(input).unwrap();
        assert!(!policy.network_allowed);
        assert!(!policy.fs_write_allowed);
        assert_eq!(policy.max_capabilities, 8);
        assert_eq!(policy.on_compromise, CompromiseAction::Kill);
    }

    #[test]
    fn parse_comments_ignored() {
        let input = b"# This is a comment\n[domain_defaults]\n# another comment\nnetwork = true\n";
        let policy = parse_policy(input).unwrap();
        assert!(policy.network_allowed);
    }

    #[test]
    fn parse_bool_values() {
        assert_eq!(parse_bool(b"true"), Ok(true));
        assert_eq!(parse_bool(b"false"), Ok(false));
        assert!(parse_bool(b"yes").is_err());
    }

    #[test]
    fn parse_u32_values() {
        assert_eq!(parse_u32(b"0"), Ok(0));
        assert_eq!(parse_u32(b"4096"), Ok(4096));
        assert_eq!(parse_u32(b"32768"), Ok(32768));
        assert!(parse_u32(b"").is_err());
        assert!(parse_u32(b"abc").is_err());
    }

    #[test]
    fn parse_string_values() {
        assert_eq!(parse_string(b"\"hello\""), Ok(b"hello" as &[u8]));
        assert!(parse_string(b"hello").is_err());
        assert!(parse_string(b"\"").is_err());
    }

    #[test]
    fn parse_ipc_targets() {
        let input = b"[on_exec]\nipc_targets = [\"net\", \"dns\", \"vfs\"]\nnetwork = true\n";
        let policy = parse_policy(input).unwrap();
        assert_eq!(policy.ipc_target_count, 3);
        assert_eq!(&policy.ipc_targets[0][..3], b"net");
        assert_eq!(&policy.ipc_targets[1][..3], b"dns");
        assert_eq!(&policy.ipc_targets[2][..3], b"vfs");
    }

    #[test]
    fn unknown_section_is_error() {
        let input = b"[nonexistent]\nkey = \"value\"\n";
        assert_eq!(parse_policy(input), Err(ParseError::UnknownSection));
    }

    #[test]
    fn unknown_key_is_error() {
        let input = b"[domain_defaults]\nbad_key = true\n";
        assert_eq!(parse_policy(input), Err(ParseError::UnknownKey));
    }
}
