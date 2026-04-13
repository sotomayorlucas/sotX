//! Segmented colored shell prompt with ANSI SGR truecolor escapes.
//!
//! Renders a prompt buffer consisting of `user@host`, an abbreviated `cwd`,
//! and a final chevron glyph that is green on success and red on failure.
//!
//! Colors come from the canonical Tokyo Night palette, copied locally here
//! to keep the shell self-contained. Unit 22 will consolidate these into
//! `sotos-theme`.
//!
//! Design constraints:
//! - `#![no_std]`, no heap, no `format!`. All output built into a single
//!   fixed-size static buffer.
//! - `$PS1`, if set, is rendered verbatim and the segmented layout is skipped.
//! - Every returned slice ends in `\x1b[0m ` (reset + trailing space).

use crate::env::env_get;

// ---------------------------------------------------------------------------
// Tokyo Night palette (truecolor -- copied from
// services/compositor/src/decorations.rs:68 `TOKYO_NIGHT`).
// Unit 22 will consolidate these into a shared theme module.
// ---------------------------------------------------------------------------

/// TN blue -- `#7AA2F7` -- used for `user@host`.
const TN_BLUE: &[u8] = b"\x1b[38;2;122;162;247m";
/// TN cyan -- `#7DCFFF` -- used for the cwd segment.
const TN_CYAN: &[u8] = b"\x1b[38;2;125;207;255m";
/// TN green -- `#9ECE6A` -- used for the success chevron.
const TN_GREEN: &[u8] = b"\x1b[38;2;158;206;106m";
/// TN red -- `#F7768E` -- used for the failure chevron.
const TN_RED: &[u8] = b"\x1b[38;2;247;118;142m";
/// TN foreground -- `#C0CAF5` -- used for the ASCII startup banner.
pub const TN_FG: &[u8] = b"\x1b[38;2;192;202;245m";
/// TN purple -- `#BB9AF7` -- used for banner accent.
const TN_PURPLE: &[u8] = b"\x1b[38;2;187;154;247m";
/// TN dark-fg -- `#565F89` -- used for dim text.
const TN_DIM: &[u8] = b"\x1b[38;2;86;95;137m";
/// SGR reset.
const RESET: &[u8] = b"\x1b[0m";

// ---------------------------------------------------------------------------
// Static prompt scratch buffer
// ---------------------------------------------------------------------------

/// Scratch buffer for the rendered prompt. Large enough for truecolor escapes
/// (each ~19 bytes) plus user@host, a 40-char cwd, and punctuation.
const PROMPT_BUF_LEN: usize = 256;
static mut PROMPT_BUF: [u8; PROMPT_BUF_LEN] = [0u8; PROMPT_BUF_LEN];

// ---------------------------------------------------------------------------
// Render prompt
// ---------------------------------------------------------------------------

/// Build and return the rendered prompt as a static byte slice.
///
/// `last_exit` selects the chevron color: zero yields the green chevron,
/// non-zero yields the red chevron. `cwd` is the caller's current directory
/// (already obtained via `getcwd`); it is abbreviated and length-clamped
/// before rendering.
///
/// If `$PS1` is set in the shell environment, it is returned verbatim with
/// no further processing. Otherwise a segmented Tokyo Night prompt is
/// rendered.
pub fn render_prompt(last_exit: i32, cwd: &[u8]) -> &'static [u8] {
    // Honor $PS1 verbatim if set.
    if let Some(ps1) = env_get(b"PS1") {
        return copy_to_buf(ps1);
    }

    let mut w = Writer::new();

    // Segment 1: user@host in TN blue.
    w.put(TN_BLUE);
    let user = env_get(b"USER").unwrap_or(b"root");
    let host = env_get(b"HOSTNAME").unwrap_or(b"sotos");
    w.put(user);
    w.put(b"@");
    w.put(host);

    // Segment 2: abbreviated cwd in TN cyan.
    w.put(b" ");
    w.put(TN_CYAN);
    let mut cwd_tmp = [0u8; 40];
    let cwd_slice = abbreviate_cwd(cwd, &mut cwd_tmp);
    w.put(cwd_slice);

    // Segment 3: exit-status chevron.
    w.put(b" ");
    if last_exit == 0 {
        w.put(TN_GREEN);
    } else {
        w.put(TN_RED);
    }
    // UTF-8 for U+276F HEAVY RIGHT-POINTING ANGLE QUOTATION MARK.
    w.put(b"\xE2\x9D\xAF");

    // Reset + trailing space so the cursor sits one column after the chevron.
    w.put(RESET);
    w.put(b" ");

    w.finish()
}

// ---------------------------------------------------------------------------
// Startup banner
// ---------------------------------------------------------------------------

/// Print the startup banner to serial via the caller's `print` function.
/// Uses Tokyo Night colors for a clean, compact ASCII logo.
///
/// Layout:
///   - Small stylized "LUCAS" wordmark in purple
///   - Version + OS tagline in foreground color
///   - Hint line in dim color
///   - Blank line separator before the first prompt
pub fn print_banner(print_fn: fn(&[u8])) {
    print_fn(b"\n");
    print_fn(TN_PURPLE);
    print_fn(b"  _    _   _  ___   _   ___\n");
    print_fn(b" | |  | | | |/ __| /_\\ / __|\n");
    print_fn(b" | |__| |_| | (__ / _ \\\\__ \\\n");
    print_fn(b" |____|\\___/ \\___/_/ \\_\\___/\n");

    print_fn(TN_FG);
    print_fn(b"  v0.3 ");
    print_fn(TN_DIM);
    print_fn(b"\xE2\x80\x94 sotX microkernel shell\n"); // U+2014 em dash
    print_fn(TN_DIM);
    print_fn(b"  Type \"help\" for commands\n");
    print_fn(RESET);
    print_fn(b"\n");
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Abbreviate `cwd`:
/// - Replace a leading `$HOME` match (or `/home/<user>`) with `~`.
/// - Truncate to `out.len()` bytes, prefixing `...` if truncation occurs.
///
/// Returns the prefix of `out` that was written.
fn abbreviate_cwd<'a>(cwd: &[u8], out: &'a mut [u8; 40]) -> &'a [u8] {
    // Find a suffix that replaces the "home" prefix with a literal "~".
    let mut rest: &[u8] = cwd;
    let mut prefix_tilde = false;

    if let Some(home) = env_get(b"HOME") {
        if !home.is_empty() && cwd.len() >= home.len() && &cwd[..home.len()] == home {
            let tail = &cwd[home.len()..];
            // Only collapse when the match is a path-component boundary.
            if tail.is_empty() || tail[0] == b'/' {
                rest = tail;
                prefix_tilde = true;
            }
        }
    }
    if !prefix_tilde && cwd.len() >= 6 && &cwd[..6] == b"/home/" {
        // Fallback: /home/<anything>[/...] -> ~[...]
        let after = &cwd[6..];
        let mut i = 0;
        while i < after.len() && after[i] != b'/' {
            i += 1;
        }
        rest = &after[i..];
        prefix_tilde = true;
    }

    let tilde_len = if prefix_tilde { 1 } else { 0 };
    let total = tilde_len + rest.len();

    // Empty cwd -> show "/".
    if total == 0 {
        out[0] = b'/';
        return &out[..1];
    }

    // Fits as-is.
    if total <= out.len() {
        if prefix_tilde {
            out[0] = b'~';
        }
        out[tilde_len..total].copy_from_slice(rest);
        return &out[..total];
    }

    // Truncation: "..." + the last (out.len() - 3) bytes of the tilde-expanded path.
    out[0] = b'.';
    out[1] = b'.';
    out[2] = b'.';
    let tail_len = out.len() - 3;
    let skip = rest.len() - tail_len;
    out[3..3 + tail_len].copy_from_slice(&rest[skip..]);
    &out[..]
}

/// Copy `src` into the static prompt buffer and return it. Used for the
/// `$PS1` verbatim path.
fn copy_to_buf(src: &[u8]) -> &'static [u8] {
    let mut w = Writer::new();
    w.put(src);
    w.finish()
}

/// Byte writer over `PROMPT_BUF` that silently saturates at the buffer end.
struct Writer {
    len: usize,
}

impl Writer {
    fn new() -> Self {
        Self { len: 0 }
    }

    fn put(&mut self, s: &[u8]) {
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(PROMPT_BUF) };
        let take = s.len().min(buf.len() - self.len);
        buf[self.len..self.len + take].copy_from_slice(&s[..take]);
        self.len += take;
    }

    fn finish(self) -> &'static [u8] {
        let buf = unsafe { &*core::ptr::addr_of!(PROMPT_BUF) };
        &buf[..self.len]
    }
}
