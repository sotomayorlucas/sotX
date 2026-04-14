//! Minimal framebuffer-backed line editor.
//!
//! Replaces `rustyline` for the `no_std` build. Reads PS/2 scancodes from
//! the shared `KB_RING_ADDR` buffer (written by the `kbd` / `xhci`
//! services) and echoes typed characters to the kernel debug serial via
//! `sotos_common::sys::debug_print`.
//!
//! Scope:
//! - ASCII chars, Enter finalises a line, Backspace erases the last byte.
//! - **B4c**: up/down arrow keys walk an injected `History` ring; the
//!   current buffer is replaced + redrawn. Arrow scancodes arrive as the
//!   two-byte PS/2 set-1 sequence `0xE0 0x48` (up) / `0xE0 0x50` (down).
//!
//! Ring layout (from `sotos_common`): `[write_idx: u32, read_idx: u32,
//! data: [u8; 256]]` at `KB_RING_ADDR`. Scancodes are set-1; key release
//! events have bit 7 set and are ignored.

extern crate alloc;

use alloc::string::String;

use sotos_common::sys;
use sotos_common::KB_RING_ADDR;

use crate::history::History;

/// Maximum editable line length. Anything beyond is silently dropped
/// (preserves the simplest possible control flow — no reallocation).
pub const LINE_CAP: usize = 1024;

/// PS/2 set-1 scancode constants used by the editor.
const SC_ENTER: u8 = 0x1C;
const SC_BACKSPACE: u8 = 0x0E;
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;
const SC_RELEASE_MASK: u8 = 0x80;
const SC_EXT_PREFIX: u8 = 0xE0;
const SC_UP: u8 = 0x48;
const SC_DOWN: u8 = 0x50;

/// Fixed-size editable line buffer. Using `no_std`-friendly stack storage
/// rather than `alloc::vec::Vec` keeps the line editor reentrant even if
/// the bump allocator later runs dry.
pub struct LineEditor {
    buf: [u8; LINE_CAP],
    len: usize,
    shift_held: bool,
    /// Set when we've just seen a 0xE0 prefix; the next scancode is part
    /// of an "extended" key (arrows, numpad-nav, etc).
    ext_pending: bool,
    /// Snapshot of the user's in-progress line when they start walking
    /// history — restored when the cursor returns "past newest".
    saved: Option<String>,
}

impl LineEditor {
    pub const fn new() -> Self {
        Self {
            buf: [0; LINE_CAP],
            len: 0,
            shift_held: false,
            ext_pending: false,
            saved: None,
        }
    }

    /// Display the prompt, read one line of input, return it.
    ///
    /// The returned slice borrows from the editor's internal buffer and is
    /// valid until the next `read_line` call.
    pub fn read_line(&mut self, prompt: &[u8], history: &mut History) -> &[u8] {
        write_bytes(prompt);
        self.len = 0;
        self.ext_pending = false;
        self.saved = None;
        history.reset_cursor();

        loop {
            let sc = match read_scancode() {
                Some(s) => s,
                None => {
                    sys::yield_now();
                    continue;
                }
            };

            // Extended-key prefix: next byte is the real scancode.
            if sc == SC_EXT_PREFIX {
                self.ext_pending = true;
                continue;
            }

            // Track shift state from both press (0x2A/0x36) and release
            // (0xAA/0xB6) before filtering out release events. Shift
            // scancodes are never extended, so clear the prefix first.
            if sc == SC_LSHIFT || sc == SC_RSHIFT {
                self.shift_held = true;
                self.ext_pending = false;
                continue;
            }
            if sc == (SC_LSHIFT | SC_RELEASE_MASK) || sc == (SC_RSHIFT | SC_RELEASE_MASK) {
                self.shift_held = false;
                self.ext_pending = false;
                continue;
            }
            if sc & SC_RELEASE_MASK != 0 {
                // Releases always terminate a pending extended sequence.
                self.ext_pending = false;
                continue;
            }

            // Handle extended keys (arrows). Anything we don't recognise
            // gets dropped so stray 0xE0-prefixed keys don't flood the
            // editable buffer.
            if self.ext_pending {
                self.ext_pending = false;
                match sc {
                    SC_UP => {
                        // Snapshot the in-progress line before the first
                        // walk so down-past-newest can restore it.
                        if self.saved.is_none() && history.len() > 0 {
                            if let Ok(s) = core::str::from_utf8(&self.buf[..self.len]) {
                                self.saved = Some(String::from(s));
                            }
                        }
                        let candidate = history.prev().map(String::from);
                        self.apply_history(candidate);
                    }
                    SC_DOWN => {
                        let candidate = history.next().map(String::from);
                        self.apply_history(candidate);
                    }
                    _ => {}
                }
                continue;
            }

            if sc == SC_ENTER {
                write_bytes(b"\n");
                if self.len > 0 {
                    if let Ok(s) = core::str::from_utf8(&self.buf[..self.len]) {
                        history.add(String::from(s));
                    }
                }
                self.saved = None;
                return &self.buf[..self.len];
            }
            if sc == SC_BACKSPACE {
                if self.len > 0 {
                    self.len -= 1;
                    // VT100 erase: back up one cell, overwrite with
                    // space, back up again. Pure serial-safe.
                    write_bytes(b"\x08 \x08");
                }
                continue;
            }

            if let Some(ch) = scancode_to_ascii(sc, self.shift_held) {
                if self.len < LINE_CAP {
                    self.buf[self.len] = ch;
                    self.len += 1;
                    sys::debug_print(ch);
                }
            }
        }
    }

    /// Replace the live buffer with the candidate history line (or, if
    /// `None` arrives from `next()`, the pre-walk snapshot if any). Redraws
    /// the current line using plain VT100 escapes.
    fn apply_history(&mut self, candidate: Option<String>) {
        let replacement: &str = match candidate.as_deref() {
            Some(s) => s,
            None => self.saved.as_deref().unwrap_or(""),
        };

        // Erase the current line, then re-emit the prompt + replacement.
        write_bytes(b"\r\x1b[K");
        write_bytes(PROMPT_HINT);

        self.len = 0;
        for &b in replacement.as_bytes() {
            if self.len >= LINE_CAP {
                break;
            }
            self.buf[self.len] = b;
            self.len += 1;
            sys::debug_print(b);
        }
    }
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

/// Prompt echoed after a history redraw. Kept in sync with `main.rs`'s
/// `PROMPT` constant; promote to a field on `LineEditor` if the prompt
/// ever becomes dynamic.
const PROMPT_HINT: &[u8] = b"sotsh> ";

/// Non-blocking pop of one scancode from the KB ring. Returns `None` when
/// the ring is empty. Mirrors the pattern used by `sot-launcher` and the
/// compositor — raw volatile u32 load on [head,tail], u8 payload.
fn read_scancode() -> Option<u8> {
    // Safety: the KB ring is a shared kernel/userspace page, mapped into
    // every graphical service. Volatile loads/stores are the documented
    // access pattern; the pointer is a compile-time constant.
    unsafe {
        let head_ptr = KB_RING_ADDR as *const u32;
        let tail_ptr = (KB_RING_ADDR + 4) as *const u32;
        let head = core::ptr::read_volatile(head_ptr);
        let tail = core::ptr::read_volatile(tail_ptr);
        if head == tail {
            return None;
        }
        let slot = (tail & 0xFF) as u64;
        let sc = core::ptr::read_volatile((KB_RING_ADDR + 8 + slot) as *const u8);
        core::ptr::write_volatile((KB_RING_ADDR + 4) as *mut u32, tail.wrapping_add(1) & 0xFF);
        Some(sc)
    }
}

/// Write a byte slice to the kernel debug serial, one byte per syscall.
/// Mirrors the `fn print` helper copied into every native sotOS service.
fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        sys::debug_print(b);
    }
}

/// PS/2 scancode set-1 -> ASCII, respecting shift for letters and the
/// common punctuation. Unknown scancodes map to `None`. Kept in sync with
/// the launcher's table at `services/sot-launcher/src/main.rs`.
fn scancode_to_ascii(sc: u8, shift: bool) -> Option<u8> {
    let (lo, hi) = match sc {
        0x02 => (b'1', b'!'),
        0x03 => (b'2', b'@'),
        0x04 => (b'3', b'#'),
        0x05 => (b'4', b'$'),
        0x06 => (b'5', b'%'),
        0x07 => (b'6', b'^'),
        0x08 => (b'7', b'&'),
        0x09 => (b'8', b'*'),
        0x0A => (b'9', b'('),
        0x0B => (b'0', b')'),
        0x0C => (b'-', b'_'),
        0x0D => (b'=', b'+'),
        0x10 => (b'q', b'Q'),
        0x11 => (b'w', b'W'),
        0x12 => (b'e', b'E'),
        0x13 => (b'r', b'R'),
        0x14 => (b't', b'T'),
        0x15 => (b'y', b'Y'),
        0x16 => (b'u', b'U'),
        0x17 => (b'i', b'I'),
        0x18 => (b'o', b'O'),
        0x19 => (b'p', b'P'),
        0x1A => (b'[', b'{'),
        0x1B => (b']', b'}'),
        0x1E => (b'a', b'A'),
        0x1F => (b's', b'S'),
        0x20 => (b'd', b'D'),
        0x21 => (b'f', b'F'),
        0x22 => (b'g', b'G'),
        0x23 => (b'h', b'H'),
        0x24 => (b'j', b'J'),
        0x25 => (b'k', b'K'),
        0x26 => (b'l', b'L'),
        0x27 => (b';', b':'),
        0x28 => (b'\'', b'"'),
        0x29 => (b'`', b'~'),
        0x2B => (b'\\', b'|'),
        0x2C => (b'z', b'Z'),
        0x2D => (b'x', b'X'),
        0x2E => (b'c', b'C'),
        0x2F => (b'v', b'V'),
        0x30 => (b'b', b'B'),
        0x31 => (b'n', b'N'),
        0x32 => (b'm', b'M'),
        0x33 => (b',', b'<'),
        0x34 => (b'.', b'>'),
        0x35 => (b'/', b'?'),
        0x39 => (b' ', b' '),
        _ => return None,
    };
    Some(if shift { hi } else { lo })
}
