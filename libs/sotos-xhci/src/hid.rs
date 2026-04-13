//! HID boot protocol keyboard support.
//!
//! Converts USB HID boot protocol reports into PS/2 Set 1 scancodes
//! compatible with the existing sotX keyboard ring buffer.

/// HID boot protocol keyboard report (8 bytes).
///
/// Layout is fixed by USB HID 1.11 §B.1: one byte of modifier keys,
/// a reserved byte, then up to six simultaneously-pressed non-modifier
/// keys identified by HID usage code.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootReport {
    /// Modifier-key bitmask — see the `MOD_*` constants.
    pub modifiers: u8,
    /// Reserved byte (written by the device, ignored by the host).
    pub _reserved: u8,
    /// Up to 6 simultaneously pressed key HID usage codes. `0` = empty slot.
    pub keys: [u8; 6],
}

impl BootReport {
    /// All-zeros report — convenient as the "previous report" baseline
    /// before the first interrupt IN completes.
    pub const fn empty() -> Self {
        BootReport { modifiers: 0, _reserved: 0, keys: [0; 6] }
    }

    /// Parse the first 8 bytes of `buf` into a [`BootReport`]. Shorter
    /// buffers are treated as an all-zeros report.
    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut r = Self::empty();
        if buf.len() >= 8 {
            r.modifiers = buf[0];
            r._reserved = buf[1];
            r.keys[0] = buf[2];
            r.keys[1] = buf[3];
            r.keys[2] = buf[4];
            r.keys[3] = buf[5];
            r.keys[4] = buf[6];
            r.keys[5] = buf[7];
        }
        r
    }
}

// Modifier bit positions (USB HID 1.11 §B.1 Table B-1).
/// Left Ctrl — bit 0 of `BootReport::modifiers`.
pub const MOD_LCTRL: u8 = 0;
/// Left Shift — bit 1 of `BootReport::modifiers`.
pub const MOD_LSHIFT: u8 = 1;
/// Left Alt — bit 2 of `BootReport::modifiers`.
pub const MOD_LALT: u8 = 2;
/// Left GUI (Windows / Command) — bit 3.
pub const MOD_LGUI: u8 = 3;
/// Right Ctrl — bit 4.
pub const MOD_RCTRL: u8 = 4;
/// Right Shift — bit 5.
pub const MOD_RSHIFT: u8 = 5;
/// Right Alt (AltGr) — bit 6.
pub const MOD_RALT: u8 = 6;
/// Right GUI — bit 7.
pub const MOD_RGUI: u8 = 7;

/// PS/2 scancode for each modifier. 0xFF = needs E0 prefix.
/// Format: (scancode, needs_e0_prefix)
const MODIFIER_PS2: [(u8, bool); 8] = [
    (0x1D, false), // LCtrl
    (0x2A, false), // LShift
    (0x38, false), // LAlt
    (0x5B, true),  // LGUI (E0 5B)
    (0x1D, true),  // RCtrl (E0 1D)
    (0x36, false), // RShift
    (0x38, true),  // RAlt (E0 38)
    (0x5C, true),  // RGUI (E0 5C)
];

/// HID usage ID (index 0x00–0x73) → PS/2 Set 1 make code.
/// 0 = no mapping. Values >= 0x80 indicate extended (E0-prefixed) keys with code = val & 0x7F.
static HID_TO_PS2: [u8; 116] = [
    0x00, 0x00, 0x00, 0x00, // 0x00-0x03: reserved
    0x1E, // 0x04: A
    0x30, // 0x05: B
    0x2E, // 0x06: C
    0x20, // 0x07: D
    0x12, // 0x08: E
    0x21, // 0x09: F
    0x22, // 0x0A: G
    0x23, // 0x0B: H
    0x17, // 0x0C: I
    0x24, // 0x0D: J
    0x25, // 0x0E: K
    0x26, // 0x0F: L
    0x32, // 0x10: M
    0x31, // 0x11: N
    0x18, // 0x12: O
    0x19, // 0x13: P
    0x10, // 0x14: Q
    0x13, // 0x15: R
    0x1F, // 0x16: S
    0x14, // 0x17: T
    0x16, // 0x18: U
    0x2F, // 0x19: V
    0x11, // 0x1A: W
    0x2D, // 0x1B: X
    0x15, // 0x1C: Y
    0x2C, // 0x1D: Z
    0x02, // 0x1E: 1
    0x03, // 0x1F: 2
    0x04, // 0x20: 3
    0x05, // 0x21: 4
    0x06, // 0x22: 5
    0x07, // 0x23: 6
    0x08, // 0x24: 7
    0x09, // 0x25: 8
    0x0A, // 0x26: 9
    0x0B, // 0x27: 0
    0x1C, // 0x28: Enter
    0x01, // 0x29: Escape
    0x0E, // 0x2A: Backspace
    0x0F, // 0x2B: Tab
    0x39, // 0x2C: Space
    0x0C, // 0x2D: Minus
    0x0D, // 0x2E: Equal
    0x1A, // 0x2F: LeftBracket
    0x1B, // 0x30: RightBracket
    0x2B, // 0x31: Backslash
    0x00, // 0x32: (non-US)
    0x27, // 0x33: Semicolon
    0x28, // 0x34: Quote
    0x29, // 0x35: Grave/Tilde
    0x33, // 0x36: Comma
    0x34, // 0x37: Period
    0x35, // 0x38: Slash
    0x3A, // 0x39: CapsLock
    0x3B, // 0x3A: F1
    0x3C, // 0x3B: F2
    0x3D, // 0x3C: F3
    0x3E, // 0x3D: F4
    0x3F, // 0x3E: F5
    0x40, // 0x3F: F6
    0x41, // 0x40: F7
    0x42, // 0x41: F8
    0x43, // 0x42: F9
    0x44, // 0x43: F10
    0x57, // 0x44: F11
    0x58, // 0x45: F12
    0x00, // 0x46: PrintScreen (complex)
    0x46, // 0x47: ScrollLock
    0x00, // 0x48: Pause (complex)
    0xD2, // 0x49: Insert (E0 52) — 0x80|0x52
    0xC7, // 0x4A: Home (E0 47) — 0x80|0x47
    0xC9, // 0x4B: PageUp (E0 49) — 0x80|0x49
    0xD3, // 0x4C: Delete (E0 53) — 0x80|0x53
    0xCF, // 0x4D: End (E0 4F) — 0x80|0x4F
    0xD1, // 0x4E: PageDown (E0 51) — 0x80|0x51
    0xCD, // 0x4F: Right (E0 4D) — 0x80|0x4D
    0xCB, // 0x50: Left (E0 4B) — 0x80|0x4B
    0xD0, // 0x51: Down (E0 50) — 0x80|0x50
    0xC8, // 0x52: Up (E0 48) — 0x80|0x48
    0x45, // 0x53: NumLock
    // Keypad keys 0x54-0x63
    0xB5, // 0x54: KP / (E0 35) — 0x80|0x35
    0x37, // 0x55: KP *
    0x4A, // 0x56: KP -
    0x4E, // 0x57: KP +
    0x9C, // 0x58: KP Enter (E0 1C) — 0x80|0x1C
    0x4F, // 0x59: KP 1
    0x50, // 0x5A: KP 2
    0x51, // 0x5B: KP 3
    0x4B, // 0x5C: KP 4
    0x4C, // 0x5D: KP 5
    0x4D, // 0x5E: KP 6
    0x47, // 0x5F: KP 7
    0x48, // 0x60: KP 8
    0x49, // 0x61: KP 9
    0x52, // 0x62: KP 0
    0x53, // 0x63: KP .
    0x00, // 0x64: non-US
    0x00, // 0x65: Application
    0x00, // 0x66: Power
    0x00, // 0x67: KP =
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x68-0x6F
    0x00, 0x00, 0x00, 0x00, // 0x70-0x73
];

/// Scancode event: a single PS/2 scancode byte to emit.
/// Extended keys emit two events: E0 prefix + code.
pub struct ScancodeEvent {
    /// Up to two scancode bytes (E0 prefix + scancode for extended keys).
    pub bytes: [u8; 2],
    /// Number of valid bytes in `bytes` (1 or 2).
    pub len: u8,
}

/// Process a HID boot report and emit PS/2 scancodes by diffing with the previous report.
/// Calls `emit(scancode_byte)` for each scancode byte to write to the KB ring.
pub fn process_report<F: FnMut(u8)>(
    prev: &BootReport,
    curr: &BootReport,
    emit: &mut F,
) {
    // --- Modifier key changes ---
    let mod_diff = prev.modifiers ^ curr.modifiers;
    for bit in 0..8u8 {
        if mod_diff & (1 << bit) == 0 {
            continue;
        }
        let (code, needs_e0) = MODIFIER_PS2[bit as usize];
        let pressed = curr.modifiers & (1 << bit) != 0;
        if needs_e0 {
            emit(0xE0);
        }
        if pressed {
            emit(code); // make
        } else {
            emit(code | 0x80); // break
        }
    }

    // --- Key releases: keys in prev but not in curr ---
    for &pk in &prev.keys {
        if pk == 0 {
            continue;
        }
        let mut still_pressed = false;
        for &ck in &curr.keys {
            if ck == pk {
                still_pressed = true;
                break;
            }
        }
        if !still_pressed {
            emit_key_scancode(pk, false, emit);
        }
    }

    // --- Key presses: keys in curr but not in prev ---
    for &ck in &curr.keys {
        if ck == 0 {
            continue;
        }
        let mut was_pressed = false;
        for &pk in &prev.keys {
            if pk == ck {
                was_pressed = true;
                break;
            }
        }
        if !was_pressed {
            emit_key_scancode(ck, true, emit);
        }
    }
}

fn emit_key_scancode<F: FnMut(u8)>(hid_code: u8, pressed: bool, emit: &mut F) {
    if (hid_code as usize) >= HID_TO_PS2.len() {
        return;
    }
    let ps2 = HID_TO_PS2[hid_code as usize];
    if ps2 == 0 {
        return;
    }
    if ps2 & 0x80 != 0 {
        // Extended key: E0 prefix + (ps2 & 0x7F).
        let code = ps2 & 0x7F;
        emit(0xE0);
        if pressed {
            emit(code);
        } else {
            emit(code | 0x80);
        }
    } else {
        if pressed {
            emit(ps2);
        } else {
            emit(ps2 | 0x80);
        }
    }
}
