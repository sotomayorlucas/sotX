//! Keyboard input handling for sotos-term.
//!
//! Receives wl_keyboard::key events from the compositor (via IPC), converts
//! Linux keycodes to ASCII bytes, and feeds them to serial COM1 so LUCAS
//! receives them as if typed on the console. This makes sotos-term an
//! interactive Wayland terminal even when LUCAS reads from COM1.

use sotos_common::sys;

// ---------------------------------------------------------------------------
// Modifier state
// ---------------------------------------------------------------------------

/// Shift key held (left or right).
static mut SHIFT: bool = false;
/// Ctrl key held (left or right).
static mut CTRL: bool = false;

// ---------------------------------------------------------------------------
// Linux keycode -> ASCII mapping
// ---------------------------------------------------------------------------
// These tables map Linux input keycodes (which for the basic US keyboard
// are numerically identical to PS/2 set-1 scancodes) to ASCII bytes.
// Copied from `services/init/src/framebuffer.rs` scancode tables.

/// Normal (unshifted) keycode -> ASCII.
static KEYCODE_TO_ASCII: [u8; 128] = [
    0,  27, b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9',b'0',b'-',b'=',0x08,b'\t',
    b'q',b'w',b'e',b'r',b't',b'y',b'u',b'i',b'o',b'p',b'[',b']',b'\n', 0, b'a',b's',
    b'd',b'f',b'g',b'h',b'j',b'k',b'l',b';',b'\'',b'`', 0, b'\\',b'z',b'x',b'c',b'v',
    b'b',b'n',b'm',b',',b'.',b'/', 0, b'*', 0, b' ', 0, 0,0,0,0,0,
    0,0,0,0,0, 0, 0, 0,0,0,b'-', 0,0,0,b'+', 0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
];

/// Shifted keycode -> ASCII.
static KEYCODE_TO_ASCII_SHIFT: [u8; 128] = [
    0,  27, b'!',b'@',b'#',b'$',b'%',b'^',b'&',b'*',b'(',b')',b'_',b'+',0x08,b'\t',
    b'Q',b'W',b'E',b'R',b'T',b'Y',b'U',b'I',b'O',b'P',b'{',b'}',b'\n', 0, b'A',b'S',
    b'D',b'F',b'G',b'H',b'J',b'K',b'L',b':',b'"',b'~', 0, b'|',b'Z',b'X',b'C',b'V',
    b'B',b'N',b'M',b'<',b'>',b'?', 0, b'*', 0, b' ', 0, 0,0,0,0,0,
    0,0,0,0,0, 0, 0, 0,0,0,b'-', 0,0,0,b'+', 0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
];

/// Linux keycodes for modifier keys.
const KEY_LEFT_CTRL: u32 = 29;
const KEY_LEFT_SHIFT: u32 = 42;
const KEY_RIGHT_SHIFT: u32 = 54;
const KEY_RIGHT_CTRL: u32 = 97;

/// Process a wl_keyboard::key event.
///
/// `keycode` is a Linux input keycode, `state` is 0 for release, 1 for press.
/// Returns `Some(ascii)` if the key should produce a character, `None` for
/// modifier-only or unmapped keys.
pub fn process_key(keycode: u32, state: u32) -> Option<u8> {
    let pressed = state == 1;

    // Track modifier state.
    match keycode {
        KEY_LEFT_SHIFT | KEY_RIGHT_SHIFT => {
            unsafe { SHIFT = pressed; }
            return None;
        }
        KEY_LEFT_CTRL | KEY_RIGHT_CTRL => {
            unsafe { CTRL = pressed; }
            return None;
        }
        _ => {}
    }

    // Only produce ASCII on key press, not release.
    if !pressed {
        return None;
    }

    if keycode >= 128 {
        return None;
    }

    let ascii = unsafe {
        if SHIFT {
            KEYCODE_TO_ASCII_SHIFT[keycode as usize]
        } else {
            KEYCODE_TO_ASCII[keycode as usize]
        }
    };

    if ascii == 0 {
        return None;
    }

    // Ctrl + letter -> control character (Ctrl+C = 0x03, Ctrl+D = 0x04, etc.)
    unsafe {
        if CTRL {
            if ascii >= b'a' && ascii <= b'z' {
                return Some(ascii - b'a' + 1);
            }
            if ascii >= b'A' && ascii <= b'Z' {
                return Some(ascii - b'A' + 1);
            }
        }
    }

    Some(ascii)
}

/// Feed a byte into serial COM1 so LUCAS receives it as keyboard input.
///
/// This bridges the gap between Wayland keyboard events and the serial-based
/// LUCAS shell: the user types in the Wayland window, sotos-term converts
/// the keypress to ASCII, and writes it to COM1 where LUCAS reads it.
pub fn send_to_serial(byte: u8) {
    sys::debug_print(byte);
}
