//! wl_seat -- input device management.
//!
//! Events:
//!   0 = capabilities(caps: uint) -- bitfield: pointer=1, keyboard=2, touch=4
//!   1 = name(name: string)
//!
//! Requests:
//!   0 = get_pointer(id: new_id) -> new wl_pointer
//!   1 = get_keyboard(id: new_id) -> new wl_keyboard
//!   2 = get_touch(id: new_id) -> stub
//!   3 = release

use super::{WlEvent, WlMessage};

/// Seat capability flags.
pub const WL_SEAT_CAP_POINTER: u32 = 1;
pub const WL_SEAT_CAP_KEYBOARD: u32 = 2;

/// Send seat capabilities when wl_seat is bound.
pub fn send_capabilities(seat_id: u32, events: &mut [WlEvent; 16], event_count: &mut usize) {
    if *event_count >= events.len() {
        return;
    }
    let mut ev = WlEvent::new();
    ev.begin(seat_id, 0); // wl_seat::capabilities
    ev.put_u32(WL_SEAT_CAP_POINTER | WL_SEAT_CAP_KEYBOARD);
    ev.finish();
    events[*event_count] = ev;
    *event_count += 1;

    // Also send seat name
    if *event_count >= events.len() {
        return;
    }
    let mut name_ev = WlEvent::new();
    name_ev.begin(seat_id, 1); // wl_seat::name
    name_ev.put_string(b"seat0");
    name_ev.finish();
    events[*event_count] = name_ev;
    *event_count += 1;
}

/// Handle wl_seat requests.
/// Returns Some((kind, id)) where kind=0 for pointer, 1 for keyboard.
pub fn handle_request(msg: &WlMessage) -> Option<(u32, u32)> {
    match msg.opcode {
        0 => Some((0, msg.arg_u32(0))), // get_pointer
        1 => Some((1, msg.arg_u32(0))), // get_keyboard
        _ => None,
    }
}

/// PS/2 scancode set 1 -> Linux keycode mapping (partial, common keys).
/// Returns 0 for unmapped scancodes.
pub fn scancode_to_linux_keycode(scancode: u8) -> u32 {
    match scancode {
        0x01 => 1,   // ESC
        0x02 => 2,   // 1
        0x03 => 3,   // 2
        0x04 => 4,   // 3
        0x05 => 5,   // 4
        0x06 => 6,   // 5
        0x07 => 7,   // 6
        0x08 => 8,   // 7
        0x09 => 9,   // 8
        0x0A => 10,  // 9
        0x0B => 11,  // 0
        0x0C => 12,  // -
        0x0D => 13,  // =
        0x0E => 14,  // Backspace
        0x0F => 15,  // Tab
        0x10 => 16,  // Q
        0x11 => 17,  // W
        0x12 => 18,  // E
        0x13 => 19,  // R
        0x14 => 20,  // T
        0x15 => 21,  // Y
        0x16 => 22,  // U
        0x17 => 23,  // I
        0x18 => 24,  // O
        0x19 => 25,  // P
        0x1A => 26,  // [
        0x1B => 27,  // ]
        0x1C => 28,  // Enter
        0x1D => 29,  // Left Ctrl
        0x1E => 30,  // A
        0x1F => 31,  // S
        0x20 => 32,  // D
        0x21 => 33,  // F
        0x22 => 34,  // G
        0x23 => 35,  // H
        0x24 => 36,  // J
        0x25 => 37,  // K
        0x26 => 38,  // L
        0x27 => 39,  // ;
        0x28 => 40,  // '
        0x29 => 41,  // `
        0x2A => 42,  // Left Shift
        0x2B => 43,  // backslash
        0x2C => 44,  // Z
        0x2D => 45,  // X
        0x2E => 46,  // C
        0x2F => 47,  // V
        0x30 => 48,  // B
        0x31 => 49,  // N
        0x32 => 50,  // M
        0x33 => 51,  // ,
        0x34 => 52,  // .
        0x35 => 53,  // /
        0x36 => 54,  // Right Shift
        0x38 => 56,  // Left Alt
        0x39 => 57,  // Space
        _ => 0,
    }
}
