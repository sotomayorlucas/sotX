//! USB HID boot protocol mouse support.
//!
//! Parses USB HID boot protocol mouse reports (4 bytes) into `MouseEvent`s.
//! Boot protocol mouse reports have a fixed format:
//!   Byte 0: Button state (bit 0=left, bit 1=right, bit 2=middle)
//!   Byte 1: X displacement (signed 8-bit)
//!   Byte 2: Y displacement (signed 8-bit)
//!   Byte 3: Wheel (signed 8-bit, optional)

use crate::event::MouseEvent;

/// Minimum boot protocol mouse report size (without wheel).
pub const MIN_REPORT_SIZE: usize = 3;
/// Full boot protocol mouse report size (with wheel).
pub const FULL_REPORT_SIZE: usize = 4;

/// USB HID boot protocol mouse report.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootMouseReport {
    /// Button state: bit 0=left, bit 1=right, bit 2=middle.
    pub buttons: u8,
    /// X displacement (signed 8-bit, positive = right).
    pub x: i8,
    /// Y displacement (signed 8-bit, positive = down in USB convention).
    pub y: i8,
    /// Wheel displacement (signed 8-bit, positive = scroll up). Optional.
    pub wheel: i8,
}

impl BootMouseReport {
    /// Create an empty (zeroed) report.
    pub const fn empty() -> Self {
        Self { buttons: 0, x: 0, y: 0, wheel: 0 }
    }

    /// Parse from a byte buffer (3 or 4 bytes).
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < MIN_REPORT_SIZE {
            return None;
        }
        Some(Self {
            buttons: buf[0],
            x: buf[1] as i8,
            y: buf[2] as i8,
            wheel: if buf.len() >= FULL_REPORT_SIZE { buf[3] as i8 } else { 0 },
        })
    }

    /// Convert this report to a `MouseEvent`.
    ///
    /// USB HID Y-axis convention: positive = "down" on screen.
    /// Our MouseEvent also uses positive = down, so no inversion needed.
    pub fn to_event(&self) -> MouseEvent {
        MouseEvent {
            buttons: self.buttons & 0x07, // Only lower 3 bits for standard buttons.
            dx: self.x as i16,
            dy: self.y as i16,
            dz: self.wheel,
        }
    }
}

/// USB HID mouse report processor.
///
/// Tracks the previous report for delta/button-change detection.
pub struct UsbMouseProcessor {
    /// Previous report for button-change detection.
    prev: BootMouseReport,
}

impl UsbMouseProcessor {
    /// Create a new processor.
    pub const fn new() -> Self {
        Self {
            prev: BootMouseReport::empty(),
        }
    }

    /// Process a new HID report. Returns a MouseEvent.
    ///
    /// The report bytes should come from a USB interrupt IN transfer
    /// on the mouse's interrupt endpoint.
    pub fn process(&mut self, buf: &[u8]) -> Option<MouseEvent> {
        let report = BootMouseReport::from_bytes(buf)?;
        let event = report.to_event();
        self.prev = report;
        Some(event)
    }

    /// Get the previous report (for comparison if needed).
    pub fn prev_report(&self) -> &BootMouseReport {
        &self.prev
    }

    /// Check if buttons changed since the last report.
    pub fn buttons_changed(&self, current: &BootMouseReport) -> bool {
        (self.prev.buttons & 0x07) != (current.buttons & 0x07)
    }
}

// ---------------------------------------------------------------------------
// USB HID class constants for mouse setup
// ---------------------------------------------------------------------------

/// USB HID class code.
pub const USB_CLASS_HID: u8 = 0x03;
/// USB HID subclass: Boot Interface.
pub const USB_SUBCLASS_BOOT: u8 = 0x01;
/// USB HID protocol: Mouse.
pub const USB_PROTOCOL_MOUSE: u8 = 0x02;
/// USB HID protocol: Keyboard (for reference).
pub const USB_PROTOCOL_KEYBOARD: u8 = 0x01;

/// HID class request: SET_PROTOCOL.
pub const HID_SET_PROTOCOL: u8 = 0x0B;
/// HID class request: GET_PROTOCOL.
pub const HID_GET_PROTOCOL: u8 = 0x03;
/// HID class request: SET_IDLE.
pub const HID_SET_IDLE: u8 = 0x0A;

// HID protocol values (USB HID 1.11 §7.2.5).
/// Boot protocol — simplified reports defined by the HID boot spec.
pub const HID_PROTOCOL_BOOT: u16 = 0;
/// Report protocol — full report format described by the device's HID descriptor.
pub const HID_PROTOCOL_REPORT: u16 = 1;

/// Build the 8-byte USB setup packet for SET_PROTOCOL(Boot).
///
/// - `interface`: USB interface number.
pub fn set_boot_protocol_setup(interface: u16) -> u64 {
    // bmRequestType=0x21 (class, interface, host-to-device)
    // bRequest=SET_PROTOCOL (0x0B)
    // wValue=0 (boot protocol)
    // wIndex=interface
    // wLength=0
    let setup: u64 = 0x21                       // bmRequestType
        | ((HID_SET_PROTOCOL as u64) << 8)      // bRequest
        | ((HID_PROTOCOL_BOOT as u64) << 16)    // wValue
        | ((interface as u64) << 32)             // wIndex
        | (0u64 << 48);                          // wLength
    setup
}

/// Build the 8-byte USB setup packet for SET_IDLE(0) — no idle rate.
///
/// - `interface`: USB interface number.
pub fn set_idle_setup(interface: u16) -> u64 {
    // bmRequestType=0x21 (class, interface, host-to-device)
    // bRequest=SET_IDLE (0x0A)
    // wValue=0 (idle rate 0 = report only on change)
    // wIndex=interface
    // wLength=0
    let setup: u64 = 0x21
        | ((HID_SET_IDLE as u64) << 8)
        | (0u64 << 16)                          // wValue = 0
        | ((interface as u64) << 32)
        | (0u64 << 48);
    setup
}
