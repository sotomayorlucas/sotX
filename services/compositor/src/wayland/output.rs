//! wl_output -- output (monitor) advertisement.
//!
//! Events sent to client (in order on bind):
//!   0 = geometry(x, y, physical_width, physical_height, subpixel,
//!                make, model, transform)
//!   1 = mode(flags, width, height, refresh_mhz)
//!   2 = scale(factor)                 -- since v2
//!   4 = name(name)                    -- since v4
//!   5 = description(description)      -- since v4
//!   3 = done()                        -- terminates the init burst
//!
//! Requests:
//!   0 = release  (stub)
//!
//! Reference: https://wayland.app/protocols/wayland#wl_output

use super::{WlEvent, MAX_EVENTS};
use sotos_common::SyncUnsafeCell;

/// Protocol version we advertise.
pub const WL_OUTPUT_VERSION: u32 = 4;

/// Interface name advertised via wl_registry.
pub const WL_OUTPUT_INTERFACE: &[u8] = b"wl_output";

// --- wl_output enums ---------------------------------------------------

/// wl_output::subpixel
pub const WL_OUTPUT_SUBPIXEL_UNKNOWN: i32 = 0;

/// wl_output::transform
pub const WL_OUTPUT_TRANSFORM_NORMAL: i32 = 0;

/// wl_output::mode flags
pub const WL_OUTPUT_MODE_CURRENT: u32 = 0x1;
pub const WL_OUTPUT_MODE_PREFERRED: u32 = 0x2;

// --- Descriptor --------------------------------------------------------

/// Maximum length of make/model/name/description strings (bytes, without NUL).
pub const MAX_STR: usize = 48;

/// A fixed-size byte string to keep the descriptor `Copy` and heap-free.
#[derive(Clone, Copy)]
pub struct FixedStr {
    pub bytes: [u8; MAX_STR],
    pub len: usize,
}

impl FixedStr {
    /// Build a FixedStr from a byte slice, truncating to MAX_STR.
    pub const fn from_bytes(s: &[u8]) -> Self {
        let mut out = [0u8; MAX_STR];
        let n = if s.len() < MAX_STR { s.len() } else { MAX_STR };
        let mut i = 0;
        while i < n {
            out[i] = s[i];
            i += 1;
        }
        Self { bytes: out, len: n }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Static description of the single output we advertise.
///
/// All fields match the wl_output protocol verbatim. `refresh_mhz` is the
/// refresh rate in millihertz (e.g. 60000 = 60 Hz).
#[derive(Clone, Copy)]
pub struct OutputDescriptor {
    pub x: i32,
    pub y: i32,
    pub physical_width_mm: i32,
    pub physical_height_mm: i32,
    pub subpixel: i32,
    pub make: FixedStr,
    pub model: FixedStr,
    pub transform: i32,
    pub width: i32,
    pub height: i32,
    pub refresh_mhz: i32,
    pub scale: i32,
    pub name: FixedStr,
    pub description: FixedStr,
}

impl OutputDescriptor {
    /// Sensible default used until `set_descriptor` overrides it.
    pub const fn default_placeholder() -> Self {
        Self {
            x: 0,
            y: 0,
            physical_width_mm: 0,
            physical_height_mm: 0,
            subpixel: WL_OUTPUT_SUBPIXEL_UNKNOWN,
            make: FixedStr::from_bytes(b"sotOS"),
            model: FixedStr::from_bytes(b"Framebuffer"),
            transform: WL_OUTPUT_TRANSFORM_NORMAL,
            width: 0,
            height: 0,
            refresh_mhz: 60_000,
            scale: 1,
            name: FixedStr::from_bytes(b"HEADLESS-0"),
            description: FixedStr::from_bytes(b"sotOS framebuffer output"),
        }
    }
}

/// Single static descriptor for the only wl_output we advertise.
static DESCRIPTOR: SyncUnsafeCell<OutputDescriptor> =
    SyncUnsafeCell::new(OutputDescriptor::default_placeholder());

/// Update the cached descriptor. Call once at startup from main.rs after
/// reading the framebuffer dimensions from BootInfo.
pub fn set_descriptor(d: OutputDescriptor) {
    unsafe { *DESCRIPTOR.get() = d; }
}

/// Return a copy of the current descriptor.
pub fn current() -> OutputDescriptor {
    unsafe { *DESCRIPTOR.get() }
}

// --- Event emission ----------------------------------------------------

/// Push the full wl_output init burst into the caller's event queue.
///
/// Order: geometry (0), mode (1), scale (2), name (4), description (5),
/// done (3) -- matches the protocol's "initial event sequence on bind".
///
/// `object_id` is the client-assigned ID from the wl_registry::bind request.
/// Silently truncates if the event queue is full; the client will simply
/// miss some init events but the compositor will not panic.
pub fn send_init_events(
    object_id: u32,
    events: &mut [WlEvent; MAX_EVENTS],
    event_count: &mut usize,
) {
    let d = current();

    // 0: geometry(x, y, phys_w_mm, phys_h_mm, subpixel, make, model, transform)
    if *event_count < events.len() {
        let mut ev = WlEvent::new();
        ev.begin(object_id, 0);
        ev.put_i32(d.x);
        ev.put_i32(d.y);
        ev.put_i32(d.physical_width_mm);
        ev.put_i32(d.physical_height_mm);
        ev.put_i32(d.subpixel);
        ev.put_string(d.make.as_slice());
        ev.put_string(d.model.as_slice());
        ev.put_i32(d.transform);
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }

    // 1: mode(flags, width, height, refresh)
    if *event_count < events.len() {
        let mut ev = WlEvent::new();
        ev.begin(object_id, 1);
        ev.put_u32(WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED);
        ev.put_i32(d.width);
        ev.put_i32(d.height);
        ev.put_i32(d.refresh_mhz);
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }

    // 2: scale(factor) -- since v2
    if *event_count < events.len() {
        let mut ev = WlEvent::new();
        ev.begin(object_id, 2);
        ev.put_i32(d.scale);
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }

    // 4: name(name) -- since v4
    if *event_count < events.len() {
        let mut ev = WlEvent::new();
        ev.begin(object_id, 4);
        ev.put_string(d.name.as_slice());
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }

    // 5: description(description) -- since v4
    if *event_count < events.len() {
        let mut ev = WlEvent::new();
        ev.begin(object_id, 5);
        ev.put_string(d.description.as_slice());
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }

    // 3: done() -- terminates the init burst
    if *event_count < events.len() {
        let mut ev = WlEvent::new();
        ev.begin(object_id, 3);
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }
}
