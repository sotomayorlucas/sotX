//! wp_fractional_scale_v1 -- fractional scaling protocol stub.
//!
//! See: https://wayland.app/protocols/fractional-scale-v1
//!
//! This is a STUB: the compositor still renders at 1x. Its only purpose
//! is to advertise the global so clients can ask for a preferred scale,
//! and to reply with `preferred_scale(120)` (= 1.0x in 120-fixed units).
//!
//! Protocol summary:
//!
//! wp_fractional_scale_manager_v1 requests:
//!   0 = destroy
//!   1 = get_fractional_scale(id: new_id, surface: object)
//!
//! wp_fractional_scale_v1 requests:
//!   0 = destroy
//!
//! wp_fractional_scale_v1 events:
//!   0 = preferred_scale(scale: uint) -- scale is 120-fixed (120 = 1.0x)

use super::{WlEvent, MAX_EVENTS};
use sotos_common::SyncUnsafeCell;

/// Protocol version we advertise in the registry.
pub const FRACTIONAL_SCALE_VERSION: u32 = 1;

/// 120-fixed representation of 1.0x scale (unity).
pub const SCALE_120FIXED_1X: u32 = 120;

/// Maximum tracked wp_fractional_scale_v1 objects (server-wide).
pub const MAX_FRACTIONAL_SCALE_OBJECTS: usize = 32;

/// A tracked wp_fractional_scale_v1 object.
#[derive(Clone, Copy)]
pub struct FractionalScale {
    pub object_id: u32,
    pub surface_id: u32,
    pub current_scale: u32,
    pub active: bool,
}

impl FractionalScale {
    pub const fn empty() -> Self {
        Self {
            object_id: 0,
            surface_id: 0,
            current_scale: SCALE_120FIXED_1X,
            active: false,
        }
    }
}

/// Fixed-size pool of fractional_scale objects.
///
/// Uses `SyncUnsafeCell` to match the convention shared by
/// `layer_shell`, `animation`, and the rest of the compositor's
/// server-wide tables (raw `static mut` triggers the
/// `static_mut_refs` lint).
static POOL: SyncUnsafeCell<[FractionalScale; MAX_FRACTIONAL_SCALE_OBJECTS]> =
    SyncUnsafeCell::new([FractionalScale::empty(); MAX_FRACTIONAL_SCALE_OBJECTS]);

/// Allocate a new fractional_scale slot for the given surface/object pair.
/// Returns the slot index on success, or `None` if the pool is exhausted.
pub fn allocate(object_id: u32, surface_id: u32) -> Option<usize> {
    let pool = unsafe { &mut *POOL.get() };
    for (idx, slot) in pool.iter_mut().enumerate() {
        if !slot.active {
            slot.object_id = object_id;
            slot.surface_id = surface_id;
            slot.current_scale = SCALE_120FIXED_1X;
            slot.active = true;
            return Some(idx);
        }
    }
    None
}

/// Get a mutable reference to a tracked fractional_scale by object ID.
pub fn get_mut(object_id: u32) -> Option<&'static mut FractionalScale> {
    let pool = unsafe { &mut *POOL.get() };
    for slot in pool.iter_mut() {
        if slot.active && slot.object_id == object_id {
            return Some(slot);
        }
    }
    None
}

/// Destroy a tracked fractional_scale by object ID (frees the slot).
pub fn destroy(object_id: u32) {
    let pool = unsafe { &mut *POOL.get() };
    for slot in pool.iter_mut() {
        if slot.active && slot.object_id == object_id {
            *slot = FractionalScale::empty();
            return;
        }
    }
}

/// Queue a `preferred_scale(scale_120fixed)` event addressed to a tracked
/// `wp_fractional_scale_v1` object. The event is always delivered to the
/// Wayland object id (not the client / registry id).
pub fn send_preferred_scale(
    object_id: u32,
    scale_120fixed: u32,
    events: &mut [WlEvent; MAX_EVENTS],
    event_count: &mut usize,
) {
    if *event_count >= events.len() {
        return;
    }
    // Cache the scale on the tracked slot (best-effort).
    if let Some(fs) = get_mut(object_id) {
        fs.current_scale = scale_120fixed;
    }

    let mut ev = WlEvent::new();
    ev.begin(object_id, 0); // wp_fractional_scale_v1::preferred_scale
    ev.put_u32(scale_120fixed);
    ev.finish();
    events[*event_count] = ev;
    *event_count += 1;
}
