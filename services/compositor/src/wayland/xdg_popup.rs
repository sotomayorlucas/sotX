//! xdg_positioner + xdg_popup support.
//!
//! Implements the xdg-shell popup protocol so menus, combo-box drop-downs,
//! and tooltips can be created. Toplevels remain handled by `shell.rs` and
//! are **not** touched by this module.
//!
//! Protocol (xdg_positioner v2):
//!   request set_size(w, h)
//!   request set_anchor_rect(x, y, w, h)     -- rect on parent window
//!   request set_anchor(anchor)               -- which edge/corner of the
//!                                                rect the popup attaches to
//!   request set_gravity(gravity)             -- direction the popup grows
//!   request set_constraint_adjustment(bits)  -- slide/flip/resize on clip
//!   request set_offset(x, y)                 -- extra pixel offset
//!
//! Protocol (xdg_popup):
//!   request grab(seat, serial)
//!   request reposition(positioner, token)
//!   request destroy
//!
//! Anchor / gravity constants mirror the upstream `xdg_shell.xml`.

use sotos_common::SyncUnsafeCell;

/// Maximum number of positioner objects tracked across all clients.
pub const MAX_POSITIONERS: usize = 16;

/// Maximum number of xdg_popup objects tracked across all clients.
pub const MAX_POPUPS: usize = 16;

// ---------------------------------------------------------------------------
// xdg_positioner.anchor enumeration
// ---------------------------------------------------------------------------

pub const ANCHOR_NONE: u32 = 0;
pub const ANCHOR_TOP: u32 = 1;
pub const ANCHOR_BOTTOM: u32 = 2;
pub const ANCHOR_LEFT: u32 = 3;
pub const ANCHOR_RIGHT: u32 = 4;
pub const ANCHOR_TOP_LEFT: u32 = 5;
pub const ANCHOR_BOTTOM_LEFT: u32 = 6;
pub const ANCHOR_TOP_RIGHT: u32 = 7;
pub const ANCHOR_BOTTOM_RIGHT: u32 = 8;

// ---------------------------------------------------------------------------
// xdg_positioner.gravity enumeration (same bit layout as anchor)
// ---------------------------------------------------------------------------

pub const GRAVITY_NONE: u32 = 0;
pub const GRAVITY_TOP: u32 = 1;
pub const GRAVITY_BOTTOM: u32 = 2;
pub const GRAVITY_LEFT: u32 = 3;
pub const GRAVITY_RIGHT: u32 = 4;
pub const GRAVITY_TOP_LEFT: u32 = 5;
pub const GRAVITY_BOTTOM_LEFT: u32 = 6;
pub const GRAVITY_TOP_RIGHT: u32 = 7;
pub const GRAVITY_BOTTOM_RIGHT: u32 = 8;

// ---------------------------------------------------------------------------
// Positioner
// ---------------------------------------------------------------------------

/// A cached xdg_positioner. Clients call `set_*` to configure one before
/// passing it to `xdg_surface::get_popup`.
#[derive(Clone, Copy)]
pub struct Positioner {
    pub object_id: u32,
    pub size_w: i32,
    pub size_h: i32,
    pub anchor_x: i32,
    pub anchor_y: i32,
    pub anchor_w: i32,
    pub anchor_h: i32,
    pub anchor: u32,
    pub gravity: u32,
    pub constraint_adjustment: u32,
    pub offset_x: i32,
    pub offset_y: i32,
    pub active: bool,
}

impl Positioner {
    pub const fn empty() -> Self {
        Self {
            object_id: 0,
            size_w: 0,
            size_h: 0,
            anchor_x: 0,
            anchor_y: 0,
            anchor_w: 0,
            anchor_h: 0,
            anchor: ANCHOR_NONE,
            gravity: GRAVITY_NONE,
            constraint_adjustment: 0,
            offset_x: 0,
            offset_y: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Popup
// ---------------------------------------------------------------------------

/// A tracked xdg_popup. Absolute screen coordinates are filled in by
/// [`place_popup`] once the parent position is known.
#[derive(Clone, Copy)]
pub struct Popup {
    pub object_id: u32,
    pub surface_id: u32,
    pub parent_surface_id: u32,
    pub positioner_id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub grabbed: bool,
    pub active: bool,
}

impl Popup {
    pub const fn empty() -> Self {
        Self {
            object_id: 0,
            surface_id: 0,
            parent_surface_id: 0,
            positioner_id: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            grabbed: false,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Static pools
// ---------------------------------------------------------------------------

static POSITIONERS: SyncUnsafeCell<[Positioner; MAX_POSITIONERS]> =
    SyncUnsafeCell::new([Positioner::empty(); MAX_POSITIONERS]);

static POPUPS: SyncUnsafeCell<[Popup; MAX_POPUPS]> =
    SyncUnsafeCell::new([Popup::empty(); MAX_POPUPS]);

// ---------------------------------------------------------------------------
// Public allocator / accessor API
// ---------------------------------------------------------------------------

/// Allocate a free positioner slot and return its index.
pub fn allocate_positioner() -> Option<usize> {
    let pool = unsafe { &mut *POSITIONERS.get() };
    for (i, p) in pool.iter_mut().enumerate() {
        if !p.active {
            *p = Positioner::empty();
            p.active = true;
            return Some(i);
        }
    }
    None
}

/// Get a mutable reference to a positioner by index.
pub fn get_positioner_mut(id: usize) -> Option<&'static mut Positioner> {
    if id >= MAX_POSITIONERS {
        return None;
    }
    let pool = unsafe { &mut *POSITIONERS.get() };
    if pool[id].active {
        Some(&mut pool[id])
    } else {
        None
    }
}

/// Look up an active positioner by its Wayland object id.
pub fn find_positioner_by_object(object_id: u32) -> Option<usize> {
    if object_id == 0 {
        return None;
    }
    let pool = unsafe { &*POSITIONERS.get() };
    for (i, p) in pool.iter().enumerate() {
        if p.active && p.object_id == object_id {
            return Some(i);
        }
    }
    None
}

/// Release a positioner slot.
#[allow(dead_code)]
pub fn destroy_positioner(object_id: u32) {
    if let Some(i) = find_positioner_by_object(object_id) {
        let pool = unsafe { &mut *POSITIONERS.get() };
        pool[i].active = false;
    }
}

/// Allocate a free popup slot and return its index.
pub fn allocate_popup() -> Option<usize> {
    let pool = unsafe { &mut *POPUPS.get() };
    for (i, p) in pool.iter_mut().enumerate() {
        if !p.active {
            *p = Popup::empty();
            p.active = true;
            return Some(i);
        }
    }
    None
}

/// Get a mutable reference to a popup by index.
pub fn get_popup_mut(id: usize) -> Option<&'static mut Popup> {
    if id >= MAX_POPUPS {
        return None;
    }
    let pool = unsafe { &mut *POPUPS.get() };
    if pool[id].active {
        Some(&mut pool[id])
    } else {
        None
    }
}

/// Look up an active popup by its Wayland object id.
pub fn find_popup_by_object(object_id: u32) -> Option<usize> {
    if object_id == 0 {
        return None;
    }
    let pool = unsafe { &*POPUPS.get() };
    for (i, p) in pool.iter().enumerate() {
        if p.active && p.object_id == object_id {
            return Some(i);
        }
    }
    None
}

/// Release a popup slot.
pub fn destroy_popup(object_id: u32) {
    if let Some(i) = find_popup_by_object(object_id) {
        let pool = unsafe { &mut *POPUPS.get() };
        pool[i].active = false;
    }
}

// ---------------------------------------------------------------------------
// place_popup
// ---------------------------------------------------------------------------

/// Resolve the absolute screen coordinates of `popup` given its positioner
/// and the parent window's top-left position.
///
/// Algorithm (simplified, ignores `constraint_adjustment`):
/// 1. Compute the anchor point on the parent anchor rect from
///    `positioner.anchor`. `ANCHOR_NONE` maps to the rect's center.
/// 2. Translate to screen space by adding `(parent_x, parent_y)`.
/// 3. Offset the popup origin according to `positioner.gravity` (the popup
///    grows in the gravity direction from the anchor point).
/// 4. Apply `positioner.offset_{x,y}`.
/// 5. Write the result into `popup.x/y/width/height`.
pub fn place_popup(
    popup: &mut Popup,
    positioner: &Positioner,
    parent_x: i32,
    parent_y: i32,
) {
    // 1. anchor point on the parent rect
    let (ax, ay) = anchor_point(
        positioner.anchor,
        positioner.anchor_x,
        positioner.anchor_y,
        positioner.anchor_w,
        positioner.anchor_h,
    );

    // 2. translate to screen space
    let screen_ax = parent_x + ax;
    let screen_ay = parent_y + ay;

    // 3 + 4. gravity offset + user offset
    let w = positioner.size_w.max(0);
    let h = positioner.size_h.max(0);
    let (gdx, gdy) = gravity_offset(positioner.gravity, w, h);

    popup.x = screen_ax + gdx + positioner.offset_x;
    popup.y = screen_ay + gdy + positioner.offset_y;
    popup.width = w as u32;
    popup.height = h as u32;
}

/// Return the anchor point `(dx, dy)` within the anchor rect described by
/// `(rx, ry, rw, rh)` for a given `anchor` constant. `ANCHOR_NONE` resolves
/// to the rect's geometric center.
fn anchor_point(anchor: u32, rx: i32, ry: i32, rw: i32, rh: i32) -> (i32, i32) {
    let cx = rx + rw / 2;
    let cy = ry + rh / 2;
    let left = rx;
    let right = rx + rw;
    let top = ry;
    let bottom = ry + rh;

    match anchor {
        ANCHOR_TOP => (cx, top),
        ANCHOR_BOTTOM => (cx, bottom),
        ANCHOR_LEFT => (left, cy),
        ANCHOR_RIGHT => (right, cy),
        ANCHOR_TOP_LEFT => (left, top),
        ANCHOR_BOTTOM_LEFT => (left, bottom),
        ANCHOR_TOP_RIGHT => (right, top),
        ANCHOR_BOTTOM_RIGHT => (right, bottom),
        _ => (cx, cy), // ANCHOR_NONE + anything unknown
    }
}

/// Return the `(dx, dy)` offset from the anchor point to the popup's
/// top-left corner, based on the gravity direction and the popup `(w, h)`.
///
/// Example: `GRAVITY_BOTTOM` means the popup grows downward from the anchor,
/// so it's horizontally centered (`-w/2`) and its top edge sits on the
/// anchor (`0`).
fn gravity_offset(gravity: u32, w: i32, h: i32) -> (i32, i32) {
    match gravity {
        GRAVITY_TOP => (-w / 2, -h),
        GRAVITY_BOTTOM => (-w / 2, 0),
        GRAVITY_LEFT => (-w, -h / 2),
        GRAVITY_RIGHT => (0, -h / 2),
        GRAVITY_TOP_LEFT => (-w, -h),
        GRAVITY_BOTTOM_LEFT => (-w, 0),
        GRAVITY_TOP_RIGHT => (0, -h),
        GRAVITY_BOTTOM_RIGHT => (0, 0),
        _ => (-w / 2, -h / 2), // GRAVITY_NONE centers on the anchor
    }
}

// ---------------------------------------------------------------------------
// Tests (only compiled under `cargo test`, which is not usable on the
// compositor's `x86_64-unknown-none` target — kept for documentation and
// for manual verification via the `scripts/test_xdg_popup.rs` standalone
// harness that mirrors this logic).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(anchor: u32, gravity: u32, w: i32, h: i32) -> Positioner {
        let mut p = Positioner::empty();
        p.active = true;
        p.size_w = w;
        p.size_h = h;
        p.anchor_x = 50;
        p.anchor_y = 40;
        p.anchor_w = 100;
        p.anchor_h = 20;
        p.anchor = anchor;
        p.gravity = gravity;
        p
    }

    fn popup() -> Popup {
        Popup::empty()
    }

    #[test]
    fn anchor_none_centers_in_rect() {
        let p = pos(ANCHOR_NONE, GRAVITY_NONE, 40, 10);
        let mut pu = popup();
        place_popup(&mut pu, &p, 0, 0);
        assert_eq!(pu.x, 80);
        assert_eq!(pu.y, 45);
        assert_eq!(pu.width, 40);
        assert_eq!(pu.height, 10);
    }

    #[test]
    fn anchor_bottom_gravity_bottom_is_menu_style() {
        let p = pos(ANCHOR_BOTTOM, GRAVITY_BOTTOM, 80, 200);
        let mut pu = popup();
        place_popup(&mut pu, &p, 10, 10);
        assert_eq!(pu.x, 70);
        assert_eq!(pu.y, 70);
        assert_eq!(pu.width, 80);
        assert_eq!(pu.height, 200);
    }

    #[test]
    fn offset_is_applied_last() {
        let mut p = pos(ANCHOR_BOTTOM, GRAVITY_BOTTOM, 50, 50);
        p.offset_x = 7;
        p.offset_y = -3;
        let mut pu = popup();
        place_popup(&mut pu, &p, 0, 0);
        assert_eq!(pu.x, 82);
        assert_eq!(pu.y, 57);
    }
}
