//! xdg_wm_base + xdg_surface + xdg_toplevel -- window management.
//!
//! xdg_wm_base requests:
//!   0 = destroy
//!   1 = create_positioner(id: new_id) -- stub
//!   2 = get_xdg_surface(id: new_id, surface: object) -> new xdg_surface
//!   3 = pong(serial: uint) -- response to ping
//!
//! xdg_surface requests:
//!   0 = destroy
//!   1 = get_toplevel(id: new_id) -> new xdg_toplevel
//!   2 = get_popup(...) -- stub
//!   3 = set_window_geometry(x, y, width, height)
//!   4 = ack_configure(serial: uint)
//!
//! xdg_toplevel requests:
//!   0 = destroy
//!   1 = set_parent(parent: object)
//!   2 = set_title(title: string)
//!   3 = set_app_id(app_id: string)
//!   ... (move, resize, minimize, maximize, fullscreen, etc.)

use super::{WlEvent, WlMessage, xdg_popup};

/// Handle xdg_wm_base requests.
/// Returns Some(xdg_surface_id, wl_surface_id) for get_xdg_surface.
pub fn handle_wm_base_request(msg: &WlMessage) -> Option<(u32, u32)> {
    match msg.opcode {
        2 => {
            // get_xdg_surface(id, surface)
            let xdg_surface_id = msg.arg_u32(0);
            let wl_surface_id = msg.arg_u32(4);
            Some((xdg_surface_id, wl_surface_id))
        }
        3 => {
            // pong -- acknowledge, no response needed
            None
        }
        _ => None,
    }
}

/// Handle xdg_surface requests.
/// Returns Some(toplevel_id) for get_toplevel.
pub fn handle_xdg_surface_request(msg: &WlMessage) -> Option<u32> {
    match msg.opcode {
        1 => {
            // get_toplevel(id)
            Some(msg.arg_u32(0))
        }
        4 => {
            // ack_configure -- acknowledged
            None
        }
        _ => None,
    }
}

/// Send xdg_surface::configure event.
pub fn send_configure(xdg_surface_id: u32, serial: u32, events: &mut [WlEvent; 16], event_count: &mut usize) {
    if *event_count >= events.len() {
        return;
    }
    let mut ev = WlEvent::new();
    ev.begin(xdg_surface_id, 0); // xdg_surface::configure
    ev.put_u32(serial);
    ev.finish();
    events[*event_count] = ev;
    *event_count += 1;
}

/// Send xdg_toplevel::configure event (width, height, states array).
pub fn send_toplevel_configure(
    toplevel_id: u32,
    width: u32,
    height: u32,
    events: &mut [WlEvent; 16],
    event_count: &mut usize,
) {
    if *event_count >= events.len() {
        return;
    }
    let mut ev = WlEvent::new();
    ev.begin(toplevel_id, 0); // xdg_toplevel::configure
    ev.put_i32(width as i32);
    ev.put_i32(height as i32);
    // Empty states array (length=0)
    ev.put_u32(0);
    ev.finish();
    events[*event_count] = ev;
    *event_count += 1;
}

// ---------------------------------------------------------------------------
// xdg-shell popup extensions
// ---------------------------------------------------------------------------
//
// The routines below cover xdg_wm_base::create_positioner, the whole
// xdg_positioner request surface, xdg_surface::get_popup, and the
// xdg_popup::grab / reposition / destroy requests. Existing xdg_toplevel
// handling in this file is intentionally left untouched.

/// Handle `xdg_wm_base::create_positioner` (opcode 1).
///
/// Allocates a fresh [`Positioner`](super::xdg_popup::Positioner) slot and
/// returns the Wayland object id the client chose, so the caller can route
/// subsequent requests for that id to [`handle_positioner_request`].
pub fn handle_wm_base_create_positioner(msg: &WlMessage) -> Option<u32> {
    if msg.opcode != 1 {
        return None;
    }
    let object_id = msg.arg_u32(0);
    if object_id == 0 {
        return None;
    }
    let idx = xdg_popup::allocate_positioner()?;
    if let Some(p) = xdg_popup::get_positioner_mut(idx) {
        p.object_id = object_id;
    }
    Some(object_id)
}

/// Handle any request targeted at an existing xdg_positioner object.
///
/// Opcodes (xdg_positioner v2):
///   0 = destroy
///   1 = set_size(w, h)
///   2 = set_anchor_rect(x, y, w, h)
///   3 = set_anchor(anchor)
///   4 = set_gravity(gravity)
///   5 = set_constraint_adjustment(bits)
///   6 = set_offset(x, y)
pub fn handle_positioner_request(msg: &WlMessage) {
    let Some(idx) = xdg_popup::find_positioner_by_object(msg.object_id) else {
        return;
    };
    let Some(p) = xdg_popup::get_positioner_mut(idx) else { return; };

    match msg.opcode {
        0 => {
            // destroy
            p.active = false;
        }
        1 => {
            p.size_w = msg.arg_i32(0);
            p.size_h = msg.arg_i32(4);
        }
        2 => {
            p.anchor_x = msg.arg_i32(0);
            p.anchor_y = msg.arg_i32(4);
            p.anchor_w = msg.arg_i32(8);
            p.anchor_h = msg.arg_i32(12);
        }
        3 => {
            p.anchor = msg.arg_u32(0);
        }
        4 => {
            p.gravity = msg.arg_u32(0);
        }
        5 => {
            p.constraint_adjustment = msg.arg_u32(0);
        }
        6 => {
            p.offset_x = msg.arg_i32(0);
            p.offset_y = msg.arg_i32(4);
        }
        _ => {}
    }
}

/// Parsed arguments of `xdg_surface::get_popup`.
#[derive(Clone, Copy)]
pub struct PopupBirth {
    /// New xdg_popup object id requested by the client.
    pub popup_id: u32,
    /// Parent xdg_surface (may be 0 — popup without a parent).
    pub parent_xdg_surface: u32,
    /// xdg_positioner object used to place the popup.
    pub positioner_id: u32,
}

/// Handle `xdg_surface::get_popup` (opcode 3).
///
/// Returns the parsed ids on success so the caller can wire the popup up
/// in its own surface tables. Does *not* allocate a [`Popup`] slot — the
/// caller does that via [`spawn_popup`] after resolving the parent's
/// wl_surface and absolute coordinates.
pub fn handle_xdg_surface_get_popup(msg: &WlMessage) -> Option<PopupBirth> {
    if msg.opcode != 3 {
        return None;
    }
    let popup_id = msg.arg_u32(0);
    let parent_xdg_surface = msg.arg_u32(4);
    let positioner_id = msg.arg_u32(8);
    if popup_id == 0 || positioner_id == 0 {
        return None;
    }
    Some(PopupBirth { popup_id, parent_xdg_surface, positioner_id })
}

/// Populate a fresh popup slot and place it relative to its parent.
///
/// `parent_origin` is the top-left of the parent surface in screen space.
/// Returns the popup pool index on success.
pub fn spawn_popup(
    birth: PopupBirth,
    surface_id: u32,
    parent_surface_id: u32,
    parent_origin: (i32, i32),
) -> Option<usize> {
    let pos_idx = xdg_popup::find_positioner_by_object(birth.positioner_id)?;
    let positioner = *xdg_popup::get_positioner_mut(pos_idx)?;

    let popup_idx = xdg_popup::allocate_popup()?;
    let popup = xdg_popup::get_popup_mut(popup_idx)?;
    popup.object_id = birth.popup_id;
    popup.surface_id = surface_id;
    popup.parent_surface_id = parent_surface_id;
    popup.positioner_id = birth.positioner_id;
    xdg_popup::place_popup(popup, &positioner, parent_origin.0, parent_origin.1);
    Some(popup_idx)
}

/// Handle requests targeted at an existing xdg_popup object.
///
/// Opcodes (xdg_popup):
///   0 = destroy
///   1 = grab(seat, serial)
///   2 = reposition(positioner, token)
///
/// For `reposition`, only the `positioner_id` field is updated here. The
/// caller (`main.rs`) knows the real parent origin and re-runs
/// [`xdg_popup::place_popup`] against the latest positioner — keeping this
/// function free of screen-space knowledge.
pub fn handle_popup_request(msg: &WlMessage) {
    let Some(idx) = xdg_popup::find_popup_by_object(msg.object_id) else {
        return;
    };

    match msg.opcode {
        0 => {
            xdg_popup::destroy_popup(msg.object_id);
        }
        1 => {
            if let Some(p) = xdg_popup::get_popup_mut(idx) {
                p.grabbed = true;
            }
        }
        2 => {
            // reposition(positioner, token)
            let new_positioner = msg.arg_u32(0);
            if xdg_popup::find_positioner_by_object(new_positioner).is_none() {
                return;
            }
            if let Some(p) = xdg_popup::get_popup_mut(idx) {
                p.positioner_id = new_positioner;
            }
        }
        _ => {}
    }
}

/// Send `xdg_popup::configure(x, y, width, height)`.
#[allow(dead_code)]
pub fn send_popup_configure(
    popup_id: u32,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    events: &mut [WlEvent; 16],
    event_count: &mut usize,
) {
    if *event_count >= events.len() {
        return;
    }
    let mut ev = WlEvent::new();
    ev.begin(popup_id, 0); // xdg_popup::configure
    ev.put_i32(x);
    ev.put_i32(y);
    ev.put_i32(width as i32);
    ev.put_i32(height as i32);
    ev.finish();
    events[*event_count] = ev;
    *event_count += 1;
}

/// A toplevel window tracked by the compositor.
pub struct Toplevel {
    pub toplevel_id: u32,
    pub xdg_surface_id: u32,
    pub wl_surface_id: u32,
    pub title: [u8; 64],
    pub title_len: usize,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub active: bool,
}

impl Toplevel {
    pub const fn empty() -> Self {
        Self {
            toplevel_id: 0,
            xdg_surface_id: 0,
            wl_surface_id: 0,
            title: [0; 64],
            title_len: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            active: false,
        }
    }
}
