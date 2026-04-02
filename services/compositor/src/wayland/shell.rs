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

use super::{WlEvent, WlMessage};

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
