//! wl_registry -- advertises available global interfaces.
//!
//! Events sent to client:
//!   0 = global(name: uint, interface: string, version: uint)
//!
//! Requests from client:
//!   0 = bind(name: uint, id: new_id) -- client binds a global

use super::{WlEvent, WlMessage};
use super::output::{WL_OUTPUT_INTERFACE, WL_OUTPUT_VERSION};

/// Global interface entries advertised to clients.
pub struct GlobalEntry {
    pub name: u32,
    pub interface: &'static [u8],
    pub version: u32,
}

/// The globals we advertise.
///
/// Global `name` numbers are arbitrary per-server identifiers; we use
/// small integers starting at 1. The dispatcher in `mod.rs` maps the
/// name back to the bound-object slot on the client side when a
/// `wl_registry::bind` arrives.
///
/// Name reservations across compositor PRs:
///   1 = wl_compositor
///   2 = wl_shm
///   3 = xdg_wm_base
///   4 = wl_seat
///   5 = zwlr_layer_shell_v1            (PR #69, merged)
///   6 = wp_fractional_scale_manager_v1 (PR #60)
///   7 = wl_output                      (this PR)
pub static GLOBALS: [GlobalEntry; 6] = [
    GlobalEntry { name: 1, interface: super::WL_COMPOSITOR_INTERFACE, version: 4 },
    GlobalEntry { name: 2, interface: super::WL_SHM_INTERFACE, version: 1 },
    GlobalEntry { name: 3, interface: super::XDG_WM_BASE_INTERFACE, version: 2 },
    GlobalEntry { name: 4, interface: super::WL_SEAT_INTERFACE, version: 5 },
    GlobalEntry { name: 5, interface: super::ZWLR_LAYER_SHELL_V1_INTERFACE, version: 4 },
    GlobalEntry { name: 7, interface: WL_OUTPUT_INTERFACE, version: WL_OUTPUT_VERSION },
];

/// Send all global advertisements to a newly created registry.
pub fn send_globals(registry_id: u32, events: &mut [WlEvent; 16], event_count: &mut usize) {
    for g in GLOBALS.iter() {
        if *event_count >= events.len() {
            break;
        }
        let mut ev = WlEvent::new();
        ev.begin(registry_id, 0); // wl_registry::global
        ev.put_u32(g.name);
        ev.put_string(g.interface);
        ev.put_u32(g.version);
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }
}

/// Bound object tracking.
pub struct BoundObject {
    pub global_name: u32,
    pub client_id: u32,
}

/// Handle wl_registry::bind request.
/// Returns the bound global name so the caller can track it.
pub fn handle_bind(msg: &WlMessage) -> Option<BoundObject> {
    if msg.opcode != 0 {
        return None;
    }
    let name = msg.arg_u32(0);
    // The new_id argument is at offset 4, but for wl_registry::bind
    // it's encoded as (interface_string, version, id) -- simplified:
    // In practice, the bind message for our compositor just needs the
    // name and the client-assigned ID (at known offset after interface+version).
    // For a minimal compositor, we accept any bind and track it.
    let client_id = msg.arg_u32(4); // simplified: direct ID
    Some(BoundObject { global_name: name, client_id })
}
