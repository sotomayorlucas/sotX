//! wl_compositor -- creates wl_surface and wl_region objects.
//!
//! Requests:
//!   0 = create_surface(id: new_id) -> new wl_surface object
//!   1 = create_region(id: new_id)  -> new wl_region object (stub)

use super::WlMessage;

/// Handle wl_compositor requests.
/// Returns Some(surface_id) for create_surface, None otherwise.
pub fn handle_request(msg: &WlMessage) -> Option<u32> {
    match msg.opcode {
        0 => {
            // create_surface -- client provides the new_id
            let surface_id = msg.arg_u32(0);
            Some(surface_id)
        }
        1 => {
            // create_region -- stub, accept and ignore
            None
        }
        _ => None,
    }
}
