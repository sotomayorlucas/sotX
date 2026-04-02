//! wl_display -- core global object (always object ID 1).
//!
//! Requests:
//!   0 = sync(callback: new_id)      -> sends wl_callback::done event
//!   1 = get_registry(registry: new_id) -> creates wl_registry

use super::{WlMessage, WlEvent};

/// Handle a wl_display request. Returns events to send back.
/// `callback_ids`: track allocated callback IDs for done events.
pub fn handle_request(
    msg: &WlMessage,
    events: &mut [WlEvent; 4],
    event_count: &mut usize,
    registry_id: &mut u32,
) {
    match msg.opcode {
        // sync -- allocate a callback, immediately send done(serial=0)
        0 => {
            let callback_id = msg.arg_u32(0);
            let mut ev = WlEvent::new();
            ev.begin(callback_id, 0); // wl_callback::done
            ev.put_u32(0);            // serial
            ev.finish();
            if *event_count < events.len() {
                events[*event_count] = ev;
                *event_count += 1;
            }

            // Send wl_display::delete_id for the callback
            let mut del = WlEvent::new();
            del.begin(super::WL_DISPLAY_ID, 1); // wl_display::delete_id
            del.put_u32(callback_id);
            del.finish();
            if *event_count < events.len() {
                events[*event_count] = del;
                *event_count += 1;
            }
        }
        // get_registry
        1 => {
            *registry_id = msg.arg_u32(0);
            // Events (global advertisements) sent by the registry module
        }
        _ => {}
    }
}
