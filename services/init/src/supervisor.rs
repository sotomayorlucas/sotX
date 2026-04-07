//! Sprint 2 — passive service supervisor.
//!
//! This is the *passive* form of "panic / respawn": init records the
//! live thread count after spawning each critical service, then a
//! later `check()` call compares against the recorded baseline and
//! reports any thread loss to the serial console. It does **not**
//! actually respawn yet — that requires a kernel-side death-notify
//! hook (parked in TODO.md as "P5: respawn requires SYS_THREAD_NOTIFY").
//!
//! What it gets you today:
//!
//!   * A single source of truth for "which services should be alive".
//!   * Loud detection at boot when one of them silently dies, so a
//!     regression in `init/_start` doesn't get masked by later phases.
//!   * A scaffold the real respawn logic can drop into without
//!     touching every spawn site.
//!
//! Usage from `_start`:
//!
//! ```ignore
//! supervisor::record(b"sot-dtrace");
//! spawn_process(b"sot-dtrace");
//! // ... do work ...
//! supervisor::check_all();  // prints any losses
//! ```

use crate::framebuffer::{print, print_u64};
use sotos_common::sys;

const MAX_TRACKED: usize = 16;
const NAME_LEN: usize = 16;

#[derive(Clone, Copy)]
struct Tracked {
    in_use: bool,
    name: [u8; NAME_LEN],
    nlen: usize,
    /// Thread count *after* spawning this service. If the live count
    /// later drops below this baseline minus the supervisor's slack,
    /// the service is presumed dead.
    baseline: u64,
}

impl Tracked {
    const fn empty() -> Self {
        Self { in_use: false, name: [0; NAME_LEN], nlen: 0, baseline: 0 }
    }
}

static mut TRACKED: [Tracked; MAX_TRACKED] = [const { Tracked::empty() }; MAX_TRACKED];

fn slots() -> &'static mut [Tracked; MAX_TRACKED] { unsafe { &mut TRACKED } }

/// Record that `name` was just spawned. Captures the current
/// `thread_count()` as the baseline so a later check can spot a drop.
pub fn record(name: &[u8]) {
    let baseline = sys::thread_count();
    let entries = slots();
    for slot in entries.iter_mut() {
        if !slot.in_use {
            *slot = Tracked { in_use: true, name: [0; NAME_LEN], nlen: 0, baseline };
            let take = name.len().min(NAME_LEN);
            slot.name[..take].copy_from_slice(&name[..take]);
            slot.nlen = take;
            return;
        }
    }
    print(b"SUPERVISOR: tracked-table full, dropping ");
    print(name);
    print(b"\n");
}

/// Walk every tracked service and complain if the global thread count
/// has fallen below the supervisor's tolerance window. This is a
/// passive smoke check — it does not respawn (parked).
pub fn check_all() {
    let live = sys::thread_count();
    let entries = slots();
    let mut tracked = 0u64;
    let mut healthy = 0u64;
    for slot in entries.iter() {
        if !slot.in_use { continue; }
        tracked += 1;
        // The thread count fluctuates as ephemeral worker threads
        // come and go. We treat "current count >= baseline - 4" as
        // "service still alive": this catches the case where a
        // critical service has actually exited (count drops by ~10+)
        // without false-positiving on every transient worker.
        if live + 4 >= slot.baseline {
            healthy += 1;
        } else {
            print(b"SUPERVISOR: service '");
            print(&slot.name[..slot.nlen]);
            print(b"' may be dead (baseline=");
            print_u64(slot.baseline);
            print(b" live=");
            print_u64(live);
            print(b")\n");
        }
    }
    print(b"SUPERVISOR: ");
    print_u64(healthy);
    print(b"/");
    print_u64(tracked);
    print(b" tracked services healthy (live tids=");
    print_u64(live);
    print(b")\n");
}
