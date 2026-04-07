//! Notification objects — binary semaphores for shared-memory IPC.
//!
//! A notification provides a wake/sleep signal between threads:
//! - `signal()`: if a waiter exists, wake it; otherwise set `pending = true`
//! - `wait()`: if `pending`, clear and return immediately; otherwise block
//!
//! Lock ordering: NOTIFICATIONS dropped before scheduler calls.

use sotos_common::SysError;

use crate::pool::{Pool, PoolHandle};
use crate::sched::{self, ThreadId};
use crate::sync::ticket::TicketMutex;

/// Notification identifier (wraps a generation-checked PoolHandle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyId(pub PoolHandle);

struct Notification {
    pending: bool,
    waiting: Option<u32>,
}

impl Notification {
    fn new() -> Self {
        Self {
            pending: false,
            waiting: None,
        }
    }
}

static NOTIFICATIONS: TicketMutex<Pool<Notification>> = TicketMutex::new(Pool::new());

/// Tier 5 KARL: burn padding notification slots so visible IDs drift
/// across reboots. Called once from kmain.
pub fn init() {
    let burn = ((crate::karl::boot_seed() >> 8) & 0xF) as usize;
    let mut ns = NOTIFICATIONS.lock();
    for _ in 0..burn {
        let _ = ns.alloc(Notification::new());
    }
}

/// Allocate a new notification.
pub fn create() -> Option<NotifyId> {
    let mut ns = NOTIFICATIONS.lock();
    let handle = ns.alloc(Notification::new());
    Some(NotifyId(handle))
}

/// Action decided under NOTIFICATIONS lock, executed after drop.
enum WaitAction {
    /// Notification was already pending — consumed immediately.
    AlreadyPending,
    /// Must block until signal arrives.
    Block,
}

/// Wait on a notification: if pending, clear and return; otherwise block.
///
/// SMP fix: sets thread state to Blocked while holding NOTIFICATIONS lock,
/// so signal() on another CPU always finds the thread Blocked when it wakes.
/// Without this, there's a race window between registering as waiter and
/// actually blocking where signal()'s wake() finds state=Running and no-ops.
pub fn wait(handle: PoolHandle) -> Result<(), SysError> {
    let action = {
        let mut ns = NOTIFICATIONS.lock();
        let n = ns.get_mut(handle).ok_or(SysError::NotFound)?;

        if n.pending {
            n.pending = false;
            WaitAction::AlreadyPending
        } else {
            let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
            n.waiting = Some(my_tid.0);
            // Set Blocked while NOTIFICATIONS lock is held (SMP atomicity).
            // signal() can only run after we release this lock, at which
            // point our state is Blocked and wake() will succeed.
            sched::block_current_state_only();
            WaitAction::Block
        }
    };
    // NOTIFICATIONS lock dropped. signal() can now fire and wake us.

    match action {
        WaitAction::AlreadyPending => Ok(()),
        WaitAction::Block => {
            // If signal() already woke us (set Ready + enqueued), schedule()
            // handles it via the self-switch guard: dequeues us, sets Running,
            // returns without context switch.
            sched::schedule();
            Ok(())
        }
    }
}

/// Action decided under NOTIFICATIONS lock, executed after drop.
enum SignalAction {
    /// A waiter was present — wake it.
    WakeWaiter(u32),
    /// No waiter — set pending flag.
    SetPending,
}

/// Signal a notification: if a waiter exists, wake it; otherwise set pending.
pub fn signal(handle: PoolHandle) -> Result<(), SysError> {
    let action = {
        let mut ns = NOTIFICATIONS.lock();
        let n = ns.get_mut(handle).ok_or(SysError::NotFound)?;

        if let Some(tid) = n.waiting.take() {
            SignalAction::WakeWaiter(tid)
        } else {
            n.pending = true;
            SignalAction::SetPending
        }
    };
    // NOTIFICATIONS lock dropped.

    match action {
        SignalAction::WakeWaiter(tid) => {
            sched::wake(ThreadId(tid));
            Ok(())
        }
        SignalAction::SetPending => Ok(()),
    }
}
