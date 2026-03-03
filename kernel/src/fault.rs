//! Fault queue — forwards user page faults to the VMM server.
//!
//! The kernel pushes `FaultInfo` entries and signals a notification.
//! The VMM server drains the queue via `SYS_FAULT_RECV`.
//!
//! Lock ordering: FAULT_STATE → drop → NOTIFICATIONS → drop → SCHEDULER

use alloc::collections::VecDeque;
use spin::Mutex;

use crate::ipc::notify;

/// Information about a user-mode page fault.
pub struct FaultInfo {
    pub tid: u32,
    pub addr: u64,
    pub code: u64,
}

struct FaultState {
    notify_id: Option<u32>,
    queue: VecDeque<FaultInfo>,
}

static FAULT_STATE: Mutex<FaultState> = Mutex::new(FaultState {
    notify_id: None,
    queue: VecDeque::new(),
});

/// Register the notification object used to wake the VMM on faults.
pub fn register(notify_id: u32) {
    let mut state = FAULT_STATE.lock();
    state.notify_id = Some(notify_id);
}

/// Push a fault onto the queue and signal the VMM.
/// Returns `false` if no VMM is registered (caller should kill the thread).
pub fn push_fault(tid: u32, addr: u64, code: u64) -> bool {
    let notify_id = {
        let mut state = FAULT_STATE.lock();
        let nid = match state.notify_id {
            Some(id) => id,
            None => return false,
        };
        state.queue.push_back(FaultInfo { tid, addr, code });
        nid
    };
    // FAULT_STATE dropped — safe to call into notify (which acquires NOTIFICATIONS).
    let _ = notify::signal(notify_id);
    true
}

/// Pop the next fault from the queue (called by VMM via SYS_FAULT_RECV).
pub fn pop_fault() -> Option<FaultInfo> {
    let mut state = FAULT_STATE.lock();
    state.queue.pop_front()
}
