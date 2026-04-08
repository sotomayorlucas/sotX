//! Fault queue — forwards user page faults to the VMM server.
//!
//! Supports per-address-space fault handlers: each address space (CR3) can
//! register its own notification. If no per-AS handler is found, falls back
//! to a global handler (backward compatible with single-VMM setup).
//!
//! Also maintains a cr3 → AS cap_id mapping so the VMM can receive the
//! correct capability for map_into on CoW faults from child address spaces.
//!
//! Lock ordering: FAULT_STATE → drop → NOTIFICATIONS → drop → SCHEDULER

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use crate::ipc::notify;
use crate::pool::PoolHandle;

/// Information about a user-mode page fault.
pub struct FaultInfo {
    pub tid: u32,
    pub addr: u64,
    pub code: u64,
    pub cr3: u64,
    /// AS capability ID for the faulting address space (0 = unknown).
    pub as_cap_id: u32,
}

/// Per-AS fault handler entry.
struct FaultHandler {
    cr3: u64,
    notify_handle: PoolHandle,
    queue: VecDeque<FaultInfo>,
}

/// Mapping from CR3 to AS capability ID.
struct Cr3CapEntry {
    cr3: u64,
    cap_id: u32,
}

struct FaultState {
    /// Per-AS fault handlers.
    handlers: Vec<FaultHandler>,
    /// Global/fallback handler (backward compat: register with cr3=0).
    global_notify: Option<PoolHandle>,
    global_queue: VecDeque<FaultInfo>,
    /// CR3 → AS cap_id map (for CoW child address spaces).
    cr3_caps: Vec<Cr3CapEntry>,
}

impl FaultState {
    fn find_handler_mut(&mut self, cr3: u64) -> Option<&mut FaultHandler> {
        self.handlers.iter_mut().find(|h| h.cr3 == cr3)
    }

    fn lookup_cap_id(&self, cr3: u64) -> u32 {
        for e in self.cr3_caps.iter() {
            if e.cr3 == cr3 {
                return e.cap_id;
            }
        }
        0
    }
}

static FAULT_STATE: Mutex<FaultState> = Mutex::new(FaultState {
    handlers: Vec::new(),
    global_notify: None,
    global_queue: VecDeque::new(),
    cr3_caps: Vec::new(),
});

/// Register a notification for fault delivery.
///
/// If `cr3` is 0, registers as the global/fallback handler (backward compat).
/// Otherwise, registers for faults in the specified address space.
pub fn register(notify_handle: PoolHandle, cr3: u64) {
    let mut state = FAULT_STATE.lock();
    if cr3 == 0 {
        state.global_notify = Some(notify_handle);
    } else if let Some(h) = state.find_handler_mut(cr3) {
        h.notify_handle = notify_handle;
    } else {
        state.handlers.push(FaultHandler {
            cr3,
            notify_handle,
            queue: VecDeque::new(),
        });
    }
}

/// Register a cr3 → AS cap_id mapping so fault_recv can deliver the cap.
pub fn register_cr3_cap(cr3: u64, cap_id: u32) {
    let mut state = FAULT_STATE.lock();
    // Update existing entry or add new one.
    for e in state.cr3_caps.iter_mut() {
        if e.cr3 == cr3 {
            e.cap_id = cap_id;
            return;
        }
    }
    state.cr3_caps.push(Cr3CapEntry { cr3, cap_id });
}

/// Push a fault onto the queue and signal the VMM.
/// Returns `false` if no VMM is registered (caller should kill the thread).
pub fn push_fault(tid: u32, addr: u64, code: u64, cr3: u64) -> bool {
    let notify_handle = {
        let mut state = FAULT_STATE.lock();
        let as_cap_id = state.lookup_cap_id(cr3);

        // Try per-AS handler first.
        if let Some(h) = state.find_handler_mut(cr3) {
            let handle = h.notify_handle;
            h.queue.push_back(FaultInfo {
                tid,
                addr,
                code,
                cr3,
                as_cap_id,
            });
            drop(state);
            let _ = notify::signal(handle);
            return true;
        }

        // Fall back to global handler.
        match state.global_notify {
            Some(h) => {
                state.global_queue.push_back(FaultInfo {
                    tid,
                    addr,
                    code,
                    cr3,
                    as_cap_id,
                });
                h
            }
            None => return false,
        }
    };
    // FAULT_STATE dropped — safe to call into notify (which acquires NOTIFICATIONS).
    let _ = notify::signal(notify_handle);
    true
}

/// Pop the next fault from the queue (called by VMM via SYS_FAULT_RECV).
///
/// Checks per-AS queues first (for handlers the caller registered), then global.
/// For simplicity, pops from the first non-empty queue found.
pub fn pop_fault() -> Option<FaultInfo> {
    let mut state = FAULT_STATE.lock();

    // Check per-AS queues.
    for h in state.handlers.iter_mut() {
        if let Some(info) = h.queue.pop_front() {
            return Some(info);
        }
    }

    // Check global queue.
    state.global_queue.pop_front()
}
