//! Fault forwarding syscall handlers (VMM support).

use crate::arch::x86_64::syscall::TrapFrame;
use crate::sched::{self, ThreadId};
use sotos_common::SysError;

use super::SYS_FAULT_RECV;

/// Handle fault forwarding syscalls. Returns `true` if the syscall was handled.
///
/// Note: SYS_FAULT_REGISTER needs `saved_user_rsp` for early return on error,
/// so it is handled in mod.rs directly.
/// SYS_GET_FAULT_INFO uses sotos_common::SYS_GET_FAULT_INFO (176) and is also
/// handled here.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_FAULT_RECV — pop next fault from queue
        // Returns: rdi=addr, rsi=code, rdx=tid, r8=cr3, r9=as_cap_id (or WouldBlock)
        SYS_FAULT_RECV => match crate::fault::pop_fault() {
            Some(info) => {
                frame.rax = 0;
                frame.rdi = info.addr;
                frame.rsi = info.code;
                frame.rdx = info.tid as u64;
                frame.r8 = info.cr3;
                frame.r9 = info.as_cap_id as u64;
            }
            None => {
                frame.rax = SysError::WouldBlock as i64 as u64;
            }
        },

        // SYS_GET_FAULT_INFO (176) — get fault addr/code for a thread's last kernel signal.
        // rdi = thread_id (raw), returns: rax = fault_addr, rdx = fault_code.
        sotos_common::SYS_GET_FAULT_INFO => {
            let target_tid = frame.rdi as u32;
            let mut sched_lock = sched::SCHEDULER.lock();
            if let Some(slot) = sched_lock.slot_of(ThreadId(target_tid)) {
                if let Some(t) = sched_lock.threads.get_mut_by_index(slot) {
                    frame.rax = t.fault_addr;
                    frame.rdx = t.fault_code;
                    // Consume: clear after read
                    t.fault_addr = 0;
                    t.fault_code = 0;
                } else {
                    frame.rax = 0;
                    frame.rdx = 0;
                }
            } else {
                frame.rax = 0;
                frame.rdx = 0;
            }
            drop(sched_lock);
        }

        _ => return false,
    }
    true
}
