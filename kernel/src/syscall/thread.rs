//! Thread management syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::mm::paging;
use crate::sched::{self, ThreadId};
use sotos_common::SysError;

use super::{
    USER_ADDR_LIMIT,
    SYS_THREAD_CREATE, SYS_THREAD_EXIT, SYS_THREAD_RESUME,
    SYS_THREAD_INFO, SYS_THREAD_COUNT, SYS_RESOURCE_LIMIT,
    SYS_SET_FSBASE, SYS_GET_FSBASE,
};

/// Syscall number — set FS_BASE for a target thread (by thread cap).
const SYS_SET_THREAD_FSBASE: u64 = 162;

/// Handle thread management syscalls. Returns `true` if the syscall was handled.
///
/// Note: SYS_THREAD_CREATE_IN (122) requires `saved_user_rsp` for early return,
/// so it is handled in mod.rs directly.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_THREAD_CREATE — create a new user thread in caller's address space
        // rdi = entry RIP, rsi = stack RSP, rdx = optional redirect endpoint cap (0 = none)
        // returns thread cap_id
        SYS_THREAD_CREATE => {
            let rip = frame.rdi;
            let rsp = frame.rsi;
            let redirect_cap = frame.rdx;
            if rip == 0 || rsp == 0 || rip >= USER_ADDR_LIMIT || rsp >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Validate optional redirect endpoint cap
                let redirect_ep = if redirect_cap != 0 {
                    match cap::validate(redirect_cap as u32, Rights::READ.or(Rights::WRITE)) {
                        Ok(CapObject::Endpoint { id: ep_id }) => Some(ep_id),
                        _ => {
                            frame.rax = SysError::InvalidCap as i64 as u64;
                            return true;
                        }
                    }
                } else {
                    None
                };
                let cr3 = paging::read_cr3();
                let tid = if let Some(ep_id) = redirect_ep {
                    sched::spawn_user_with_redirect(rip, rsp, cr3, ep_id)
                } else {
                    sched::spawn_user(rip, rsp, cr3)
                };
                match cap::insert(CapObject::Thread { id: tid.0 }, Rights::ALL, None) {
                    Some(cap_id) => frame.rax = cap_id.raw() as u64,
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
        }

        // SYS_THREAD_EXIT — terminate the current thread (never returns)
        SYS_THREAD_EXIT => {
            sched::exit_current();
        }

        // SYS_THREAD_RESUME — resume a faulted thread (rdi = tid)
        SYS_THREAD_RESUME => {
            let tid = frame.rdi as u32;
            if sched::resume_faulted(ThreadId(tid)) {
                frame.rax = 0;
            } else {
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        // SYS_THREAD_INFO — get info about a thread by pool index
        // rdi = thread pool index; returns rdi=tid, rsi=state, rdx=priority,
        // r8=cpu_ticks, r9=mem_pages, r10=is_user
        SYS_THREAD_INFO => {
            let idx = frame.rdi as u32;
            match sched::thread_info(idx) {
                Some((tid, state, pri, ticks, mem, is_user)) => {
                    frame.rax = 0;
                    frame.rdi = tid as u64;
                    frame.rsi = state as u64;
                    frame.rdx = pri as u64;
                    frame.r8 = ticks;
                    frame.r9 = mem as u64;
                    frame.r10 = if is_user { 1 } else { 0 };
                }
                None => frame.rax = SysError::NotFound as i64 as u64,
            }
        }

        // SYS_RESOURCE_LIMIT — set resource limits on current thread
        // rdi = cpu_tick_limit (0 = unlimited), rsi = mem_page_limit (0 = unlimited)
        SYS_RESOURCE_LIMIT => {
            if let Some(tid) = sched::current_tid() {
                sched::set_resource_limits(tid, frame.rdi, frame.rsi as u32);
                frame.rax = 0;
            } else {
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        // SYS_THREAD_COUNT — get total live thread count
        SYS_THREAD_COUNT => {
            frame.rax = sched::thread_count() as u64;
        }

        // SYS_SET_FSBASE — set FS_BASE MSR for current thread (TLS)
        // rdi = new FS base address
        SYS_SET_FSBASE => {
            sched::set_current_fs_base(frame.rdi);
            frame.rax = 0;
        }

        // SYS_GET_FSBASE — get FS_BASE of current thread
        SYS_GET_FSBASE => {
            frame.rax = sched::get_current_fs_base();
        }

        // SYS_SET_THREAD_FSBASE (162) — set FS_BASE for a target thread (by thread cap)
        // rdi = thread_cap (WRITE), rsi = new FS base address
        SYS_SET_THREAD_FSBASE => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Thread { id: tid }) => {
                    sched::set_thread_fs_base(ThreadId(tid), frame.rsi);
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_GET_THREAD_REGS (172) — read saved user registers of a blocked thread.
        // Used by LUCAS for signal frame construction.
        // rdi = thread_id, rsi = output buffer pointer (20 u64s in caller's space).
        // Returns: [0..14]=GPRs, [15]=RSP, [16]=fs_base, [17]=kernel_signal,
        //          [18]=real_rip, [19]=real_rflags (non-zero when from interrupt context).
        sotos_common::SYS_GET_THREAD_REGS => {
            let target_tid = frame.rdi as u32;
            let buf_ptr = frame.rsi;
            if buf_ptr == 0 || buf_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                match sched::get_thread_signal_regs(ThreadId(target_tid)) {
                    Some(regs) => {
                        let out = buf_ptr as *mut u64;
                        unsafe {
                            for i in 0..20 {
                                core::ptr::write_volatile(out.add(i), regs[i]);
                            }
                        }
                        frame.rax = 0;
                    }
                    None => {
                        frame.rax = SysError::NotFound as i64 as u64;
                    }
                }
            }
        }

        // SYS_SIGNAL_ENTRY (173) — set the async signal trampoline address for a thread.
        // rdi = thread_cap (WRITE), rsi = trampoline address in child's address space.
        sotos_common::SYS_SIGNAL_ENTRY => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Thread { id: tid }) => {
                    sched::set_signal_trampoline(ThreadId(tid), frame.rsi);
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_SIGNAL_INJECT (174) — inject an async signal into a thread.
        // rdi = thread_id (raw), rsi = signal number (1..31).
        // Sets the pending_signals bit. The timer handler will deliver it on
        // the next return-to-user.
        sotos_common::SYS_SIGNAL_INJECT => {
            let target_tid = frame.rdi as u32;
            let sig = frame.rsi;
            if sig == 0 || sig >= 32 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                sched::set_pending_signal(ThreadId(target_tid), sig);
                frame.rax = 0;
            }
        }

        _ => return false,
    }
    true
}
