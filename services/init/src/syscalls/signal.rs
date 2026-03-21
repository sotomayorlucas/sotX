// ---------------------------------------------------------------------------
// Signal syscalls: rt_sigaction, rt_sigprocmask, sigaltstack, signal trampoline
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::process::*;
use crate::vdso;
use super::context::SyscallContext;
use super::task::SyscallAction;

// ─── Signal check at top of syscall loop ─────────────────────────

/// Check for pending unblocked signals and handle them.
/// Called at the top of each syscall dispatch iteration.
/// Returns: Some(SyscallAction) if the signal was handled (caller should
/// break/continue), None if no actionable signal or delivery fell through.
pub(crate) fn check_pending_signals(
    ep_cap: u64,
    pid: usize,
    kernel_tid: u64,
    child_as_cap: u64,
) -> Option<SyscallAction> {
    let sig = sig_dequeue(pid);
    if sig == 0 {
        return None;
    }
    match sig_dispatch(pid, sig) {
        1 => Some(SyscallAction::Break),        // terminated
        2 => {
            reply_val(ep_cap, -EINTR);
            Some(SyscallAction::Continue)        // -EINTR
        }
        3 => {
            // User handler registered — deliver signal via frame injection
            if signal_deliver(ep_cap, pid, sig, kernel_tid, 0, false, 0, 0, child_as_cap) {
                Some(SyscallAction::Continue)    // signal_deliver already replied
            } else {
                None // Delivery failed — fall through to normal dispatch
            }
        }
        _ => None, // ignored, continue to normal dispatch
    }
}

// ─── SYS_RT_SIGACTION (13) ───────────────────────────────────────

/// SYS_RT_SIGACTION (13): install/query signal handler.
pub(crate) fn sys_rt_sigaction(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let signo = msg.regs[0] as usize;
    let act_ptr = msg.regs[1];
    let oldact = msg.regs[2];
    let sigsetsize = msg.regs[3].max(8) as usize;
    let ksa_size = (24 + sigsetsize).min(64);
    if signo == 0 || signo >= 32 || signo == 9 || signo == 19 {
        // SIGKILL(9) and SIGSTOP(19) cannot be caught
        if signo == 9 || signo == 19 {
            reply_val(ctx.ep_cap, -EINVAL);
            return;
        }
    }
    let idx = ctx.pid - 1;
    // Write old handler to oldact
    if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
        let mut buf = [0u8; 64];
        if signo > 0 && signo < 32 {
            let old_h = PROCESSES[idx].sig_handler[signo].load(Ordering::Acquire);
            let old_f = PROCESSES[idx].sig_flags[signo].load(Ordering::Acquire);
            let old_r = PROCESSES[idx].sig_restorer[signo].load(Ordering::Acquire);
            buf[0..8].copy_from_slice(&old_h.to_le_bytes());
            buf[8..16].copy_from_slice(&old_f.to_le_bytes());
            buf[16..24].copy_from_slice(&old_r.to_le_bytes());
        }
        ctx.guest_write(oldact, &buf[..ksa_size]);
    }
    // Install new handler from act
    if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
        let mut act_buf = [0u8; 24];
        ctx.guest_read(act_ptr, &mut act_buf);
        let handler = u64::from_le_bytes(act_buf[0..8].try_into().unwrap());
        let flags = u64::from_le_bytes(act_buf[8..16].try_into().unwrap());
        let restorer = u64::from_le_bytes(act_buf[16..24].try_into().unwrap());
        PROCESSES[idx].sig_handler[signo].store(handler, Ordering::Release);
        PROCESSES[idx].sig_flags[signo].store(flags, Ordering::Release);
        PROCESSES[idx].sig_restorer[signo].store(restorer, Ordering::Release);
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── SYS_RT_SIGPROCMASK (14) ────────────────────────────────────

/// SYS_RT_SIGPROCMASK (14): block/unblock signals.
pub(crate) fn sys_rt_sigprocmask(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let how = msg.regs[0];
    let set_ptr = msg.regs[1];
    let oldset = msg.regs[2];
    let idx = ctx.pid - 1;
    let cur_mask = PROCESSES[idx].sig_blocked.load(Ordering::Acquire);
    // Write old mask
    if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
        ctx.guest_write(oldset, &cur_mask.to_le_bytes());
    }
    // Apply new mask
    if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
        let new_set = ctx.guest_read_u64(set_ptr);
        // Can't block SIGKILL or SIGSTOP
        let safe_set = new_set & !((1 << SIGKILL) | (1 << 19));
        match how {
            0 => PROCESSES[idx].sig_blocked.store(cur_mask | safe_set, Ordering::Release),  // SIG_BLOCK
            1 => PROCESSES[idx].sig_blocked.store(cur_mask & !safe_set, Ordering::Release), // SIG_UNBLOCK
            2 => PROCESSES[idx].sig_blocked.store(safe_set, Ordering::Release),             // SIG_SETMASK
            _ => {}
        }
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── SYS_SIGALTSTACK (131) ──────────────────────────────────────

/// SYS_SIGALTSTACK (131): get/set alternate signal stack.
/// Linux signature: sigaltstack(const stack_t *ss, stack_t *old_ss)
/// stack_t layout (24 bytes): { ss_sp: *mut void (8), ss_flags: i32 (padded to 8), ss_size: usize (8) }
/// msg.regs[7] = caller's user RSP (passed by kernel in IPC redirect).
pub(crate) fn sys_sigaltstack(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let new_ss = msg.regs[0]; // 1st arg: pointer to new stack_t (or 0/NULL)
    let old_ss = msg.regs[1]; // 2nd arg: pointer to old stack_t output (or 0/NULL)
    let caller_rsp = msg.regs[7]; // user RSP at syscall entry
    let idx = ctx.pid - 1;
    let p = &PROCESSES[idx];

    // Compute whether the caller is currently on the alt stack
    let cur_sp = p.sig_alt_sp.load(Ordering::Acquire);
    let cur_flags = p.sig_alt_flags.load(Ordering::Acquire);
    let cur_size = p.sig_alt_size.load(Ordering::Acquire);
    let on_altstack = cur_flags != SS_DISABLE
        && cur_sp != 0 && cur_size != 0
        && caller_rsp >= cur_sp && caller_rsp < cur_sp + cur_size;

    // Write current alt stack state to old_ss if non-null
    if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
        let report_flags = if cur_flags == SS_DISABLE {
            SS_DISABLE
        } else if on_altstack {
            SS_ONSTACK
        } else {
            0 // enabled, not currently on it
        };
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&cur_sp.to_le_bytes());
        buf[8..16].copy_from_slice(&report_flags.to_le_bytes());
        buf[16..24].copy_from_slice(&cur_size.to_le_bytes());
        ctx.guest_write(old_ss, &buf);
    }

    // Read and apply new alt stack from new_ss if non-null
    if new_ss != 0 && new_ss < 0x0000_8000_0000_0000 {
        // Cannot change alt stack while currently on it
        if on_altstack {
            reply_val(ctx.ep_cap, -EPERM);
            return;
        }

        let mut ss_buf = [0u8; 24];
        ctx.guest_read(new_ss, &mut ss_buf);
        let ss_sp = u64::from_le_bytes(ss_buf[0..8].try_into().unwrap());
        let ss_flags = u64::from_le_bytes(ss_buf[8..16].try_into().unwrap());
        let ss_size = u64::from_le_bytes(ss_buf[16..24].try_into().unwrap());

        if ss_flags & SS_DISABLE != 0 {
            // Disabling alt stack
            p.sig_alt_sp.store(0, Ordering::Release);
            p.sig_alt_size.store(0, Ordering::Release);
            p.sig_alt_flags.store(SS_DISABLE, Ordering::Release);
        } else {
            // Enabling alt stack — validate size
            if ss_size < MINSIGSTKSZ {
                reply_val(ctx.ep_cap, -ENOMEM);
                return;
            }
            p.sig_alt_sp.store(ss_sp, Ordering::Release);
            p.sig_alt_size.store(ss_size, Ordering::Release);
            p.sig_alt_flags.store(0, Ordering::Release); // enabled
        }
    }

    reply_val(ctx.ep_cap, 0);
}

// ─── SYS_RT_SIGPENDING (127) ────────────────────────────────────

/// SYS_RT_SIGPENDING (127): return pending signals set.
pub(crate) fn sys_rt_sigpending(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let set_ptr = msg.regs[0];
    if set_ptr != 0 {
        ctx.guest_write(set_ptr, &0u64.to_le_bytes()); // empty pending set
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── SYS_RT_SIGTIMEDWAIT (128) ──────────────────────────────────

/// SYS_RT_SIGTIMEDWAIT (128): stub.
pub(crate) fn sys_rt_sigtimedwait(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -EAGAIN);
}

// ─── SYS_RT_SIGSUSPEND (130) ────────────────────────────────────

/// SYS_RT_SIGSUSPEND (130): stub.
pub(crate) fn sys_rt_sigsuspend(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -EINTR);
}

// ─── SYS_RT_SIGQUEUEINFO (129) ──────────────────────────────────

/// SYS_RT_SIGQUEUEINFO (129): stub.
pub(crate) fn sys_rt_sigqueueinfo(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

// ─── 0x7F00: Async signal trampoline ─────────────────────────────

/// Handle 0x7F00 (async signal delivery from vDSO trampoline).
/// Returns SyscallAction::Break if signal terminates the process.
pub(crate) fn sys_signal_trampoline(ctx: &mut SyscallContext, msg: &IpcMsg) -> SyscallAction {
    let child_tid = msg.regs[6];

    // Read saved regs ONCE (get_thread_signal_regs auto-clears signal_ctx_valid,
    // so calling it twice would lose the real RIP on the second call).
    let mut saved_regs = [0u64; 20];
    let regs_ok = sys::get_thread_regs(child_tid, &mut saved_regs).is_ok();

    let mut sig = sig_dequeue(ctx.pid);

    // If no init-side signal, check kernel-generated signal (regs[17]).
    if sig == 0 && regs_ok {
        let kernel_sig = saved_regs[17];
        if kernel_sig > 0 && kernel_sig < 32 {
            sig = kernel_sig;
        }
    }

    if sig != 0 {
        // For kernel-generated signals (#PF SIGSEGV), read fault address and error code.
        let (fault_addr, fault_code) = if sig == 11 {
            sys::get_fault_info(child_tid)
        } else {
            (0u64, 0u64)
        };
        match sig_dispatch(ctx.pid, sig) {
            1 => return SyscallAction::Break, // terminated
            2 => {
                reply_val(ctx.ep_cap, -EINTR);
                return SyscallAction::Continue;
            }
            3 => {
                if signal_deliver(ctx.ep_cap, ctx.pid, sig, child_tid, 0, true, fault_addr, fault_code, ctx.child_as_cap) {
                    return SyscallAction::Continue;
                }
            }
            _ => {} // ignored — fall through to resume
        }
    }

    // Clear sig_in_handler: if we reach here with no pending signal,
    // any previous SIGSEGV handler has returned successfully.
    PROCESSES[ctx.pid - 1].sig_in_handler.store(0, Ordering::Release);

    // No signal — resume directly without writing to the child's stack.
    // Previously this wrote a SignalFrame below RSP + called rt_sigreturn,
    // but that corrupts the child's stack data (e.g., sendmsg iovecs)
    // when the timer interrupt fires during a syscall setup.
    // SIG_REDIRECT_TAG restores RCX(→RIP), RDI, RSI, RDX, RSP, RAX.
    // Other GPRs (RBX, RBP, R8-R15 except R11) are preserved by the
    // trampoline (which only does `mov eax, 0x7F00; syscall`).
    if !regs_ok {
        sys::yield_now();
        if sys::get_thread_regs(child_tid, &mut saved_regs).is_err() {
            crate::framebuffer::print(b"SIGNAL-RESUME-FAIL P");
            crate::framebuffer::print_u64(ctx.pid as u64);
            crate::framebuffer::print(b" tid=");
            crate::framebuffer::print_u64(child_tid);
            crate::framebuffer::print(b"\n");
            let reply = sotos_common::IpcMsg {
                tag: sotos_common::SIG_REDIRECT_TAG,
                regs: [
                    vdso::SIGRETURN_RESTORER_ADDR, 0, 0, 0,
                    0x900000, 0, 0, 0,
                ],
            };
            let _ = sys::send(ctx.ep_cap, &reply);
            return SyscallAction::Continue;
        }
    }
    let saved_rsp = saved_regs[15];
    let real_rip = if saved_regs[18] != 0 { saved_regs[18] } else { saved_regs[2] };
    let reply = sotos_common::IpcMsg {
        tag: sotos_common::SIG_REDIRECT_TAG,
        regs: [
            real_rip,        // → RCX/RIP: resume at original instruction
            saved_regs[5],   // → RDI: restore original rdi
            saved_regs[4],   // → RSI: restore original rsi
            saved_regs[3],   // → RDX: restore original rdx
            saved_rsp,       // → RSP: restore original stack pointer
            saved_regs[0],   // → RAX: restore original rax
            0, 0,
        ],
    };
    let _ = sys::send(ctx.ep_cap, &reply);
    SyscallAction::Continue
}
