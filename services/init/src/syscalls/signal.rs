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
            if signal_deliver(ep_cap, pid, sig, kernel_tid, 0, false) {
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
        // PWC watchpoint: check around oldact write
        let pwc_pre = crate::fd::PIPE_WRITE_CLOSED[1].load(Ordering::Relaxed);
        let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size) };
        for b in buf.iter_mut() { *b = 0; }
        if signo > 0 && signo < 32 {
            let old_h = PROCESSES[idx].sig_handler[signo].load(Ordering::Acquire);
            let old_f = PROCESSES[idx].sig_flags[signo].load(Ordering::Acquire);
            let old_r = PROCESSES[idx].sig_restorer[signo].load(Ordering::Acquire);
            buf[0..8].copy_from_slice(&old_h.to_le_bytes());
            buf[8..16].copy_from_slice(&old_f.to_le_bytes());
            buf[16..24].copy_from_slice(&old_r.to_le_bytes());
        }
        let pwc_post = crate::fd::PIPE_WRITE_CLOSED[1].load(Ordering::Relaxed);
        if pwc_pre != pwc_post {
            crate::framebuffer::print(b"!! SIGACT-CORRUPT P");
            crate::framebuffer::print_u64(ctx.pid as u64);
            crate::framebuffer::print(b" oldact=0x");
            crate::framebuffer::print_hex64(oldact);
            crate::framebuffer::print(b" ksa=");
            crate::framebuffer::print_u64(ksa_size as u64);
            crate::framebuffer::print(b"\n");
        }
    }
    // Install new handler from act
    if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
        let handler = unsafe { *(act_ptr as *const u64) };
        let flags = unsafe { *((act_ptr + 8) as *const u64) };
        let restorer = unsafe { *((act_ptr + 16) as *const u64) };
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
        unsafe { *(oldset as *mut u64) = cur_mask; }
    }
    // Apply new mask
    if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
        let new_set = unsafe { *(set_ptr as *const u64) };
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

/// SYS_SIGALTSTACK (131): stub returning SS_DISABLE.
pub(crate) fn sys_sigaltstack(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let old_ss = msg.regs[1];
    if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
        let buf = unsafe { core::slice::from_raw_parts_mut(old_ss as *mut u8, 24) };
        for b in buf.iter_mut() { *b = 0; }
        buf[8..12].copy_from_slice(&2u32.to_le_bytes());
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── SYS_RT_SIGPENDING (127) ────────────────────────────────────

/// SYS_RT_SIGPENDING (127): return pending signals set.
pub(crate) fn sys_rt_sigpending(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let set_ptr = msg.regs[0];
    if set_ptr != 0 {
        unsafe { *(set_ptr as *mut u64) = 0; } // empty pending set
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
    let sig = sig_dequeue(ctx.pid);
    if sig != 0 {
        match sig_dispatch(ctx.pid, sig) {
            1 => return SyscallAction::Break, // terminated
            3 => {
                if signal_deliver(ctx.ep_cap, ctx.pid, sig, child_tid, 0, true) {
                    return SyscallAction::Continue;
                }
            }
            _ => {}
        }
    }
    // No signal — resume with saved pre-interrupt state via rt_sigreturn
    let mut saved_regs = [0u64; 18];
    if sys::get_thread_regs(child_tid, &mut saved_regs).is_ok() {
        let saved_rsp = saved_regs[15];
        let frame_size = sotos_common::SIGNAL_FRAME_SIZE as u64;
        let new_rsp = ((saved_rsp - frame_size) & !0xF) - 8;
        let fp = new_rsp as *mut u64;
        unsafe {
            core::ptr::write_volatile(fp.add(0),  vdso::SIGRETURN_RESTORER_ADDR);
            core::ptr::write_volatile(fp.add(1),  0);
            core::ptr::write_volatile(fp.add(2),  saved_regs[0]);
            core::ptr::write_volatile(fp.add(3),  saved_regs[1]);
            core::ptr::write_volatile(fp.add(4),  saved_regs[2]);
            core::ptr::write_volatile(fp.add(5),  saved_regs[3]);
            core::ptr::write_volatile(fp.add(6),  saved_regs[4]);
            core::ptr::write_volatile(fp.add(7),  saved_regs[5]);
            core::ptr::write_volatile(fp.add(8),  saved_regs[6]);
            core::ptr::write_volatile(fp.add(9),  saved_regs[7]);
            core::ptr::write_volatile(fp.add(10), saved_regs[8]);
            core::ptr::write_volatile(fp.add(11), saved_regs[9]);
            core::ptr::write_volatile(fp.add(12), saved_regs[10]);
            core::ptr::write_volatile(fp.add(13), saved_regs[11]);
            core::ptr::write_volatile(fp.add(14), saved_regs[12]);
            core::ptr::write_volatile(fp.add(15), saved_regs[13]);
            core::ptr::write_volatile(fp.add(16), saved_regs[14]);
            core::ptr::write_volatile(fp.add(17), saved_regs[2]);
            core::ptr::write_volatile(fp.add(18), saved_rsp);
            core::ptr::write_volatile(fp.add(19), saved_regs[10]);
            core::ptr::write_volatile(fp.add(20), saved_regs[16]);
            core::ptr::write_volatile(fp.add(21), 0);
        }
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::SIG_REDIRECT_TAG,
            regs: [
                vdso::SIGRETURN_RESTORER_ADDR, 0, 0, 0,
                new_rsp, 0, 0, 0,
            ],
        };
        let _ = sys::send(ctx.ep_cap, &reply);
    } else {
        reply_val(ctx.ep_cap, 0);
    }
    SyscallAction::Continue
}
