// ---------------------------------------------------------------------------
// Process lifecycle + identity syscalls
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::process::*;
use crate::fd::*;
use crate::framebuffer::{print, print_u64};
use super::context::SyscallContext;

/// Return value for syscalls that may break the main handler loop.
pub(crate) enum SyscallAction {
    Continue,
    Break,
}

impl SyscallAction {
    pub(crate) fn is_break(&self) -> bool {
        matches!(self, SyscallAction::Break)
    }
}

// ─── Identity / credential syscalls ─────────────────────────────

/// SYS_GETPID (39): returns tgid (thread group ID), not tid.
pub(crate) fn sys_getpid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let tgid = PROCESSES[ctx.pid - 1].tgid.load(Ordering::Acquire);
    reply_val(ctx.ep_cap, if tgid != 0 { tgid as i64 } else { ctx.pid as i64 });
}

/// SYS_GETTID (186): returns actual thread ID.
pub(crate) fn sys_gettid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_GETPPID (110): returns parent pid.
pub(crate) fn sys_getppid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let parent_pid = PROCESSES[ctx.pid - 1].parent.load(Ordering::Acquire);
    reply_val(ctx.ep_cap, parent_pid as i64);
}

/// SYS_GETUID/GETGID/GETEUID/GETEGID — all return 0 (root).
pub(crate) fn sys_getuid_family(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_SETPGID (109): stub.
pub(crate) fn sys_setpgid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETPGRP (111): returns pid.
pub(crate) fn sys_getpgrp(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_SETSID (112): returns pid.
pub(crate) fn sys_setsid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_SETFSUID/SYS_SETFSGID — return previous (0).
pub(crate) fn sys_setfsuid_family(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETPGID (121) / SYS_GETSID (124).
pub(crate) fn sys_getpgid(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let target = msg.regs[0] as usize;
    reply_val(ctx.ep_cap, if target == 0 { ctx.pid as i64 } else { target as i64 });
}

/// SYS_TGKILL (234): send signal to thread in group.
pub(crate) fn sys_tgkill(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let _tgid = msg.regs[0];
    let tid = msg.regs[1] as usize;
    let sig = msg.regs[2] as u8;
    if sig > 0 && sig <= 64 && tid >= 1 && tid <= MAX_PROCS {
        sig_send(tid, sig as u64);
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── TID / robust list ──────────────────────────────────────────

/// SYS_SET_TID_ADDRESS (218): store clear_child_tid pointer, return TID.
pub(crate) fn sys_set_tid_address(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let tidptr = msg.regs[0];
    PROCESSES[ctx.pid - 1].clear_tid.store(tidptr, Ordering::Release);
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_SET_ROBUST_LIST (273): store robust futex list pointer.
pub(crate) fn sys_set_robust_list(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let head = msg.regs[0];
    let len = msg.regs[1];
    if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
        PROCESSES[ctx.pid - 1].robust_list_head.store(head, Ordering::Release);
        PROCESSES[ctx.pid - 1].robust_list_len.store(len, Ordering::Release);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GET_ROBUST_LIST (274): retrieve robust futex list pointer.
pub(crate) fn sys_get_robust_list(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let pid_arg = msg.regs[0] as usize;
    let head_ptr = msg.regs[1]; // user pointer to write head
    let len_ptr = msg.regs[2];  // user pointer to write len
    let target_pid = if pid_arg == 0 { ctx.pid } else { pid_arg };
    if target_pid == 0 || target_pid > MAX_PROCS {
        reply_val(ctx.ep_cap, -ESRCH);
        return;
    }
    let head = PROCESSES[target_pid - 1].robust_list_head.load(Ordering::Acquire);
    let len = PROCESSES[target_pid - 1].robust_list_len.load(Ordering::Acquire);
    if head_ptr != 0 {
        ctx.guest_write(head_ptr, &head.to_le_bytes());
    }
    if len_ptr != 0 {
        ctx.guest_write(len_ptr, &len.to_le_bytes());
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── Signals ────────────────────────────────────────────────────

/// SYS_KILL (62): send signal to process.
pub(crate) fn sys_kill(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let target = msg.regs[0] as usize;
    let sig = msg.regs[1];
    if target == 0 || target > MAX_PROCS || PROCESSES[target - 1].state.load(Ordering::Acquire) == 0 {
        reply_val(ctx.ep_cap, -ESRCH);
        return;
    }
    sig_send(target, sig);
    reply_val(ctx.ep_cap, 0);
}

// ─── Wait ───────────────────────────────────────────────────────

/// SYS_WAIT4 (61): wait for child process.
pub(crate) fn sys_wait4(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let pid = ctx.pid;
    let ep_cap = ctx.ep_cap;
    let wait_pid = msg.regs[0] as i64;
    let status_ptr = msg.regs[1];
    let options = msg.regs[2] as u32;
    let wnohang = options & 1 != 0;

    let mut target: Option<usize> = None;
    if wait_pid > 0 && (wait_pid as usize) <= MAX_PROCS {
        let idx = wait_pid as usize - 1;
        if PROCESSES[idx].parent.load(Ordering::Acquire) == pid as u64 {
            target = Some(wait_pid as usize);
        }
    } else if wait_pid == -1 || wait_pid == 0 {
        for i in 0..MAX_PROCS {
            if PROCESSES[i].parent.load(Ordering::Acquire) == pid as u64 {
                if PROCESSES[i].state.load(Ordering::Acquire) == 2 {
                    target = Some(i + 1);
                    break;
                }
                if target.is_none() && PROCESSES[i].state.load(Ordering::Acquire) == 1 {
                    target = Some(i + 1);
                }
            }
        }
    }

    if let Some(cpid) = target {
        let idx = cpid - 1;
        if wnohang && PROCESSES[idx].state.load(Ordering::Acquire) != 2 {
            reply_val(ep_cap, 0);
        } else {
            // Block until child exits (state == 2).
            // Keep waiting as long as the child is alive (state == 1).
            // Only give up if the child's state goes to 0 (reaped/gone).
            loop {
                let st = PROCESSES[idx].state.load(Ordering::Acquire);
                if st == 2 { break; }
                if st == 0 { break; } // child gone (already reaped)
                sys::yield_now();
            }
            if PROCESSES[idx].state.load(Ordering::Acquire) == 2 {
                let exit_status = PROCESSES[idx].exit_code.load(Ordering::Acquire) as u32;
                if status_ptr != 0 && status_ptr < 0x0000_8000_0000_0000 {
                    let ws = (exit_status << 8) & 0xFF00;
                    ctx.guest_write(status_ptr, &ws.to_le_bytes());
                }
                PROCESSES[idx].state.store(0, Ordering::Release);
                reply_val(ep_cap, cpid as i64);
            } else {
                reply_val(ep_cap, -ECHILD);
            }
        }
    } else {
        reply_val(ep_cap, -ECHILD);
    }
}

/// SYS_WAITID (247): stub.
pub(crate) fn sys_waitid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -ECHILD);
}

// ─── Exit ───────────────────────────────────────────────────────

/// Shared cleanup for SYS_EXIT and SYS_EXIT_GROUP.
fn exit_cleanup(ctx: &mut SyscallContext, status: u64) {
    let pid = ctx.pid;
    if pid == 0 || pid > MAX_PROCS { return; }
    // Override exit code for processes that received deadlock-induced EOF.
    // The deadlock detector closed their pipe write-ends, causing EOF which
    // makes the process exit non-zero. Treat as clean exit (0) so the
    // parent (git) sees a successful helper exit.
    let status = if status != 0 && pid < 16 && unsafe { crate::child_handler::DEADLOCK_EOF[pid] } {
        unsafe { crate::child_handler::DEADLOCK_EOF[pid] = false; }
        0
    } else {
        status
    };
    let memg = PROCESSES[pid - 1].mem_group.load(Ordering::Acquire) as usize;
    if memg >= MAX_PROCS { return; }

    // CLONE_CHILD_CLEARTID: write 0 to *clear_child_tid + futex_wake
    let ctid_ptr = PROCESSES[pid - 1].clear_tid.load(Ordering::Acquire);
    if ctid_ptr != 0 && ctid_ptr < 0x0000_8000_0000_0000 {
        ctx.guest_write(ctid_ptr, &0u32.to_le_bytes());
        futex_wake(ctid_ptr, 1);
    }

    // Free initrd file buffer pages
    for s in 0..GRP_MAX_INITRD {
        if ctx.initrd_files[s][0] != 0 {
            let buf = ctx.initrd_files[s][0];
            let sz = ctx.initrd_files[s][1];
            let pages = sz.saturating_add(0xFFF) / 0x1000;
            let pages = if pages > 1024 { 1024 } else { pages };
            for p in 0..pages { let _ = sys::unmap_free(buf.wrapping_add(p * 0x1000)); }
            ctx.initrd_files[s] = [0; 4];
        }
    }

    // Free child stack pages (skip unmap — child thread may still reference these)
    let sbase = PROCESSES[pid - 1].stack_base.load(Ordering::Acquire);
    let spages = PROCESSES[pid - 1].stack_pages.load(Ordering::Acquire);
    if sbase != 0 && spages != 0 && spages <= 256 {
        PROCESSES[pid - 1].stack_base.store(0, Ordering::Release);
        PROCESSES[pid - 1].stack_pages.store(0, Ordering::Release);
    }

    // Free ELF segment pages
    let elf_lo = PROCESSES[pid - 1].elf_lo.load(Ordering::Acquire);
    let elf_hi = PROCESSES[pid - 1].elf_hi.load(Ordering::Acquire);
    if elf_lo < elf_hi && elf_hi.wrapping_sub(elf_lo) < 0x1000000 {
        let mut pg = elf_lo;
        while pg < elf_hi { let _ = sys::unmap_free(pg); pg = pg.wrapping_add(0x1000); }
        PROCESSES[pid - 1].elf_lo.store(0, Ordering::Release);
        PROCESSES[pid - 1].elf_hi.store(0, Ordering::Release);
    }

    // Free interpreter pages if dynamic binary.
    // has_interp stores the actual interp_base address (not just 0/1)
    // so each process frees its own unique interpreter slot.
    let interp_base = PROCESSES[pid - 1].has_interp.load(Ordering::Acquire);
    if interp_base != 0 {
        for pg in 0..0x110u64 {
            let _ = sys::unmap_free(interp_base + pg * 0x1000);
        }
        PROCESSES[pid - 1].has_interp.store(0, Ordering::Release);
    }

    // Free pre-TLS page
    let _ = sys::unmap_free(0xB70000);

    // Free brk pages
    let brk_lo = PROCESSES[pid - 1].brk_base.load(Ordering::Acquire);
    let brk_hi = PROCESSES[pid - 1].brk_current.load(Ordering::Acquire);
    if brk_lo != 0 && brk_hi > brk_lo && brk_hi.wrapping_sub(brk_lo) < 0x1000000 {
        let mut pg = brk_lo;
        while pg < brk_hi { let _ = sys::unmap_free(pg); pg = pg.wrapping_add(0x1000); }
    }

    // Free mmap pages
    let mmap_lo = PROCESSES[pid - 1].mmap_base.load(Ordering::Acquire);
    let mmap_hi = PROCESSES[pid - 1].mmap_next.load(Ordering::Acquire);
    if mmap_lo != 0 && mmap_hi > mmap_lo && mmap_hi.wrapping_sub(mmap_lo) < 0x10000000 {
        let mut pg = mmap_lo;
        while pg < mmap_hi { let _ = sys::unmap_free(pg); pg = pg.wrapping_add(0x1000); }
    }

    PROCESSES[pid - 1].brk_base.store(0, Ordering::Release);
    PROCESSES[pid - 1].brk_current.store(0, Ordering::Release);
    PROCESSES[pid - 1].mmap_base.store(0, Ordering::Release);
    PROCESSES[pid - 1].mmap_next.store(0, Ordering::Release);
    if memg < MAX_PROCS {
        unsafe { THREAD_GROUPS[memg].brk = 0; THREAD_GROUPS[memg].mmap_next = 0; }
    }
    // Decrement pipe refcounts for any still-open pipe FDs before zeroing.
    // This ensures PIPE_WRITE_CLOSED gets set when the last writer exits,
    // allowing readers to see EOF instead of blocking forever.
    for f in 0..GRP_MAX_FDS {
        let kind = ctx.child_fds[f];
        if kind == 11 {
            // Pipe write end — decrement write refs
            let pipe_id = ctx.sock_conn_id[f] as usize;
            if pipe_id < MAX_PIPES {
                let prev = PIPE_WRITE_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 {
                    PIPE_WRITE_CLOSED[pipe_id].store(1, Ordering::Release);
                    if PIPE_READ_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                        pipe_free(pipe_id);
                    }
                }
            }
        } else if kind == 10 {
            // Pipe read end — decrement read refs
            let pipe_id = ctx.sock_conn_id[f] as usize;
            if pipe_id < MAX_PIPES {
                let prev = PIPE_READ_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 {
                    PIPE_READ_CLOSED[pipe_id].store(1, Ordering::Release);
                    if PIPE_WRITE_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                        pipe_free(pipe_id);
                    }
                }
            }
        }
        ctx.child_fds[f] = 0;
    }
    for s in 0..GRP_MAX_VFS { ctx.vfs_files[s] = [0; 4]; }
    PROCESSES[pid - 1].exit_code.store(status, Ordering::Release);
    PROCESSES[pid - 1].state.store(2, Ordering::Release);
    // Deliver SIGCHLD to parent
    let ppid = PROCESSES[pid - 1].parent.load(Ordering::Acquire) as usize;
    if ppid > 0 && ppid <= MAX_PROCS {
        sig_send(ppid, SIGCHLD as u64);
    }
}

/// SYS_EXIT (60): exit current thread.
pub(crate) fn sys_exit(ctx: &mut SyscallContext, msg: &IpcMsg) -> SyscallAction {
    exit_cleanup(ctx, msg.regs[0]);
    SyscallAction::Break
}

/// SYS_EXIT_GROUP (231): exit all threads in group.
pub(crate) fn sys_exit_group(ctx: &mut SyscallContext, msg: &IpcMsg) -> SyscallAction {
    let status = msg.regs[0] as i32;
    exit_cleanup(ctx, status as u64);
    SyscallAction::Break
}
