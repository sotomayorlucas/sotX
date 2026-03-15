// ---------------------------------------------------------------------------
// Time, system info, scheduling, resource limits, and misc stubs.
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::{reply_val, rdtsc};
use crate::process::*;
use crate::fd::*;
use super::context::SyscallContext;

// ─── Time syscalls ──────────────────────────────────────────────

/// SYS_CLOCK_GETTIME (228): return monotonic/realtime clock.
/// CLOCK_REALTIME(0): elapsed + epoch offset. CLOCK_MONOTONIC(1): elapsed only.
pub(crate) fn sys_clock_gettime(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let clock_id = msg.regs[0];
    let tp_ptr = msg.regs[1];
    if tp_ptr != 0 {
        let tsc = rdtsc();
        let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
        let elapsed_ns = if tsc > boot_tsc { (tsc - boot_tsc) / 2 } else { 0 };
        let total_ns = if clock_id == 1 { elapsed_ns } else { elapsed_ns + UPTIME_OFFSET_NS };
        let secs = (total_ns / 1_000_000_000) as i64;
        let nsecs = (total_ns % 1_000_000_000) as i64;
        let mut tp = [0u8; 16];
        tp[0..8].copy_from_slice(&secs.to_le_bytes());
        tp[8..16].copy_from_slice(&nsecs.to_le_bytes());
        ctx.guest_write(tp_ptr, &tp);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETTIMEOFDAY (96): return time of day (always CLOCK_REALTIME).
pub(crate) fn sys_gettimeofday(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let tv_ptr = msg.regs[0];
    if tv_ptr != 0 {
        let tsc = rdtsc();
        let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
        let elapsed_us = if tsc > boot_tsc { (tsc - boot_tsc) / 2000 } else { 0 };
        let total_secs = elapsed_us / 1_000_000 + UPTIME_OFFSET_SECS;
        let usecs = elapsed_us % 1_000_000;
        let mut tv = [0u8; 16];
        tv[0..8].copy_from_slice(&total_secs.to_le_bytes());
        tv[8..16].copy_from_slice(&usecs.to_le_bytes());
        ctx.guest_write(tv_ptr, &tv);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_TIME (201): return seconds since epoch.
pub(crate) fn sys_time(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let tsc = rdtsc();
    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
    let elapsed_secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 };
    let secs = elapsed_secs + UPTIME_OFFSET_SECS;
    let tloc = msg.regs[0];
    if tloc != 0 {
        ctx.guest_write(tloc, &secs.to_le_bytes());
    }
    reply_val(ctx.ep_cap, secs as i64);
}

/// SYS_NANOSLEEP (35): stub returning 0.
pub(crate) fn sys_nanosleep(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_CLOCK_GETRES (229): return 1ns resolution.
pub(crate) fn sys_clock_getres(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let tp = msg.regs[1];
    if tp != 0 {
        let mut buf = [0u8; 16];
        buf[8] = 1; // tv_nsec = 1 (1ns resolution)
        ctx.guest_write(tp, &buf);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_CLOCK_NANOSLEEP (230): sleep stub (yield a few times).
pub(crate) fn sys_clock_nanosleep(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    for _ in 0..10 { sys::yield_now(); }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_TIMES (100): return process times.
pub(crate) fn sys_times(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf = msg.regs[0];
    if buf != 0 {
        // struct tms = 4 * i64 = 32 bytes (clock_t = i64 on x86_64)
        let zeros = [0u8; 32];
        ctx.guest_write(buf, &zeros);
    }
    // Return clock ticks since boot
    let tsc = rdtsc();
    reply_val(ctx.ep_cap, (tsc / 20_000_000) as i64); // ~100 Hz ticks
}

/// SYS_GETITIMER (36) / SYS_SETITIMER (38): timer stubs.
pub(crate) fn sys_getitimer(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf = msg.regs[1];
    if buf != 0 { let zeros = [0u8; 32]; ctx.guest_write(buf, &zeros); }
    reply_val(ctx.ep_cap, 0);
}

pub(crate) fn sys_setitimer(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let old = msg.regs[2];
    if old != 0 { let zeros = [0u8; 32]; ctx.guest_write(old, &zeros); }
    reply_val(ctx.ep_cap, 0);
}

// ─── System info ────────────────────────────────────────────────

/// SYS_SYSINFO (99): return system info struct.
pub(crate) fn sys_sysinfo(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf_addr = msg.regs[0];
    if buf_addr != 0 {
        // struct sysinfo is 112 bytes on x86_64
        let mut si = [0u8; 112];
        let tsc = rdtsc();
        let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
        let secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 };
        // offset 0: uptime (i64)
        si[0..8].copy_from_slice(&(secs + UPTIME_OFFSET_SECS).to_le_bytes());
        // offset 32: totalram (u64) — report 1 GiB
        si[32..40].copy_from_slice(&(1024u64 * 1024 * 1024).to_le_bytes());
        // offset 40: freeram (u64) — report 512 MiB
        si[40..48].copy_from_slice(&(512u64 * 1024 * 1024).to_le_bytes());
        // offset 80: procs (u16)
        si[80..82].copy_from_slice(&1u16.to_le_bytes());
        // offset 104: mem_unit (u32) — 1 byte
        si[104..108].copy_from_slice(&1u32.to_le_bytes());
        ctx.guest_write(buf_addr, &si);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETRUSAGE (98): return zeroed rusage.
pub(crate) fn sys_getrusage(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf = msg.regs[1];
    if buf != 0 {
        let zeros = [0u8; 144];
        ctx.guest_write(buf, &zeros);
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── Resource limits ────────────────────────────────────────────

/// SYS_PRLIMIT64 (302): query/set resource limits.
pub(crate) fn sys_prlimit64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let new_limit = msg.regs[2];
    let old_limit = msg.regs[3];
    if old_limit != 0 && old_limit < 0x0000_8000_0000_0000 {
        let big: u64 = 0x7FFF_FFFF_FFFF_FFFF;
        let mut rl = [0u8; 16];
        rl[0..8].copy_from_slice(&big.to_le_bytes()); // rlim_cur
        rl[8..16].copy_from_slice(&big.to_le_bytes()); // rlim_max
        ctx.guest_write(old_limit, &rl);
    }
    let _ = new_limit;
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETRLIMIT (97): return generous resource limits.
pub(crate) fn sys_getrlimit(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let rlim_ptr = msg.regs[1];
    if rlim_ptr != 0 {
        let big: u64 = 0x7FFF_FFFF_FFFF_FFFF;
        let mut rl = [0u8; 16];
        rl[0..8].copy_from_slice(&big.to_le_bytes());
        rl[8..16].copy_from_slice(&big.to_le_bytes());
        ctx.guest_write(rlim_ptr, &rl);
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── Scheduling ─────────────────────────────────────────────────

/// SYS_SCHED_YIELD (24): yield CPU.
pub(crate) fn sys_sched_yield(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    sys::yield_now();
    reply_val(ctx.ep_cap, 0);
}

/// SYS_SCHED_GETAFFINITY (204): return CPU mask.
pub(crate) fn sys_sched_getaffinity(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let mask_ptr = msg.regs[2];
    let len = msg.regs[1] as usize;
    if mask_ptr != 0 && len > 0 {
        let safe_len = len.min(128);
        let mut mask = [0u8; 128];
        mask[0] = 1; // CPU 0
        ctx.guest_write(mask_ptr, &mask[..safe_len]);
    }
    reply_val(ctx.ep_cap, len.min(128) as i64);
}

/// SYS_SCHED_GETPARAM (143): return sched priority.
pub(crate) fn sys_sched_getparam(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf = msg.regs[1];
    if buf != 0 { ctx.guest_write(buf, &0i32.to_le_bytes()); } // sched_priority = 0
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETRANDOM (318): fill buffer with random bytes.
pub(crate) fn sys_getrandom(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf_ptr = msg.regs[0];
    let buflen = msg.regs[1] as usize;
    let safe_len = buflen.min(4096);
    let mut local = [0u8; 4096];
    crate::child_handler::fill_random(&mut local[..safe_len]);
    ctx.guest_write(buf_ptr, &local[..safe_len]);
    reply_val(ctx.ep_cap, safe_len as i64);
}

// ─── Process control ────────────────────────────────────────────

/// SYS_PRCTL (157): process control operations.
pub(crate) fn sys_prctl(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let option = msg.regs[0] as u32;
    match option {
        15 => { // PR_SET_NAME: store in proc_name
            let buf = msg.regs[1];
            if buf != 0 && ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                let mut raw = [0u8; 16];
                ctx.guest_read(buf, &mut raw);
                // NUL-terminate at 15
                raw[15] = 0;
                let w0 = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let w1 = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                PROCESSES[ctx.pid - 1].proc_name[0].store(w0, Ordering::Release);
                PROCESSES[ctx.pid - 1].proc_name[1].store(w1, Ordering::Release);
            }
            reply_val(ctx.ep_cap, 0);
        }
        16 => { // PR_GET_NAME: return stored name (or "program" default)
            let buf = msg.regs[1];
            if buf != 0 && ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                let w0 = PROCESSES[ctx.pid - 1].proc_name[0].load(Ordering::Acquire);
                let w1 = PROCESSES[ctx.pid - 1].proc_name[1].load(Ordering::Acquire);
                let mut name = [0u8; 16];
                if w0 == 0 && w1 == 0 {
                    name[..7].copy_from_slice(b"program");
                } else {
                    name[0..8].copy_from_slice(&w0.to_le_bytes());
                    name[8..16].copy_from_slice(&w1.to_le_bytes());
                }
                ctx.guest_write(buf, &name);
            }
            reply_val(ctx.ep_cap, 0);
        }
        38 => reply_val(ctx.ep_cap, 0), // PR_SET_NO_NEW_PRIVS
        _ => reply_val(ctx.ep_cap, -EINVAL),
    }
}

// ─── Futex ──────────────────────────────────────────────────────

/// SYS_FUTEX (202): fast userspace locking.
pub(crate) fn sys_futex(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let uaddr = msg.regs[0];
    let op = (msg.regs[1] & 0x7F) as u32; // mask off FUTEX_PRIVATE_FLAG
    let val = msg.regs[2] as u32;
    match op {
        0 => { // FUTEX_WAIT
            // Read the futex value from the child's address space (not init's).
            // Without this, CoW fork children read stale/wrong values → -EAGAIN spin.
            let mut buf = [0u8; 4];
            ctx.guest_read(uaddr, &mut buf);
            let current = u32::from_le_bytes(buf);
            if current != val {
                reply_val(ctx.ep_cap, -EAGAIN);
            } else {
                let result = futex_wait(uaddr, val);
                reply_val(ctx.ep_cap, result);
            }
        }
        1 => { // FUTEX_WAKE
            let result = futex_wake(uaddr, val);
            reply_val(ctx.ep_cap, result);
        }
        _ => reply_val(ctx.ep_cap, 0), // other ops: stub
    }
}

// ─── Identity / credential stubs ────────────────────────────────

/// SYS_GETRESUID (118) / SYS_GETRESGID (120): return all-root.
pub(crate) fn sys_getresuid(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let (r, e, s) = (msg.regs[0], msg.regs[1], msg.regs[2]);
    if r != 0 { unsafe { *(r as *mut u32) = 0; } }
    if e != 0 { unsafe { *(e as *mut u32) = 0; } }
    if s != 0 { unsafe { *(s as *mut u32) = 0; } }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_CAPGET (125): return empty capabilities.
pub(crate) fn sys_capget(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let data = msg.regs[1];
    if data != 0 {
        let zeros = [0u8; 24];
        ctx.guest_write(data, &zeros);
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── Event subsystems (eventfd, timerfd, memfd) ─────────────────

/// SYS_EVENTFD (284) / SYS_EVENTFD2 (290): create eventfd.
pub(crate) fn sys_eventfd(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let initval = msg.regs[0];
    let flags = if syscall_nr == SYS_EVENTFD2 { msg.regs[1] as u32 } else { 0 };
    let mut fd = None;
    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
    let mut slot = None;
    for i in 0..super::context::MAX_EVENTFDS { if ctx.eventfd_slot_fd[i] == usize::MAX { slot = Some(i); break; } }
    if let (Some(f), Some(s)) = (fd, slot) {
        ctx.child_fds[f] = 22;
        ctx.eventfd_slot_fd[s] = f;
        ctx.eventfd_counter[s] = initval;
        ctx.eventfd_flags[s] = flags;
        reply_val(ctx.ep_cap, f as i64);
    } else { reply_val(ctx.ep_cap, -EMFILE); }
}

/// SYS_TIMERFD_CREATE (283): create timerfd.
pub(crate) fn sys_timerfd_create(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let mut fd = None;
    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
    let mut slot = None;
    for i in 0..super::context::MAX_TIMERFDS { if ctx.timerfd_slot_fd[i] == usize::MAX { slot = Some(i); break; } }
    if let (Some(f), Some(s)) = (fd, slot) {
        ctx.child_fds[f] = 23;
        ctx.timerfd_slot_fd[s] = f;
        ctx.timerfd_expiry_tsc[s] = 0;
        ctx.timerfd_interval_ns[s] = 0;
        reply_val(ctx.ep_cap, f as i64);
    } else { reply_val(ctx.ep_cap, -EMFILE); }
}

/// SYS_TIMERFD_SETTIME (286): arm/disarm timer.
pub(crate) fn sys_timerfd_settime(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let _flags = msg.regs[1] as u32;
    let new_value_ptr = msg.regs[2];
    let old_value_ptr = msg.regs[3];
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 23 {
        if let Some(slot) = ctx.timerfd_slot_fd.iter().position(|&x| x == fd) {
            if old_value_ptr != 0 {
                let zeros = [0u8; 32];
                ctx.guest_write(old_value_ptr, &zeros);
            }
            if new_value_ptr != 0 {
                let mut tv = [0u8; 32];
                ctx.guest_read(new_value_ptr, &mut tv);
                let int_sec = u64::from_le_bytes(tv[0..8].try_into().unwrap());
                let int_ns = u64::from_le_bytes(tv[8..16].try_into().unwrap());
                let val_sec = u64::from_le_bytes(tv[16..24].try_into().unwrap());
                let val_ns = u64::from_le_bytes(tv[24..32].try_into().unwrap());
                let interval_ns = int_sec * 1_000_000_000 + int_ns;
                let value_ns = val_sec * 1_000_000_000 + val_ns;
                ctx.timerfd_interval_ns[slot] = interval_ns;
                if value_ns == 0 {
                    ctx.timerfd_expiry_tsc[slot] = 0; // disarm
                } else {
                    ctx.timerfd_expiry_tsc[slot] = rdtsc() + value_ns * 2; // ~2GHz TSC
                }
            }
            reply_val(ctx.ep_cap, 0);
        } else { reply_val(ctx.ep_cap, -EBADF); }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// SYS_TIMERFD_GETTIME (287): query timer state.
pub(crate) fn sys_timerfd_gettime(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf = msg.regs[1];
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 23 {
        if let Some(slot) = ctx.timerfd_slot_fd.iter().position(|&x| x == fd) {
            if buf != 0 {
                let mut its = [0u8; 32];
                let now = rdtsc();
                let exp = ctx.timerfd_expiry_tsc[slot];
                if exp > now {
                    let remaining_ns = (exp - now) / 2;
                    its[16..24].copy_from_slice(&(remaining_ns / 1_000_000_000).to_le_bytes());
                    its[24..32].copy_from_slice(&(remaining_ns % 1_000_000_000).to_le_bytes());
                }
                let int_ns = ctx.timerfd_interval_ns[slot];
                if int_ns != 0 {
                    its[0..8].copy_from_slice(&(int_ns / 1_000_000_000).to_le_bytes());
                    its[8..16].copy_from_slice(&(int_ns % 1_000_000_000).to_le_bytes());
                }
                ctx.guest_write(buf, &its);
            }
            reply_val(ctx.ep_cap, 0);
        } else { reply_val(ctx.ep_cap, -EBADF); }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// SYS_MEMFD_CREATE (319): create anonymous memory-backed fd.
pub(crate) fn sys_memfd_create(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    const MAP_WRITABLE: u64 = 2;
    let mut fd = None;
    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
    let mut slot = None;
    for i in 0..super::context::MAX_MEMFDS { if ctx.memfd_slot_fd[i] == usize::MAX { slot = Some(i); break; } }
    let mut vslot = None;
    for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
    if let (Some(f), Some(s), Some(vs)) = (fd, slot, vslot) {
        const MEMFD_INIT_PAGES: u64 = 16;
        let base = *ctx.mmap_next;
        *ctx.mmap_next += MEMFD_INIT_PAGES * 0x1000;
        let mut ok = true;
        for p in 0..MEMFD_INIT_PAGES {
            if let Ok(frame) = sys::frame_alloc() {
                if sys::map(base + p * 0x1000, frame, MAP_WRITABLE).is_err() { ok = false; break; }
            } else { ok = false; break; }
        }
        if ok {
            unsafe { core::ptr::write_bytes(base as *mut u8, 0, (MEMFD_INIT_PAGES * 0x1000) as usize); }
            ctx.child_fds[f] = 25;
            ctx.memfd_slot_fd[s] = f;
            ctx.memfd_base[s] = base;
            ctx.memfd_size[s] = 0;
            ctx.memfd_cap[s] = MEMFD_INIT_PAGES * 0x1000;
            ctx.vfs_files[vs] = [0xFEFD, 0, 0, f as u64]; // sentinel OID, offset tracking
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -ENOMEM); }
    } else { reply_val(ctx.ep_cap, -EMFILE); }
}

// ─── Notification / IPC stubs ───────────────────────────────────

/// SYS_INOTIFY_INIT1 (294): return fake fd.
pub(crate) fn sys_inotify_init1(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let mut fd = None;
    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
    if let Some(f) = fd {
        ctx.child_fds[f] = 8;
        reply_val(ctx.ep_cap, f as i64);
    } else { reply_val(ctx.ep_cap, -EMFILE); }
}

/// SYS_SIGNALFD (282) / SYS_SIGNALFD4 (289): return dummy fd.
pub(crate) fn sys_signalfd(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let mut fd = None;
    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
    if let Some(f) = fd {
        ctx.child_fds[f] = 8;
        reply_val(ctx.ep_cap, f as i64);
    } else { reply_val(ctx.ep_cap, -EMFILE); }
}

// ─── Simple one-liner stubs (batch) ─────────────────────────────

/// Batch stubs that return 0: personality, alarm, setuid/gid/etc, unshare, etc.
pub(crate) fn sys_identity_stubs(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_PAUSE (29): return -EINTR.
pub(crate) fn sys_pause(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -EINTR);
}
