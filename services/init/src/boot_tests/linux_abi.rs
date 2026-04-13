//! Hand-rolled Linux-ABI test drivers (hello-linux and hello-musl).
#![allow(unused_imports)]

use sotos_common::sys;
use sotos_common::linux_abi::*;
use core::sync::atomic::Ordering;
use crate::framebuffer::{print, print_u64, fb_putchar};
use crate::exec::{reply_val, exec_from_initrd, rdtsc, EXEC_LOCK, MAP_WRITABLE};
use crate::process::*;
use crate::fd::*;

pub(crate) fn run_linux_test() {
    print(b"LINUX-TEST: loading hello-linux...\n");

    // Acquire exec lock
    while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    let ep_cap = match exec_from_initrd(b"hello-linux") {
        Ok((ep, _tc)) => {
            EXEC_LOCK.store(0, Ordering::Release);
            ep
        }
        Err(e) => {
            EXEC_LOCK.store(0, Ordering::Release);
            print(b"LINUX-TEST: failed to load (errno=");
            print_u64((-e) as u64);
            print(b")\n");
            return;
        }
    };

    print(b"LINUX-TEST: running...\n");

    // Use a temp PID slot for signal state (slot 15 = MAX_PROCS-1)
    let test_pid: usize = MAX_PROCS; // Use last slot (index MAX_PROCS-1)

    // brk/mmap state for this child
    let mut current_brk: u64 = BRK_BASE;
    let mut mmap_next: u64 = MMAP_BASE;

    // Handle the child's syscalls until it exits
    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let nr = msg.tag;
        match nr {
            // write(fd, buf, len)
            1 => {
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                for &b in data {
                    sys::debug_print(b);
                    unsafe { fb_putchar(b); }
                }
                reply_val(ep_cap, len as i64);
            }
            // getpid
            39 => reply_val(ep_cap, 999),
            // arch_prctl — handled by kernel redirect intercept, shouldn't reach here
            158 => reply_val(ep_cap, 0),
            // brk(addr)
            12 => {
                let addr = msg.regs[0];
                if addr == 0 || addr <= current_brk {
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    let new_brk = (addr + 0xFFF) & !0xFFF;
                    let mut ok = true;
                    let mut pg = (current_brk + 0xFFF) & !0xFFF;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() {
                                ok = false;
                                break;
                            }
                        } else {
                            ok = false;
                            break;
                        }
                        pg += 0x1000;
                    }
                    if ok {
                        current_brk = new_brk;
                    }
                    reply_val(ep_cap, current_brk as i64);
                }
            }
            // mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let len = msg.regs[1];
                let fd = msg.regs[4] as i64;
                if fd >= 0 {
                    reply_val(ep_cap, -EINVAL); // -EINVAL: no file-backed mmap
                } else {
                    let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                    let base = mmap_next;
                    let mut ok = true;
                    for p in 0..pages {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                ok = false;
                                break;
                            }
                        } else {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        mmap_next += pages * 0x1000;
                        reply_val(ep_cap, base as i64);
                    } else {
                        reply_val(ep_cap, -ENOMEM); // -ENOMEM
                    }
                }
            }
            // munmap
            11 => reply_val(ep_cap, 0),
            // uname(buf)
            63 => {
                let buf = msg.regs[0] as *mut u8;
                unsafe {
                    // Each field is 65 bytes in struct utsname
                    core::ptr::write_bytes(buf, 0, 390);
                    let sysname = b"sotX";
                    core::ptr::copy_nonoverlapping(sysname.as_ptr(), buf, sysname.len());
                    let nodename = b"lucas";
                    core::ptr::copy_nonoverlapping(nodename.as_ptr(), buf.add(65), nodename.len());
                    let release = b"0.1.0";
                    core::ptr::copy_nonoverlapping(release.as_ptr(), buf.add(130), release.len());
                    let version = b"sotX 0.1.0 LUCAS";
                    core::ptr::copy_nonoverlapping(version.as_ptr(), buf.add(195), version.len());
                    let machine = b"x86_64";
                    core::ptr::copy_nonoverlapping(machine.as_ptr(), buf.add(260), machine.len());
                }
                reply_val(ep_cap, 0);
            }
            // close
            3 => reply_val(ep_cap, 0),
            // nanosleep
            35 => reply_val(ep_cap, 0),
            // exit / exit_group
            60 | 231 => {
                let status = msg.regs[0] as i64;
                print(b"LINUX-TEST: exited with status ");
                print_u64(status as u64);
                print(b"\n");
                break;
            }
            // rt_sigaction(sig, act, oldact, sigsetsize)
            13 => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize;
                let ksa_size = (24 + sigsetsize).min(64);
                let idx = test_pid - 1;
                if signo == 9 || signo == 19 {
                    reply_val(ep_cap, -EINVAL); continue;
                }
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
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
                }
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    let restorer = unsafe { *((act_ptr + 16) as *const u64) };
                    PROCESSES[idx].sig_handler[signo].store(handler, Ordering::Release);
                    PROCESSES[idx].sig_flags[signo].store(flags, Ordering::Release);
                    PROCESSES[idx].sig_restorer[signo].store(restorer, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }
            // rt_sigprocmask(how, set, oldset, sigsetsize)
            14 => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = test_pid - 1;
                let cur_mask = PROCESSES[idx].sig_blocked.load(Ordering::Acquire);
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur_mask; }
                }
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    let safe_set = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => PROCESSES[idx].sig_blocked.store(cur_mask | safe_set, Ordering::Release),
                        1 => PROCESSES[idx].sig_blocked.store(cur_mask & !safe_set, Ordering::Release),
                        2 => PROCESSES[idx].sig_blocked.store(safe_set, Ordering::Release),
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }
            // sigaltstack — stub
            131 => reply_val(ep_cap, 0),
            // writev(fd, iov, iovcnt)
            20 => {
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let mut total: usize = 0;
                let cnt = iovcnt.min(16);
                for i in 0..cnt {
                    let entry = iov_ptr + (i as u64) * 16;
                    let base = unsafe { *(entry as *const u64) };
                    let len = unsafe { *((entry + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                    total += len;
                }
                reply_val(ep_cap, total as i64);
            }
            // set_tid_address
            218 => reply_val(ep_cap, 999),
            // clock_gettime
            228 => {
                let tp = msg.regs[1] as *mut u64;
                unsafe {
                    *tp = 0;
                    *tp.add(1) = 0;
                }
                reply_val(ep_cap, 0);
            }
            _ => {
                print(b"LINUX-TEST: unhandled syscall ");
                print_u64(nr);
                print(b"\n");
                reply_val(ep_cap, -ENOSYS); // -ENOSYS
            }
        }
    }

    print(b"LINUX-TEST: complete\n");
}

/// Run a real musl-static binary (hello-musl) via LUCAS redirect.
/// This is the Busybox milestone test — proves LUCAS can run real Linux binaries.
pub(crate) fn run_musl_test() {
    print(b"MUSL-TEST: loading hello-musl...\n");

    // Acquire exec lock
    while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    let ep_cap = match exec_from_initrd(b"hello-musl") {
        Ok((ep, _tc)) => {
            EXEC_LOCK.store(0, Ordering::Release);
            ep
        }
        Err(e) => {
            EXEC_LOCK.store(0, Ordering::Release);
            print(b"MUSL-TEST: failed to load (errno=");
            print_u64((-e) as u64);
            print(b")\n");
            return;
        }
    };

    print(b"MUSL-TEST: running musl-static binary...\n");

    // Use temp PID slot for signal state
    let test_pid: usize = MAX_PROCS;

    // brk/mmap state
    let mut current_brk: u64 = BRK_BASE;
    let mut mmap_next: u64 = MMAP_BASE;

    // Handle the musl binary's syscalls
    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let nr = msg.tag;
        // Debug: log syscall number
        print(b"MUSL-SYS: ");
        print_u64(nr);
        print(b"\n");
        match nr {
            // write(fd, buf, len)
            1 => {
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if len > 0 && buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                }
                reply_val(ep_cap, len as i64);
            }
            // read(fd, buf, len)
            0 => reply_val(ep_cap, 0), // EOF
            // close
            3 => reply_val(ep_cap, 0),
            // poll(fds, nfds, timeout) — Rust std sanitize_standard_fds
            7 => {
                // Return 0 = no events ready (fds are valid)
                let nfds = msg.regs[1] as usize;
                // Zero out revents in each pollfd struct (8 bytes each)
                let fds_ptr = msg.regs[0];
                if fds_ptr != 0 && fds_ptr < 0x0000_8000_0000_0000 {
                    for i in 0..nfds.min(16) {
                        let revents_ptr = (fds_ptr + (i as u64) * 8 + 6) as *mut u16;
                        unsafe { *revents_ptr = 0; }
                    }
                }
                reply_val(ep_cap, 0);
            }
            // fstat(fd, statbuf) — musl uses this
            5 => {
                let stat_ptr = msg.regs[1];
                if stat_ptr != 0 && stat_ptr < 0x0000_8000_0000_0000 {
                    write_linux_stat(stat_ptr, 0, 0, false);
                }
                reply_val(ep_cap, 0);
            }
            // mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let len = msg.regs[1];
                let flags = msg.regs[3];
                if !MFlags::from_bits_truncate(flags as u32).contains(MFlags::ANONYMOUS) {
                    reply_val(ep_cap, -EINVAL); // No file-backed mmap in test handler
                    continue;
                }
                let pages = ((len + 0xFFF) / 0x1000) as u32;
                let base = mmap_next;
                let mut ok = true;
                for p in 0..pages {
                    match sys::frame_alloc() {
                        Ok(frame) => {
                            if sys::map(base + (p as u64) * 0x1000, frame, MAP_WRITABLE).is_err() {
                                ok = false; break;
                            }
                        }
                        Err(_) => { ok = false; break; }
                    }
                }
                if !ok { reply_val(ep_cap, -ENOMEM); continue; }
                let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (pages as usize) * 0x1000) };
                for b in region.iter_mut() { *b = 0; }
                mmap_next += (pages as u64) * 0x1000;
                reply_val(ep_cap, base as i64);
            }
            // mprotect(addr, len, prot)
            10 => reply_val(ep_cap, 0),
            // munmap
            11 => reply_val(ep_cap, 0),
            // brk
            12 => {
                let new_brk = msg.regs[0];
                if new_brk == 0 {
                    reply_val(ep_cap, current_brk as i64);
                } else if new_brk < current_brk {
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    let mut ok = true;
                    let mut pg = (current_brk + 0xFFF) & !0xFFF;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
                        } else { ok = false; break; }
                        pg += 0x1000;
                    }
                    if ok { current_brk = new_brk; }
                    reply_val(ep_cap, current_brk as i64);
                }
            }
            // rt_sigaction(signo, act, oldact, sigsetsize)
            // Kernel struct: handler(8) + flags(8) + restorer(8) + mask(sigsetsize)
            13 => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize; // r10 = sigsetsize
                let ksa_size = 24 + sigsetsize; // handler + flags + restorer + mask
                let idx = test_pid - 1;
                if signo == 9 || signo == 19 { reply_val(ep_cap, -EINVAL); continue; }
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size.min(64)) };
                    for b in buf.iter_mut() { *b = 0; }
                    if signo > 0 && signo < 32 {
                        let h = PROCESSES[idx].sig_handler[signo].load(Ordering::Acquire);
                        let f = PROCESSES[idx].sig_flags[signo].load(Ordering::Acquire);
                        buf[0..8].copy_from_slice(&h.to_le_bytes());
                        buf[8..16].copy_from_slice(&f.to_le_bytes());
                    }
                }
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    PROCESSES[idx].sig_handler[signo].store(handler, Ordering::Release);
                    PROCESSES[idx].sig_flags[signo].store(flags, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }
            // rt_sigprocmask
            14 => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = test_pid - 1;
                let cur = PROCESSES[idx].sig_blocked.load(Ordering::Acquire);
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur; }
                }
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    let safe = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => PROCESSES[idx].sig_blocked.store(cur | safe, Ordering::Release),
                        1 => PROCESSES[idx].sig_blocked.store(cur & !safe, Ordering::Release),
                        2 => PROCESSES[idx].sig_blocked.store(safe, Ordering::Release),
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }
            // ioctl — return ENOTTY for terminal queries
            16 => reply_val(ep_cap, -ENOTTY),
            // writev(fd, iov, iovcnt)
            20 => {
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let mut total: usize = 0;
                let cnt = iovcnt.min(16);
                for i in 0..cnt {
                    let entry = iov_ptr + (i as u64) * 16;
                    let base = unsafe { *(entry as *const u64) };
                    let len = unsafe { *((entry + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                    total += len;
                }
                reply_val(ep_cap, total as i64);
            }
            // getpid
            39 => reply_val(ep_cap, test_pid as i64),
            // nanosleep
            35 => reply_val(ep_cap, 0),
            // exit / exit_group
            60 | 231 => {
                let status = msg.regs[0] as i64;
                print(b"MUSL-TEST: exited with status ");
                print_u64(status as u64);
                print(b"\n");
                if status == 0 {
                    print(b"MUSL-TEST: SUCCESS -- real musl-static binary ran under LUCAS!\n");
                } else {
                    print(b"MUSL-TEST: FAILED\n");
                }
                break;
            }
            // uname
            63 => {
                let buf_ptr = msg.regs[0];
                if buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 390) };
                    for b in buf.iter_mut() { *b = 0; }
                    let fields: [&[u8]; 5] = [b"sotX", b"sotos", b"0.1.0", b"sotX 0.1.0 LUCAS", b"x86_64"];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                }
                reply_val(ep_cap, 0);
            }
            // getuid/getgid/geteuid/getegid
            102 | 104 | 107 | 108 => reply_val(ep_cap, 0),
            // sigaltstack
            131 => {
                let old_ss = msg.regs[1];
                if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_ss as *mut u8, 24) };
                    for b in buf.iter_mut() { *b = 0; }
                    buf[8..12].copy_from_slice(&2u32.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }
            // set_tid_address
            218 => reply_val(ep_cap, test_pid as i64),
            // clock_gettime
            228 => {
                let tp_ptr = msg.regs[1];
                if tp_ptr != 0 && tp_ptr < 0x0000_8000_0000_0000 {
                    let elapsed = rdtsc().saturating_sub(BOOT_TSC.load(Ordering::Acquire));
                    let elapsed_ns = elapsed.saturating_mul(10);
                    let tp = unsafe { core::slice::from_raw_parts_mut(tp_ptr as *mut u8, 16) };
                    tp[0..8].copy_from_slice(&((elapsed_ns / 1_000_000_000) as i64).to_le_bytes());
                    tp[8..16].copy_from_slice(&((elapsed_ns % 1_000_000_000) as i64).to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }
            // getrandom
            318 => {
                let buf = msg.regs[0];
                let len = msg.regs[1] as usize;
                if buf != 0 && buf < 0x0000_8000_0000_0000 && len > 0 {
                    let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
                    let mut seed = rdtsc();
                    for b in dst.iter_mut() {
                        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                        *b = seed as u8;
                    }
                }
                reply_val(ep_cap, msg.regs[1] as i64);
            }
            // tkill(tid, sig) — used by raise()/abort()
            200 => {
                // We don't implement signals, just return success
                // so the caller thinks the signal was delivered.
                reply_val(ep_cap, 0);
            }
            // prlimit64
            302 => reply_val(ep_cap, 0),
            // sched_getaffinity — musl sometimes calls this
            204 => reply_val(ep_cap, -ENOSYS), // -ENOSYS
            // futex — real implementation
            202 => {
                let uaddr = msg.regs[0];
                let op = (msg.regs[1] & 0x7F) as u32;
                let val = msg.regs[2] as u32;
                match op {
                    0 => reply_val(ep_cap, futex_wait(uaddr, val)),
                    1 => reply_val(ep_cap, futex_wake(uaddr, val)),
                    _ => reply_val(ep_cap, 0),
                }
            }
            // readlinkat — /proc/self/exe
            267 => reply_val(ep_cap, -EINVAL),
            // Unknown syscall — log and return -ENOSYS
            _ => {
                print(b"MUSL-TEST: unhandled syscall ");
                print_u64(nr);
                print(b"\n");
                reply_val(ep_cap, -ENOSYS); // -ENOSYS
            }
        }
    }

    print(b"MUSL-TEST: complete\n");
}
