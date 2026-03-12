// ---------------------------------------------------------------------------
// File/IO syscalls: read, write, open, close, stat, lseek, ioctl, etc.
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::{reply_val, rdtsc, copy_guest_path, starts_with,
                  format_uptime_into, format_proc_self_stat};
use crate::process::*;
use crate::fd::*;
use crate::child_handler::{open_virtual_file, fill_random, mark_pipe_retry_on};
use crate::{NET_EP_CAP, vfs_lock, vfs_unlock, shared_store};
use crate::net::{NET_CMD_TCP_SEND, NET_CMD_TCP_RECV, NET_CMD_TCP_CLOSE,
                 NET_CMD_UDP_SENDTO, NET_CMD_UDP_RECV};
use crate::framebuffer::{print, print_u64, fb_putchar, kb_has_char, kb_read_char};
use crate::syscall_log::format_syslog_into;
use super::context::SyscallContext;

const MAP_WRITABLE: u64 = 2;

pub(crate) fn sys_read(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF); // -EBADF
        return;
    }
    match ctx.child_fds[fd] {
        1 => {
            // stdin
            if len == 0 { reply_val(ctx.ep_cap, 0); return; }
            loop {
                let s = sig_dequeue(ctx.pid);
                if s != 0 && sig_dispatch(ctx.pid, s) >= 1 {
                    reply_val(ctx.ep_cap, -EINTR); break; // -EINTR
                }
                match unsafe { kb_read_char() } {
                    Some(0x03) => { reply_val(ctx.ep_cap, -EINTR); break; }
                    Some(ch) => {
                        ctx.guest_write(buf_ptr, &[ch]);
                        let reply = IpcMsg {
                            tag: 0,
                            regs: [1, ch as u64, 0, 0, 0, 0, 0, 0],
                        };
                        let _ = sys::send(ctx.ep_cap, &reply);
                        break;
                    }
                    None => { sys::yield_now(); }
                }
            }
        }
        9 => {
            // /dev/zero: fill buffer with zeros
            let n = len.min(4096);
            if n > 0 {
                unsafe { core::ptr::write_bytes(buf_ptr as *mut u8, 0, n); }
            }
            reply_val(ctx.ep_cap, n as i64);
        }
        20 => {
            // /dev/urandom: fill buffer with ChaCha20 CSPRNG
            let n = len.min(4096);
            if n > 0 {
                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                fill_random(dst);
            }
            reply_val(ctx.ep_cap, n as i64);
        }
        8 => reply_val(ctx.ep_cap, 0), // /dev/null: EOF
        22 => {
            // eventfd read: return counter, reset to 0
            if len < 8 { reply_val(ctx.ep_cap, -EINVAL); return; }
            if let Some(slot) = ctx.eventfd_slot_fd.iter().position(|&x| x == fd) {
                let val = ctx.eventfd_counter[slot];
                if val == 0 {
                    // Non-blocking: EAGAIN. Wine uses EFD_NONBLOCK.
                    reply_val(ctx.ep_cap, -EAGAIN);
                } else {
                    unsafe { *(buf_ptr as *mut u64) = val; }
                    ctx.eventfd_counter[slot] = 0;
                    reply_val(ctx.ep_cap, 8);
                }
            } else { reply_val(ctx.ep_cap, -EBADF); }
        }
        23 => {
            // timerfd read: return expiration count
            if len < 8 { reply_val(ctx.ep_cap, -EINVAL); return; }
            if let Some(slot) = ctx.timerfd_slot_fd.iter().position(|&x| x == fd) {
                let now = rdtsc();
                let exp = ctx.timerfd_expiry_tsc[slot];
                if exp != 0 && now >= exp {
                    unsafe { *(buf_ptr as *mut u64) = 1; }
                    // Re-arm if interval set
                    if ctx.timerfd_interval_ns[slot] != 0 {
                        ctx.timerfd_expiry_tsc[slot] = now + ctx.timerfd_interval_ns[slot] * 2; // ~2GHz
                    } else {
                        ctx.timerfd_expiry_tsc[slot] = 0; // one-shot, disarmed
                    }
                    reply_val(ctx.ep_cap, 8);
                } else {
                    reply_val(ctx.ep_cap, -EAGAIN); // not expired
                }
            } else { reply_val(ctx.ep_cap, -EBADF); }
        }
        25 => {
            // memfd read
            if let Some(slot) = ctx.memfd_slot_fd.iter().position(|&x| x == fd) {
                let base = ctx.memfd_base[slot];
                let sz = ctx.memfd_size[slot];
                // Use vfs_files for offset tracking
                let mut offset = 0u64;
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] == 0xFEFD {
                        offset = ctx.vfs_files[s][2];
                        let avail = if offset < sz { sz - offset } else { 0 };
                        let n = (len as u64).min(avail) as usize;
                        if n > 0 {
                            unsafe { core::ptr::copy_nonoverlapping((base + offset) as *const u8, buf_ptr as *mut u8, n); }
                            ctx.vfs_files[s][2] += n as u64;
                        }
                        reply_val(ctx.ep_cap, n as i64);
                        break;
                    }
                }
            } else { reply_val(ctx.ep_cap, -EBADF); }
        }
        12 => {
            // Initrd file: find the slot for this FD
            let mut found = false;
            for s in 0..GRP_MAX_INITRD {
                if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                    let data_base = ctx.initrd_files[s][0];
                    let file_size = ctx.initrd_files[s][1];
                    let pos = ctx.initrd_files[s][2];
                    let avail = if pos < file_size { file_size - pos } else { 0 };
                    let to_read = (len as u64).min(avail) as usize;
                    if to_read > 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (data_base + pos) as *const u8,
                                buf_ptr as *mut u8,
                                to_read,
                            );
                        }
                        ctx.initrd_files[s][2] = pos + to_read as u64;
                    }
                    reply_val(ctx.ep_cap, to_read as i64);
                    found = true;
                    break;
                }
            }
            if !found { reply_val(ctx.ep_cap, -EBADF); }
        }
        13 => {
            // VFS file: read via shared ObjectStore
            let mut found = false;
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    let oid = ctx.vfs_files[s][0];
                    let pos = ctx.vfs_files[s][2] as usize;
                    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
                    vfs_lock();
                    let result = unsafe { shared_store() }
                        .and_then(|store| store.read_obj_range(oid, pos, dst).ok());
                    vfs_unlock();
                    match result {
                        Some(n) => {
                            ctx.vfs_files[s][2] += n as u64;
                            reply_val(ctx.ep_cap, n as i64);
                        }
                        None => reply_val(ctx.ep_cap, -EIO), // -EIO
                    }
                    found = true;
                    break;
                }
            }
            if !found { reply_val(ctx.ep_cap, -EBADF); }
        }
        15 => {
            // Procfs virtual file: read from dir_buf
            let avail = if *ctx.dir_pos < *ctx.dir_len { *ctx.dir_len - *ctx.dir_pos } else { 0 };
            let to_read = len.min(avail);
            if to_read > 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ctx.dir_buf[*ctx.dir_pos..].as_ptr(),
                        buf_ptr as *mut u8,
                        to_read,
                    );
                }
                *ctx.dir_pos += to_read;
            }
            reply_val(ctx.ep_cap, to_read as i64);
        }
        16 => {
            // TCP socket read: NET_CMD_TCP_RECV (retry up to 5000 times)
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            let conn_id = ctx.sock_conn_id[fd] as u64;
            let recv_len = len.min(64);
            let mut got = 0usize;
            let mut tcp_retries = 0u32;
            while tcp_retries < 5000 {
                let req = IpcMsg {
                    tag: NET_CMD_TCP_RECV,
                    regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                };
                match sys::call_timeout(net_cap, &req, 200) {
                    Ok(resp) => {
                        let n = resp.tag as usize; // tag = byte count
                        if n > 0 && n <= recv_len {
                            unsafe {
                                let src = &resp.regs[0] as *const u64 as *const u8; // data at regs[0]
                                core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                            }
                            got = n;
                            break;
                        }
                        // n==0: no data yet, retry
                    }
                    Err(_) => {} // timeout, retry
                }
                sys::yield_now();
                tcp_retries += 1;
            }
            if got > 0 {
                reply_val(ctx.ep_cap, got as i64);
            } else {
                reply_val(ctx.ep_cap, -EAGAIN); // -EAGAIN after exhausting retries
            }
        }
        17 => {
            // UDP socket read: NET_CMD_UDP_RECV
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            let port = ctx.sock_udp_local_port[fd];
            let recv_len = len.min(56);
            if net_cap == 0 || port == 0 {
                reply_val(ctx.ep_cap, -EBADF);
            } else {
                let req = IpcMsg {
                    tag: NET_CMD_UDP_RECV,
                    regs: [port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                };
                match sys::call_timeout(net_cap, &req, 500) {
                    Ok(resp) => {
                        let n = resp.tag as usize; // tag = byte count
                        if n > 0 && n <= recv_len {
                            unsafe {
                                let src = &resp.regs[0] as *const u64 as *const u8; // data at regs[0]
                                core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                            }
                        }
                        reply_val(ctx.ep_cap, n as i64);
                    }
                    Err(_) => reply_val(ctx.ep_cap, 0),
                }
            }
        }
        10 => {
            // Pipe read: non-blocking check with kernel-side retry.
            let pipe_id = ctx.sock_conn_id[fd] as usize;
            // Check writer state
            let want = len.min(4096);
            let mut tmp = [0u8; 4096];
            let n = pipe_read(pipe_id, &mut tmp[..want]);
            if n > 0 {
                crate::child_handler::clear_pipe_stall(ctx.pid);
                ctx.guest_write(buf_ptr, &tmp[..n]);
                reply_val(ctx.ep_cap, n as i64);
            } else if pipe_writer_closed(pipe_id) {
                reply_val(ctx.ep_cap, 0); // EOF
            } else {
                // No data, writer alive — ask kernel to retry after yielding.
                // Deadlock detection: if both this process AND another are
                // stalled on pipe reads, they're deadlocked. Reply EOF (0)
                // directly so the kernel stops retrying and the process
                // can proceed with its cleanup/exit path.
                let stall = unsafe { crate::child_handler::PIPE_STALL[ctx.pid] };
                if stall > 1000 {
                    // Only trigger if another process is ALSO stuck on a pipe
                    // read for a long time — suggests a real deadlock cycle.
                    // Note: two processes waiting for a third (e.g. during exec)
                    // is NOT a deadlock — just a temporary stall.
                    let mut other_pid = 0usize;
                    for p in 1..16usize {
                        if p != ctx.pid && unsafe { crate::child_handler::PIPE_STALL[p] } > 1000 {
                            other_pid = p;
                            break;
                        }
                    }
                    if other_pid != 0 {
                        // Resolve deadlock: close write ends for BOTH pipes
                        // so both processes get natural EOF simultaneously.
                        let other_pipe = unsafe { crate::child_handler::PIPE_STALL_ID[other_pid] } as usize;
                        print(b"PIPE-DEADLOCK: pid="); print_u64(ctx.pid as u64);
                        print(b" pipe="); print_u64(pipe_id as u64);
                        print(b" other="); print_u64(other_pid as u64);
                        print(b" other_pipe="); print_u64(other_pipe as u64);
                        print(b"\n");
                        crate::fd::pipe_close_all_writers(pipe_id);
                        if other_pipe < crate::fd::MAX_PIPES && other_pipe != pipe_id {
                            crate::fd::pipe_close_all_writers(other_pipe);
                        }
                        crate::child_handler::clear_pipe_stall(ctx.pid);
                        crate::child_handler::clear_pipe_stall(other_pid);
                        // Mark both processes as deadlock-EOF recipients so their
                        // exit codes get overridden to 0 (clean exit).
                        unsafe {
                            crate::child_handler::DEADLOCK_EOF[ctx.pid] = true;
                            crate::child_handler::DEADLOCK_EOF[other_pid] = true;
                        }
                        // Don't reply — let retry continue. Next iteration
                        // pipe_writer_closed() returns true → normal EOF.
                    }
                }
                mark_pipe_retry_on(ctx.pid, pipe_id);
                let reply = sotos_common::IpcMsg {
                    tag: sotos_common::PIPE_RETRY_TAG,
                    regs: [0; 8],
                };
                let _ = sys::send(ctx.ep_cap, &reply);
            }
        }
        _ => reply_val(ctx.ep_cap, -EBADF),
    }
}

/// SYS_WRITE (1): write to fd (stdout, /dev/null, eventfd, memfd, TCP, UDP, pipe, VFS file).
pub(crate) fn sys_write(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    // (debug logging removed — serial is too slow for per-syscall prints)
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }
    match ctx.child_fds[fd] {
        2 => {
            // stdout/stderr — read child's data via guest_read for CoW fork compat
            let safe_len = len.min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(buf_ptr, &mut local_buf[..safe_len]);
            for i in 0..safe_len { sys::debug_print(local_buf[i]); unsafe { fb_putchar(local_buf[i]); } }
            reply_val(ctx.ep_cap, safe_len as i64);
        }
        8 => reply_val(ctx.ep_cap, len as i64), // /dev/null: discard
        22 => {
            // eventfd write: add value to counter
            if len < 8 { reply_val(ctx.ep_cap, -EINVAL); return; }
            if let Some(slot) = ctx.eventfd_slot_fd.iter().position(|&x| x == fd) {
                let val = unsafe { *(buf_ptr as *const u64) };
                ctx.eventfd_counter[slot] = ctx.eventfd_counter[slot].saturating_add(val);
                reply_val(ctx.ep_cap, 8);
            } else { reply_val(ctx.ep_cap, -EBADF); }
        }
        25 => {
            // memfd write
            if let Some(slot) = ctx.memfd_slot_fd.iter().position(|&x| x == fd) {
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] == 0xFEFD {
                        let offset = ctx.vfs_files[s][2] as usize;
                        let cap = ctx.memfd_cap[slot] as usize;
                        let n = len.min(cap.saturating_sub(offset));
                        if n > 0 {
                            let base = ctx.memfd_base[slot];
                            unsafe { core::ptr::copy_nonoverlapping(buf_ptr as *const u8, (base + offset as u64) as *mut u8, n); }
                            ctx.vfs_files[s][2] += n as u64;
                            let new_end = ctx.vfs_files[s][2];
                            if new_end > ctx.memfd_size[slot] { ctx.memfd_size[slot] = new_end; }
                        }
                        reply_val(ctx.ep_cap, n as i64);
                        break;
                    }
                }
            } else { reply_val(ctx.ep_cap, -EBADF); }
        }
        16 => {
            // TCP socket write: NET_CMD_TCP_SEND (multi-chunk)
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            let conn_id = ctx.sock_conn_id[fd] as u64;
            let mut total_sent = 0usize;
            let mut off = 0usize;
            while off < len {
                let chunk = (len - off).min(40);
                let mut req = sotos_common::IpcMsg {
                    tag: NET_CMD_TCP_SEND,
                    regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
                };
                let data = unsafe { core::slice::from_raw_parts((buf_ptr + off as u64) as *const u8, chunk) };
                unsafe {
                    let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                    core::ptr::copy_nonoverlapping(data.as_ptr(), dst, chunk);
                }
                match sys::call_timeout(net_cap, &req, 500) {
                    Ok(resp) => {
                        let n = resp.regs[0] as i64;
                        if n <= 0 {
                            if ctx.pid > 1 && total_sent == 0 {
                                print(b"TCP-SEND-FAIL fd=");
                                print_u64(fd as u64);
                                print(b" conn=");
                                print_u64(conn_id);
                                print(b" n=");
                                print_u64(resp.regs[0]);
                                print(b"\n");
                            }
                            break;
                        }
                        let n = n as usize;
                        total_sent += n;
                        off += n;
                    }
                    Err(_) => {
                        if ctx.pid > 1 && total_sent == 0 {
                            print(b"TCP-SEND-IPC-ERR conn=");
                            print_u64(conn_id);
                            print(b"\n");
                        }
                        break;
                    }
                }
            }
            if total_sent > 0 {
                reply_val(ctx.ep_cap, total_sent as i64);
            } else {
                reply_val(ctx.ep_cap, -EIO);
            }
        }
        17 => {
            // UDP socket write: NET_CMD_UDP_SENDTO with stored remote addr
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            let remote_ip = ctx.sock_udp_remote_ip[fd];
            let remote_port = ctx.sock_udp_remote_port[fd];
            let src_port = ctx.sock_udp_local_port[fd];
            if net_cap == 0 || remote_ip == 0 {
                reply_val(ctx.ep_cap, -EDESTADDRREQ);
            } else {
                let send_len = len.min(32);
                let mut req = sotos_common::IpcMsg {
                    tag: NET_CMD_UDP_SENDTO,
                    regs: [remote_ip as u64, remote_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                };
                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                unsafe {
                    let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                    core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                }
                match sys::call_timeout(net_cap, &req, 500) {
                    Ok(resp) => reply_val(ctx.ep_cap, resp.regs[0] as i64),
                    Err(_) => reply_val(ctx.ep_cap, -EIO),
                }
            }
        }
        11 => {
            // Pipe write: write to shared pipe buffer
            let pipe_id = ctx.sock_conn_id[fd] as usize;
            // Read child's data into local buffer (handles CoW fork)
            let safe_len = len.min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(buf_ptr, &mut local_buf[..safe_len]);
            let src = &local_buf[..safe_len];
            // Log pipe write data for git debugging
            if ctx.pid >= 3 {
                print(b"PIPE-W P"); print_u64(ctx.pid as u64);
                print(b" fd="); print_u64(fd as u64);
                print(b" len="); print_u64(len as u64);
                print(b" [");
                let show = safe_len.min(80);
                for i in 0..show {
                    if src[i] == 0x0A { print(b"\\n"); }
                    else if src[i] >= 0x20 && src[i] < 0x7F {
                        sys::debug_print(src[i]);
                    } else { print(b"."); }
                }
                print(b"]\n");
                // Hex dump for small pipe writes
                if safe_len <= 8 {
                    print(b"  hex:");
                    for i in 0..safe_len {
                        print(b" 0x");
                        crate::framebuffer::print_hex64(src[i] as u64);
                    }
                    print(b"\n");
                }
            }
            let mut written = 0usize;
            let mut retries = 0u32;
            while written < safe_len {
                let n = pipe_write(pipe_id, &src[written..]);
                written += n;
                if n == 0 {
                    retries += 1;
                    if retries > 10000 { break; }
                    sys::yield_now();
                } else {
                    retries = 0;
                }
            }
            reply_val(ctx.ep_cap, written as i64);
        }
        13 => {
            // VFS file: write via shared ObjectStore
            let mut found = false;
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    let oid = ctx.vfs_files[s][0];
                    let pos = ctx.vfs_files[s][2] as usize;
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    vfs_lock();
                    let result = unsafe { shared_store() }
                        .and_then(|store| {
                            let f_pre = store.find_slot_pub(oid).map(|sl| store.dir[sl].flags);
                            let r = store.write_obj_range(oid, pos, data).ok();
                            let f_post = store.find_slot_pub(oid).map(|sl| store.dir[sl].flags);
                            if f_pre != f_post {
                                print(b"WRITE-FLAG-CORRUPT: oid="); print_u64(oid);
                                print(b" flags "); print_u64(f_pre.unwrap_or(99) as u64);
                                print(b"->"); print_u64(f_post.unwrap_or(99) as u64);
                                print(b"\n");
                            }
                            r
                        });
                    vfs_unlock();
                    match result {
                        Some(_) => {
                            ctx.vfs_files[s][2] += len as u64;
                            let new_end = ctx.vfs_files[s][2];
                            if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                            reply_val(ctx.ep_cap, len as i64);
                        }
                        None => {
                            reply_val(ctx.ep_cap, -EIO);
                        }
                    }
                    found = true;
                    break;
                }
            }
            if !found { reply_val(ctx.ep_cap, -EBADF); }
        }
        _ => {
            reply_val(ctx.ep_cap, -EBADF);
        }
    }
}

/// SYS_FSTAT (5): fstat on an open fd.
pub(crate) fn sys_fstat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let stat_ptr = msg.regs[1];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        let mut size = 0u64;
        let mut ino = 0u64;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                size = ctx.initrd_files[s][1];
                ino = ctx.initrd_files[s][0]; // use buffer address as unique inode
                break;
            }
        }
        // dev=1 for initrd files (distinct from VFS dev=2)
        write_linux_stat_dev(stat_ptr, 1, ino, size, false);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
        // VFS file (13) or VFS directory (14): get real size from store
        let is_vfs_dir = ctx.child_fds[fd] == 14;
        let mut size = 0u64;
        let mut oid = 0u64;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                oid = ctx.vfs_files[s][0];
                vfs_lock();
                if let Some(store) = unsafe { shared_store() } {
                    if let Some(entry) = store.stat(oid) {
                        size = entry.size;
                    }
                }
                vfs_unlock();
                break;
            }
        }
        // dev=2 for VFS files (distinct from initrd dev=1)
        write_linux_stat_dev(stat_ptr, 2, oid, size, is_vfs_dir);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 15 {
        // Procfs virtual file: report content length
        write_linux_stat(stat_ptr, fd as u64, *ctx.dir_len as u64, false);
        reply_val(ctx.ep_cap, 0);
    } else {
        write_linux_stat(stat_ptr, fd as u64, 0, false);
        reply_val(ctx.ep_cap, 0);
    }
}

/// SYS_STAT (4) / SYS_LSTAT (6): stat a path (same code path for both).
pub(crate) fn sys_stat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let stat_ptr = msg.regs[1];
    let mut path = [0u8; 128];
    let path_len = copy_guest_path(path_ptr, &mut path);
    // Resolve relative paths against CWD
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    // First try initrd by basename
    let mut basename_start = 0usize;
    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
    let basename = &name[basename_start..];
    if !basename.is_empty() {
        if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
            write_linux_stat(stat_ptr, 0, sz, false);
            reply_val(ctx.ep_cap, 0);
            return;
        }
    }

    // Try VFS
    vfs_lock();
    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        Some((oid, entry.size, entry.is_dir()))
    });
    vfs_unlock();

    if let Some((oid, size, is_dir)) = vfs_stat {
        write_linux_stat(stat_ptr, oid, size, is_dir);
        reply_val(ctx.ep_cap, 0);
    } else {
        // Fall back to exact directory name stubs
        let is_known_dir = name == b"." || path_len == 0
            || name == b"/" || name == b"/usr" || name == b"/etc"
            || name == b"/lib" || name == b"/lib64"
            || name == b"/bin" || name == b"/sbin"
            || name == b"/tmp" || name == b"/home" || name == b"/var"
            || name == b"/usr/bin" || name == b"/usr/lib"
            || name == b"/usr/sbin" || name == b"/usr/lib64"
            || name == b"/usr/share" || name == b"/usr/libexec"
            || name == b"/usr/libexec/git-core"
            || name == b"/usr/local" || name == b"/usr/local/bin"
            || starts_with(name, b"/dev/");
        if is_known_dir {
            write_linux_stat(stat_ptr, 0, 4096, true);
            reply_val(ctx.ep_cap, 0);
        } else {
            if ctx.pid > 1 {
                let has_libexec = name.windows(7).any(|w| w == b"libexec");
                let has_index = name.windows(5).any(|w| w == b"index");
                if has_libexec || has_index {
                    print(b"STAT: VFS-miss ");
                    print(name);
                    print(b"\n");
                }
            }
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_LSEEK (8): seek on an open fd.
pub(crate) fn sys_lseek(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let offset_val = msg.regs[1] as i64;
    let whence = msg.regs[2] as u32;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF); // -EBADF
    } else if ctx.child_fds[fd] == 12 {
        let mut found = false;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                let file_size = ctx.initrd_files[s][1] as i64;
                let cur_pos = ctx.initrd_files[s][2] as i64;
                let new_pos = match whence {
                    0 => offset_val,                    // SEEK_SET
                    1 => cur_pos + offset_val,          // SEEK_CUR
                    2 => file_size + offset_val,        // SEEK_END
                    _ => { reply_val(ctx.ep_cap, -EINVAL); found = true; break; }
                };
                if new_pos < 0 {
                    reply_val(ctx.ep_cap, -EINVAL); // -EINVAL
                } else {
                    ctx.initrd_files[s][2] = new_pos as u64;
                    reply_val(ctx.ep_cap, new_pos);
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
        // VFS file or directory: seek
        let mut found = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let file_size = ctx.vfs_files[s][1] as i64;
                let cur_pos = ctx.vfs_files[s][2] as i64;
                let new_pos = match whence {
                    0 => offset_val,
                    1 => cur_pos + offset_val,
                    2 => file_size + offset_val,
                    _ => { reply_val(ctx.ep_cap, -EINVAL); found = true; break; }
                };
                if new_pos < 0 {
                    reply_val(ctx.ep_cap, -EINVAL);
                } else {
                    ctx.vfs_files[s][2] = new_pos as u64;
                    reply_val(ctx.ep_cap, new_pos);
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else {
        reply_val(ctx.ep_cap, -ESPIPE); // -ESPIPE (not seekable)
    }
}

/// SYS_PREAD64 (17): pread at offset without changing file position.
pub(crate) fn sys_pread64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let count = msg.regs[2] as usize;
    let off = msg.regs[3];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        let mut found = false;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                let data_base = ctx.initrd_files[s][0];
                let file_size = ctx.initrd_files[s][1];
                let avail = if off < file_size { (file_size - off) as usize } else { 0 };
                let to_read = count.min(avail);
                if to_read > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            (data_base + off) as *const u8,
                            buf_ptr as *mut u8,
                            to_read,
                        );
                    }
                }
                reply_val(ctx.ep_cap, to_read as i64);
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else if ctx.child_fds[fd] == 13 {
        // VFS file pread64
        let mut found = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let oid = ctx.vfs_files[s][0];
                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };
                vfs_lock();
                let result = unsafe { shared_store() }
                    .and_then(|store| store.read_obj_range(oid, off as usize, dst).ok());
                vfs_unlock();
                match result {
                    Some(n) => reply_val(ctx.ep_cap, n as i64),
                    None => reply_val(ctx.ep_cap, -EIO), // -EIO
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// Internal: close a single fd, cleaning up associated resources, without sending a reply.
/// Returns true if the fd was valid and closed.
pub(crate) fn close_fd_internal(ctx: &mut SyscallContext, fd: usize) -> bool {
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 { return false; }
    if ctx.pid >= 3 {
        let k = ctx.child_fds[fd];
        if k == 10 || k == 11 {
            print(b"FD-CLOSE P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" k="); print_u64(k as u64);
            print(b" pipe="); print_u64(ctx.sock_conn_id[fd] as u64);
            print(b"\n");
        }
    }
    if ctx.child_fds[fd] == 12 {
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 {
                ctx.initrd_files[s][3] = u64::MAX; // mark FD closed but data alive
                break;
            }
        }
    } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 { ctx.vfs_files[s] = [0; 4]; break; }
        }
    } else if ctx.child_fds[fd] == 22 {
        // eventfd close
        if let Some(slot) = ctx.eventfd_slot_fd.iter().position(|&x| x == fd) {
            ctx.eventfd_slot_fd[slot] = usize::MAX;
            ctx.eventfd_counter[slot] = 0;
        }
    } else if ctx.child_fds[fd] == 23 {
        // timerfd close
        if let Some(slot) = ctx.timerfd_slot_fd.iter().position(|&x| x == fd) {
            ctx.timerfd_slot_fd[slot] = usize::MAX;
            ctx.timerfd_expiry_tsc[slot] = 0;
            ctx.timerfd_interval_ns[slot] = 0;
        }
    } else if ctx.child_fds[fd] == 25 {
        // memfd close — free pages
        if let Some(slot) = ctx.memfd_slot_fd.iter().position(|&x| x == fd) {
            let cap_pages = (ctx.memfd_cap[slot] + 0xFFF) / 0x1000;
            for p in 0..cap_pages { let _ = sys::unmap_free(ctx.memfd_base[slot] + p * 0x1000); }
            ctx.memfd_slot_fd[slot] = usize::MAX;
            ctx.memfd_base[slot] = 0;
            ctx.memfd_size[slot] = 0;
            ctx.memfd_cap[slot] = 0;
        }
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] == 0xFEFD {
                ctx.vfs_files[s] = [0; 4]; break;
            }
        }
    } else if ctx.child_fds[fd] == 16 {
        // TCP socket close -> NET_CMD_TCP_CLOSE
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let cid = ctx.sock_conn_id[fd];
        if net_cap != 0 && cid != 0xFFFF {
            let req = sotos_common::IpcMsg {
                tag: NET_CMD_TCP_CLOSE,
                regs: [cid as u64, 0, 0, 0, 0, 0, 0, 0],
            };
            let _ = sys::call_timeout(net_cap, &req, 500);
        }
        ctx.sock_conn_id[fd] = 0xFFFF;
    } else if ctx.child_fds[fd] == 11 {
        // Pipe write end close — decrement refcount, mark closed when last ref gone
        let pipe_id = ctx.sock_conn_id[fd] as usize;
        if pipe_id < MAX_PIPES {
            let prev = PIPE_WRITE_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
            if ctx.pid >= 3 {
                print(b"CLOSE-PW P"); print_u64(ctx.pid as u64);
                print(b" fd="); print_u64(fd as u64);
                print(b" pipe="); print_u64(pipe_id as u64);
                print(b" wrefs="); print_u64(prev); // prev = before decrement
                print(b"->"); print_u64(if prev > 0 { prev - 1 } else { 0 });
                print(b"\n");
            }
            if prev <= 1 {
                print(b"PWC-SET close P"); print_u64(ctx.pid as u64);
                print(b" pipe="); print_u64(pipe_id as u64);
                print(b"\n");
                PIPE_WRITE_CLOSED[pipe_id].store(1, Ordering::Release);
                if PIPE_READ_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                    pipe_free(pipe_id);
                }
            }
        }
        ctx.sock_conn_id[fd] = 0xFFFF;
    } else if ctx.child_fds[fd] == 10 {
        // Pipe read end close — decrement refcount, mark closed when last ref gone
        let pipe_id = ctx.sock_conn_id[fd] as usize;
        if pipe_id < MAX_PIPES {
            let prev = PIPE_READ_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
            if prev <= 1 {
                PIPE_READ_CLOSED[pipe_id].store(1, Ordering::Release);
                if PIPE_WRITE_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                    pipe_free(pipe_id);
                }
            }
        }
        ctx.sock_conn_id[fd] = 0xFFFF;
    }
    ctx.child_fds[fd] = 0;
    // Clear cloexec bit
    if fd < 128 { *ctx.fd_cloexec &= !(1u128 << fd); }
    true
}

/// SYS_CLOSE (3): close fd, cleaning up associated resources.
pub(crate) fn sys_close(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    close_fd_internal(ctx, fd);
    reply_val(ctx.ep_cap, 0);
}

/// Close all fds marked with FD_CLOEXEC (called during execve).
/// Also closes any pipe fds (kind 10/11) above fd 2 that lack CLOEXEC —
/// programs rely on pipe fds not leaking through fork+exec, but may use
/// plain pipe() without O_CLOEXEC and expect the child to close them.
pub(crate) fn close_cloexec_fds(ctx: &mut SyscallContext) {
    let mut bits = *ctx.fd_cloexec;
    while bits != 0 {
        let fd = bits.trailing_zeros() as usize;
        if fd >= 128 { break; }
        print(b"CLOEXEC-CLOSE P"); print_u64(ctx.pid as u64);
        print(b" fd="); print_u64(fd as u64);
        print(b" kind="); print_u64(ctx.child_fds[fd] as u64);
        print(b"\n");
        close_fd_internal(ctx, fd);
        bits &= !(1u128 << fd);
    }
    // Close inherited pipe fds > 2 that weren't CLOEXEC.
    // After fork+exec, the child dup2's needed pipes to 0/1/2 and
    // explicitly closes the originals. Any remaining pipe fds are leaks.
    for fd in 3..GRP_MAX_FDS {
        let k = ctx.child_fds[fd];
        if k == 10 || k == 11 {
            print(b"EXEC-PIPE-CLOSE P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" kind="); print_u64(k as u64);
            print(b"\n");
            close_fd_internal(ctx, fd);
        }
    }
    // Clear orphaned initrd entries (fd == u64::MAX) inherited from forked parent.
    // After exec, the new binary has no use for the parent's stale initrd buffers.
    // Leaving them causes mmap to match the wrong file data.
    for s in 0..GRP_MAX_INITRD {
        if ctx.initrd_files[s][0] != 0 && ctx.initrd_files[s][3] == u64::MAX {
            ctx.initrd_files[s] = [0; 4];
        }
    }
}

/// SYS_OPEN (2): open file by path — devices, virtual files, directories, initrd, VFS.
pub(crate) fn sys_open(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let flags = msg.regs[1] as u32;
    let mut path = [0u8; 128];
    let path_len = copy_guest_path(path_ptr, &mut path);
    // Resolve relative paths against CWD
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    let kind = if name == b"/dev/null" { 8u8 }
        else if name == b"/dev/zero" { 9u8 }
        else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
        else { 0u8 };

    if kind != 0 {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = kind;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if starts_with(name, b"/etc/") || starts_with(name, b"/proc/")
           || starts_with(name, b"/sys/") {
        // Virtual files — same logic as SYS_OPENAT
        let virt_len = open_virtual_file(name, ctx.dir_buf);
        if let Some(gen_len) = virt_len {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15; // kind=15 = virtual file
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    } else if name == b"/" || name == b"/bin" || name == b"/lib"
           || name == b"/lib64" || name == b"/sbin" || name == b"/tmp"
           || name == b"/usr" || name == b"/etc" || name == b"/proc"
           || name == b"." {
        // Directory opens -> resolve VFS OID + DirList fd (for getdents64)
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        let mut vslot = None;
        for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
        if let (Some(f), Some(vs)) = (fd, vslot) {
            // Resolve directory OID from VFS
            let mut dir_oid = 0u64;
            vfs_lock();
            if let Some(store) = unsafe { shared_store() } {
                use sotos_objstore::ROOT_OID;
                if name == b"/" || name == b"." {
                    dir_oid = ROOT_OID;
                } else {
                    if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                        dir_oid = oid;
                    }
                }
            }
            vfs_unlock();
            if dir_oid == 0 { dir_oid = sotos_objstore::ROOT_OID; }
            ctx.child_fds[f] = 14; // kind=14 = directory
            ctx.vfs_files[vs] = [dir_oid, 0, 0, f as u64];
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else {
        // Try initrd — extract basename
        let mut basename_start = 0usize;
        for idx in 0..path_len {
            if name[idx] == b'/' { basename_start = idx + 1; }
        }
        let basename = &name[basename_start..];

        let mut slot = None;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
        }

        if basename.is_empty() || slot.is_none() {
            reply_val(ctx.ep_cap, -ENOENT);
            return;
        }
        let slot = slot.unwrap();

        let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0x300000;
        const FILE_BUF_PAGES_OPEN: u64 = 576; // 2.25 MiB (for libc.so.6 ~2.1 MB)
        let mut buf_ok = true;
        for p in 0..FILE_BUF_PAGES_OPEN {
            if let Ok(f) = sys::frame_alloc() {
                if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                    buf_ok = false; break;
                }
            } else { buf_ok = false; break; }
        }
        if !buf_ok {
            reply_val(ctx.ep_cap, -ENOMEM);
            return;
        }

        match sys::initrd_read(
            basename.as_ptr() as u64,
            basename.len() as u64,
            file_buf,
            FILE_BUF_PAGES_OPEN * 0x1000,
        ) {
            Ok(sz) => {
                let mut fd = None;
                for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                if let Some(f) = fd {
                    ctx.child_fds[f] = 12;
                    ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                    reply_val(ctx.ep_cap, f as i64);
                } else {
                    for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            }
            Err(_) => {
                for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                // Initrd failed — try VFS as fallback
                let mut vfs_found = false;
                vfs_lock();
                let vfs_result = unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    // Try resolve existing
                    if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                        let entry = store.stat(oid)?;
                        // O_TRUNC: reset file size
                        if flags & O_TRUNC != 0 && !entry.is_dir() {
                            store.write_obj(oid, &[]).ok();
                            return Some((oid, 0u64, false));
                        }
                        return Some((oid, entry.size, entry.is_dir()));
                    }
                    // O_CREAT: create file in parent dir
                    if flags & O_CREAT != 0 {
                        let mut last_slash = None;
                        for (i, &b) in name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
                        let (parent, fname) = match last_slash {
                            Some(pos) => {
                                let p = if pos == 0 { ROOT_OID } else {
                                    store.resolve_path(&name[..pos], ROOT_OID).ok()?
                                };
                                (p, &name[pos+1..path_len])
                            }
                            None => (ROOT_OID, name),
                        };
                        let oid = store.create_in(fname, &[], parent).ok()?;
                        return Some((oid, 0, false));
                    }
                    None
                });
                vfs_unlock();
                if let Some((oid, size, is_dir)) = vfs_result {
                    let mut vslot = None;
                    for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                    let mut fd = None;
                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                    if let (Some(vs), Some(f)) = (vslot, fd) {
                        ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                        ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                        reply_val(ctx.ep_cap, f as i64);
                        vfs_found = true;
                    }
                }
                if !vfs_found {
                    reply_val(ctx.ep_cap, -ENOENT);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SYS_ioctl -- terminal emulation
// ---------------------------------------------------------------------------
pub(crate) fn sys_ioctl(ctx: &mut SyscallContext, msg: &IpcMsg) {
    use sotos_common::linux_abi::*;
    let fd = msg.regs[0] as usize;
    let req = msg.regs[1] as u32;
    if fd <= 2 {
        match req {
            TCGETS => {
                let buf = msg.regs[2] as *mut u8;
                if !buf.is_null() {
                    // Kernel TCGETS writes struct __kernel_termios (36 bytes on x86_64).
                    // Layout: c_iflag(4) c_oflag(4) c_cflag(4) c_lflag(4) c_line(1) c_cc[19].
                    unsafe { core::ptr::write_bytes(buf, 0, 36); }
                    let p = buf as *mut u32;
                    unsafe {
                        *p = 0x0100 | 0x0400;           // c_iflag: ICRNL | IXON
                        *p.add(1) = 0x0001 | 0x0004;   // c_oflag: OPOST | ONLCR
                        *p.add(2) = 0x0030 | 0x0080 | 0x000F; // c_cflag: CS8|CREAD|B38400
                        *p.add(3) = 0x0008 | 0x0010 | 0x0020 | 0x0002 | 0x0001 | 0x8000 | 0x0200 | 0x0800; // c_lflag
                    }
                    let cc = unsafe { buf.add(17) };
                    unsafe {
                        *cc = 0x03;           // VINTR = Ctrl-C
                        *cc.add(1) = 0x1C;   // VQUIT = Ctrl-backslash
                        *cc.add(2) = 0x7F;   // VERASE = DEL
                        *cc.add(3) = 0x15;   // VKILL = Ctrl-U
                        *cc.add(4) = 0x04;   // VEOF = Ctrl-D
                        *cc.add(6) = 0x01;   // VMIN = 1
                        *cc.add(13) = 0x1A;  // VSUSP = Ctrl-Z
                    }
                }
                reply_val(ctx.ep_cap, 0);
            }
            TCSETS | TCSETSW | TCSETSF => reply_val(ctx.ep_cap, 0),
            TIOCGWINSZ => {
                let ws = Winsize::default_serial();
                let buf = msg.regs[2] as *mut Winsize;
                if !buf.is_null() { unsafe { *buf = ws; } }
                reply_val(ctx.ep_cap, 0);
            }
            TIOCSWINSZ => reply_val(ctx.ep_cap, 0),
            TIOCGPGRP | TIOCSPGRP => {
                if req == TIOCGPGRP {
                    let buf = msg.regs[2] as *mut i32;
                    if !buf.is_null() { unsafe { *buf = ctx.pid as i32; } }
                }
                reply_val(ctx.ep_cap, 0);
            }
            FIONREAD => {
                let buf = msg.regs[2] as *mut i32;
                if !buf.is_null() {
                    let avail = if unsafe { kb_has_char() } { 1i32 } else { 0i32 };
                    unsafe { *buf = avail; }
                }
                reply_val(ctx.ep_cap, 0);
            }
            _ => reply_val(ctx.ep_cap, -ENOTTY), // -ENOTTY
        }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

// ---------------------------------------------------------------------------
// SYS_readv(fd, iov, iovcnt) -- scatter read
// ---------------------------------------------------------------------------
pub(crate) fn sys_readv(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF); // -EBADF
    } else if ctx.child_fds[fd] == 1 {
        // stdin readv: read one char into first iovec
        if iovcnt > 0 && iov_ptr < 0x0000_8000_0000_0000 {
            let base = unsafe { *(iov_ptr as *const u64) };
            loop {
                let s = sig_dequeue(ctx.pid);
                if s != 0 && sig_dispatch(ctx.pid, s) >= 1 {
                    reply_val(ctx.ep_cap, -EINTR); break;
                }
                match unsafe { kb_read_char() } {
                    Some(ch) => {
                        if base != 0 { unsafe { *(base as *mut u8) = ch; } }
                        reply_val(ctx.ep_cap, 1); break;
                    }
                    None => { sys::yield_now(); }
                }
            }
        } else {
            reply_val(ctx.ep_cap, 0);
        }
    } else if ctx.child_fds[fd] == 12 {
        // Initrd file readv
        let mut total: usize = 0;
        let mut found = false;
        for s_idx in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s_idx][3] == fd as u64 && ctx.initrd_files[s_idx][0] != 0 {
                let data_base = ctx.initrd_files[s_idx][0];
                let file_size = ctx.initrd_files[s_idx][1];
                let mut pos = ctx.initrd_files[s_idx][2];
                let cnt = iovcnt.min(16);
                for i in 0..cnt {
                    let entry = iov_ptr + (i as u64) * 16;
                    if entry + 16 > 0x0000_8000_0000_0000 { break; }
                    let base = unsafe { *(entry as *const u64) };
                    let len = unsafe { *((entry + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    let avail = if pos < file_size { (file_size - pos) as usize } else { 0 };
                    let to_read = len.min(avail);
                    if to_read > 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (data_base + pos) as *const u8,
                                base as *mut u8,
                                to_read,
                            );
                        }
                        pos += to_read as u64;
                        total += to_read;
                    }
                    if to_read < len { break; } // EOF mid-iovec
                }
                ctx.initrd_files[s_idx][2] = pos;
                found = true;
                break;
            }
        }
        if found {
            reply_val(ctx.ep_cap, total as i64);
        } else {
            reply_val(ctx.ep_cap, -EBADF);
        }
    } else if ctx.child_fds[fd] == 13 {
        // VFS file readv
        let mut total: usize = 0;
        let mut found = false;
        for s_idx in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s_idx][3] == fd as u64 && ctx.vfs_files[s_idx][0] != 0 {
                let oid = ctx.vfs_files[s_idx][0];
                let mut pos = ctx.vfs_files[s_idx][2] as usize;
                let cnt = iovcnt.min(16);
                for i in 0..cnt {
                    let entry = iov_ptr + (i as u64) * 16;
                    if entry + 16 > 0x0000_8000_0000_0000 { break; }
                    let base = unsafe { *(entry as *const u64) };
                    let len = unsafe { *((entry + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
                    vfs_lock();
                    let n = unsafe { shared_store() }
                        .and_then(|store| store.read_obj_range(oid, pos, dst).ok())
                        .unwrap_or(0);
                    vfs_unlock();
                    pos += n;
                    total += n;
                    if n < len { break; } // EOF mid-iovec
                }
                ctx.vfs_files[s_idx][2] = pos as u64;
                found = true;
                break;
            }
        }
        if found {
            reply_val(ctx.ep_cap, total as i64);
        } else {
            reply_val(ctx.ep_cap, -EBADF);
        }
    } else if ctx.child_fds[fd] == 16 {
        // TCP socket readv -> gather into iovecs via TCP_RECV
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let mut total = 0usize;
        let cnt = iovcnt.min(16);
        for i in 0..cnt {
            let entry = iov_ptr + (i as u64) * 16;
            if entry + 16 > 0x0000_8000_0000_0000 { break; }
            let base = unsafe { *(entry as *const u64) };
            let ilen = unsafe { *((entry + 8) as *const u64) } as usize;
            if base == 0 || ilen == 0 { continue; }
            // Fill this iovec with TCP data in 64-byte chunks
            let mut off = 0usize;
            while off < ilen {
                let chunk = (ilen - off).min(64);
                let mut got = 0usize;
                for _ in 0..5000u32 {
                    let req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_RECV,
                        regs: [conn_id, chunk as u64, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 200) {
                        Ok(resp) => {
                            let n = resp.tag as usize;
                            if n > 0 && n <= chunk {
                                unsafe {
                                    let src = &resp.regs[0] as *const u64 as *const u8;
                                    core::ptr::copy_nonoverlapping(src, (base + off as u64) as *mut u8, n);
                                }
                                got = n;
                                break;
                            }
                        }
                        Err(_) => {}
                    }
                    sys::yield_now();
                }
                if got == 0 { break; } // no more data
                off += got;
                total += got;
                if got < chunk { break; } // short read, don't fill more
            }
            if off == 0 { break; } // no data for this iovec, stop
        }
        if total > 0 {
            reply_val(ctx.ep_cap, total as i64);
        } else {
            reply_val(ctx.ep_cap, -EAGAIN);
        }
    } else if ctx.child_fds[fd] == 10 {
        // Pipe read via readv: non-blocking with kernel-side retry
        let pipe_id = ctx.sock_conn_id[fd] as usize;
        let cnt = iovcnt.min(16);
        let mut total = 0usize;
        // Log iov structure for debugging
        if ctx.pid >= 3 && cnt > 0 {
            print(b"PIPEV-R P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" iovcnt="); print_u64(cnt as u64);
            for j in 0..cnt.min(3) {
                let e = iov_ptr + (j as u64) * 16;
                if e + 16 > 0x0000_8000_0000_0000 { break; }
                let b = unsafe { *(e as *const u64) };
                let l = unsafe { *((e + 8) as *const u64) };
                print(b" ["); print_u64(b); print(b","); print_u64(l); print(b"]");
            }
            print(b"\n");
        }
        for i in 0..cnt {
            let entry = iov_ptr + (i as u64) * 16;
            if entry + 16 > 0x0000_8000_0000_0000 { break; }
            let base = unsafe { *(entry as *const u64) };
            let ilen = unsafe { *((entry + 8) as *const u64) } as usize;
            if base == 0 || ilen == 0 { continue; }
            let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, ilen) };
            let n = pipe_read(pipe_id, dst);
            total += n;
            if n < ilen { break; } // short read or no data
        }
        if total > 0 {
            // Log data read
            if ctx.pid >= 3 {
                print(b"PIPEV-R P"); print_u64(ctx.pid as u64);
                print(b" fd="); print_u64(fd as u64);
                print(b" total="); print_u64(total as u64);
                print(b" pipe="); print_u64(pipe_id as u64);
                print(b"\n");
            }
            reply_val(ctx.ep_cap, total as i64);
        } else if pipe_writer_closed(pipe_id) {
            if ctx.pid >= 3 {
                print(b"PIPEV-R P"); print_u64(ctx.pid as u64);
                print(b" fd="); print_u64(fd as u64);
                print(b" pipe="); print_u64(pipe_id as u64);
                print(b" EOF\n");
            }
            reply_val(ctx.ep_cap, 0); // EOF
        } else {
            // No data, writer alive — ask kernel to retry
            mark_pipe_retry_on(ctx.pid, pipe_id);
            let reply = sotos_common::IpcMsg {
                tag: sotos_common::PIPE_RETRY_TAG,
                regs: [0; 8],
            };
            let _ = sys::send(ctx.ep_cap, &reply);
        }
    } else if ctx.child_fds[fd] == 2 {
        // stdout/stderr readv -> -EBADF (write-only)
        reply_val(ctx.ep_cap, -EBADF);
    } else {
        reply_val(ctx.ep_cap, 0); // other FD types: EOF
    }
}

// ---------------------------------------------------------------------------
// SYS_writev
// ---------------------------------------------------------------------------
pub(crate) fn sys_writev(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    // (debug logging removed — serial too slow for per-syscall prints)
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 2 {
        let mut total: usize = 0;
        let cnt = iovcnt.min(16);
        for i in 0..cnt {
            let entry = iov_ptr + (i as u64) * 16;
            if entry + 16 > 0x0000_8000_0000_0000 { break; }
            let base = ctx.guest_read_u64(entry);
            let len = ctx.guest_read_u64(entry + 8) as usize;
            if base == 0 || len == 0 { continue; }
            let safe_len = len.min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(base, &mut local_buf[..safe_len]);
            for j in 0..safe_len { sys::debug_print(local_buf[j]); unsafe { fb_putchar(local_buf[j]); } }
            total += safe_len;
        }
        reply_val(ctx.ep_cap, total as i64);
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 8 {
        // /dev/null: count bytes and discard
        let mut total: usize = 0;
        let cnt = iovcnt.min(16);
        for i in 0..cnt {
            let entry = iov_ptr + (i as u64) * 16;
            if entry + 16 > 0x0000_8000_0000_0000 { break; }
            let len = unsafe { *((entry + 8) as *const u64) } as usize;
            total += len;
        }
        reply_val(ctx.ep_cap, total as i64);
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 16 {
        // TCP socket writev -- gather into single write
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let cnt = iovcnt.min(16);
        let mut total_sent = 0usize;
        for i in 0..cnt {
            let entry = iov_ptr + (i as u64) * 16;
            if entry + 16 > 0x0000_8000_0000_0000 { break; }
            let base = unsafe { *(entry as *const u64) };
            let ilen = unsafe { *((entry + 8) as *const u64) } as usize;
            if base == 0 || ilen == 0 { continue; }
            // Send in 40-byte chunks
            let mut off = 0;
            while off < ilen {
                let chunk = (ilen - off).min(40);
                let mut req = sotos_common::IpcMsg {
                    tag: NET_CMD_TCP_SEND,
                    regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
                };
                let data = unsafe { core::slice::from_raw_parts((base + off as u64) as *const u8, chunk) };
                unsafe {
                    let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                    core::ptr::copy_nonoverlapping(data.as_ptr(), dst, chunk);
                }
                match sys::call_timeout(net_cap, &req, 500) {
                    Ok(resp) => {
                        let n = resp.regs[0] as usize;
                        total_sent += n;
                        off += n;
                        if n == 0 { break; }
                    }
                    Err(_) => { break; }
                }
            }
        }
        reply_val(ctx.ep_cap, total_sent as i64);
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        // VFS file writev: gather iovecs and write to VFS
        let cnt = iovcnt.min(16);
        let mut total: usize = 0;
        let mut ok = true;
        for i in 0..cnt {
            let entry = iov_ptr + (i as u64) * 16;
            if entry + 16 > 0x0000_8000_0000_0000 { break; }
            let base = unsafe { *(entry as *const u64) };
            let ilen = unsafe { *((entry + 8) as *const u64) } as usize;
            if base == 0 || ilen == 0 { continue; }
            let data = unsafe { core::slice::from_raw_parts(base as *const u8, ilen) };
            // Find the VFS file slot for this fd
            let mut wrote = false;
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    let oid = ctx.vfs_files[s][0];
                    let pos = ctx.vfs_files[s][2] as usize;
                    vfs_lock();
                    let result = unsafe { shared_store() }
                        .and_then(|store| store.write_obj_range(oid, pos, data).ok());
                    vfs_unlock();
                    match result {
                        Some(_) => {
                            ctx.vfs_files[s][2] += ilen as u64;
                            let new_end = ctx.vfs_files[s][2];
                            if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                            total += ilen;
                            wrote = true;
                        }
                        None => { ok = false; }
                    }
                    break;
                }
            }
            if !wrote && ok { ok = false; }
            if !ok { break; }
        }
        reply_val(ctx.ep_cap, if ok && total > 0 { total as i64 } else { -EIO });
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 11 {
        // Pipe write via writev: gather iovecs and write to pipe buffer
        let pipe_id = ctx.sock_conn_id[fd] as usize;
        let cnt = iovcnt.min(16);
        let mut total = 0usize;
        // Log all iovec content for git debugging
        if ctx.pid >= 3 && cnt > 0 {
            // Compute total length
            let mut tlen = 0usize;
            for j in 0..cnt {
                let e = iov_ptr + (j as u64) * 16;
                if e + 16 > 0x0000_8000_0000_0000 { break; }
                let il = unsafe { *((e + 8) as *const u64) } as usize;
                tlen += il;
            }
            print(b"PIPEV-W P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" pipe="); print_u64(pipe_id as u64);
            print(b" len="); print_u64(tlen as u64);
            print(b" [");
            let mut shown = 0usize;
            for j in 0..cnt {
                let e = iov_ptr + (j as u64) * 16;
                if e + 16 > 0x0000_8000_0000_0000 { break; }
                let base = unsafe { *(e as *const u64) };
                let il = unsafe { *((e + 8) as *const u64) } as usize;
                if base == 0 || il == 0 { continue; }
                let lim = il.min(80 - shown);
                for k in 0..lim {
                    let b = unsafe { *(base as *const u8).add(k) };
                    if b == 0x0A { print(b"\\n"); }
                    else if b >= 0x20 && b < 0x7F { sys::debug_print(b); }
                    else { print(b"."); }
                }
                shown += lim;
                if shown >= 80 { break; }
            }
            print(b"]\n");
        }
        for i in 0..cnt {
            let entry = iov_ptr + (i as u64) * 16;
            if entry + 16 > 0x0000_8000_0000_0000 { break; }
            let base = ctx.guest_read_u64(entry);
            let ilen = ctx.guest_read_u64(entry + 8) as usize;
            if base == 0 || ilen == 0 { continue; }
            let safe_ilen = ilen.min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(base, &mut local_buf[..safe_ilen]);
            let src = &local_buf[..safe_ilen];
            let mut written = 0usize;
            let mut retries = 0u32;
            while written < safe_ilen {
                let n = pipe_write(pipe_id, &src[written..]);
                written += n;
                if n == 0 {
                    retries += 1;
                    if retries > 10000 { break; }
                    sys::yield_now();
                } else {
                    retries = 0;
                }
            }
            total += written;
            if written < safe_ilen { break; } // pipe full, stop
        }
        reply_val(ctx.ep_cap, total as i64);
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}


/// SYS_ACCESS (21) / SYS_FACCESSAT (269): check file accessibility.
pub(crate) fn sys_access(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let path_ptr = if syscall_nr == SYS_FACCESSAT { msg.regs[1] } else { msg.regs[0] };
    let mut path = [0u8; 128];
    let path_len = copy_guest_path(path_ptr, &mut path);
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];
    let is_dir = name == b"." || name == b".."
        || name == b"/" || name == b"/usr" || name == b"/etc"
        || name == b"/lib" || name == b"/lib64"
        || name == b"/bin" || name == b"/sbin"
        || name == b"/tmp" || name == b"/home" || name == b"/var"
        || name == b"/usr/bin" || name == b"/usr/lib"
        || name == b"/usr/sbin" || name == b"/usr/lib64"
        || name == b"/usr/share" || name == b"/usr/share/terminfo";
    let is_virtual = name == b"/etc/passwd" || name == b"/etc/group"
        || name == b"/etc/resolv.conf" || name == b"/etc/hostname"
        || name == b"/etc/nsswitch.conf"
        || name == b"/dev/null" || name == b"/dev/zero"
        || name == b"/dev/urandom" || name == b"/dev/random";
    if is_dir || is_virtual {
        reply_val(ctx.ep_cap, 0);
    } else {
        let mut basename_start = 0usize;
        for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
        let basename = &name[basename_start..];
        if !basename.is_empty() {
            match sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                Ok(_) => reply_val(ctx.ep_cap, 0),
                Err(_) => {
                    vfs_lock();
                    let found = unsafe { shared_store() }.and_then(|store| {
                        store.resolve_path(name, sotos_objstore::ROOT_OID).ok()
                    }).is_some();
                    vfs_unlock();
                    // Only print access for config-related paths (reduced noise)
                    if ctx.pid > 1 && name.windows(6).any(|w| w == b"config") {
                        print(if found { b"ACCESS-OK: " } else { b"ACCESS-MISS: " });
                        print(name);
                        print(b"\n");
                    }
                    reply_val(ctx.ep_cap, if found { 0 } else { -ENOENT });
                }
            }
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_PIPE (22): create pipe.
pub(crate) fn sys_pipe(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let pipefd = msg.regs[0] as *mut i32;
    let mut r_fd = None;
    let mut w_fd = None;
    for i in 3..GRP_MAX_FDS {
        if ctx.child_fds[i] == 0 {
            if r_fd.is_none() { r_fd = Some(i); }
            else if w_fd.is_none() { w_fd = Some(i); break; }
        }
    }
    if let (Some(r), Some(w)) = (r_fd, w_fd) {
        if let Some(pipe_id) = pipe_alloc() {
            ctx.child_fds[r] = 10;
            ctx.child_fds[w] = 11;
            ctx.sock_conn_id[r] = pipe_id as u32;
            ctx.sock_conn_id[w] = pipe_id as u32;
            unsafe { *pipefd = r as i32; *pipefd.add(1) = w as i32; }
            if ctx.pid >= 3 {
                print(b"FD-PIPE P"); print_u64(ctx.pid as u64);
                print(b" r="); print_u64(r as u64);
                print(b" w="); print_u64(w as u64);
                print(b" pipe="); print_u64(pipe_id as u64);
                print(b"\n");
            }
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else {
        reply_val(ctx.ep_cap, -EMFILE);
    }
}

/// SYS_DUP (32): duplicate fd.
pub(crate) fn sys_dup(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let oldfd = msg.regs[0] as usize;
    if oldfd >= GRP_MAX_FDS || ctx.child_fds[oldfd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else {
        let mut newfd = None;
        for i in 0..GRP_MAX_FDS {
            if ctx.child_fds[i] == 0 { newfd = Some(i); break; }
        }
        if let Some(nfd) = newfd {
            // Increment pipe refcount for the dup'd fd
            let ok = ctx.child_fds[oldfd];
            let op = ctx.sock_conn_id[oldfd] as usize;
            if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
            else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
            ctx.child_fds[nfd] = ctx.child_fds[oldfd];
            ctx.sock_conn_id[nfd] = ctx.sock_conn_id[oldfd];
            ctx.sock_udp_local_port[nfd] = ctx.sock_udp_local_port[oldfd];
            ctx.sock_udp_remote_ip[nfd] = ctx.sock_udp_remote_ip[oldfd];
            ctx.sock_udp_remote_port[nfd] = ctx.sock_udp_remote_port[oldfd];
            // dup does NOT set FD_CLOEXEC on new fd
            if nfd < 128 { *ctx.fd_cloexec &= !(1u128 << nfd); }
            if ctx.pid >= 3 {
                print(b"FD-DUP P"); print_u64(ctx.pid as u64);
                print(b" "); print_u64(oldfd as u64);
                print(b"->"); print_u64(nfd as u64);
                print(b" k="); print_u64(ok as u64);
                print(b" pipe="); print_u64(op as u64);
                print(b"\n");
            }
            reply_val(ctx.ep_cap, nfd as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    }
}

/// SYS_DUP2 (33): duplicate fd to specific number.
pub(crate) fn sys_dup2(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let oldfd = msg.regs[0] as usize;
    let newfd = msg.regs[1] as usize;
    if oldfd >= GRP_MAX_FDS || ctx.child_fds[oldfd] == 0 || newfd >= GRP_MAX_FDS {
        reply_val(ctx.ep_cap, -EBADF);
    } else {
        // If newfd was a pipe, decrement its refcount before overwriting
        if newfd < GRP_MAX_FDS && ctx.child_fds[newfd] != 0 {
            let nk = ctx.child_fds[newfd];
            let np = ctx.sock_conn_id[newfd] as usize;
            if nk == 11 && np < MAX_PIPES {
                let prev = PIPE_WRITE_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 {
                    print(b"PWC-SET dup2 P"); print_u64(ctx.pid as u64);
                    print(b" pipe="); print_u64(np as u64);
                    print(b"\n");
                    PIPE_WRITE_CLOSED[np].store(1, Ordering::Release);
                }
            } else if nk == 10 && np < MAX_PIPES {
                let prev = PIPE_READ_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 { PIPE_READ_CLOSED[np].store(1, Ordering::Release); }
            }
        }
        // Increment refcount for the pipe being dup'd
        let ok = ctx.child_fds[oldfd];
        let op = ctx.sock_conn_id[oldfd] as usize;
        if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
        else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
        ctx.child_fds[newfd] = ctx.child_fds[oldfd];
        ctx.sock_conn_id[newfd] = ctx.sock_conn_id[oldfd];
        ctx.sock_udp_local_port[newfd] = ctx.sock_udp_local_port[oldfd];
        ctx.sock_udp_remote_ip[newfd] = ctx.sock_udp_remote_ip[oldfd];
        ctx.sock_udp_remote_port[newfd] = ctx.sock_udp_remote_port[oldfd];
        // dup2 does NOT set FD_CLOEXEC on new fd
        if newfd < 128 { *ctx.fd_cloexec &= !(1u128 << newfd); }
        if ctx.pid >= 3 {
            let ok = ctx.child_fds[newfd];
            let op = ctx.sock_conn_id[newfd] as u64;
            print(b"FD-DUP2 P"); print_u64(ctx.pid as u64);
            print(b" "); print_u64(oldfd as u64);
            print(b"->"); print_u64(newfd as u64);
            print(b" k="); print_u64(ok as u64);
            print(b" pipe="); print_u64(op);
            print(b"\n");
        }
        reply_val(ctx.ep_cap, newfd as i64);
    }
}

/// SYS_FCNTL (72): file control.
pub(crate) fn sys_fcntl(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let cmd = msg.regs[1] as u32;
    match cmd {
        0 | 1030 => { // F_DUPFD / F_DUPFD_CLOEXEC
            let min = msg.regs[2] as usize;
            if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 { reply_val(ctx.ep_cap, -EBADF); }
            else {
                let mut nfd = None;
                for i in min..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { nfd = Some(i); break; } }
                if let Some(n) = nfd {
                    // Increment pipe refcount
                    let ok = ctx.child_fds[fd];
                    let op = ctx.sock_conn_id[fd] as usize;
                    if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
                    else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
                    ctx.child_fds[n] = ctx.child_fds[fd];
                    ctx.sock_conn_id[n] = ctx.sock_conn_id[fd];
                    ctx.sock_udp_local_port[n] = ctx.sock_udp_local_port[fd];
                    ctx.sock_udp_remote_ip[n] = ctx.sock_udp_remote_ip[fd];
                    ctx.sock_udp_remote_port[n] = ctx.sock_udp_remote_port[fd];
                    // Copy VFS file tracking for dup'd VFS fds
                    if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
                        for s in 0..GRP_MAX_VFS {
                            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                                for s2 in 0..GRP_MAX_VFS {
                                    if ctx.vfs_files[s2][0] == 0 {
                                        ctx.vfs_files[s2] = ctx.vfs_files[s];
                                        ctx.vfs_files[s2][3] = n as u64;
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                    // Set cloexec on new fd if F_DUPFD_CLOEXEC
                    if cmd == 1030 && n < 128 {
                        *ctx.fd_cloexec |= 1u128 << n;
                    }
                    if ctx.pid >= 3 {
                        print(b"FD-FCNTL P"); print_u64(ctx.pid as u64);
                        print(b" F_DUPFD"); if cmd == 1030 { print(b"_CX"); }
                        print(b" "); print_u64(fd as u64);
                        print(b"->"); print_u64(n as u64);
                        print(b" k="); print_u64(ok as u64);
                        print(b" pipe="); print_u64(op as u64);
                        print(b"\n");
                    }
                    reply_val(ctx.ep_cap, n as i64);
                }
                else { reply_val(ctx.ep_cap, -EMFILE); }
            }
        }
        1 => { // F_GETFD
            if fd < 128 {
                let val = if *ctx.fd_cloexec & (1u128 << fd) != 0 { 1 } else { 0 };
                reply_val(ctx.ep_cap, val);
            } else { reply_val(ctx.ep_cap, 0); }
        }
        2 => { // F_SETFD
            if fd < 128 {
                let flags = msg.regs[2] as u32;
                if flags & 1 != 0 { // FD_CLOEXEC = 1
                    *ctx.fd_cloexec |= 1u128 << fd;
                } else {
                    *ctx.fd_cloexec &= !(1u128 << fd);
                }
            }
            reply_val(ctx.ep_cap, 0);
        }
        3 => { // F_GETFL
            let flags = if fd < GRP_MAX_FDS { ctx.fd_flags[fd] } else { 0 };
            reply_val(ctx.ep_cap, flags as i64);
        }
        4 => { // F_SETFL — save flags (O_NONBLOCK, O_APPEND, etc.)
            if fd < GRP_MAX_FDS {
                ctx.fd_flags[fd] = msg.regs[2] as u32;
            }
            reply_val(ctx.ep_cap, 0);
        }
        _ => reply_val(ctx.ep_cap, -EINVAL),
    }
}

/// SYS_GETCWD (79): get current working directory.
pub(crate) fn sys_getcwd(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf = msg.regs[0] as *mut u8;
    let size = msg.regs[1] as usize;
    let mut cwd_len = 0;
    while cwd_len < GRP_CWD_MAX && ctx.cwd[cwd_len] != 0 { cwd_len += 1; }
    if cwd_len == 0 { cwd_len = 1; ctx.cwd[0] = b'/'; }
    if size > cwd_len {
        unsafe {
            core::ptr::copy_nonoverlapping(ctx.cwd.as_ptr(), buf, cwd_len);
            *buf.add(cwd_len) = 0;
        }
        reply_val(ctx.ep_cap, buf as i64);
    } else {
        reply_val(ctx.ep_cap, -ERANGE);
    }
}

/// SYS_FSYNC (74) / SYS_FDATASYNC (75): flush (no-op).
pub(crate) fn sys_fsync(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_FTRUNCATE (77): truncate file.
pub(crate) fn sys_ftruncate(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let length = msg.regs[1] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        let mut done = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                ctx.vfs_files[s][1] = length as u64;
                done = true;
                break;
            }
        }
        reply_val(ctx.ep_cap, if done { 0 } else { -9 });
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// SYS_RENAME (82): rename file in VFS.
pub(crate) fn sys_rename(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let old_ptr = msg.regs[0];
    let new_ptr = msg.regs[1];
    let mut old_path = [0u8; 128];
    let mut new_path = [0u8; 128];
    let old_len = copy_guest_path(old_ptr, &mut old_path);
    let new_len = copy_guest_path(new_ptr, &mut new_path);
    let (old_path, old_len) = if old_len > 0 && old_path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &old_path[..old_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (old_path, old_len) };
    let (new_path, new_len) = if new_len > 0 && new_path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &new_path[..new_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (new_path, new_len) };
    let old_name = &old_path[..old_len];
    let new_name = &new_path[..new_len];

    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let old_oid = store.resolve_path(old_name, ROOT_OID).ok()?;
        let mut last_slash = None;
        for (i, &b) in new_name.iter().enumerate() {
            if b == b'/' { last_slash = Some(i); }
        }
        let (new_parent, new_basename) = match last_slash {
            Some(pos) => {
                let pp = &new_name[..pos];
                let p = if pp.is_empty() { ROOT_OID }
                    else { store.resolve_path(pp, ROOT_OID).ok()? };
                (p, &new_name[pos + 1..])
            }
            None => (ROOT_OID, new_name),
        };
        store.rename(old_oid, new_basename, new_parent).ok()?;
        // Post-rename verification: check renamed entry's flags
        if let Some(entry) = store.stat(old_oid) {
            if entry.is_dir() {
                print(b"REN-POSTCHECK-DIR: oid=");
                print_u64(old_oid);
                print(b" flags=");
                print_u64(entry.flags as u64);
                print(b" name=[");
                print(entry.name_as_str());
                print(b"]\n");
            }
        }
        // Also check if old name still resolves (shouldn't!)
        if store.resolve_path(old_name, ROOT_OID).is_ok() {
            print(b"REN-OLDNAME-STILL-EXISTS: ");
            print(old_name);
            print(b"\n");
        }
        Some(())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -2 });
}

/// SYS_OPENAT (257): open file relative to directory fd.
pub(crate) fn sys_openat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let flags = msg.regs[2] as u32;
    let mut path = [0u8; 128];
    let path_len = copy_guest_path(path_ptr, &mut path);
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    let kind = if name == b"/dev/null" { 8u8 }
        else if name == b"/dev/zero" { 9u8 }
        else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
        else { 0u8 };

    if kind != 0 {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = kind;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if starts_with(name, b"/etc/") {
        let virt_len = open_virtual_file(name, ctx.dir_buf);
        if let Some(gen_len) = virt_len {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
        let mut gen_len: usize = 0;
        let mut handled = true;
        if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
            gen_len = super::mm::format_proc_maps(ctx.memg, ctx.dir_buf);
        } else if name == b"/proc/self/status" {
            gen_len = format_proc_status(ctx.dir_buf, ctx.pid);
        } else if name == b"/proc/self/stat" {
            gen_len = format_proc_self_stat(ctx.dir_buf, ctx.pid);
        } else if name == b"/proc/cpuinfo" {
            let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/meminfo" {
            let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/uptime" {
            let tsc = rdtsc();
            let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
            let secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 } + UPTIME_OFFSET_SECS;
            gen_len = format_uptime_into(ctx.dir_buf, secs);
        } else if name == b"/proc/version" {
            let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/loadavg" {
            let info = b"0.01 0.05 0.10 1/32 42\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/self/auxv" || name == b"/proc/self/environ" {
            // Empty content
        } else if starts_with(name, b"/proc/syslog/") {
            let rest = &path[13..path_len];
            let (max_n, _) = parse_u64_from(rest);
            let max_entries = if max_n == 0 { 10 } else { max_n as usize };
            gen_len = format_syslog_into(ctx.dir_buf, max_entries);
        } else if starts_with(name, b"/proc/netmirror/") {
            let rest = &path[16..path_len];
            let enable = rest == b"on" || rest == b"1";
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            if net_cap != 0 {
                let cmd_msg = sotos_common::IpcMsg {
                    tag: 12,
                    regs: [if enable { 1 } else { 0 }, 0, 0, 0, 0, 0, 0, 0],
                };
                let _ = sys::call(net_cap, &cmd_msg);
            }
            let msg_text = if enable { b"packet mirroring: ON\n" as &[u8] } else { b"packet mirroring: OFF\n" };
            let n = msg_text.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&msg_text[..n]);
            gen_len = n;
        } else if starts_with(name, b"/proc/") {
            let rest = &path[6..path_len];
            let (n, consumed) = parse_u64_from(rest);
            if consumed > 0 && n >= 1 && n <= MAX_PROCS as u64
                && PROCESSES[n as usize - 1].state.load(Ordering::Acquire) != 0
            {
                let after = &rest[consumed..];
                if after == b"/status" || after.is_empty() {
                    gen_len = format_proc_status(ctx.dir_buf, n as usize);
                } else {
                    handled = false;
                }
            } else {
                handled = false;
            }
        } else if starts_with(name, b"/sys/") {
            if name == b"/sys/devices/system/cpu/online" {
                let info = b"0-0\n";
                ctx.dir_buf[..info.len()].copy_from_slice(info);
                gen_len = info.len();
            } else if name == b"/sys/devices/system/cpu/possible" {
                let info = b"0-0\n";
                ctx.dir_buf[..info.len()].copy_from_slice(info);
                gen_len = info.len();
            } else if starts_with(name, b"/sys/devices/system/cpu/cpu0/") {
                gen_len = 0;
            } else {
                handled = false;
            }
        }

        if !handled {
            reply_val(ctx.ep_cap, -ENOENT);
        } else {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        }
    } else {
        // Try to open from initrd
        let is_lib_path = starts_with(name, b"/lib/") || starts_with(name, b"/usr/lib/");
        let mut basename_start = 0usize;
        for idx in 0..path_len {
            if name[idx] == b'/' { basename_start = idx + 1; }
        }
        let basename = &name[basename_start..];
        let mut opened_initrd = false;

        if !basename.is_empty() && !is_lib_path {
            let mut slot = None;
            for s in 0..GRP_MAX_INITRD {
                if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
            }
            if let Some(slot) = slot {
                let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0x300000;
                const FILE_BUF_PAGES_OPEN: u64 = 576;
                let mut buf_ok = true;
                for p in 0..FILE_BUF_PAGES_OPEN {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            buf_ok = false; break;
                        }
                    } else { buf_ok = false; break; }
                }
                if buf_ok {
                    if let Ok(sz) = sys::initrd_read(
                        basename.as_ptr() as u64,
                        basename.len() as u64,
                        file_buf,
                        FILE_BUF_PAGES_OPEN * 0x1000,
                    ) {
                        let mut fd = None;
                        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            ctx.child_fds[f] = 12;
                            ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                            reply_val(ctx.ep_cap, f as i64);
                            opened_initrd = true;
                        } else {
                            for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                            reply_val(ctx.ep_cap, -EMFILE);
                            opened_initrd = true;
                        }
                    } else {
                        for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                    }
                }
            }
        }

        if !opened_initrd {
            let oflags = OFlags::from_bits_truncate(flags as u32);
            let has_creat = oflags.contains(OFlags::CREAT);
            let has_trunc = oflags.contains(OFlags::TRUNC);
            let has_dir = oflags.contains(OFlags::DIRECTORY);

            vfs_lock();
            let vfs_result = unsafe { shared_store() }.and_then(|store| {
                use sotos_objstore::ROOT_OID;
                match store.resolve_path(name, ROOT_OID) {
                    Ok(oid) => {
                        let entry = store.stat(oid)?;
                        if has_dir && !entry.is_dir() {
                            return None;
                        }
                        if has_trunc && !entry.is_dir() {
                            store.write_obj(oid, &[]).ok();
                            Some((oid, 0u64, false))
                        } else {
                            Some((oid, entry.size, entry.is_dir()))
                        }
                    }
                    Err(_) if has_creat => {
                        let mut last_slash = None;
                        for (i, &b) in name.iter().enumerate() {
                            if b == b'/' { last_slash = Some(i); }
                        }
                        let (parent_oid, filename) = match last_slash {
                            Some(pos) => {
                                let parent_path = &name[..pos];
                                let fname = &name[pos + 1..];
                                let p = if parent_path.is_empty() {
                                    ROOT_OID
                                } else {
                                    store.resolve_path(parent_path, ROOT_OID).ok()?
                                };
                                (p, fname)
                            }
                            None => (ROOT_OID, name),
                        };
                        match store.create_in(filename, &[], parent_oid) {
                            Ok(oid) => Some((oid, 0u64, false)),
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                }
            });
            vfs_unlock();

            if ctx.pid > 1 && has_creat && vfs_result.is_none() {
                print(b"CREAT-FAIL: ");
                print(name);
                print(b"\n");
            }

            match vfs_result {
                Some((oid, size, is_dir)) => {
                    let mut vslot = None;
                    for s in 0..GRP_MAX_VFS {
                        if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; }
                    }
                    let mut fd = None;
                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                    if let (Some(vs), Some(f)) = (vslot, fd) {
                        ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                        ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                        reply_val(ctx.ep_cap, f as i64);
                    } else {
                        reply_val(ctx.ep_cap, -EMFILE);
                    }
                }
                None => {
                    // Last resort: try initrd by basename
                    let mut found_initrd = false;
                    if !basename.is_empty() {
                        let mut slot = None;
                        for s in 0..GRP_MAX_INITRD {
                            if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
                        }
                        if let Some(slot) = slot {
                            let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0x300000;
                            const FILE_BUF_PAGES_OPEN: u64 = 576;
                            let mut buf_ok = true;
                            for p in 0..FILE_BUF_PAGES_OPEN {
                                if let Ok(f) = sys::frame_alloc() {
                                    if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                        buf_ok = false; break;
                                    }
                                } else { buf_ok = false; break; }
                            }
                            if buf_ok {
                                if let Ok(sz) = sys::initrd_read(
                                    basename.as_ptr() as u64,
                                    basename.len() as u64,
                                    file_buf,
                                    FILE_BUF_PAGES_OPEN * 0x1000,
                                ) {
                                    let mut fd = None;
                                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                                    if let Some(f) = fd {
                                        ctx.child_fds[f] = 12;
                                        ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                        reply_val(ctx.ep_cap, f as i64);
                                        found_initrd = true;
                                    } else {
                                        for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                        reply_val(ctx.ep_cap, -EMFILE);
                                        found_initrd = true;
                                    }
                                } else {
                                    for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                }
                            }
                        }
                    }
                    if !found_initrd {
                        reply_val(ctx.ep_cap, -ENOENT);
                    }
                }
            }
        }
    }
}

/// SYS_FSTATAT (262): stat relative to dirfd.
pub(crate) fn sys_fstatat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let dirfd = msg.regs[0] as i64;
    let path_ptr = msg.regs[1];
    let stat_ptr = msg.regs[2];
    let flags = msg.regs[3] as u32;
    let mut path = [0u8; 128];
    let path_len = copy_guest_path(path_ptr, &mut path);
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    // AT_EMPTY_PATH: use dirfd as the file descriptor
    if (flags & AT_EMPTY_PATH) != 0 && path_len == 0 {
        let fd = dirfd as usize;
        if fd < GRP_MAX_FDS && ctx.child_fds[fd] != 0 {
            if ctx.child_fds[fd] == 12 {
                let mut size = 0u64;
                let mut ino = 0u64;
                for s in 0..GRP_MAX_INITRD {
                    if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                        size = ctx.initrd_files[s][1];
                        ino = ctx.initrd_files[s][0];
                        break;
                    }
                }
                write_linux_stat_dev(stat_ptr, 1, ino, size, false);
            } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
                let is_vfs_dir = ctx.child_fds[fd] == 14;
                let mut size = 0u64;
                let mut oid = 0u64;
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                        oid = ctx.vfs_files[s][0];
                        size = ctx.vfs_files[s][1];
                        break;
                    }
                }
                write_linux_stat_dev(stat_ptr, 2, oid, size, is_vfs_dir);
            } else {
                write_linux_stat(stat_ptr, fd as u64, 0, false);
            }
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -EBADF);
        }
        return;
    }

    // First try initrd by basename
    let mut basename_start = 0usize;
    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
    let basename = &name[basename_start..];
    if !basename.is_empty() {
        if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
            write_linux_stat(stat_ptr, 0, sz, false);
            reply_val(ctx.ep_cap, 0);
            return;
        }
    }
    // Try VFS
    vfs_lock();
    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        Some((entry.oid, entry.size, entry.is_dir()))
    });
    vfs_unlock();
    if let Some((oid, size, is_dir)) = vfs_stat {
        write_linux_stat(stat_ptr, oid, size, is_dir);
        reply_val(ctx.ep_cap, 0);
    } else {
        let is_known_dir = name == b"." || path_len == 0
            || name == b"/" || name == b"/usr" || name == b"/etc"
            || name == b"/lib" || name == b"/lib64"
            || name == b"/bin" || name == b"/sbin"
            || name == b"/tmp" || name == b"/home" || name == b"/var"
            || name == b"/usr/bin" || name == b"/usr/lib"
            || name == b"/usr/sbin" || name == b"/usr/lib64"
            || name == b"/usr/share" || name == b"/usr/libexec"
            || name == b"/usr/libexec/git-core"
            || name == b"/usr/local" || name == b"/usr/local/bin"
            || starts_with(name, b"/dev/");
        if is_known_dir {
            write_linux_stat(stat_ptr, 0, 4096, true);
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_READLINKAT (267): read symbolic link.
pub(crate) fn sys_readlinkat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let out_buf = msg.regs[2];
    let bufsiz = msg.regs[3] as usize;
    let mut rpath = [0u8; 64];
    let rpath_len = copy_guest_path(path_ptr, &mut rpath);
    if rpath_len >= 14 && &rpath[..14] == b"/proc/self/exe" {
        let exe = b"/bin/program";
        let n = exe.len().min(bufsiz);
        if out_buf != 0 && out_buf < 0x0000_8000_0000_0000 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    exe.as_ptr(), out_buf as *mut u8, n,
                );
            }
        }
        reply_val(ctx.ep_cap, n as i64);
    } else {
        reply_val(ctx.ep_cap, -EINVAL);
    }
}

/// SYS_GETDENTS64 (217): read directory entries.
pub(crate) fn sys_getdents64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    use sotos_common::linux_abi::{DT_REG, DT_DIR};
    let fd = msg.regs[0] as usize;
    let dirp = msg.regs[1];
    let count = msg.regs[2] as usize;

    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] != 14 {
        reply_val(ctx.ep_cap, -EBADF);
    } else {
        let mut need_populate = true;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                if ctx.vfs_files[s][2] == 0xDEAD { need_populate = false; }
                break;
            }
        }
        if need_populate {
            *ctx.dir_len = 0;
            *ctx.dir_pos = 0;
            let mut dir_oid = 0u64;
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    dir_oid = ctx.vfs_files[s][0];
                    break;
                }
            }
            if dir_oid != 0 {
                vfs_lock();
                if let Some(store) = unsafe { shared_store() } {
                    for entry in &store.dir {
                        if entry.is_free() || entry.parent_oid != dir_oid || entry.oid == dir_oid {
                            continue;
                        }
                        let ename = entry.name_as_str();
                        let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8;
                        if *ctx.dir_len + reclen > ctx.dir_buf.len() { break; }
                        let d = &mut ctx.dir_buf[*ctx.dir_len..*ctx.dir_len + reclen];
                        for b in d.iter_mut() { *b = 0; }
                        d[0..8].copy_from_slice(&entry.oid.to_le_bytes());
                        d[8..16].copy_from_slice(&((*ctx.dir_len + reclen) as u64).to_le_bytes());
                        d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                        d[18] = if entry.is_dir() { DT_DIR } else { DT_REG };
                        let nlen = ename.len().min(reclen - 19);
                        d[19..19 + nlen].copy_from_slice(&ename[..nlen]);
                        *ctx.dir_len += reclen;
                    }
                }
                vfs_unlock();
            }
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    ctx.vfs_files[s][2] = 0xDEAD;
                    break;
                }
            }
        }

        let remaining = if *ctx.dir_pos < *ctx.dir_len { *ctx.dir_len - *ctx.dir_pos } else { 0 };
        if remaining == 0 {
            reply_val(ctx.ep_cap, 0); // EOF
        } else {
            let copy_len = remaining.min(count);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    ctx.dir_buf[*ctx.dir_pos..].as_ptr(),
                    dirp as *mut u8,
                    copy_len,
                );
            }
            *ctx.dir_pos += copy_len;
            reply_val(ctx.ep_cap, copy_len as i64);
        }
    }
}

/// SYS_FADVISE64 (221): stub.
pub(crate) fn sys_fadvise64(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_MKDIR (83): create directory in VFS.
pub(crate) fn sys_mkdir(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    let name = &path[..plen];
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, name, &mut abs);
    let abs_name = &abs[..alen];
    vfs_lock();
    let mut mkdir_ok = false;
    if let Some(store) = unsafe { shared_store() } {
        use sotos_objstore::ROOT_OID;
        let mut last_slash = None;
        for (i, &b) in abs_name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, dname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else {
                    match store.resolve_path(&abs_name[..pos], ROOT_OID) {
                        Ok(oid) => oid,
                        Err(_) => { vfs_unlock(); reply_val(ctx.ep_cap, -ENOENT); return; }
                    }
                };
                (p, &abs_name[pos+1..alen])
            }
            None => (ROOT_OID, abs_name),
        };
        if store.resolve_path(dname, parent).is_ok() {
            mkdir_ok = true;
        } else if store.mkdir(dname, parent).is_ok() {
            mkdir_ok = true;
        }
    }
    vfs_unlock();
    if ctx.pid > 1 {
        print(b"MKDIR: ");
        print(abs_name);
        print(if mkdir_ok { b" OK\n" } else { b" FAIL\n" });
    }
    reply_val(ctx.ep_cap, if mkdir_ok { 0 } else { -ENOSPC });
}

/// SYS_PIPE2 (293): pipe with flags.
pub(crate) fn sys_pipe2(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let pipefd_ptr = msg.regs[0];
    let flags = msg.regs[1] as u32;
    let mut rfd = None;
    let mut wfd = None;
    for i in 3..GRP_MAX_FDS {
        if ctx.child_fds[i] == 0 {
            if rfd.is_none() { rfd = Some(i); }
            else if wfd.is_none() { wfd = Some(i); break; }
        }
    }
    if let (Some(r), Some(w)) = (rfd, wfd) {
        if let Some(pipe_id) = pipe_alloc() {
            ctx.child_fds[r] = 10;
            ctx.child_fds[w] = 11;
            ctx.sock_conn_id[r] = pipe_id as u32;
            ctx.sock_conn_id[w] = pipe_id as u32;
            // Set close-on-exec if O_CLOEXEC requested
            if flags & O_CLOEXEC != 0 {
                if r < 128 { *ctx.fd_cloexec |= 1u128 << r; }
                if w < 128 { *ctx.fd_cloexec |= 1u128 << w; }
            }
            unsafe {
                *(pipefd_ptr as *mut i32) = r as i32;
                *((pipefd_ptr + 4) as *mut i32) = w as i32;
            }
            reply_val(ctx.ep_cap, 0);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
    } else { reply_val(ctx.ep_cap, -EMFILE); }
}

/// SYS_PWRITE64 (18): write at offset (VFS).
pub(crate) fn sys_pwrite64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf = msg.regs[1];
    let count = msg.regs[2] as usize;
    let offset = msg.regs[3] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        let mut done = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let oid = ctx.vfs_files[s][0];
                let data = unsafe { core::slice::from_raw_parts(buf as *const u8, count.min(4096)) };
                vfs_lock();
                let ok = unsafe { shared_store() }
                    .and_then(|store| store.write_obj_range(oid, offset, data).ok())
                    .is_some();
                vfs_unlock();
                if ok {
                    let new_end = (offset + data.len()) as u64;
                    if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                    reply_val(ctx.ep_cap, data.len() as i64);
                } else { reply_val(ctx.ep_cap, -EIO); }
                done = true; break;
            }
        }
        if !done { reply_val(ctx.ep_cap, -EBADF); }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// SYS_READLINK (89): read symbolic link (/proc/self/exe).
pub(crate) fn sys_readlink(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let buf = msg.regs[1];
    let bufsiz = msg.regs[2] as usize;
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    let name = &path[..plen];
    if name == b"/proc/self/exe" {
        let target = b"/bin/program";
        let n = target.len().min(bufsiz);
        unsafe { core::ptr::copy_nonoverlapping(target.as_ptr(), buf as *mut u8, n); }
        reply_val(ctx.ep_cap, n as i64);
    } else { reply_val(ctx.ep_cap, -EINVAL); }
}

/// SYS_DUP3 (292): dup with O_CLOEXEC.
pub(crate) fn sys_dup3(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let oldfd = msg.regs[0] as usize;
    let newfd = msg.regs[1] as usize;
    let flags = msg.regs[2] as u32;
    if oldfd >= GRP_MAX_FDS || ctx.child_fds[oldfd] == 0 || newfd >= GRP_MAX_FDS {
        reply_val(ctx.ep_cap, -EBADF);
    } else if oldfd == newfd {
        reply_val(ctx.ep_cap, -EINVAL);
    } else {
        // Decrement refcount for existing pipe at newfd
        if ctx.child_fds[newfd] != 0 {
            let nk = ctx.child_fds[newfd];
            let np = ctx.sock_conn_id[newfd] as usize;
            if nk == 11 && np < MAX_PIPES {
                let prev = PIPE_WRITE_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 {
                    print(b"PWC-SET dup3 P"); print_u64(ctx.pid as u64);
                    print(b" pipe="); print_u64(np as u64);
                    print(b"\n");
                    PIPE_WRITE_CLOSED[np].store(1, Ordering::Release);
                }
            } else if nk == 10 && np < MAX_PIPES {
                let prev = PIPE_READ_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 { PIPE_READ_CLOSED[np].store(1, Ordering::Release); }
            }
            ctx.child_fds[newfd] = 0;
        }
        // Increment refcount for pipe being dup'd
        let ok = ctx.child_fds[oldfd];
        let op = ctx.sock_conn_id[oldfd] as usize;
        if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
        else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
        ctx.child_fds[newfd] = ctx.child_fds[oldfd];
        ctx.sock_conn_id[newfd] = ctx.sock_conn_id[oldfd];
        ctx.sock_udp_local_port[newfd] = ctx.sock_udp_local_port[oldfd];
        ctx.sock_udp_remote_ip[newfd] = ctx.sock_udp_remote_ip[oldfd];
        ctx.sock_udp_remote_port[newfd] = ctx.sock_udp_remote_port[oldfd];
        // Set or clear FD_CLOEXEC based on flags
        if newfd < 128 {
            if flags & O_CLOEXEC != 0 {
                *ctx.fd_cloexec |= 1u128 << newfd;
            } else {
                *ctx.fd_cloexec &= !(1u128 << newfd);
            }
        }
        reply_val(ctx.ep_cap, newfd as i64);
    }
}

/// SYS_STATFS (137) / SYS_FSTATFS (138): filesystem info.
pub(crate) fn sys_statfs(ctx: &mut SyscallContext, msg: &IpcMsg, _syscall_nr: u64) {
    let buf = msg.regs[1];
    if buf != 0 {
        // struct statfs is 120 bytes on x86_64
        unsafe { core::ptr::write_bytes(buf as *mut u8, 0, 120); }
        unsafe {
            let p = buf as *mut u64;
            *p = 0xEF53; // f_type = EXT4_SUPER_MAGIC
            *p.add(1) = 4096; // f_bsize
            *p.add(2) = 1024 * 1024; // f_blocks
            *p.add(3) = 512 * 1024; // f_bfree
            *p.add(4) = 512 * 1024; // f_bavail
            *p.add(5) = 65536; // f_files
            *p.add(6) = 32768; // f_ffree
            // f_fsid = 0 (already zeroed)
            *p.add(9) = 255; // f_namelen
        }
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_CREAT (85): stub.
pub(crate) fn sys_creat(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    // Treat as open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)
    // Just return -ENOENT for now; programs should use openat
    reply_val(ctx.ep_cap, -ENOENT);
}

/// SYS_RMDIR (84): remove directory.
pub(crate) fn sys_rmdir(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
    let abs_name = &abs[..alen];
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        store.resolve_path(abs_name, ROOT_OID).ok()
            .and_then(|oid| store.delete(oid).ok())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
}

/// SYS_UNLINK (87): delete file from VFS.
pub(crate) fn sys_unlink(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    // Resolve relative paths against CWD
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
    let abs_name = &abs[..alen];
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        store.resolve_path(abs_name, ROOT_OID).ok()
            .and_then(|oid| store.delete(oid).ok())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
}

/// SYS_UNLINKAT (263): unlink with dirfd.
pub(crate) fn sys_unlinkat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let flags = msg.regs[2] as u32;
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    // Resolve relative paths against CWD
    let (path, plen) = if plen > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, plen)
    };
    let name = &path[..plen];
    if flags & 0x200 != 0 {
        // AT_REMOVEDIR -> rmdir
        reply_val(ctx.ep_cap, 0);
    } else {
        vfs_lock();
        let result = unsafe { shared_store() }.and_then(|store| {
            use sotos_objstore::ROOT_OID;
            store.resolve_path(name, ROOT_OID).ok()
                .and_then(|oid| store.delete(oid).ok())
        });
        vfs_unlock();
        reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
    }
}

/// SYS_RENAMEAT (264) / SYS_RENAMEAT2 (316): rename with dirfd.
pub(crate) fn sys_renameat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let oldpath_ptr = msg.regs[1];
    let newpath_ptr = msg.regs[3];
    let mut oldpath = [0u8; 128];
    let mut newpath = [0u8; 128];
    let olen = copy_guest_path(oldpath_ptr, &mut oldpath);
    let nlen = copy_guest_path(newpath_ptr, &mut newpath);
    // Resolve relative paths against CWD
    let (oldpath, olen) = if olen > 0 && oldpath[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &oldpath[..olen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (oldpath, olen) };
    let (newpath, nlen) = if nlen > 0 && newpath[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &newpath[..nlen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (newpath, nlen) };
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let oid = store.resolve_path(&oldpath[..olen], ROOT_OID).ok()?;
        // Find new parent and filename
        let mut last_slash = None;
        for (i, &b) in newpath[..nlen].iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, fname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else { store.resolve_path(&newpath[..pos], ROOT_OID).ok()? };
                (p, &newpath[pos+1..nlen])
            }
            None => (ROOT_OID, &newpath[..nlen]),
        };
        store.rename(oid, fname, parent).ok()
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
}

/// SYS_MKDIRAT (258): mkdir with dirfd.
pub(crate) fn sys_mkdirat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    // Resolve relative paths against CWD
    let (path, plen) = if plen > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, plen)
    };
    let name = &path[..plen];
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let mut last_slash = None;
        for (i, &b) in name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, dname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else { store.resolve_path(&name[..pos], ROOT_OID).ok()? };
                (p, &name[pos+1..plen])
            }
            None => (ROOT_OID, name),
        };
        // Check if already exists (like SYS_MKDIR does)
        if store.resolve_path(dname, parent).is_ok() {
            Some(0u64) // already exists
        } else {
            store.mkdir(dname, parent).ok()
        }
    });
    vfs_unlock();
    if ctx.pid > 1 {
        print(b"MKDIR: ");
        print(name);
        if result.is_some() { print(b" OK\n"); } else { print(b" FAIL\n"); }
    }
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOSPC });
}

/// SYS_PREADV (295): scatter read at offset.
pub(crate) fn sys_preadv(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    let offset = msg.regs[3];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF); return;
    }
    let mut total = 0i64;
    for i in 0..iovcnt.min(16) {
        let iov = unsafe { iov_ptr.wrapping_add((i * 16) as u64) };
        let base = unsafe { *(iov as *const u64) };
        let len = unsafe { *((iov + 8) as *const u64) } as usize;
        if base == 0 || len == 0 { continue; }
        // Read from VFS at offset + total
        if ctx.child_fds[fd] == 13 {
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    let oid = ctx.vfs_files[s][0];
                    let pos = (offset as usize) + (total as usize);
                    let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
                    vfs_lock();
                    let n = unsafe { shared_store() }
                        .and_then(|store| store.read_obj_range(oid, pos, dst).ok())
                        .unwrap_or(0);
                    vfs_unlock();
                    total += n as i64;
                    break;
                }
            }
        }
    }
    reply_val(ctx.ep_cap, total);
}

/// SYS_PWRITEV (296): scatter write at offset.
pub(crate) fn sys_pwritev(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    let offset = msg.regs[3];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF); return;
    }
    let mut total = 0i64;
    for i in 0..iovcnt.min(16) {
        let iov = unsafe { iov_ptr.wrapping_add((i * 16) as u64) };
        let base = unsafe { *(iov as *const u64) };
        let len = unsafe { *((iov + 8) as *const u64) } as usize;
        if base == 0 || len == 0 { continue; }
        if ctx.child_fds[fd] == 13 {
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    let oid = ctx.vfs_files[s][0];
                    let pos = (offset as usize) + (total as usize);
                    let data = unsafe { core::slice::from_raw_parts(base as *const u8, len.min(4096)) };
                    vfs_lock();
                    let ok = unsafe { shared_store() }
                        .and_then(|store| store.write_obj_range(oid, pos, data).ok())
                        .is_some();
                    vfs_unlock();
                    if ok { total += data.len() as i64; }
                    break;
                }
            }
        }
    }
    reply_val(ctx.ep_cap, total);
}

/// SYS_COPY_FILE_RANGE (326): stub.
pub(crate) fn sys_copy_file_range(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    // Stub: report unsupported, libc falls back to read+write
    reply_val(ctx.ep_cap, -ENOSYS);
}

/// SYS_SENDFILE (40): stub.
pub(crate) fn sys_sendfile(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    // Stub: report unsupported for now
    reply_val(ctx.ep_cap, -ENOSYS);
}

/// File metadata stubs: LINK, SYMLINK, FCHMOD, FCHOWN, LCHOWN, FLOCK, FALLOCATE, UTIMES,
/// LINKAT, SYMLINKAT, FCHMODAT, FCHOWNAT, UTIMENSAT, FUTIMESAT, MKNOD, MKNODAT.
pub(crate) fn sys_file_metadata_stubs(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_UMASK (95): return old umask.
pub(crate) fn sys_umask(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0o022);
}

/// SYS_FACCESSAT2 (439): like faccessat.
pub(crate) fn sys_faccessat2(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    // Resolve relative paths against CWD
    let (path, plen) = if plen > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, plen)
    };
    let name = &path[..plen];
    let is_dir = name.is_empty() || name == b"." || name == b"/"
        || name == b"/bin" || name == b"/lib" || name == b"/usr"
        || name == b"/etc" || name == b"/proc" || name == b"/tmp"
        || name == b"/sbin" || name == b"/var" || name == b"/home"
        || name == b"/usr/bin" || name == b"/usr/lib" || name == b"/usr/sbin";
    let is_virtual = name == b"/etc/passwd" || name == b"/etc/group"
        || name == b"/etc/resolv.conf" || name == b"/etc/hostname"
        || name == b"/dev/null" || name == b"/dev/zero"
        || name == b"/dev/urandom" || name == b"/dev/random";
    if is_dir || is_virtual {
        reply_val(ctx.ep_cap, 0);
    } else {
        // Check initrd
        let mut bstart = 0usize;
        for idx in 0..plen { if name[idx] == b'/' { bstart = idx + 1; } }
        let bname = &name[bstart..];
        let mut found = false;
        if !bname.is_empty() {
            if sys::initrd_read(bname.as_ptr() as u64, bname.len() as u64, 0, 0).is_ok() {
                found = true;
            }
        }
        if !found {
            vfs_lock();
            found = unsafe { shared_store() }
                .and_then(|store| store.resolve_path(name, sotos_objstore::ROOT_OID).ok())
                .is_some();
            vfs_unlock();
        }
        reply_val(ctx.ep_cap, if found { 0 } else { -ENOENT });
    }
}

/// SYS_CHDIR (80): change working directory.
pub(crate) fn sys_chdir(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = copy_guest_path(path_ptr, &mut path);
    let name = &path[..plen];
    // Resolve relative path against current CWD
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, name, &mut abs);
    let abs_name = &abs[..alen];
    // Check if target is a known directory (root, well-known, or VFS dir)
    let is_root = alen == 1 && abs[0] == b'/';
    let is_well_known = abs_name == b"/tmp" || abs_name == b"/home"
        || abs_name == b"/var" || abs_name == b"/usr"
        || abs_name == b"/bin" || abs_name == b"/lib"
        || abs_name == b"/lib64" || abs_name == b"/sbin"
        || abs_name == b"/etc" || abs_name == b"/proc"
        || abs_name == b"/usr/bin" || abs_name == b"/usr/lib"
        || abs_name == b"/usr/sbin" || abs_name == b"/usr/share";
    let vfs_ok = if !is_root && !is_well_known {
        vfs_lock();
        let ok = unsafe { shared_store() }.and_then(|store| {
            store.resolve_path(abs_name, sotos_objstore::ROOT_OID).ok()
        }).is_some();
        vfs_unlock();
        ok
    } else { false };
    if is_root || is_well_known || vfs_ok {
        // Update CWD
        let copy_len = alen.min(GRP_CWD_MAX - 1);
        ctx.cwd[..copy_len].copy_from_slice(&abs[..copy_len]);
        ctx.cwd[copy_len] = 0;
        // Remove trailing slash (except for root "/")
        if copy_len > 1 && ctx.cwd[copy_len - 1] == b'/' {
            ctx.cwd[copy_len - 1] = 0;
        }
        reply_val(ctx.ep_cap, 0);
    } else {
        reply_val(ctx.ep_cap, -ENOENT);
    }
}

