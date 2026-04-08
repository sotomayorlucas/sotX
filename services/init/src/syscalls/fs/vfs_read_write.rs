//! VFS read/write operations: read/write/close for VFS files (kind=13),
//! TCP/UDP sockets (kind=16/17), virtual/procfs files (kind=15), pread64,
//! pwrite64, readv/writev, preadv/pwritev, sendfile, copy_file_range.

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::fd::*;
use crate::{NET_EP_CAP, vfs_lock, vfs_unlock, shared_store};
use crate::net::{NET_CMD_TCP_SEND, NET_CMD_TCP_RECV, NET_CMD_TCP_CLOSE,
                 NET_CMD_UDP_SENDTO, NET_CMD_UDP_RECV};
use crate::framebuffer::{print, print_u64};
use crate::syscalls::context::SyscallContext;

/// Handle sys_read for VFS file (kind=13).
pub(crate) fn read_vfs(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let mut found = false;
    for s in 0..GRP_MAX_VFS {
        if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
            let oid = ctx.vfs_files[s][0];
            let pos = ctx.vfs_files[s][2] as usize;
            let safe_len = len.min(4096);
            let mut local_buf = [0u8; 4096];
            let dst = &mut local_buf[..safe_len];
            vfs_lock();
            let result = unsafe { shared_store() }
                .and_then(|store| store.read_obj_range(oid, pos, dst).ok());
            vfs_unlock();
            match result {
                Some(n) => {
                    ctx.guest_write(buf_ptr, &local_buf[..n]);
                    ctx.vfs_files[s][2] += n as u64;
                    reply_val(ctx.ep_cap, n as i64);
                }
                None => reply_val(ctx.ep_cap, -EIO),
            }
            found = true;
            break;
        }
    }
    if !found { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle sys_read for virtual/procfs file (kind=15).
pub(crate) fn read_virtual(ctx: &mut SyscallContext, buf_ptr: u64, len: usize) {
    let avail = if *ctx.dir_pos < *ctx.dir_len { *ctx.dir_len - *ctx.dir_pos } else { 0 };
    let to_read = len.min(avail);
    if to_read > 0 {
        ctx.guest_write(buf_ptr, &ctx.dir_buf[*ctx.dir_pos..*ctx.dir_pos + to_read]);
        *ctx.dir_pos += to_read;
    }
    reply_val(ctx.ep_cap, to_read as i64);
}

/// Handle sys_read for TCP socket (kind=16).
pub(crate) fn read_tcp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let conn_id = ctx.sock_conn_id[fd] as u64;
    let max_read = len.min(32768);
    let mut total = 0usize;
    let mut empty_retries = 0u32;
    let mut saw_eof = false;

    while total < max_read && empty_retries < 50000 {
        let want = (max_read - total).min(4096) as u64;
        let req = IpcMsg {
            tag: NET_CMD_TCP_RECV,
            regs: [conn_id, 64, 0, want, 0, 0, 0, 0],
        };
        match sys::call_timeout(net_cap, &req, 200) {
            Ok(resp) => {
                let first_n = resp.tag as usize;
                if first_n == 0xFFFE {
                    saw_eof = true; break;
                }
                if first_n == 0 {
                    if total > 0 {
                        break;
                    }
                    empty_retries += 1;
                    sys::yield_now();
                    continue;
                }
                let actual_first = first_n.min(64);
                let src = unsafe {
                    core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, actual_first)
                };
                ctx.guest_write(buf_ptr + total as u64, src);
                total += actual_first;
                empty_retries = 0;

                let mut buf_offset = actual_first;
                while total < max_read && buf_offset < 4096 {
                    let cont_req = IpcMsg {
                        tag: NET_CMD_TCP_RECV,
                        regs: [conn_id, 64, buf_offset as u64, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &cont_req, 100) {
                        Ok(cont_resp) => {
                            let cn = cont_resp.tag as usize;
                            if cn == 0 || cn == 0xFFFE { break; }
                            let actual_cn = cn.min(64);
                            let cont_src = unsafe {
                                core::slice::from_raw_parts(&cont_resp.regs[0] as *const u64 as *const u8, actual_cn)
                            };
                            ctx.guest_write(buf_ptr + total as u64, cont_src);
                            total += actual_cn;
                            buf_offset += actual_cn;
                            if actual_cn < 64 { break; }
                        }
                        Err(_) => break,
                    }
                }
                if first_n < 64 { break; }
            }
            Err(_) => {
                if total > 0 { break; }
                empty_retries += 1;
                sys::yield_now();
            }
        }
    }
    if total > 0 {
        reply_val(ctx.ep_cap, total as i64);
    } else if saw_eof {
        reply_val(ctx.ep_cap, 0);
    } else {
        reply_val(ctx.ep_cap, -EAGAIN);
    }
}

/// Handle sys_read for UDP socket (kind=17).
pub(crate) fn read_udp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
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
                let n = resp.tag as usize;
                if n > 0 && n <= recv_len {
                    let src = unsafe {
                        core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, n)
                    };
                    ctx.guest_write(buf_ptr, src);
                }
                reply_val(ctx.ep_cap, n as i64);
            }
            Err(_) => reply_val(ctx.ep_cap, 0),
        }
    }
}

/// Handle sys_write for VFS file (kind=13).
pub(crate) fn write_vfs(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let mut found = false;
    for s in 0..GRP_MAX_VFS {
        if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
            let oid = ctx.vfs_files[s][0];
            let pos = ctx.vfs_files[s][2] as usize;
            let safe_len = len.min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(buf_ptr, &mut local_buf[..safe_len]);
            let data = &local_buf[..safe_len];
            vfs_lock();
            let result = unsafe { shared_store() }
                .and_then(|store| store.write_obj_range(oid, pos, data).ok());
            vfs_unlock();
            match result {
                Some(_) => {
                    ctx.vfs_files[s][2] += safe_len as u64;
                    let new_end = ctx.vfs_files[s][2];
                    if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                    trace!(Debug, FS, {
                        print(b"VFS-W P"); print_u64(ctx.pid as u64);
                        print(b" fd="); print_u64(fd as u64);
                        print(b" oid=0x"); crate::framebuffer::print_hex64(oid);
                        print(b" pos="); print_u64(pos as u64);
                        print(b" len="); print_u64(safe_len as u64);
                    });
                    reply_val(ctx.ep_cap, safe_len as i64);
                }
                None => {
                    trace!(Error, FS, {
                        print(b"VFS-W-FAIL P"); print_u64(ctx.pid as u64);
                        print(b" fd="); print_u64(fd as u64);
                        print(b" oid=0x"); crate::framebuffer::print_hex64(oid);
                    });
                    reply_val(ctx.ep_cap, -EIO);
                }
            }
            found = true;
            break;
        }
    }
    if !found {
        trace!(Error, FS, {
            print(b"VFS-W-NOFD P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
        });
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// Handle sys_write for TCP socket (kind=16).
pub(crate) fn write_tcp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
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
        let mut data = [0u8; 40];
        ctx.guest_read(buf_ptr + off as u64, &mut data[..chunk]);
        unsafe {
            let dst = &mut req.regs[3] as *mut u64 as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, chunk);
        }
        match sys::call_timeout(net_cap, &req, 500) {
            Ok(resp) => {
                let n = resp.regs[0] as i64;
                if n <= 0 {
                    if total_sent == 0 {
                        trace!(Error, FS, {
                            print(b"TCP-SEND-FAIL fd=");
                            print_u64(fd as u64);
                            print(b" conn=");
                            print_u64(conn_id);
                            print(b" n=");
                            print_u64(resp.regs[0]);
                        });
                    }
                    break;
                }
                let n = n as usize;
                total_sent += n;
                off += n;
            }
            Err(_) => {
                if total_sent == 0 {
                    trace!(Error, FS, {
                        print(b"TCP-SEND-IPC-ERR conn=");
                        print_u64(conn_id);
                    });
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

/// Handle sys_write for UDP socket (kind=17).
pub(crate) fn write_udp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let remote_ip = ctx.sock_udp_remote_ip[fd];
    let remote_port = ctx.sock_udp_remote_port[fd];
    let src_port = ctx.sock_udp_local_port[fd];
    if net_cap == 0 || remote_ip == 0 {
        reply_val(ctx.ep_cap, -EDESTADDRREQ);
    } else {
        let send_len = len.min(56);
        let packed_tag = NET_CMD_UDP_SENDTO | ((send_len as u64) << 16);
        let packed_r0 = (remote_ip as u64)
            | ((remote_port as u64) << 32)
            | ((src_port as u64) << 48);
        let mut req = sotos_common::IpcMsg {
            tag: packed_tag,
            regs: [packed_r0, 0, 0, 0, 0, 0, 0, 0],
        };
        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
        unsafe {
            let dst = &mut req.regs[1] as *mut u64 as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
        }
        match sys::call_timeout(net_cap, &req, 500) {
            Ok(resp) => reply_val(ctx.ep_cap, resp.regs[0] as i64),
            Err(_) => reply_val(ctx.ep_cap, -EIO),
        }
    }
}

/// Handle close for VFS file (kind=13) or directory (kind=14).
pub(crate) fn close_vfs(ctx: &mut SyscallContext, fd: usize) {
    for s in 0..GRP_MAX_VFS {
        if ctx.vfs_files[s][3] == fd as u64 { ctx.vfs_files[s] = [0; 4]; break; }
    }
}

/// Handle close for TCP socket (kind=16).
pub(crate) fn close_tcp(ctx: &mut SyscallContext, fd: usize) {
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
}

/// SYS_PREAD64 (17): pread at offset.
pub(crate) fn sys_pread64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let count = msg.regs[2] as usize;
    let off = msg.regs[3];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        super::fs_initrd::pread64_initrd(ctx, fd, buf_ptr, count, off);
    } else if ctx.child_fds[fd] == 13 {
        let mut found = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let oid = ctx.vfs_files[s][0];
                let safe_count = count.min(4096);
                let mut local_buf = [0u8; 4096];
                let dst = &mut local_buf[..safe_count];
                vfs_lock();
                let result = unsafe { shared_store() }
                    .and_then(|store| store.read_obj_range(oid, off as usize, dst).ok());
                vfs_unlock();
                match result {
                    Some(n) => {
                        ctx.guest_write(buf_ptr, &local_buf[..n]);
                        reply_val(ctx.ep_cap, n as i64);
                    }
                    None => reply_val(ctx.ep_cap, -EIO),
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

/// Readv for VFS files (kind=13).
pub(crate) fn readv_vfs(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
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
                let base = ctx.guest_read_u64(entry);
                let len = ctx.guest_read_u64(entry + 8) as usize;
                if base == 0 || len == 0 { continue; }
                let safe_len = len.min(4096);
                let mut local_buf = [0u8; 4096];
                let dst = &mut local_buf[..safe_len];
                vfs_lock();
                let n = unsafe { shared_store() }
                    .and_then(|store| store.read_obj_range(oid, pos, dst).ok())
                    .unwrap_or(0);
                vfs_unlock();
                if n > 0 { ctx.guest_write(base, &local_buf[..n]); }
                pos += n;
                total += n;
                if n < len { break; }
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
}

/// Readv for TCP socket (kind=16).
pub(crate) fn readv_tcp(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let conn_id = ctx.sock_conn_id[fd] as u64;
    let mut total = 0usize;
    let mut saw_eof = false;
    let cnt = iovcnt.min(16);
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let mut off = 0usize;
        let mut empty = 0u32;
        while off < ilen && !saw_eof {
            let chunk = (ilen - off).min(64);
            let want = (ilen - off).min(4096) as u64;
            let req = sotos_common::IpcMsg {
                tag: NET_CMD_TCP_RECV,
                regs: [conn_id, chunk as u64, 0, want, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 200) {
                Ok(resp) => {
                    let n = resp.tag as usize;
                    if n == 0xFFFE { saw_eof = true; break; }
                    if n > 0 && n <= 64 {
                        let src = unsafe {
                            core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, n)
                        };
                        ctx.guest_write(base + off as u64, src);
                        off += n;
                        total += n;
                        empty = 0;
                        let mut buf_off = n;
                        while off < ilen && buf_off < 4096 {
                            let cr = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_RECV,
                                regs: [conn_id, 64, buf_off as u64, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &cr, 100) {
                                Ok(r) => {
                                    let cn = r.tag as usize;
                                    if cn == 0 || cn == 0xFFFE { break; }
                                    let an = cn.min(64);
                                    let cs = unsafe {
                                        core::slice::from_raw_parts(&r.regs[0] as *const u64 as *const u8, an)
                                    };
                                    ctx.guest_write(base + off as u64, cs);
                                    off += an;
                                    total += an;
                                    buf_off += an;
                                    if an < 64 { break; }
                                }
                                Err(_) => break,
                            }
                        }
                        if n < 64 { break; }
                    } else {
                        if total > 0 || off > 0 { break; }
                        empty += 1;
                        if empty > 5000 { break; }
                        sys::yield_now();
                    }
                }
                Err(_) => {
                    if total > 0 || off > 0 { break; }
                    empty += 1;
                    if empty > 5000 { break; }
                    sys::yield_now();
                }
            }
        }
        if off == 0 && !saw_eof { break; }
    }
    if total > 0 {
        reply_val(ctx.ep_cap, total as i64);
    } else if saw_eof {
        reply_val(ctx.ep_cap, 0);
    } else {
        reply_val(ctx.ep_cap, -EAGAIN);
    }
}

/// Readv for virtual file (kind=15).
pub(crate) fn readv_virtual(ctx: &mut SyscallContext, iov_ptr: u64, iovcnt: usize) {
    let cnt = iovcnt.min(16);
    let mut total = 0usize;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let avail = if *ctx.dir_pos < *ctx.dir_len { *ctx.dir_len - *ctx.dir_pos } else { 0 };
        let to_read = ilen.min(avail);
        if to_read > 0 {
            ctx.guest_write(base, &ctx.dir_buf[*ctx.dir_pos..*ctx.dir_pos + to_read]);
            *ctx.dir_pos += to_read;
            total += to_read;
        }
        if to_read < ilen { break; }
    }
    reply_val(ctx.ep_cap, total as i64);
}

/// Writev for /dev/null (kind=8).
pub(crate) fn writev_devnull(ctx: &mut SyscallContext, iov_ptr: u64, iovcnt: usize) {
    let mut total: usize = 0;
    let cnt = iovcnt.min(16);
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        if entry + 16 > 0x0000_8000_0000_0000 { break; }
        let len = unsafe { *((entry + 8) as *const u64) } as usize;
        total += len;
    }
    reply_val(ctx.ep_cap, total as i64);
}

/// Writev for TCP socket (kind=16).
pub(crate) fn writev_tcp(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let conn_id = ctx.sock_conn_id[fd] as u64;
    let cnt = iovcnt.min(16);
    let mut total_sent = 0usize;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        if entry + 16 > 0x0000_8000_0000_0000 { break; }
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let mut off = 0;
        while off < ilen {
            let chunk = (ilen - off).min(40);
            let mut req = sotos_common::IpcMsg {
                tag: NET_CMD_TCP_SEND,
                regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
            };
            let mut data = [0u8; 40];
            ctx.guest_read(base + off as u64, &mut data[..chunk]);
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
}

/// Writev for VFS file (kind=13).
pub(crate) fn writev_vfs(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let cnt = iovcnt.min(16);
    let mut total: usize = 0;
    let mut ok = true;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        if entry + 16 > 0x0000_8000_0000_0000 { break; }
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let safe_ilen = ilen.min(4096);
        let mut local_buf = [0u8; 4096];
        ctx.guest_read(base, &mut local_buf[..safe_ilen]);
        let data = &local_buf[..safe_ilen];
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
                        ctx.vfs_files[s][2] += safe_ilen as u64;
                        let new_end = ctx.vfs_files[s][2];
                        if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                        total += safe_ilen;
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
}

/// SYS_PREADV (295).
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

/// SYS_PWRITEV (296).
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

/// SYS_PWRITE64 (18).
pub(crate) fn sys_pwrite64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf = msg.regs[1];
    let count = msg.regs[2] as usize;
    let offset = msg.regs[3] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        let mut done = false;
        let copy_len = count.min(4096);
        let mut local_buf = [0u8; 4096];
        ctx.guest_read(buf, &mut local_buf[..copy_len]);
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let oid = ctx.vfs_files[s][0];
                let data = &local_buf[..copy_len];
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

/// SYS_COPY_FILE_RANGE (326): stub.
pub(crate) fn sys_copy_file_range(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -ENOSYS);
}

/// SYS_SENDFILE (40).
pub(crate) fn sys_sendfile(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -ENOSYS);
}

