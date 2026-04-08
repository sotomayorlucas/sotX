// ---------------------------------------------------------------------------
// fs_initrd.rs — Initrd file operations: read, readv, close, pread64
// Extracted from fs.rs
// ---------------------------------------------------------------------------

use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use crate::exec::reply_val;
use crate::fd::*;
use crate::syscalls::context::SyscallContext;

/// Handle sys_read for initrd files (kind=12).
pub(crate) fn read_initrd(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let mut found = false;
    for s in 0..GRP_MAX_INITRD {
        if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
            let data_base = ctx.initrd_files[s][0];
            let file_size = ctx.initrd_files[s][1];
            let pos = ctx.initrd_files[s][2];
            let avail = if pos < file_size { file_size - pos } else { 0 };
            let to_read = (len as u64).min(avail) as usize;
            if to_read > 0 {
                let src = unsafe { core::slice::from_raw_parts((data_base + pos) as *const u8, to_read) };
                ctx.guest_write(buf_ptr, src);
                ctx.initrd_files[s][2] = pos + to_read as u64;
            }
            reply_val(ctx.ep_cap, to_read as i64);
            found = true;
            break;
        }
    }
    if !found { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle readv for initrd files (kind=12).
pub(crate) fn readv_initrd(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
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
                let mut iov_buf = [0u8; 16];
                ctx.guest_read(entry, &mut iov_buf);
                let base = u64::from_le_bytes(iov_buf[0..8].try_into().expect("invariant: 8-byte slice"));
                let len = u64::from_le_bytes(iov_buf[8..16].try_into().expect("invariant: 8-byte slice")) as usize;
                if base == 0 || len == 0 { continue; }
                let avail = if pos < file_size { (file_size - pos) as usize } else { 0 };
                let to_read = len.min(avail);
                if to_read > 0 {
                    let src = unsafe { core::slice::from_raw_parts((data_base + pos) as *const u8, to_read) };
                    ctx.guest_write(base, src);
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
}

/// Handle pread64 for initrd files (kind=12).
pub(crate) fn pread64_initrd(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, count: usize, off: u64) {
    let mut found = false;
    for s in 0..GRP_MAX_INITRD {
        if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
            let data_base = ctx.initrd_files[s][0];
            let file_size = ctx.initrd_files[s][1];
            let avail = if off < file_size { (file_size - off) as usize } else { 0 };
            let to_read = count.min(avail);
            if to_read > 0 {
                let src = unsafe { core::slice::from_raw_parts((data_base + off) as *const u8, to_read) };
                ctx.guest_write(buf_ptr, src);
            }
            reply_val(ctx.ep_cap, to_read as i64);
            found = true;
            break;
        }
    }
    if !found { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle close for initrd files (kind=12).
pub(crate) fn close_initrd(ctx: &mut SyscallContext, fd: usize) {
    for s in 0..GRP_MAX_INITRD {
        if ctx.initrd_files[s][3] == fd as u64 {
            ctx.initrd_files[s][3] = u64::MAX; // mark FD closed but data alive
            break;
        }
    }
}
