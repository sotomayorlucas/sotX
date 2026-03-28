// ---------------------------------------------------------------------------
// fs_special.rs — Special FD types: eventfd, timerfd, memfd, /dev/null,
//                 /dev/zero, /dev/urandom read/write/close
// Extracted from fs.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use crate::exec::{reply_val, rdtsc};
use crate::fd::*;
use crate::child_handler::fill_random;
use crate::syscalls::context::SyscallContext;

/// Handle sys_read for /dev/zero (kind=9).
pub(crate) fn read_dev_zero(ctx: &mut SyscallContext, buf_ptr: u64, len: usize) {
    let n = len.min(4096);
    if n > 0 {
        let zeros = [0u8; 4096];
        ctx.guest_write(buf_ptr, &zeros[..n]);
    }
    reply_val(ctx.ep_cap, n as i64);
}

/// Handle sys_read for /dev/urandom (kind=20).
pub(crate) fn read_dev_urandom(ctx: &mut SyscallContext, buf_ptr: u64, len: usize) {
    let n = len.min(4096);
    if n > 0 {
        let mut local_buf = [0u8; 4096];
        fill_random(&mut local_buf[..n]);
        ctx.guest_write(buf_ptr, &local_buf[..n]);
    }
    reply_val(ctx.ep_cap, n as i64);
}

/// Handle sys_read for eventfd (kind=22).
pub(crate) fn read_eventfd(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    if len < 8 { reply_val(ctx.ep_cap, -EINVAL); return; }
    if let Some(slot) = ctx.eventfd_slot_fd.iter().position(|&x| x == fd) {
        let val = ctx.eventfd_counter[slot];
        if val == 0 {
            reply_val(ctx.ep_cap, -EAGAIN);
        } else {
            ctx.guest_write(buf_ptr, &val.to_le_bytes());
            ctx.eventfd_counter[slot] = 0;
            reply_val(ctx.ep_cap, 8);
        }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle sys_read for timerfd (kind=23).
pub(crate) fn read_timerfd(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    if len < 8 { reply_val(ctx.ep_cap, -EINVAL); return; }
    if let Some(slot) = ctx.timerfd_slot_fd.iter().position(|&x| x == fd) {
        let now = rdtsc();
        let exp = ctx.timerfd_expiry_tsc[slot];
        if exp != 0 && now >= exp {
            let one: u64 = 1;
            ctx.guest_write(buf_ptr, &one.to_le_bytes());
            if ctx.timerfd_interval_ns[slot] != 0 {
                ctx.timerfd_expiry_tsc[slot] = now + ctx.timerfd_interval_ns[slot] * 2;
            } else {
                ctx.timerfd_expiry_tsc[slot] = 0;
            }
            reply_val(ctx.ep_cap, 8);
        } else {
            reply_val(ctx.ep_cap, -EAGAIN);
        }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle sys_read for memfd (kind=25).
pub(crate) fn read_memfd(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    if let Some(slot) = ctx.memfd_slot_fd.iter().position(|&x| x == fd) {
        let base = ctx.memfd_base[slot];
        let sz = ctx.memfd_size[slot];
        // Use vfs_files for offset tracking
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] == 0xFEFD {
                let offset = ctx.vfs_files[s][2];
                let avail = if offset < sz { sz - offset } else { 0 };
                let n = (len as u64).min(avail) as usize;
                if n > 0 {
                    let src = unsafe { core::slice::from_raw_parts((base + offset) as *const u8, n) };
                    ctx.guest_write(buf_ptr, src);
                    ctx.vfs_files[s][2] += n as u64;
                }
                reply_val(ctx.ep_cap, n as i64);
                break;
            }
        }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle sys_write for eventfd (kind=22).
pub(crate) fn write_eventfd(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    if len < 8 { reply_val(ctx.ep_cap, -EINVAL); return; }
    if let Some(slot) = ctx.eventfd_slot_fd.iter().position(|&x| x == fd) {
        let val = ctx.guest_read_u64(buf_ptr);
        ctx.eventfd_counter[slot] = ctx.eventfd_counter[slot].saturating_add(val);
        reply_val(ctx.ep_cap, 8);
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle sys_write for memfd (kind=25).
pub(crate) fn write_memfd(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    if let Some(slot) = ctx.memfd_slot_fd.iter().position(|&x| x == fd) {
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] == 0xFEFD {
                let offset = ctx.vfs_files[s][2] as usize;
                let cap = ctx.memfd_cap[slot] as usize;
                let n = len.min(cap.saturating_sub(offset));
                if n > 0 {
                    let base = ctx.memfd_base[slot];
                    let mut local_buf = [0u8; 4096];
                    let chunk = n.min(4096);
                    ctx.guest_read(buf_ptr, &mut local_buf[..chunk]);
                    unsafe { core::ptr::copy_nonoverlapping(local_buf.as_ptr(), (base + offset as u64) as *mut u8, chunk); }
                    ctx.vfs_files[s][2] += chunk as u64;
                    let new_end = ctx.vfs_files[s][2];
                    if new_end > ctx.memfd_size[slot] { ctx.memfd_size[slot] = new_end; }
                }
                reply_val(ctx.ep_cap, n as i64);
                break;
            }
        }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle close for eventfd (kind=22).
pub(crate) fn close_eventfd(ctx: &mut SyscallContext, fd: usize) {
    if let Some(slot) = ctx.eventfd_slot_fd.iter().position(|&x| x == fd) {
        ctx.eventfd_slot_fd[slot] = usize::MAX;
        ctx.eventfd_counter[slot] = 0;
    }
}

/// Handle close for timerfd (kind=23).
pub(crate) fn close_timerfd(ctx: &mut SyscallContext, fd: usize) {
    if let Some(slot) = ctx.timerfd_slot_fd.iter().position(|&x| x == fd) {
        ctx.timerfd_slot_fd[slot] = usize::MAX;
        ctx.timerfd_expiry_tsc[slot] = 0;
        ctx.timerfd_interval_ns[slot] = 0;
    }
}

/// Handle close for memfd (kind=25).
pub(crate) fn close_memfd(ctx: &mut SyscallContext, fd: usize) {
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
}
