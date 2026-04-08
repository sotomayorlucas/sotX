// ---------------------------------------------------------------------------
// File/IO syscalls: read, write, open, close, stat, lseek, ioctl, etc.
// Thin dispatch layer — delegates to submodules by FD kind.
// Extracted from child_handler.rs, split into submodules for maintainability.
// ---------------------------------------------------------------------------

pub(crate) mod fs_vfs;
pub(crate) mod vfs_read_write;
pub(crate) mod vfs_metadata;
pub(crate) mod vfs_open;
pub(crate) mod vfs_path;
pub(crate) mod vfs_delete;
pub(crate) mod fs_pipe;
pub(crate) mod fs_special;
pub(crate) mod fs_dir;
pub(crate) mod fs_stdio;
pub(crate) mod fs_initrd;
pub(crate) mod fs_fd;

use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use crate::exec::reply_val;
use crate::fd::*;
use super::context::SyscallContext;

// ---------------------------------------------------------------------------
// Shared helper used by multiple submodules
// ---------------------------------------------------------------------------

/// Store the resolved directory path for fchdir() support.
/// Allocates a slot in DIR_FD_PATHS and stores the slot index in sock_conn_id[fd].
pub(crate) fn dir_store_path(ctx: &mut SyscallContext, fd: usize, name: &[u8]) {
    let grp_base = ctx.pid.saturating_sub(1) * 8;
    for slot in 0..8usize {
        let gslot = grp_base + slot;
        if gslot >= crate::fd::MAX_DIR_SLOTS { break; }
        if unsafe { crate::fd::DIR_FD_PATHS[gslot][0] } == 0 || ctx.sock_conn_id[fd] as usize == slot {
            let resolved = if name == b"." {
                let mut clen = 0;
                while clen < GRP_CWD_MAX && ctx.cwd[clen] != 0 { clen += 1; }
                unsafe {
                    crate::fd::DIR_FD_PATHS[gslot] = [0u8; 128];
                    let copy = clen.min(127);
                    crate::fd::DIR_FD_PATHS[gslot][..copy].copy_from_slice(&ctx.cwd[..copy]);
                }
                true
            } else if !name.is_empty() && name[0] == b'/' {
                unsafe {
                    crate::fd::DIR_FD_PATHS[gslot] = [0u8; 128];
                    let copy = name.len().min(127);
                    crate::fd::DIR_FD_PATHS[gslot][..copy].copy_from_slice(&name[..copy]);
                }
                true
            } else {
                let mut abs = [0u8; 256];
                let alen = resolve_with_cwd(ctx.cwd, name, &mut abs);
                unsafe {
                    crate::fd::DIR_FD_PATHS[gslot] = [0u8; 128];
                    let copy = alen.min(127);
                    crate::fd::DIR_FD_PATHS[gslot][..copy].copy_from_slice(&abs[..copy]);
                }
                true
            };
            if resolved {
                ctx.sock_conn_id[fd] = slot as u32;
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// SYS_READ dispatch
// ---------------------------------------------------------------------------

pub(crate) fn sys_read(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }
    match ctx.child_fds[fd] {
        1  => fs_stdio::read_stdin(ctx, buf_ptr, len),
        9  => fs_special::read_dev_zero(ctx, buf_ptr, len),
        20 => fs_special::read_dev_urandom(ctx, buf_ptr, len),
        8  => { // /dev/null: block on read (like real Linux), don't return 0 in a spin
            sotos_common::sys::notify_wait(0); // yield instead of busy-loop
            reply_val(ctx.ep_cap, 0);
        }
        22 => fs_special::read_eventfd(ctx, fd, buf_ptr, len),
        23 => fs_special::read_timerfd(ctx, fd, buf_ptr, len),
        25 => fs_special::read_memfd(ctx, fd, buf_ptr, len),
        12 => fs_initrd::read_initrd(ctx, fd, buf_ptr, len),
        13 => fs_vfs::read_vfs(ctx, fd, buf_ptr, len),
        15 => fs_vfs::read_virtual(ctx, buf_ptr, len),
        16 => fs_vfs::read_tcp(ctx, fd, buf_ptr, len),
        17 => fs_vfs::read_udp(ctx, fd, buf_ptr, len),
        10 => fs_pipe::read_pipe(ctx, fd, buf_ptr, len),
        27 | 28 => fs_pipe::read_unix_socket(ctx, fd, buf_ptr, len),
        31 | 32 => {
            let device = if ctx.child_fds[fd] == 31 { 0u8 } else { 1u8 };
            let ret = crate::evdev::evdev_read(ctx, fd, buf_ptr, len as u64, device);
            reply_val(ctx.ep_cap, ret);
        }
        30 => {
            let ret = crate::drm::drm_read(ctx, buf_ptr, len);
            reply_val(ctx.ep_cap, ret);
        }
        33 => { // seatd socket
            let ret = crate::seatd::seatd_read(ctx, fd, buf_ptr, len as u64);
            reply_val(ctx.ep_cap, ret);
        }
        34 => reply_val(ctx.ep_cap, -11), // netlink dummy: -EAGAIN
        _  => reply_val(ctx.ep_cap, -EBADF),
    }
}

// ---------------------------------------------------------------------------
// SYS_WRITE dispatch
// ---------------------------------------------------------------------------

pub(crate) fn sys_write(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }
    match ctx.child_fds[fd] {
        2  => fs_stdio::write_stdout(ctx, msg, buf_ptr, len),
        8  => reply_val(ctx.ep_cap, len as i64), // /dev/null: discard
        22 => fs_special::write_eventfd(ctx, fd, buf_ptr, len),
        25 => fs_special::write_memfd(ctx, fd, buf_ptr, len),
        16 => fs_vfs::write_tcp(ctx, fd, buf_ptr, len),
        17 => fs_vfs::write_udp(ctx, fd, buf_ptr, len),
        11 => fs_pipe::write_pipe(ctx, fd, buf_ptr, len),
        13 => fs_vfs::write_vfs(ctx, fd, buf_ptr, len),
        27 | 28 => fs_pipe::write_unix_socket(ctx, fd, buf_ptr, len),
        33 => { // seatd socket
            let ret = crate::seatd::seatd_write(ctx, fd, buf_ptr, len as u64);
            reply_val(ctx.ep_cap, ret);
        }
        _  => reply_val(ctx.ep_cap, -EBADF),
    }
}

// ---------------------------------------------------------------------------
// SYS_READV dispatch
// ---------------------------------------------------------------------------

pub(crate) fn sys_readv(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 1 {
        fs_stdio::readv_stdin(ctx, iov_ptr, iovcnt);
    } else if ctx.child_fds[fd] == 12 {
        fs_initrd::readv_initrd(ctx, fd, iov_ptr, iovcnt);
    } else if ctx.child_fds[fd] == 13 {
        fs_vfs::readv_vfs(ctx, fd, iov_ptr, iovcnt);
    } else if ctx.child_fds[fd] == 16 {
        fs_vfs::readv_tcp(ctx, fd, iov_ptr, iovcnt);
    } else if ctx.child_fds[fd] == 10 {
        fs_pipe::readv_pipe(ctx, fd, iov_ptr, iovcnt);
    } else if ctx.child_fds[fd] == 15 {
        fs_vfs::readv_virtual(ctx, iov_ptr, iovcnt);
    } else if ctx.child_fds[fd] == 2 {
        reply_val(ctx.ep_cap, -EBADF); // stdout/stderr readv -> -EBADF
    } else {
        reply_val(ctx.ep_cap, 0); // other FD types: EOF
    }
}

// ---------------------------------------------------------------------------
// SYS_WRITEV dispatch
// ---------------------------------------------------------------------------

pub(crate) fn sys_writev(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 2 {
        fs_stdio::writev_stdout(ctx, msg, iov_ptr, iovcnt);
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 8 {
        fs_vfs::writev_devnull(ctx, iov_ptr, iovcnt);
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 16 {
        fs_vfs::writev_tcp(ctx, fd, iov_ptr, iovcnt);
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        fs_vfs::writev_vfs(ctx, fd, iov_ptr, iovcnt);
    } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 11 {
        fs_pipe::writev_pipe(ctx, fd, iov_ptr, iovcnt);
    } else if fd < GRP_MAX_FDS && (ctx.child_fds[fd] == 27 || ctx.child_fds[fd] == 28) {
        fs_pipe::writev_unix_socket(ctx, fd, iov_ptr, iovcnt);
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

// ---------------------------------------------------------------------------
// Re-export all entry points so callers can use fs::sys_* as before
// ---------------------------------------------------------------------------

pub(crate) use fs_vfs::{
    sys_fstat, sys_stat, sys_lseek, sys_pread64, sys_open, sys_openat,
    sys_fstatat, sys_readlinkat, sys_readlink, sys_access, sys_fsync,
    sys_ftruncate, sys_rename, sys_statfs, sys_creat, sys_pwrite64,
    sys_fadvise64, sys_copy_file_range, sys_sendfile, sys_file_metadata_stubs,
    sys_umask, sys_faccessat2, sys_preadv, sys_pwritev,
    sys_unlink, sys_unlinkat, sys_renameat, sys_statx,
};

pub(crate) use fs_pipe::{sys_pipe, sys_pipe2};

pub(crate) use fs_dir::{
    sys_getdents64, sys_mkdir, sys_mkdirat, sys_rmdir,
    sys_getcwd, sys_chdir, sys_fchdir,
};

pub(crate) use fs_fd::{
    sys_close, sys_dup, sys_dup2, sys_dup3, sys_fcntl,
    close_fd_internal, close_cloexec_fds,
};

pub(crate) use fs_stdio::sys_ioctl;
