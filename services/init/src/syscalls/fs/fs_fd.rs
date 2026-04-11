// ---------------------------------------------------------------------------
// fs_fd.rs — FD management: dup, dup2, dup3, fcntl, close_fd_internal,
//            close_cloexec_fds, dup_file_slots
// Extracted from fs.rs
// ---------------------------------------------------------------------------

use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::fd::*;
use crate::framebuffer::{print, print_u64};
use crate::syscalls::context::SyscallContext;

/// Duplicate VFS/initrd file tracking slots when dup'ing an fd.
pub(crate) fn dup_file_slots(ctx: &mut SyscallContext, oldfd: usize, newfd: usize) {
    let kind = ctx.child_fds[oldfd];
    if kind == 13 || kind == 14 {
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][0] != 0 && ctx.vfs_files[s][3] == oldfd as u64 {
                let oid = ctx.vfs_files[s][0];
                let size = ctx.vfs_files[s][1];
                let pos = ctx.vfs_files[s][2];
                for s2 in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s2][0] == 0 {
                        ctx.vfs_files[s2] = [oid, size, pos, newfd as u64];
                        break;
                    }
                }
                break;
            }
        }
    } else if kind == 12 {
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][0] != 0 && ctx.initrd_files[s][3] == oldfd as u64 {
                let data = ctx.initrd_files[s][0];
                let size = ctx.initrd_files[s][1];
                let pos = ctx.initrd_files[s][2];
                for s2 in 0..GRP_MAX_INITRD {
                    if ctx.initrd_files[s2][0] == 0 {
                        ctx.initrd_files[s2] = [data, size, pos, newfd as u64];
                        break;
                    }
                }
                break;
            }
        }
    }
}

/// Internal: close a single fd, cleaning up associated resources, without sending a reply.
/// Returns true if the fd was valid and closed.
pub(crate) fn close_fd_internal(ctx: &mut SyscallContext, fd: usize) -> bool {
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 { return false; }
    match ctx.child_fds[fd] {
        12 => super::fs_initrd::close_initrd(ctx, fd),
        13 | 14 => super::fs_vfs::close_vfs(ctx, fd),
        22 => super::fs_special::close_eventfd(ctx, fd),
        23 => super::fs_special::close_timerfd(ctx, fd),
        25 => super::fs_special::close_memfd(ctx, fd),
        16 => super::fs_vfs::close_tcp(ctx, fd),
        11 => super::fs_pipe::close_pipe_write(ctx, fd),
        10 => super::fs_pipe::close_pipe_read(ctx, fd),
        26 => super::fs_pipe::close_unix_listener(ctx, fd),
        27 | 28 => super::fs_pipe::close_unix_socket(ctx, fd),
        36 | 37 => super::fs_sotfs::close_sotfs_slot(fd),
        _ => {}
    }
    ctx.child_fds[fd] = 0;
    // Clear cloexec bit
    if fd < 128 { *ctx.fd_cloexec &= !(1u128 << fd); }
    // Auto-remove from epoll (Linux semantics: close() removes fd from all epoll instances)
    for i in 0..MAX_EPOLL_ENTRIES {
        if ctx.epoll_reg_fd[i] == fd as i32 {
            ctx.epoll_reg_fd[i] = -1;
            ctx.epoll_reg_events[i] = 0;
            ctx.epoll_reg_data[i] = 0;
        }
    }
    true
}

/// SYS_CLOSE (3): close fd, cleaning up associated resources.
pub(crate) fn sys_close(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    close_fd_internal(ctx, fd);
    reply_val(ctx.ep_cap, 0);
}

/// Close all fds marked with FD_CLOEXEC (called during execve).
pub(crate) fn close_cloexec_fds(ctx: &mut SyscallContext) {
    let mut bits = *ctx.fd_cloexec;
    while bits != 0 {
        let fd = bits.trailing_zeros() as usize;
        if fd >= 128 { break; }
        let k = ctx.child_fds[fd];
        trace!(Debug, FS, {
            print(b"CLOEXEC-CLOSE P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" kind="); print_u64(k as u64);
            if k == 10 || k == 11 {
                print(b" pipe="); print_u64(ctx.sock_conn_id[fd] as u64);
            }
        });
        close_fd_internal(ctx, fd);
        bits &= !(1u128 << fd);
    }
    // Clear orphaned initrd entries (fd == u64::MAX) inherited from forked parent.
    for s in 0..GRP_MAX_INITRD {
        if ctx.initrd_files[s][0] != 0 && ctx.initrd_files[s][3] == u64::MAX {
            ctx.initrd_files[s] = [0; 4];
        }
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
            let ok = ctx.child_fds[oldfd];
            let op = ctx.sock_conn_id[oldfd] as usize;
            if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
            else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
            if (ok == 27 || ok == 28) && op < crate::fd::MAX_UNIX_CONNS {
                crate::fd::UNIX_CONN_REFS[op].fetch_add(1, Ordering::AcqRel);
            }
            ctx.child_fds[nfd] = ctx.child_fds[oldfd];
            ctx.sock_conn_id[nfd] = ctx.sock_conn_id[oldfd];
            ctx.sock_udp_local_port[nfd] = ctx.sock_udp_local_port[oldfd];
            ctx.sock_udp_remote_ip[nfd] = ctx.sock_udp_remote_ip[oldfd];
            ctx.sock_udp_remote_port[nfd] = ctx.sock_udp_remote_port[oldfd];
            dup_file_slots(ctx, oldfd, nfd);
            if nfd < 128 { *ctx.fd_cloexec &= !(1u128 << nfd); }
            trace!(Debug, FS, {
                print(b"FD-DUP P"); print_u64(ctx.pid as u64);
                print(b" "); print_u64(oldfd as u64);
                print(b"->"); print_u64(nfd as u64);
                print(b" k="); print_u64(ok as u64);
                print(b" pipe="); print_u64(op as u64);
            });
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
        if newfd < GRP_MAX_FDS && ctx.child_fds[newfd] != 0 {
            let nk = ctx.child_fds[newfd];
            let np = ctx.sock_conn_id[newfd] as usize;
            if nk == 11 && np < MAX_PIPES {
                let prev = PIPE_WRITE_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 {
                    trace!(Debug, FS, {
                        print(b"PWC-SET dup2 P"); print_u64(ctx.pid as u64);
                        print(b" pipe="); print_u64(np as u64);
                    });
                    PIPE_WRITE_CLOSED[np].store(1, Ordering::Release);
                }
            } else if nk == 10 && np < MAX_PIPES {
                let prev = PIPE_READ_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 { PIPE_READ_CLOSED[np].store(1, Ordering::Release); }
            }
        }
        let ok = ctx.child_fds[oldfd];
        let op = ctx.sock_conn_id[oldfd] as usize;
        if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
        else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
        if (ok == 27 || ok == 28) && op < crate::fd::MAX_UNIX_CONNS {
            crate::fd::UNIX_CONN_REFS[op].fetch_add(1, Ordering::AcqRel);
        }
        for i in 0..MAX_EPOLL_ENTRIES {
            if ctx.epoll_reg_fd[i] == newfd as i32 {
                ctx.epoll_reg_fd[i] = -1;
                ctx.epoll_reg_events[i] = 0;
                ctx.epoll_reg_data[i] = 0;
            }
        }
        if ctx.child_fds[newfd] == 13 || ctx.child_fds[newfd] == 14 {
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == newfd as u64 { ctx.vfs_files[s] = [0; 4]; break; }
            }
        }
        let oldkind = ctx.child_fds[oldfd];
        if (newfd == 1 || newfd == 2) && oldkind == 8 {
            reply_val(ctx.ep_cap, newfd as i64);
            return;
        }
        ctx.child_fds[newfd] = ctx.child_fds[oldfd];
        ctx.sock_conn_id[newfd] = ctx.sock_conn_id[oldfd];
        ctx.sock_udp_local_port[newfd] = ctx.sock_udp_local_port[oldfd];
        ctx.sock_udp_remote_ip[newfd] = ctx.sock_udp_remote_ip[oldfd];
        ctx.sock_udp_remote_port[newfd] = ctx.sock_udp_remote_port[oldfd];
        dup_file_slots(ctx, oldfd, newfd);
        if newfd < 128 { *ctx.fd_cloexec &= !(1u128 << newfd); }
        trace!(Debug, FS, {
            let ok = ctx.child_fds[newfd];
            let op = ctx.sock_conn_id[newfd] as u64;
            print(b"FD-DUP2 P"); print_u64(ctx.pid as u64);
            print(b" "); print_u64(oldfd as u64);
            print(b"->"); print_u64(newfd as u64);
            print(b" k="); print_u64(ok as u64);
            print(b" pipe="); print_u64(op);
        });
        reply_val(ctx.ep_cap, newfd as i64);
    }
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
        if ctx.child_fds[newfd] != 0 {
            let nk = ctx.child_fds[newfd];
            let np = ctx.sock_conn_id[newfd] as usize;
            if nk == 11 && np < MAX_PIPES {
                let prev = PIPE_WRITE_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 {
                    trace!(Debug, FS, {
                        print(b"PWC-SET dup3 P"); print_u64(ctx.pid as u64);
                        print(b" pipe="); print_u64(np as u64);
                    });
                    PIPE_WRITE_CLOSED[np].store(1, Ordering::Release);
                }
            } else if nk == 10 && np < MAX_PIPES {
                let prev = PIPE_READ_REFS[np].fetch_sub(1, Ordering::AcqRel);
                if prev <= 1 { PIPE_READ_CLOSED[np].store(1, Ordering::Release); }
            }
            if ctx.child_fds[newfd] == 13 || ctx.child_fds[newfd] == 14 {
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][3] == newfd as u64 { ctx.vfs_files[s] = [0; 4]; break; }
                }
            }
            ctx.child_fds[newfd] = 0;
        }
        let ok = ctx.child_fds[oldfd];
        let op = ctx.sock_conn_id[oldfd] as usize;
        if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
        else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
        if (ok == 27 || ok == 28) && op < crate::fd::MAX_UNIX_CONNS {
            crate::fd::UNIX_CONN_REFS[op].fetch_add(1, Ordering::AcqRel);
        }
        ctx.child_fds[newfd] = ctx.child_fds[oldfd];
        ctx.sock_conn_id[newfd] = ctx.sock_conn_id[oldfd];
        ctx.sock_udp_local_port[newfd] = ctx.sock_udp_local_port[oldfd];
        ctx.sock_udp_remote_ip[newfd] = ctx.sock_udp_remote_ip[oldfd];
        ctx.sock_udp_remote_port[newfd] = ctx.sock_udp_remote_port[oldfd];
        dup_file_slots(ctx, oldfd, newfd);
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
                    let ok = ctx.child_fds[fd];
                    let op = ctx.sock_conn_id[fd] as usize;
                    if ok == 11 && op < MAX_PIPES { PIPE_WRITE_REFS[op].fetch_add(1, Ordering::AcqRel); }
                    else if ok == 10 && op < MAX_PIPES { PIPE_READ_REFS[op].fetch_add(1, Ordering::AcqRel); }
                    if (ok == 27 || ok == 28) && op < crate::fd::MAX_UNIX_CONNS {
                        crate::fd::UNIX_CONN_REFS[op].fetch_add(1, Ordering::AcqRel);
                    }
                    ctx.child_fds[n] = ctx.child_fds[fd];
                    ctx.sock_conn_id[n] = ctx.sock_conn_id[fd];
                    ctx.sock_udp_local_port[n] = ctx.sock_udp_local_port[fd];
                    ctx.sock_udp_remote_ip[n] = ctx.sock_udp_remote_ip[fd];
                    ctx.sock_udp_remote_port[n] = ctx.sock_udp_remote_port[fd];
                    dup_file_slots(ctx, fd, n);
                    if cmd == 1030 && n < 128 {
                        *ctx.fd_cloexec |= 1u128 << n;
                    }
                    trace!(Debug, FS, {
                        print(b"FD-FCNTL P"); print_u64(ctx.pid as u64);
                        print(b" F_DUPFD"); if cmd == 1030 { print(b"_CX"); }
                        print(b" "); print_u64(fd as u64);
                        print(b"->"); print_u64(n as u64);
                        print(b" k="); print_u64(ok as u64);
                        print(b" pipe="); print_u64(op as u64);
                    });
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
                if flags & 1 != 0 {
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
        4 => { // F_SETFL
            if fd < GRP_MAX_FDS {
                ctx.fd_flags[fd] = msg.regs[2] as u32;
            }
            reply_val(ctx.ep_cap, 0);
        }
        5 => { // F_GETLK
            let flock_ptr = msg.regs[2];
            if flock_ptr != 0 {
                ctx.guest_write(flock_ptr, &2i16.to_le_bytes()); // F_UNLCK = 2
            }
            reply_val(ctx.ep_cap, 0);
        }
        6 | 7 => { // F_SETLK / F_SETLKW
            reply_val(ctx.ep_cap, 0);
        }
        _ => reply_val(ctx.ep_cap, -EINVAL),
    }
}
