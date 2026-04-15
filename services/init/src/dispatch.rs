// ---------------------------------------------------------------------------
// dispatch: Shared Linux-ABI syscall dispatcher.
// Consumed by both lucas_handler (PID 1) and child_handler (Linux children).
// Holds the common delegation arms that previously appeared in both handlers.
// Handler-specific preprocessing (LUCAS /snap + /proc virtuals, LKL fd
// forwarding, CHILD fork/exec) stays in the respective caller.
// ---------------------------------------------------------------------------

use sotos_common::IpcMsg;
use sotos_common::linux_abi::*;
use crate::exec::reply_val;
use crate::syscalls::context::SyscallContext;
use crate::syscalls::mm as syscalls_mm;
use crate::syscalls::fs as syscalls_fs;
use crate::syscalls::net as syscalls_net;
use crate::syscalls::signal as syscalls_signal;
use crate::syscalls::info as syscalls_info;
use crate::syscalls::task as syscalls_task;

/// Outcome of a shared-arm dispatch.
pub(crate) enum DispatchOutcome {
    /// The arm was handled; reply was sent. Caller continues the loop.
    Handled,
    /// The arm was handled and requests the outer handler loop to break
    /// (exit_group, signal trampoline that terminated the process, etc.).
    Break,
    /// Unknown to this dispatcher; caller must fall through to its own arms.
    NotHandled,
}

/// Dispatch a Linux-ABI syscall through the shared arm set.
///
/// Returns `Handled` for the common cases, `Break` to signal loop exit,
/// or `NotHandled` when the caller must handle the arm itself (open,
/// clone, execve, LKL-forwarded, etc.).
pub(crate) fn dispatch_linux_arm(
    ctx: &mut SyscallContext,
    msg: &IpcMsg,
    syscall_nr: u64,
) -> DispatchOutcome {
    let ep_cap = ctx.ep_cap;
    match syscall_nr {
        // ── File / IO ──────────────────────────────────────────
        SYS_READ       => syscalls_fs::sys_read(ctx, msg),
        SYS_WRITE      => syscalls_fs::sys_write(ctx, msg),
        SYS_CLOSE      => syscalls_fs::sys_close(ctx, msg),
        SYS_STAT | SYS_LSTAT
                       => syscalls_fs::sys_stat(ctx, msg),
        SYS_FSTAT      => syscalls_fs::sys_fstat(ctx, msg),
        SYS_LSEEK      => syscalls_fs::sys_lseek(ctx, msg),
        SYS_IOCTL      => syscalls_fs::sys_ioctl(ctx, msg),
        SYS_READV      => syscalls_fs::sys_readv(ctx, msg),
        SYS_WRITEV     => syscalls_fs::sys_writev(ctx, msg),
        SYS_ACCESS     => syscalls_fs::sys_access(ctx, msg, syscall_nr),
        SYS_PIPE       => syscalls_fs::sys_pipe(ctx, msg),
        SYS_DUP        => syscalls_fs::sys_dup(ctx, msg),
        SYS_DUP2       => syscalls_fs::sys_dup2(ctx, msg),
        SYS_DUP3       => syscalls_fs::sys_dup3(ctx, msg),
        SYS_FCNTL      => syscalls_fs::sys_fcntl(ctx, msg),
        SYS_FTRUNCATE  => syscalls_fs::sys_ftruncate(ctx, msg),
        SYS_FSYNC | SYS_FDATASYNC
                       => syscalls_fs::sys_fsync(ctx, msg),
        SYS_GETCWD     => syscalls_fs::sys_getcwd(ctx, msg),
        SYS_CHDIR      => syscalls_fs::sys_chdir(ctx, msg),
        SYS_RENAME     => syscalls_fs::sys_rename(ctx, msg),
        SYS_MKDIR      => syscalls_fs::sys_mkdir(ctx, msg),
        SYS_RMDIR      => syscalls_fs::sys_rmdir(ctx, msg),
        SYS_UNLINK     => syscalls_fs::sys_unlink(ctx, msg),
        SYS_READLINK   => syscalls_fs::sys_readlink(ctx, msg),
        SYS_GETDENTS64 => syscalls_fs::sys_getdents64(ctx, msg),
        SYS_FSTATAT    => syscalls_fs::sys_fstatat(ctx, msg),
        SYS_READLINKAT => syscalls_fs::sys_readlinkat(ctx, msg),
        SYS_FACCESSAT  => syscalls_fs::sys_access(ctx, msg, syscall_nr),
        SYS_UNLINKAT   => syscalls_fs::sys_unlinkat(ctx, msg),
        SYS_RENAMEAT | SYS_RENAMEAT2
                       => syscalls_fs::sys_renameat(ctx, msg),
        SYS_MKDIRAT    => syscalls_fs::sys_mkdirat(ctx, msg),
        SYS_PREAD64    => syscalls_fs::sys_pread64(ctx, msg),
        SYS_PWRITE64   => syscalls_fs::sys_pwrite64(ctx, msg),
        SYS_PREADV     => syscalls_fs::sys_preadv(ctx, msg),
        SYS_PWRITEV    => syscalls_fs::sys_pwritev(ctx, msg),
        SYS_PIPE2      => syscalls_fs::sys_pipe2(ctx, msg),
        SYS_STATFS | SYS_FSTATFS
                       => syscalls_fs::sys_statfs(ctx, msg, syscall_nr),
        SYS_FACCESSAT2 => syscalls_fs::sys_faccessat2(ctx, msg),
        SYS_SENDFILE   => syscalls_fs::sys_sendfile(ctx, msg),
        SYS_UMASK      => syscalls_fs::sys_umask(ctx, msg),
        SYS_STATX      => syscalls_fs::sys_statx(ctx, msg),
        SYS_FADVISE64  => syscalls_fs::sys_fadvise64(ctx, msg),

        // ── Memory management ─────────────────────────────────
        SYS_BRK        => syscalls_mm::sys_brk(ctx, msg),
        SYS_MMAP       => syscalls_mm::sys_mmap(ctx, msg),
        SYS_MUNMAP     => syscalls_mm::sys_munmap(ctx, msg),
        SYS_MPROTECT   => syscalls_mm::sys_mprotect(ctx, msg),
        SYS_MREMAP     => syscalls_mm::sys_mremap(ctx, msg),
        SYS_MADVISE    => syscalls_mm::sys_madvise(ctx, msg),

        // ── Networking + poll/epoll ───────────────────────────
        SYS_POLL       => syscalls_net::sys_poll(ctx, msg),
        SYS_PPOLL      => syscalls_net::sys_ppoll(ctx, msg),
        SYS_SOCKET     => syscalls_net::sys_socket(ctx, msg),
        SYS_CONNECT    => syscalls_net::sys_connect(ctx, msg),
        SYS_SENDTO     => syscalls_net::sys_sendto(ctx, msg),
        SYS_SENDMSG    => syscalls_net::sys_sendmsg(ctx, msg),
        SYS_RECVFROM   => syscalls_net::sys_recvfrom(ctx, msg),
        SYS_RECVMSG    => syscalls_net::sys_recvmsg(ctx, msg),
        SYS_BIND       => syscalls_net::sys_bind(ctx, msg),
        SYS_LISTEN     => syscalls_net::sys_listen(ctx, msg),
        SYS_SETSOCKOPT => syscalls_net::sys_setsockopt(ctx, msg),
        SYS_GETSOCKNAME | SYS_GETPEERNAME
                       => syscalls_net::sys_getsockname(ctx, msg, syscall_nr),
        SYS_GETSOCKOPT => syscalls_net::sys_getsockopt(ctx, msg),
        SYS_SHUTDOWN   => syscalls_net::sys_shutdown(ctx, msg),
        SYS_SELECT | SYS_PSELECT6
                       => syscalls_net::sys_select(ctx, msg, syscall_nr),
        SYS_EPOLL_CREATE1 | SYS_EPOLL_CREATE
                       => syscalls_net::sys_epoll_create(ctx, msg),
        SYS_EPOLL_CTL  => syscalls_net::sys_epoll_ctl(ctx, msg),
        SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT
                       => syscalls_net::sys_epoll_wait(ctx, msg),
        SYS_SOCKETPAIR => syscalls_net::sys_socketpair(ctx, msg),
        SYS_ACCEPT | SYS_ACCEPT4
                       => syscalls_net::sys_accept(ctx, msg),

        // ── Process lifecycle + identity ──────────────────────
        SYS_GETPID     => syscalls_task::sys_getpid(ctx, msg),
        SYS_GETTID     => syscalls_task::sys_gettid(ctx, msg),
        SYS_GETPPID    => syscalls_task::sys_getppid(ctx, msg),
        SYS_GETUID | SYS_GETGID | SYS_GETEUID | SYS_GETEGID
                       => syscalls_task::sys_getuid_family(ctx, msg),
        SYS_SETFSUID | SYS_SETFSGID
                       => syscalls_task::sys_setfsuid_family(ctx, msg),
        SYS_SET_TID_ADDRESS
                       => syscalls_task::sys_set_tid_address(ctx, msg),
        SYS_SET_ROBUST_LIST
                       => syscalls_task::sys_set_robust_list(ctx, msg),
        SYS_GET_ROBUST_LIST
                       => syscalls_task::sys_get_robust_list(ctx, msg),
        SYS_KILL       => syscalls_task::sys_kill(ctx, msg),
        SYS_WAIT4      => syscalls_task::sys_wait4(ctx, msg),
        SYS_TKILL | SYS_TGKILL
                       => syscalls_task::sys_tgkill(ctx, msg),
        SYS_SETPGID    => syscalls_task::sys_setpgid(ctx, msg),
        SYS_GETPGRP    => syscalls_task::sys_getpgrp(ctx, msg),
        SYS_SETSID     => syscalls_task::sys_setsid(ctx, msg),
        SYS_GETPGID | SYS_GETSID
                       => syscalls_task::sys_getpgid(ctx, msg),
        SYS_EXIT_GROUP => {
            if syscalls_task::sys_exit_group(ctx, msg).is_break() {
                return DispatchOutcome::Break;
            }
        }

        // ── Signals ───────────────────────────────────────────
        SYS_RT_SIGACTION
                       => syscalls_signal::sys_rt_sigaction(ctx, msg),
        SYS_RT_SIGPROCMASK
                       => syscalls_signal::sys_rt_sigprocmask(ctx, msg),
        SYS_SIGALTSTACK
                       => syscalls_signal::sys_sigaltstack(ctx, msg),
        SYS_RT_SIGPENDING
                       => syscalls_signal::sys_rt_sigpending(ctx, msg),
        SYS_RT_SIGTIMEDWAIT
                       => syscalls_signal::sys_rt_sigtimedwait(ctx, msg),
        SYS_RT_SIGSUSPEND
                       => syscalls_signal::sys_rt_sigsuspend(ctx, msg),
        0x7F00         => {
            if syscalls_signal::sys_signal_trampoline(ctx, msg).is_break() {
                return DispatchOutcome::Break;
            }
        }

        // ── Info / time / scheduling / events ─────────────────
        SYS_UNAME => {
            let buf_ptr = msg.regs[0];
            if buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                let mut buf = [0u8; 390];
                let fields: [&[u8]; 5] = [b"Linux", b"sotos", b"6.1.0-sotX", b"#1 SMP sotX 0.1.0", b"x86_64"];
                for (i, field) in fields.iter().enumerate() {
                    let off = i * 65;
                    let len = field.len().min(64);
                    buf[off..off + len].copy_from_slice(&field[..len]);
                }
                ctx.guest_write(buf_ptr, &buf);
            }
            reply_val(ep_cap, 0);
        }
        SYS_CLOCK_GETTIME   => syscalls_info::sys_clock_gettime(ctx, msg),
        SYS_GETTIMEOFDAY    => syscalls_info::sys_gettimeofday(ctx, msg),
        SYS_TIME            => syscalls_info::sys_time(ctx, msg),
        SYS_NANOSLEEP       => syscalls_info::sys_nanosleep(ctx, msg),
        SYS_CLOCK_GETRES    => syscalls_info::sys_clock_getres(ctx, msg),
        SYS_CLOCK_NANOSLEEP => syscalls_info::sys_clock_nanosleep(ctx, msg),
        SYS_SYSINFO         => syscalls_info::sys_sysinfo(ctx, msg),
        SYS_PRLIMIT64       => syscalls_info::sys_prlimit64(ctx, msg),
        SYS_GETRANDOM       => syscalls_info::sys_getrandom(ctx, msg),
        SYS_FUTEX           => syscalls_info::sys_futex(ctx, msg),
        SYS_GETRUSAGE       => syscalls_info::sys_getrusage(ctx, msg),
        SYS_GETRLIMIT       => syscalls_info::sys_getrlimit(ctx, msg),
        SYS_TIMES           => syscalls_info::sys_times(ctx, msg),
        SYS_PRCTL           => syscalls_info::sys_prctl(ctx, msg),
        SYS_SCHED_YIELD     => syscalls_info::sys_sched_yield(ctx, msg),
        SYS_SCHED_GETAFFINITY
                            => syscalls_info::sys_sched_getaffinity(ctx, msg),
        SYS_EVENTFD | SYS_EVENTFD2
                            => syscalls_info::sys_eventfd(ctx, msg, syscall_nr),
        SYS_TIMERFD_CREATE  => syscalls_info::sys_timerfd_create(ctx, msg),
        SYS_TIMERFD_SETTIME => syscalls_info::sys_timerfd_settime(ctx, msg),
        SYS_TIMERFD_GETTIME => syscalls_info::sys_timerfd_gettime(ctx, msg),
        SYS_MEMFD_CREATE    => syscalls_info::sys_memfd_create(ctx, msg),
        SYS_INOTIFY_INIT1   => syscalls_info::sys_inotify_init1(ctx, msg),
        SYS_SIGNALFD | SYS_SIGNALFD4
                            => syscalls_info::sys_signalfd(ctx, msg),
        SYS_CAPGET          => syscalls_info::sys_capget(ctx, msg),
        SYS_GETRESUID | SYS_GETRESGID
                            => syscalls_info::sys_getresuid(ctx, msg),

        // ── Identity stubs (return 0, no state change) ────────
        SYS_CHMOD | SYS_SCHED_SETAFFINITY | SYS_SETRLIMIT
                            => syscalls_info::sys_identity_stubs(ctx, msg),

        // ── Explicit -ENOSYS stubs for opt-in features ────────
        SYS_RSEQ            => reply_val(ep_cap, -ENOSYS),
        SYS_CLONE3          => reply_val(ep_cap, -ENOSYS),

        // Not in the shared set — caller handles.
        _ => return DispatchOutcome::NotHandled,
    }
    DispatchOutcome::Handled
}
