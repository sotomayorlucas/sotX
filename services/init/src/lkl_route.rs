// ---------------------------------------------------------------------------
// lkl_route: child-side Linux-syscall routing to LKL.
//
// Phase 5 (deprecation plan) consolidation: all per-child LKL policy lives
// here. Owns the LKL_FDS bitmap (per-pid, tracks which guest fds are LKL-
// managed) and the full category A/B dispatch decision.
//
// Two syscall categories handled:
//   - Category A: always route to LKL when it's ready.
//       path-only        (stat/access/chdir/mkdir/unlink/rename/...)
//       info/time/sync   (uname/sysinfo/getrandom/gettimeofday/futex/...)
//       fd-creating      (open/socket/epoll_create/eventfd/...) — returned
//                        fd goes into LKL_FDS so subsequent ops on that fd
//                        route here transparently.
//   - Category B: route based on LKL_FDS bitmap ownership of regs[0].
//       (read/write/close/dup*, connect/bind/listen/shutdown/send*/recv*,
//        epoll_ctl/wait, poll/ppoll/select/pselect6, ...)
//
// PID 1 (the LUCAS shell) never owns LKL fds — its LKL forwarding is the
// simpler stateless pre-route in `crate::dispatch::dispatch_linux_arm`
// (info-domain only). Child processes go through `try_route` below.
//
// All routing gates on `lkl::LKL_READY` (which is only set when
// `SOTOS_LKL=1` was built AND the LKL kernel reported readiness via
// `lkl_bridge_ready`). With SOTOS_LKL=0 this module is inert.
// ---------------------------------------------------------------------------

use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::exec::reply_val;
use crate::lkl;
use crate::process::MAX_PROCS;

/// LKL FD ownership bitset per process: bit N set ⇒ guest fd N is managed
/// by LKL, not LUCAS. 128 fds per process (2 × AtomicU64).
///
/// Single-writer-per-slot invariant: each pid has exactly one handler
/// thread mutating its bits, so races within a slot cannot happen. Atomic
/// is used because the deadlock detector (fs_pipe) cross-reads other
/// pids' slots without the handler lock; the Acquire/Release pairing is
/// what the deadlock check's correctness depends on.
pub(crate) static LKL_FDS: [[AtomicU64; 2]; MAX_PROCS] =
    [const { [const { AtomicU64::new(0) }; 2] }; MAX_PROCS];

#[inline]
pub(crate) fn lkl_fd_set(pid: usize, fd: i64) {
    if fd >= 0 && (fd as usize) < 128 && pid > 0 && pid <= MAX_PROCS {
        let i = pid - 1;
        let bit = 1u64 << ((fd as usize) % 64);
        LKL_FDS[i][(fd as usize) / 64].fetch_or(bit, Ordering::AcqRel);
    }
}

#[inline]
pub(crate) fn lkl_fd_clear(pid: usize, fd: i64) {
    if fd >= 0 && (fd as usize) < 128 && pid > 0 && pid <= MAX_PROCS {
        let i = pid - 1;
        let bit = 1u64 << ((fd as usize) % 64);
        LKL_FDS[i][(fd as usize) / 64].fetch_and(!bit, Ordering::AcqRel);
    }
}

#[inline]
pub(crate) fn lkl_fd_is_set(pid: usize, fd: u64) -> bool {
    if (fd as usize) >= 128 || pid == 0 || pid > MAX_PROCS { return false; }
    let i = pid - 1;
    let bit = 1u64 << ((fd as usize) % 64);
    LKL_FDS[i][(fd as usize) / 64].load(Ordering::Acquire) & bit != 0
}

/// Returns `true` if the pid owns at least one LKL fd. Used for
/// multi-fd syscalls (poll/ppoll/select/pselect6) where per-fd routing
/// would require inspecting the full fd set — best-effort: route whole
/// call to LKL if it owns anything.
#[inline]
pub(crate) fn pid_has_any_lkl_fd(pid: usize) -> bool {
    if pid == 0 || pid > MAX_PROCS { return false; }
    let i = pid - 1;
    (LKL_FDS[i][0].load(Ordering::Acquire)
     | LKL_FDS[i][1].load(Ordering::Acquire)) != 0
}

/// Forward a syscall to LKL, return the result (caller decides when to
/// reply). Safe to call even when LKL isn't ready — returns -ENOSYS.
#[inline]
pub(crate) fn forward_to_lkl_ret(syscall_nr: u64,
                                 msg: &IpcMsg,
                                 pid: usize,
                                 child_as_cap: u64) -> i64 {
    let args = [msg.regs[0], msg.regs[1], msg.regs[2],
                msg.regs[3], msg.regs[4], msg.regs[5]];
    lkl::syscall(syscall_nr, &args, child_as_cap, pid)
}

/// Forward a syscall to LKL and reply immediately.
#[inline]
pub(crate) fn forward_to_lkl(ep_cap: u64,
                             syscall_nr: u64,
                             msg: &IpcMsg,
                             pid: usize,
                             child_as_cap: u64) {
    let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
    reply_val(ep_cap, ret);
}

/// Attempt to route a syscall through LKL. Returns `true` if the
/// syscall was handled (caller should `continue`), `false` if the
/// caller must fall through to the normal match/dispatch.
///
/// No-op when LKL isn't ready — always returns `false`.
pub(crate) fn try_route(syscall_nr: u64,
                        msg: &IpcMsg,
                        pid: usize,
                        child_as_cap: u64,
                        ep_cap: u64) -> bool {
    if !lkl::LKL_READY.load(Ordering::Acquire) {
        return false;
    }

    match syscall_nr {
        // ── Category A: path-only syscalls (always LKL) ──
        SYS_STAT | SYS_LSTAT | SYS_ACCESS | SYS_GETCWD | SYS_CHDIR |
        SYS_MKDIR | SYS_RMDIR | SYS_UNLINK | SYS_RENAME |
        SYS_CHMOD | SYS_FSTATAT | SYS_READLINKAT |
        SYS_FACCESSAT | SYS_MKDIRAT | SYS_UNLINKAT => {
            forward_to_lkl(ep_cap, syscall_nr, msg, pid, child_as_cap);
            true
        }
        // ── Category A: info/time/sync syscalls (always LKL) ──
        // SYS_FUTEX is safe with the per-pid scratch in lkl_bridge.c
        // (the bridge_lock was removed in PR #123).
        SYS_UNAME | SYS_SYSINFO | SYS_GETRANDOM |
        SYS_GETTIMEOFDAY | SYS_CLOCK_GETTIME | SYS_CLOCK_GETRES |
        SYS_NANOSLEEP | SYS_CLOCK_NANOSLEEP |
        SYS_FUTEX => {
            forward_to_lkl(ep_cap, syscall_nr, msg, pid, child_as_cap);
            true
        }
        // ── Category A: fd-creating via path/socket/etc → forward + mark fd ──
        SYS_OPEN | SYS_OPENAT => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret >= 0 { lkl_fd_set(pid, ret); }
            reply_val(ep_cap, ret);
            true
        }
        SYS_SOCKET | SYS_EPOLL_CREATE | SYS_EPOLL_CREATE1 |
        SYS_EVENTFD | SYS_EVENTFD2 |
        SYS_TIMERFD_CREATE | SYS_MEMFD_CREATE |
        SYS_INOTIFY_INIT1 => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret >= 0 { lkl_fd_set(pid, ret); }
            reply_val(ep_cap, ret);
            true
        }
        SYS_ACCEPT | SYS_ACCEPT4 => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret >= 0 { lkl_fd_set(pid, ret); }
            reply_val(ep_cap, ret);
            true
        }
        SYS_PIPE | SYS_PIPE2 => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret == 0 {
                // Kernel wrote two fds to guest memory at regs[0].
                let ptr = msg.regs[0] as *const [i32; 2];
                let fds = unsafe { *ptr };
                lkl_fd_set(pid, fds[0] as i64);
                lkl_fd_set(pid, fds[1] as i64);
            }
            reply_val(ep_cap, ret);
            true
        }
        SYS_SOCKETPAIR => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret == 0 {
                let ptr = msg.regs[3] as *const [i32; 2];
                let fds = unsafe { *ptr };
                lkl_fd_set(pid, fds[0] as i64);
                lkl_fd_set(pid, fds[1] as i64);
            }
            reply_val(ep_cap, ret);
            true
        }

        // ── Category B: fd-bearing syscalls → route by ownership ──
        SYS_READ | SYS_WRITE | SYS_LSEEK | SYS_FSTAT |
        SYS_PREAD64 | SYS_PWRITE64 | SYS_READV | SYS_WRITEV |
        SYS_FTRUNCATE | SYS_FSYNC | SYS_FDATASYNC |
        SYS_GETDENTS64 | SYS_FCNTL | SYS_IOCTL |
        SYS_CONNECT | SYS_BIND | SYS_LISTEN | SYS_SHUTDOWN |
        SYS_SENDTO | SYS_SENDMSG | SYS_RECVFROM | SYS_RECVMSG |
        SYS_GETSOCKOPT | SYS_SETSOCKOPT |
        SYS_GETSOCKNAME | SYS_GETPEERNAME |
        SYS_EPOLL_CTL |
        SYS_TIMERFD_SETTIME | SYS_TIMERFD_GETTIME |
        SYS_INOTIFY_ADD_WATCH | SYS_INOTIFY_RM_WATCH
        if lkl_fd_is_set(pid, msg.regs[0]) => {
            forward_to_lkl(ep_cap, syscall_nr, msg, pid, child_as_cap);
            true
        }
        // epoll_wait/pwait: epfd is regs[0].
        SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT
        if lkl_fd_is_set(pid, msg.regs[0]) => {
            forward_to_lkl(ep_cap, syscall_nr, msg, pid, child_as_cap);
            true
        }
        // Multi-fd polling: route whole call to LKL if the pid owns any
        // LKL fds. Best-effort — LKL's poll will return early on events
        // for fds it does not know, at which point LUCAS hasn't received
        // the syscall anyway (already forwarded).
        SYS_POLL | SYS_PPOLL | SYS_SELECT | SYS_PSELECT6
        if pid_has_any_lkl_fd(pid) => {
            forward_to_lkl(ep_cap, syscall_nr, msg, pid, child_as_cap);
            true
        }
        SYS_CLOSE if lkl_fd_is_set(pid, msg.regs[0]) => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret == 0 { lkl_fd_clear(pid, msg.regs[0] as i64); }
            reply_val(ep_cap, ret);
            true
        }
        SYS_DUP if lkl_fd_is_set(pid, msg.regs[0]) => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret >= 0 { lkl_fd_set(pid, ret); }
            reply_val(ep_cap, ret);
            true
        }
        SYS_DUP2 | SYS_DUP3 if lkl_fd_is_set(pid, msg.regs[0]) => {
            let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
            if ret >= 0 { lkl_fd_set(pid, ret); }
            reply_val(ep_cap, ret);
            true
        }

        // Everything else: LUCAS owns it.
        _ => false,
    }
}
