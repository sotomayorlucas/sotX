// ---------------------------------------------------------------------------
// Wine PE loader diagnostic logging.
//
// Adds targeted tracing for diagnosing `wine64 hello.exe` stalls.
// All output is gated behind `WINE_DIAG` (compile-time constant) so it
// compiles to nothing when disabled.  When enabled, logs go to serial
// via `crate::framebuffer::print*`.
//
// Enable:  set WINE_DIAG = true below.
// Disable: set WINE_DIAG = false — zero overhead.
// ---------------------------------------------------------------------------

use crate::framebuffer::{print, print_u64, print_hex64};

/// Master switch. Set to `false` to eliminate all Wine diagnostic output.
pub(crate) const WINE_DIAG: bool = true;

/// Minimum PID to trace. Wine processes are typically P4+ (wineserver=P5,
/// wine clients=P6+). Set to 4 to capture all Wine-related traffic.
pub(crate) const WINE_MIN_PID: usize = 4;

/// Log every syscall for Wine PIDs.
/// Format: `[WINE-DIAG pid=N syscall=NAME(NR) fd=F]`
#[inline(always)]
pub(crate) fn log_syscall(pid: usize, syscall_nr: u64, regs: &[u64; 8]) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" syscall=");
    print(sotos_common::trace::syscall_name(syscall_nr));
    print(b"(");
    print_u64(syscall_nr);
    print(b")");
    // For fd-bearing syscalls, show fd argument
    match syscall_nr {
        0 | 1 | 3 | 5 | 7 | 8 | 16 | 17 | 18 | 19 | 20 | 32 | 33
        | 72 | 74 | 75 | 77 | 217 | 221 | 232 | 233 | 281 | 292 => {
            print(b" fd=");
            print_u64(regs[0]);
        }
        // mmap: show addr, len, prot, flags
        9 => {
            print(b" addr=");
            print_hex64(regs[0]);
            print(b" len=");
            print_hex64(regs[1]);
            print(b" prot=");
            print_u64(regs[2]);
            print(b" flags=");
            print_hex64(regs[3]);
        }
        // open: show path pointer
        2 => {
            print(b" path=");
            print_hex64(regs[0]);
        }
        // openat: show dirfd + path pointer
        257 => {
            print(b" dirfd=");
            print_u64(regs[0]);
            print(b" path=");
            print_hex64(regs[1]);
        }
        // clone/fork: show flags
        56 => {
            print(b" flags=");
            print_hex64(regs[0]);
        }
        // futex: show addr + op
        202 => {
            print(b" addr=");
            print_hex64(regs[0]);
            print(b" op=");
            print_u64(regs[1] & 0x7F);
        }
        // socket: show domain + type
        41 => {
            print(b" domain=");
            print_u64(regs[0]);
            print(b" type=");
            print_u64(regs[1] & 0xFF);
        }
        // connect/bind: show fd + sockaddr_ptr
        42 | 49 => {
            print(b" fd=");
            print_u64(regs[0]);
            print(b" addr=");
            print_hex64(regs[1]);
        }
        // sendmsg/recvmsg: show fd
        46 | 47 => {
            print(b" fd=");
            print_u64(regs[0]);
        }
        _ => {
            // For other syscalls, show first arg
            print(b" a0=");
            print_hex64(regs[0]);
        }
    }
    print(b"]\n");
}

/// Log epoll_create with the returned fd.
#[inline(always)]
pub(crate) fn log_epoll_create(pid: usize, ret_fd: i64) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" epoll_create -> fd=");
    print_u64(ret_fd as u64);
    print(b"]\n");
}

/// Log epoll_ctl operations.
#[inline(always)]
pub(crate) fn log_epoll_ctl(pid: usize, epfd: usize, op: u32, fd: i32, events: u32, data: u64) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    let op_name = match op {
        1 => b"ADD" as &[u8],
        2 => b"DEL",
        3 => b"MOD",
        _ => b"???",
    };
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" epoll_ctl epfd=");
    print_u64(epfd as u64);
    print(b" op=");
    print(op_name);
    print(b" fd=");
    print_u64(fd as u64);
    print(b" events=");
    print_hex64(events as u64);
    print(b" data=");
    print_hex64(data);
    print(b"]\n");
}

/// Log epoll_wait entry (before polling loop).
#[inline(always)]
pub(crate) fn log_epoll_wait_enter(pid: usize, epfd: usize, max_events: usize, timeout: i32) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" epoll_wait ENTER epfd=");
    print_u64(epfd as u64);
    print(b" max=");
    print_u64(max_events as u64);
    print(b" timeout=");
    if timeout < 0 {
        print(b"-1(block)");
    } else {
        print_u64(timeout as u64);
    }
    print(b"]\n");
}

/// Log epoll_wait result.
#[inline(always)]
pub(crate) fn log_epoll_wait_result(pid: usize, ready_count: usize) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" epoll_wait -> ready=");
    print_u64(ready_count as u64);
    print(b"]\n");
}

#[inline(always)]
fn futex_op_name(op: u32) -> &'static [u8] {
    match op {
        0 => b"WAIT",
        1 => b"WAKE",
        9 => b"WAIT_BITSET",
        _ => b"???",
    }
}

/// Log futex_wait entry (blocks the handler).
#[inline(always)]
pub(crate) fn log_futex(pid: usize, op: u32, addr: u64, val: u32) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" futex op=");
    print(futex_op_name(op));
    print(b" addr=");
    print_hex64(addr);
    print(b" val=");
    print_u64(val as u64);
    print(b"]\n");
}

/// Log futex result (after wait/wake returns).
#[inline(always)]
pub(crate) fn log_futex_result(pid: usize, op: u32, result: i64) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" futex ");
    print(futex_op_name(op));
    print(b" -> ");
    if result < 0 {
        print(b"-");
        print_u64((-result) as u64);
    } else {
        print_u64(result as u64);
    }
    print(b"]\n");
}

/// Log AF_UNIX socket operations (connect/bind/sendmsg/recvmsg).
#[inline(always)]
pub(crate) fn log_unix_op(pid: usize, op: &[u8], fd: usize, conn_id: usize) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" unix ");
    print(op);
    print(b" fd=");
    print_u64(fd as u64);
    print(b" conn=");
    print_u64(conn_id as u64);
    print(b"]\n");
}

/// Log blocking recv/wait that could stall.
#[inline(always)]
pub(crate) fn log_blocking(pid: usize, what: &[u8]) {
    if !WINE_DIAG || pid < WINE_MIN_PID { return; }
    print(b"[WINE-DIAG pid=");
    print_u64(pid as u64);
    print(b" BLOCKING ");
    print(what);
    print(b"]\n");
}

