// ---------------------------------------------------------------------------
// child_handler::pipe — pipe stall / retry bookkeeping.
//
// The pipe deadlock detector in `syscalls::fs::fs_pipe` needs to know:
//   * how many times each process has been told to retry a blocking pipe op
//     (so it can print one log line at a reasonable interval), and
//   * which pipe id it last stalled on (so two processes stalled on each
//     other's endpoints can be recognised as a cycle and both broken with
//     a synthetic EOF).
//
// The state lives here rather than inline in the giant dispatch match so it
// can be shared with the async syscall handlers and with exit/wait handling
// in `syscalls::task`.
//
// NOTE: re-exported from `child_handler::mod` so existing call sites that use
// `crate::child_handler::mark_pipe_retry_on` (etc.) keep compiling unchanged.
// ---------------------------------------------------------------------------

/// Per-pid transient retry counter. Cleared by the dispatcher before every
/// syscall and re-incremented each time `mark_pipe_retry_on` is called, which
/// rate-limits repeated "pipe blocked" log lines.
pub(crate) static mut RETRY_COUNT: [u64; 16] = [0; 16];

/// Cumulative pipe stall counter per-pid. Only cleared on successful pipe
/// I/O — used by the deadlock detector to spot hung processes.
pub(crate) static mut PIPE_STALL: [u64; 16] = [0; 16];

/// Which pipe each process is currently stalling on (`0xFF` = none).
pub(crate) static mut PIPE_STALL_ID: [u8; 16] = [0xFF; 16];

/// Processes that received a synthetic EOF from the deadlock detector.
/// If they subsequently exit with a non-zero status, `wait4` treats it as a
/// clean exit (the child had no real error — we just unblocked it).
pub(crate) static mut DEADLOCK_EOF: [bool; 16] = [false; 16];

/// Record that `pid` is blocked on `pipe_id`, bumping both the transient
/// retry counter and the cumulative stall counter.
#[inline]
pub(crate) fn mark_pipe_retry_on(pid: usize, pipe_id: usize) {
    if pid < 16 {
        unsafe {
            RETRY_COUNT[pid] += 1;
            PIPE_STALL[pid] += 1;
            PIPE_STALL_ID[pid] = pipe_id as u8;
        }
    }
}

/// Reset the transient retry counter. Called by the dispatcher at the top
/// of each syscall; if the handler sends PIPE_RETRY_TAG it will bump the
/// counter back up via `mark_pipe_retry_on`.
#[inline]
pub(crate) fn clear_pipe_retry(pid: usize) {
    if pid < 16 {
        unsafe { RETRY_COUNT[pid] = 0; }
    }
}

/// Reset the cumulative stall state after a successful pipe op or after
/// the deadlock detector has forced an EOF.
#[inline]
pub(crate) fn clear_pipe_stall(pid: usize) {
    if pid < 16 {
        unsafe {
            PIPE_STALL[pid] = 0;
            PIPE_STALL_ID[pid] = 0xFF;
        }
    }
}
