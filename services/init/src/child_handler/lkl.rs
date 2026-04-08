// ---------------------------------------------------------------------------
// child_handler::lkl — LKL (Linux Kernel Library) forwarding helpers.
//
// These helpers bridge between the LUCAS syscall dispatcher (the giant match
// in `child_handler::child_handler`) and the real LKL bridge in `crate::lkl`.
// Each process owns a 128-bit bitset of "LKL-owned" guest file descriptors;
// when a syscall touches an LKL-owned fd, the dispatcher forwards the call
// into the Linux Kernel Library instead of handling it locally.
//
// This module is a *pure helpers* module — it carries no hidden state beyond
// its own `LKL_FDS` bitset, and every public function takes every piece of
// caller state as an argument. See the partial-split note in mod.rs for why
// the rest of `child_handler` still lives in one file.
// ---------------------------------------------------------------------------

use crate::process::MAX_PROCS;

/// Bitset per process: bit N set means guest fd N is managed by LKL, not LUCAS.
/// 128 fds per process (2 × u64).
static mut LKL_FDS: [[u64; 2]; MAX_PROCS] = [[0u64; 2]; MAX_PROCS];

#[inline]
pub(crate) fn fd_set(pid: usize, fd: i64) {
    if fd >= 0 && (fd as usize) < 128 && pid > 0 && pid <= MAX_PROCS {
        let i = pid - 1;
        unsafe { LKL_FDS[i][(fd as usize) / 64] |= 1u64 << ((fd as usize) % 64); }
    }
}

#[inline]
pub(crate) fn fd_clear(pid: usize, fd: i64) {
    if fd >= 0 && (fd as usize) < 128 && pid > 0 && pid <= MAX_PROCS {
        let i = pid - 1;
        unsafe { LKL_FDS[i][(fd as usize) / 64] &= !(1u64 << ((fd as usize) % 64)); }
    }
}

#[inline]
pub(crate) fn fd_is_set(pid: usize, fd: u64) -> bool {
    if (fd as usize) >= 128 || pid == 0 || pid > MAX_PROCS { return false; }
    let i = pid - 1;
    unsafe { LKL_FDS[i][(fd as usize) / 64] & (1u64 << ((fd as usize) % 64)) != 0 }
}

/// Returns true if the process has *any* LKL-owned fd at all. Used by
/// poll/select-style syscalls where per-fd routing is too expensive and
/// we best-effort forward to LKL when the bitset is non-empty.
#[inline]
pub(crate) fn fd_any_set(pid: usize) -> bool {
    if pid == 0 || pid > MAX_PROCS { return false; }
    let i = pid - 1;
    unsafe { LKL_FDS[i][0] | LKL_FDS[i][1] != 0 }
}

/// Forward a syscall to LKL and return the raw result.
/// Caller decides when to reply on the IPC endpoint.
#[inline]
pub(crate) fn forward_ret(syscall_nr: u64,
                          msg: &sotos_common::IpcMsg,
                          pid: usize,
                          child_as_cap: u64) -> i64 {
    let args = [msg.regs[0], msg.regs[1], msg.regs[2],
                msg.regs[3], msg.regs[4], msg.regs[5]];
    // Fully qualified path avoids the local `lkl` module name collision.
    crate::lkl::syscall(syscall_nr, &args, child_as_cap, pid)
}

/// Forward a syscall directly to LKL and reply immediately on `ep_cap`.
#[inline]
pub(crate) fn forward(ep_cap: u64,
                      syscall_nr: u64,
                      msg: &sotos_common::IpcMsg,
                      pid: usize,
                      child_as_cap: u64) {
    let ret = forward_ret(syscall_nr, msg, pid, child_as_cap);
    crate::exec::reply_val(ep_cap, ret);
}
