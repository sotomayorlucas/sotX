//! Syscall invocation context.
//!
//! Minimal by design: only the fields that `child_handler` already consumes
//! at entry (pid + caller address-space capability). Future fields
//! (register snapshot, mm descriptor, cap set, deception hooks) will be
//! bolted on as the migration moves actual dispatch into this crate.

use core::marker::PhantomData;

/// One live Linux syscall on behalf of a child process.
pub struct SyscallCtx<'a> {
    /// Linux pid (tgid) of the caller.
    pub pid: usize,
    /// Caller's address-space capability (sotos cap handle).
    pub as_cap: u64,
    _marker: PhantomData<&'a ()>,
}

impl<'a> SyscallCtx<'a> {
    /// Build a fresh context for a syscall dispatch.
    #[inline]
    pub fn new(pid: usize, as_cap: u64) -> Self {
        Self { pid, as_cap, _marker: PhantomData }
    }
}
