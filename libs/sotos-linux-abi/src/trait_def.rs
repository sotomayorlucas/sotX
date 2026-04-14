//! The `LinuxBackend` trait.
//!
//! Both LUCAS (hand-rolled) and LKL (Linux Kernel Library) will implement
//! this trait once the migration completes. Today it is a stable surface
//! for the rest of the system to hold a backend handle, even though every
//! implementation short-circuits to its native dispatch path.

use crate::ctx::SyscallCtx;
use crate::types::{CapSet, Fd, LinuxPid, ProcessImage, Signal, SyscallResult};

pub trait LinuxBackend: Sync {
    /// Execute one Linux syscall on behalf of `ctx`. Return value uses the
    /// raw errno-style convention (>=0 ok, negative = -errno).
    fn syscall(&self, ctx: &mut SyscallCtx, nr: u64, args: [u64; 6]) -> SyscallResult;

    /// Instantiate a new Linux process from `image` with the given capability
    /// bundle. Returns the new pid or a negative errno.
    fn create_process(&self, image: ProcessImage, caps: CapSet) -> Result<LinuxPid, SyscallResult>;

    /// Deliver `sig` to `pid`. Matches `kill(2)` semantics.
    fn signal(&self, pid: LinuxPid, sig: Signal) -> Result<(), SyscallResult>;

    /// Share `fd` from `src` into `dst`. Used by fork/exec-style fd inheritance.
    fn fd_dup_into(&self, src: LinuxPid, dst: LinuxPid, fd: Fd) -> Result<(), SyscallResult>;

    /// Tear down the backend (flush state, close resources). Typically
    /// called at system halt.
    fn shutdown(&self) -> Result<(), SyscallResult>;
}
