//! LUCAS adapter -- type marker only.
//!
//! LUCAS's real state (the `static mut` tables for fds, mm, procfs, etc.)
//! lives inside `services/init/src/`. Because this crate cannot reach into
//! that service's private internals, the adapter here is intentionally a
//! zero-sized struct: it exists so callers can hold a `&'static dyn
//! LinuxBackend` today, and so follow-up waves have a concrete place to
//! land the real dispatch glue once child_handler is decomposed.
//!
//! Every trait method returns `-ENOSYS` (-38) except `syscall`, which
//! panics. Rationale: `syscall` must never be routed through this adapter
//! while child_handler still owns dispatch; hitting it would indicate a
//! wiring bug, not a missing feature. The other methods simply mark
//! "not yet migrated".

use crate::ctx::SyscallCtx;
use crate::trait_def::LinuxBackend;
use crate::types::{CapSet, Fd, LinuxPid, ProcessImage, Signal, SyscallResult};

const ENOSYS: SyscallResult = -38;

/// Zero-sized marker for the legacy LUCAS path. See module doc.
pub struct LucasBackend;

impl LinuxBackend for LucasBackend {
    fn syscall(&self, _ctx: &mut SyscallCtx, _nr: u64, _args: [u64; 6]) -> SyscallResult {
        // Should never be reached while child_handler owns dispatch.
        panic!("LucasBackend::syscall called -- route through child_handler directly");
    }

    fn create_process(&self, _image: ProcessImage, _caps: CapSet) -> Result<LinuxPid, SyscallResult> {
        Err(ENOSYS)
    }

    fn signal(&self, _pid: LinuxPid, _sig: Signal) -> Result<(), SyscallResult> {
        Err(ENOSYS)
    }

    fn fd_dup_into(&self, _src: LinuxPid, _dst: LinuxPid, _fd: Fd) -> Result<(), SyscallResult> {
        Err(ENOSYS)
    }

    fn shutdown(&self) -> Result<(), SyscallResult> {
        Err(ENOSYS)
    }
}
