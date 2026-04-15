//! LKL (Linux Kernel Library) backend — type marker.
//!
//! Wave-3 seed of the LUCAS → LKL migration. At this stage `LklBackend`
//! is a zero-sized struct that establishes the trait shape without
//! performing any real dispatch. A future wave will wire it to the
//! FFI bindings in `services/init/src/lkl.rs` via a registered
//! function pointer (see [`set_lkl_syscall_fn`]).
//!
//! Gated by `feature = "backend-lkl"` so that default builds do not
//! link-in the LKL bridge. When `SOTOS_LKL=1` is set at init build
//! time, the init crate registers its concrete `lkl_bridge_syscall`
//! FFI with the backend; until then `LklBackend::syscall` returns
//! `-ENOSYS` for every call.

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use crate::ctx::SyscallCtx;
use crate::trait_def::LinuxBackend;
use crate::types::{CapSet, Fd, LinuxPid, ProcessImage, Signal, SyscallResult};

const ENOSYS: SyscallResult = -38;

/// Concrete signature of the FFI bridge registered by the init crate.
/// Arguments mirror `services/init/src/lkl.rs::syscall`:
///   (syscall_nr, &args[6], as_cap, pid)
pub type LklSyscallFn = fn(u64, &[u64; 6], u64, usize) -> i64;

/// Pointer to the registered syscall function. Set once at init
/// boot-time via [`set_lkl_syscall_fn`]; read on every dispatch.
static LKL_SYSCALL_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Whether the LKL kernel has finished early boot and is ready to
/// receive syscalls. Init flips this to `true` once `lkl_bridge_ready()`
/// returns non-zero.
static LKL_READY: AtomicBool = AtomicBool::new(false);

/// Register the init-side LKL FFI bridge. Safe to call multiple times
/// (last write wins). If never called, `LklBackend::syscall` returns
/// `-ENOSYS` for every call.
pub fn set_lkl_syscall_fn(f: LklSyscallFn) {
    LKL_SYSCALL_FN.store(f as *mut (), Ordering::Release);
}

/// Mark LKL as ready. Called by init once `lkl_bridge_ready()` reports
/// the kernel is up.
pub fn mark_lkl_ready() {
    LKL_READY.store(true, Ordering::Release);
}

/// True if the LKL kernel has signaled readiness. Read by
/// [`HybridBackend`] to decide whether to attempt forwarding.
#[inline]
pub fn is_lkl_ready() -> bool {
    LKL_READY.load(Ordering::Acquire)
}

/// Invoke the registered FFI bridge. Returns `-ENOSYS` if no bridge
/// was registered OR the kernel has not yet reported readiness.
#[inline]
pub fn dispatch_syscall(nr: u64, args: &[u64; 6], as_cap: u64, pid: usize) -> i64 {
    if !is_lkl_ready() { return ENOSYS; }
    let raw = LKL_SYSCALL_FN.load(Ordering::Acquire);
    if raw.is_null() { return ENOSYS; }
    // SAFETY: the pointer was stored by `set_lkl_syscall_fn` from a
    // plain `fn` with matching signature. We immediately cast back.
    let f: LklSyscallFn = unsafe { core::mem::transmute(raw) };
    f(nr, args, as_cap, pid)
}

/// Zero-sized marker implementing `LinuxBackend` by delegating to the
/// registered FFI bridge (or returning `-ENOSYS` when unregistered).
pub struct LklBackend;

impl LinuxBackend for LklBackend {
    fn syscall(&self, ctx: &mut SyscallCtx, nr: u64, args: [u64; 6]) -> SyscallResult {
        dispatch_syscall(nr, &args, ctx.as_cap, ctx.pid)
    }

    fn create_process(&self, _image: ProcessImage, _caps: CapSet) -> Result<LinuxPid, SyscallResult> {
        // LKL does not own process creation; LUCAS still owns fork/exec.
        Err(ENOSYS)
    }

    fn signal(&self, _pid: LinuxPid, _sig: Signal) -> Result<(), SyscallResult> {
        Err(ENOSYS)
    }

    fn fd_dup_into(&self, _src: LinuxPid, _dst: LinuxPid, _fd: Fd) -> Result<(), SyscallResult> {
        Err(ENOSYS)
    }

    fn shutdown(&self) -> Result<(), SyscallResult> {
        // LKL shutdown is driven by the init halt path, not the backend.
        Ok(())
    }
}
