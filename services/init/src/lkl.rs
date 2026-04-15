//! LKL (Linux Kernel Library) FFI bindings.
//! Compiled only when SOTOS_LKL=1 (cfg(lkl)).
//! When disabled, all functions are no-ops and LKL_READY is always false.
//!
//! Since fase 3, this module also publishes its `syscall` fn to the
//! hybrid backend in `sotos-linux-abi::lkl` so that HybridBackend can
//! route whitelisted calls without holding a direct FFI dependency.

use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) static LKL_READY: AtomicBool = AtomicBool::new(false);

#[cfg(lkl)]
extern "C" {
    fn lkl_bridge_init() -> i32;
    fn lkl_bridge_syscall(x86_nr: u64, args: *const u64, as_cap: u64, pid: u64) -> i64;
    fn lkl_bridge_ready() -> i32;
}

pub(crate) fn init() {
    // Register our FFI shim with the backend crate so HybridBackend can
    // dispatch without holding a direct link against lkl_bridge_*.
    // Safe to call in both lkl and non-lkl builds — under `not(lkl)` the
    // registered fn just returns -ENOSYS.
    sotos_linux_abi::lkl::set_lkl_syscall_fn(syscall);

    #[cfg(lkl)]
    unsafe {
        let rc = lkl_bridge_init();
        if rc == 0 {
            crate::framebuffer::print(b"LKL: boot thread launched (needs SMP)\n");
        } else {
            crate::framebuffer::print(b"LKL: init failed\n");
        }
    }
    #[cfg(not(lkl))]
    {
        // LKL disabled — build with SOTOS_LKL=1 to enable.
    }
}

#[cfg(lkl)]
pub(crate) fn poll_ready() {
    if !LKL_READY.load(Ordering::Acquire) {
        unsafe {
            if lkl_bridge_ready() != 0 {
                LKL_READY.store(true, Ordering::Release);
                sotos_linux_abi::lkl::mark_lkl_ready();
                crate::framebuffer::print(b"LKL: forwarding activated\n");
            }
        }
    }
}
#[cfg(not(lkl))]
pub(crate) fn poll_ready() {}

/// FFI entry into LKL. Wraps `lkl_bridge_syscall` with a FS_BASE guard so
/// callers from non-LKL-registered threads (init main, child_handler IPC
/// thread, run_linux_test, etc.) don't trip `lkl_cpu_put: unbalanced put`.
///
/// Why this is needed: LKL's `lkl_cpu_put` validates that the thread
/// releasing the global BKL is the same one that acquired it, using
/// `lkl_thread_self()` — which reads FS_BASE MSR in `host_ops.c`. Threads
/// created via `lkl_thread_create` set FS_BASE to `&ctx->slot` (a unique
/// static address). Callers from outside LKL have whatever FS_BASE the
/// sotOS kernel left them with — typically 0, which collides across
/// threads and breaks the owner check.
///
/// The fix is to pin FS_BASE to a unique-per-thread, stable-per-call
/// value for the duration of the LKL dispatch. Stack pointer, page-
/// aligned, is perfect: different threads have different stacks, and RSP
/// within one function call is stable across it.
#[cfg(lkl)]
#[inline]
pub(crate) fn syscall(nr: u64, args: &[u64; 6], as_cap: u64, pid: usize) -> i64 {
    let saved_fs = sotos_common::sys::get_fs_base();

    // Only swap FS_BASE if the caller isn't already an LKL-registered
    // thread (those have FS_BASE pointing into their ctx->slot). We detect
    // "LKL-registered" heuristically: any non-zero FS_BASE we didn't set.
    // Our own markers are in arena/high-address range; LKL slots are
    // similarly high-arena. A FS_BASE of 0 is the clearest "unregistered"
    // signal and the only case where cpu_put will definitely misbehave.
    let need_swap = saved_fs == 0;
    if need_swap {
        let mut rsp: u64;
        unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp); }
        // Page-align so two calls from the same stack region share a
        // marker (same thread → same identity). Different threads have
        // different stacks → different markers.
        let marker = rsp & !0xFFFu64;
        let _ = sotos_common::sys::set_fs_base(marker);
    }

    let ret = unsafe { lkl_bridge_syscall(nr, args.as_ptr(), as_cap, pid as u64) };

    if need_swap {
        let _ = sotos_common::sys::set_fs_base(saved_fs);
    }
    ret
}
#[cfg(not(lkl))]
#[inline]
pub(crate) fn syscall(nr: u64, args: &[u64; 6], as_cap: u64, pid: usize) -> i64 {
    let _ = (nr, args, as_cap, pid); -38 // -ENOSYS
}
