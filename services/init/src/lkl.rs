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

#[inline]
pub(crate) fn syscall(nr: u64, args: &[u64; 6], as_cap: u64, pid: usize) -> i64 {
    #[cfg(lkl)]
    unsafe { lkl_bridge_syscall(nr, args.as_ptr(), as_cap, pid as u64) }
    #[cfg(not(lkl))]
    { let _ = (nr, args, as_cap, pid); -38 } // -ENOSYS
}
