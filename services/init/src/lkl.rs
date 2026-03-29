//! LKL (Linux Kernel Library) FFI bindings.
//! Compiled only when SOTOS_LKL=1 (cfg(lkl)).
//! When disabled, all functions are no-ops and LKL_READY is always false.

use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) static LKL_READY: AtomicBool = AtomicBool::new(false);

#[cfg(lkl)]
extern "C" {
    fn lkl_bridge_init() -> i32;
    fn lkl_bridge_syscall(x86_nr: u64, args: *const u64, as_cap: u64, pid: u64) -> i64;
    fn lkl_bridge_ready() -> i32;
}

pub(crate) fn init() {
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
        crate::framebuffer::print(b"LKL: disabled (build with SOTOS_LKL=1)\n");
    }
}

#[cfg(lkl)]
pub(crate) fn poll_ready() {
    if !LKL_READY.load(Ordering::Acquire) {
        unsafe {
            if lkl_bridge_ready() != 0 {
                LKL_READY.store(true, Ordering::Release);
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
