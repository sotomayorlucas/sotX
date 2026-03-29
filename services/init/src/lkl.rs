//! LKL (Linux Kernel Library) FFI bindings.
//!
//! These functions are implemented in lkl/lkl_bridge.c and linked via liblkl_fused.a.
//! When LKL is not linked (liblkl_fused.a absent), these are dead code.

use core::sync::atomic::{AtomicBool, Ordering};

/// Set to true after lkl_bridge_init() succeeds.
pub(crate) static LKL_READY: AtomicBool = AtomicBool::new(false);

extern "C" {
    /// Initialize LKL: arena allocator + host ops + boot Linux kernel.
    /// Returns 0 on success, negative on failure.
    pub fn lkl_bridge_init() -> i32;

    /// Forward a Linux syscall to LKL with guest memory bridge.
    ///
    /// x86_nr: x86_64 syscall number
    /// args:   pointer to 6 u64 arguments
    /// as_cap: child address-space cap (for vm_read/vm_write)
    /// pid:    child process ID
    ///
    /// Returns Linux return value, or -ENOSYS if LKL not ready.
    pub fn lkl_bridge_syscall(
        x86_nr: u64,
        args: *const u64,
        as_cap: u64,
        pid: u64,
    ) -> i64;

    /// Check if LKL kernel has booted.
    pub fn lkl_bridge_ready() -> i32;
}

/// Initialize LKL. Called once from main.rs.
pub(crate) fn init() {
    unsafe {
        let rc = lkl_bridge_init();
        if rc == 0 && lkl_bridge_ready() != 0 {
            LKL_READY.store(true, Ordering::Release);
            crate::framebuffer::print(b"LKL: Linux kernel integrated\n");
        } else {
            crate::framebuffer::print(b"LKL: init failed or not linked\n");
        }
    }
}

/// Forward a syscall to LKL. Returns the Linux return value.
#[inline]
pub(crate) fn syscall(nr: u64, args: &[u64; 6], as_cap: u64, pid: usize) -> i64 {
    unsafe { lkl_bridge_syscall(nr, args.as_ptr(), as_cap, pid as u64) }
}
