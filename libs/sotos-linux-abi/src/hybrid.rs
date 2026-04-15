//! Hybrid backend — routes each Linux syscall to either LUCAS or LKL
//! based on a compile-time whitelist.
//!
//! At this wave the whitelist is empty, so every syscall falls through
//! to `LucasBackend`. Phase 4+ will grow the whitelist one domain at a
//! time (`info` → `net` → `fs` → `signal`/`task`).
//!
//! Gated on both `backend-lucas` and `backend-lkl` features.

use crate::ctx::SyscallCtx;
use crate::lkl::{LklBackend, is_lkl_ready};
use crate::lucas::LucasBackend;
use crate::trait_def::LinuxBackend;
use crate::types::{CapSet, Fd, LinuxPid, ProcessImage, Signal, SyscallResult};

/// Routing table: which syscalls should try LKL first.
///
/// Empty in wave-3 (phase 3 of the deprecation plan). Each entry is a
/// raw x86_64 Linux syscall number. If LKL is not yet ready (see
/// [`crate::lkl::is_lkl_ready`]), the HybridBackend transparently
/// falls back to LUCAS regardless of the whitelist.
///
/// Phase 4 seed (commented out; uncomment when LKL can actually serve
/// these without a virtio passthrough):
///
///   63,  // SYS_UNAME
///   99,  // SYS_SYSINFO
///   100, // SYS_TIMES
///   201, // SYS_TIME
///   228, // SYS_CLOCK_GETTIME
///   318, // SYS_GETRANDOM
pub const LKL_WHITELIST: &[u64] = &[];

/// Returns `true` if `nr` is in the LKL whitelist.
#[inline]
fn is_lkl_route(nr: u64) -> bool {
    // Linear scan is fine for the small whitelist sizes we expect
    // (<30 entries through phase 6). Switch to a perfect-hash or
    // sorted-bsearch layout if it ever grows past that.
    let mut i = 0;
    while i < LKL_WHITELIST.len() {
        if LKL_WHITELIST[i] == nr { return true; }
        i += 1;
    }
    false
}

/// Routes syscalls to LUCAS by default; forwards to LKL for the
/// whitelisted set when LKL has reported readiness.
pub struct HybridBackend {
    lucas: LucasBackend,
    lkl: LklBackend,
}

impl HybridBackend {
    pub const fn new() -> Self {
        Self { lucas: LucasBackend, lkl: LklBackend }
    }
}

impl LinuxBackend for HybridBackend {
    fn syscall(&self, ctx: &mut SyscallCtx, nr: u64, args: [u64; 6]) -> SyscallResult {
        if is_lkl_route(nr) && is_lkl_ready() {
            self.lkl.syscall(ctx, nr, args)
        } else {
            self.lucas.syscall(ctx, nr, args)
        }
    }

    fn create_process(&self, image: ProcessImage, caps: CapSet) -> Result<LinuxPid, SyscallResult> {
        // Process creation always flows through LUCAS (fork/exec
        // ownership stays there through the foreseeable future).
        self.lucas.create_process(image, caps)
    }

    fn signal(&self, pid: LinuxPid, sig: Signal) -> Result<(), SyscallResult> {
        self.lucas.signal(pid, sig)
    }

    fn fd_dup_into(&self, src: LinuxPid, dst: LinuxPid, fd: Fd) -> Result<(), SyscallResult> {
        self.lucas.fd_dup_into(src, dst, fd)
    }

    fn shutdown(&self) -> Result<(), SyscallResult> {
        // Best-effort: shut both down; report the first error encountered.
        let a = self.lkl.shutdown();
        let b = self.lucas.shutdown();
        a.and(b)
    }
}
