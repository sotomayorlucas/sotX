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
/// Each entry is a raw x86_64 Linux syscall number. If LKL is not yet
/// ready (see [`crate::lkl::is_lkl_ready`]), the HybridBackend
/// transparently falls back to LUCAS regardless of the whitelist.
///
/// Phase 4 — info domain.
/// Stateless reads of kernel metadata that LKL can serve without any
/// virtio-blk/net passthrough. All safe to forward: if LKL returns
/// -ENOSYS (unregistered / not built), the dispatch layer falls back
/// to the LUCAS implementation.
///
///   63  SYS_UNAME         — kernel name/version/machine strings
///   96  SYS_GETTIMEOFDAY  — seconds + microseconds since epoch
///   99  SYS_SYSINFO       — uptime, loads, meminfo, procs
///   100 SYS_TIMES         — process CPU-time accounting
///   201 SYS_TIME          — seconds since epoch
///   228 SYS_CLOCK_GETTIME — per-clock_id time (non-vDSO path)
///   318 SYS_GETRANDOM     — kernel RNG draw
pub const LKL_WHITELIST: &[u64] = &[
    63,   // SYS_UNAME
    96,   // SYS_GETTIMEOFDAY
    99,   // SYS_SYSINFO
    100,  // SYS_TIMES
    201,  // SYS_TIME
    228,  // SYS_CLOCK_GETTIME
    318,  // SYS_GETRANDOM
];

/// Returns `true` if `nr` is in the LKL whitelist.
///
/// Exposed so the init-side dispatcher can pre-route whitelisted
/// arms to LKL without threading a full HybridBackend handle through
/// its context machinery. A linear scan is fine for the small sizes
/// we expect (<30 entries through phase 6); switch to perfect-hash
/// if it ever grows past that.
#[inline]
pub fn is_lkl_route(nr: u64) -> bool {
    let mut i = 0;
    while i < LKL_WHITELIST.len() {
        if LKL_WHITELIST[i] == nr { return true; }
        i += 1;
    }
    false
}

/// Which backend owns a filesystem path — used by path-taking
/// syscalls (open/openat, stat, access, mkdir, unlink, ...) to decide
/// whether to forward to LKL's tmpfs+ext4 or keep it in LUCAS's
/// ObjectStore + virtual /proc,/etc,/sys layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FsRoute {
    /// LUCAS owns the file (virtual /proc, /sys, /dev, initrd + sysroot
    /// binaries, /etc configs created by sysroot_init).
    Lucas,
    /// LKL owns the file (Linux tmpfs mounted at /, ext4 bind-mounted
    /// at /mnt, anything not claimed by LUCAS).
    Lkl,
}

/// Decide which backend owns an absolute filesystem path.
///
/// The policy at Phase 6 is *LUCAS-by-exception*: everything defaults
/// to LKL, but the tree branches LUCAS has historically owned stay on
/// LUCAS. That keeps Alpine/glibc binaries working (they read
/// `/etc/passwd`, `/lib/ld-musl-x86_64.so.1`, `/proc/self/maps`
/// etc from ObjectStore + virtual files), while new writes into
/// `/tmp/` and `/mnt/` reach the real Linux tmpfs / ext4 that LKL
/// manages.
///
/// A prefix match only counts when followed by either end-of-path or
/// `/`, so `/etc` and `/etc/passwd` both match `/etc` but `/etcetera`
/// does NOT (would route to LKL).
///
/// Relative paths are treated as LKL routed — CWD-based resolution
/// lives in LUCAS today (`GRP_CWD` spinlocks), and once a fd is open
/// its backend is tracked via `LKL_FDS`, so the CWD ambiguity only
/// matters for the initial path-based op.
pub fn fs_route_path(path: &[u8]) -> FsRoute {
    const LUCAS_PREFIXES: &[&[u8]] = &[
        b"/proc", b"/sys", b"/dev",
        b"/etc",
        b"/bin", b"/sbin",
        b"/lib", b"/lib64",
        b"/usr",
        b"/root",
        b"/run",
        b"/var",
        b"/sysroot",
    ];
    for pfx in LUCAS_PREFIXES {
        if path.len() >= pfx.len() && &path[..pfx.len()] == *pfx {
            let after = if path.len() == pfx.len() { b'/' } else { path[pfx.len()] };
            if after == b'/' {
                return FsRoute::Lucas;
            }
        }
    }
    FsRoute::Lkl
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
