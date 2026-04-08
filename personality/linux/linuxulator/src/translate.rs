//! Linux syscall to SOT primitive translation layer.
//!
//! Each Linux syscall is mapped to its equivalent SOT domain operation.
//! The translation falls into three tiers:
//!
//! 1. **Direct** -- 1:1 mapping to a SOT primitive (e.g., read/write to SO invocation).
//! 2. **Composite** -- Linux semantics composed from multiple SOT primitives
//!    (e.g., `clone(CLONE_THREAD)` = domain thread creation + shared FD group).
//! 3. **Forwarded** -- no native equivalent; forwarded to LKL domain for emulation.
//!
//! Errno and signal translation is provided by [`crate::errno_map`] and
//! [`crate::signal_map`], ported from FreeBSD's Linuxulator.

use crate::errno_map;
use crate::signal_map;
use crate::syscall_table::{self, SyscallCategory};

/// Arguments to a Linux syscall (rdi, rsi, rdx, r10, r8, r9).
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
}

impl SyscallArgs {
    pub const fn new(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Self {
        Self { a0, a1, a2, a3, a4, a5 }
    }
}

// ---------------------------------------------------------------------------
// Errno and signal translation (delegates to errno_map / signal_map)
// ---------------------------------------------------------------------------

/// Translate a BSD errno (positive) to a Linux errno (positive).
///
/// This is the function the process server calls before returning an error
/// from a BSD-side operation to a Linux process. The Linux process expects
/// the negated Linux errno in RAX.
///
/// # Example
/// ```
/// let bsd_err = 61; // BSD ECONNREFUSED
/// let linux_err = translate_errno(bsd_err);
/// assert_eq!(linux_err, 111); // Linux ECONNREFUSED
/// ```
pub const fn translate_errno(bsd_errno: i32) -> i32 {
    errno_map::bsd_to_linux_errno(bsd_errno)
}

/// Translate a Linux errno (positive, from a Linux process argument) to BSD.
pub const fn translate_errno_to_bsd(linux_errno: i32) -> i32 {
    errno_map::linux_to_bsd_errno(linux_errno)
}

/// Translate a Linux signal number to a BSD signal number.
///
/// Called when a Linux process sends a signal (e.g., `kill(pid, LINUX_SIGUSR1)`).
/// The process server must translate the signal number before dispatching to
/// the BSD-side signal infrastructure.
pub const fn translate_signal(linux_sig: i32) -> i32 {
    signal_map::linux_to_bsd_signal(linux_sig)
}

/// Translate a BSD signal number to a Linux signal number.
///
/// Called when delivering a signal to a Linux process (e.g., SIGCHLD from
/// a child exit). The Linux process expects Linux signal numbering.
pub const fn translate_signal_to_linux(bsd_sig: i32) -> i32 {
    signal_map::bsd_to_linux_signal(bsd_sig)
}

// ---------------------------------------------------------------------------
// FreeBSD reference: which FreeBSD function handles each Linux syscall
// ---------------------------------------------------------------------------

/// Describes how FreeBSD's Linuxulator handles a specific syscall.
///
/// Extracted from `vendor/freebsd-linuxulator/linux_sysent.c`. This is
/// reference data for developers -- it documents where to look in FreeBSD
/// source for the canonical translation logic.
#[derive(Debug, Clone, Copy)]
pub struct FreeBsdReference {
    /// Linux syscall number.
    pub nr: u64,
    /// FreeBSD handler function name (e.g., "linux_open" or "sys_read").
    pub handler: &'static str,
    /// Whether FreeBSD uses a native BSD syscall directly (`sys_*`) or
    /// a Linux-specific translation wrapper (`linux_*`).
    pub is_native_passthrough: bool,
}

/// Look up the FreeBSD handler for a Linux syscall number.
///
/// Returns `None` for unassigned syscall numbers (gaps in the table).
pub fn freebsd_reference(nr: u64) -> Option<FreeBsdReference> {
    // Table extracted from vendor/freebsd-linuxulator/linux_sysent.c.
    // Only the first 335 entries (classic syscalls) are included;
    // newer syscalls (424+) are appended at the end.
    let (handler, native) = match nr {
        0 => ("sys_read", true),
        1 => ("linux_write", false),
        2 => ("linux_open", false),
        3 => ("sys_close", true),
        4 => ("linux_newstat", false),
        5 => ("linux_newfstat", false),
        6 => ("linux_newlstat", false),
        7 => ("linux_poll", false),
        8 => ("linux_lseek", false),
        9 => ("linux_mmap2", false),
        10 => ("linux_mprotect", false),
        11 => ("sys_munmap", true),
        12 => ("linux_brk", false),
        13 => ("linux_rt_sigaction", false),
        14 => ("linux_rt_sigprocmask", false),
        15 => ("linux_rt_sigreturn", false),
        16 => ("linux_ioctl", false),
        17 => ("linux_pread", false),
        18 => ("linux_pwrite", false),
        19 => ("sys_readv", true),
        20 => ("linux_writev", false),
        21 => ("linux_access", false),
        22 => ("linux_pipe", false),
        23 => ("linux_select", false),
        24 => ("sys_sched_yield", true),
        25 => ("linux_mremap", false),
        26 => ("linux_msync", false),
        27 => ("linux_mincore", false),
        28 => ("linux_madvise", false),
        29 => ("linux_shmget", false),
        30 => ("linux_shmat", false),
        31 => ("linux_shmctl", false),
        32 => ("sys_dup", true),
        33 => ("sys_dup2", true),
        34 => ("linux_pause", false),
        35 => ("linux_nanosleep", false),
        36 => ("linux_getitimer", false),
        37 => ("linux_alarm", false),
        38 => ("linux_setitimer", false),
        39 => ("linux_getpid", false),
        40 => ("linux_sendfile", false),
        41 => ("linux_socket", false),
        42 => ("linux_connect", false),
        43 => ("linux_accept", false),
        44 => ("linux_sendto", false),
        45 => ("linux_recvfrom", false),
        46 => ("linux_sendmsg", false),
        47 => ("linux_recvmsg", false),
        48 => ("linux_shutdown", false),
        49 => ("linux_bind", false),
        50 => ("linux_listen", false),
        51 => ("linux_getsockname", false),
        52 => ("linux_getpeername", false),
        53 => ("linux_socketpair", false),
        54 => ("linux_setsockopt", false),
        55 => ("linux_getsockopt", false),
        56 => ("linux_clone", false),
        57 => ("linux_fork", false),
        58 => ("linux_vfork", false),
        59 => ("linux_execve", false),
        60 => ("linux_exit", false),
        61 => ("linux_wait4", false),
        62 => ("linux_kill", false),
        63 => ("linux_newuname", false),
        64 => ("linux_semget", false),
        65 => ("sys_semop", true),
        66 => ("linux_semctl", false),
        67 => ("linux_shmdt", false),
        68 => ("linux_msgget", false),
        69 => ("linux_msgsnd", false),
        70 => ("linux_msgrcv", false),
        71 => ("linux_msgctl", false),
        72 => ("linux_fcntl", false),
        73 => ("sys_flock", true),
        74 => ("sys_fsync", true),
        75 => ("linux_fdatasync", false),
        76 => ("linux_truncate", false),
        77 => ("linux_ftruncate", false),
        78 => ("linux_getdents", false),
        79 => ("linux_getcwd", false),
        80 => ("linux_chdir", false),
        81 => ("sys_fchdir", true),
        82 => ("linux_rename", false),
        83 => ("linux_mkdir", false),
        84 => ("linux_rmdir", false),
        85 => ("linux_creat", false),
        86 => ("linux_link", false),
        87 => ("linux_unlink", false),
        88 => ("linux_symlink", false),
        89 => ("linux_readlink", false),
        90 => ("linux_chmod", false),
        91 => ("sys_fchmod", true),
        92 => ("linux_chown", false),
        93 => ("sys_fchown", true),
        94 => ("linux_lchown", false),
        95 => ("sys_umask", true),
        96 => ("sys_gettimeofday", true),
        97 => ("linux_getrlimit", false),
        98 => ("sys_getrusage", true),
        99 => ("linux_sysinfo", false),
        100 => ("linux_times", false),
        101 => ("linux_ptrace", false),
        102 => ("linux_getuid", false),
        103 => ("linux_syslog", false),
        104 => ("linux_getgid", false),
        105 => ("sys_setuid", true),
        106 => ("sys_setgid", true),
        107 => ("sys_geteuid", true),
        108 => ("sys_getegid", true),
        109 => ("sys_setpgid", true),
        110 => ("linux_getppid", false),
        111 => ("sys_getpgrp", true),
        112 => ("sys_setsid", true),
        113 => ("sys_setreuid", true),
        114 => ("sys_setregid", true),
        115 => ("linux_getgroups", false),
        116 => ("linux_setgroups", false),
        117 => ("sys_setresuid", true),
        118 => ("sys_getresuid", true),
        119 => ("sys_setresgid", true),
        120 => ("sys_getresgid", true),
        121 => ("sys_getpgid", true),
        122 => ("linux_setfsuid", false),
        123 => ("linux_setfsgid", false),
        124 => ("linux_getsid", false),
        125 => ("linux_capget", false),
        126 => ("linux_capset", false),
        127 => ("linux_rt_sigpending", false),
        128 => ("linux_rt_sigtimedwait", false),
        129 => ("linux_rt_sigqueueinfo", false),
        130 => ("linux_rt_sigsuspend", false),
        131 => ("linux_sigaltstack", false),
        132 => ("linux_utime", false),
        133 => ("linux_mknod", false),
        135 => ("linux_personality", false),
        137 => ("linux_statfs", false),
        138 => ("linux_fstatfs", false),
        140 => ("linux_getpriority", false),
        141 => ("sys_setpriority", true),
        142 => ("linux_sched_setparam", false),
        143 => ("linux_sched_getparam", false),
        144 => ("linux_sched_setscheduler", false),
        145 => ("linux_sched_getscheduler", false),
        146 => ("linux_sched_get_priority_max", false),
        147 => ("linux_sched_get_priority_min", false),
        148 => ("linux_sched_rr_get_interval", false),
        149 => ("sys_mlock", true),
        150 => ("sys_munlock", true),
        151 => ("sys_mlockall", true),
        152 => ("sys_munlockall", true),
        153 => ("linux_vhangup", false),
        157 => ("linux_prctl", false),
        158 => ("linux_arch_prctl", false),
        160 => ("linux_setrlimit", false),
        161 => ("sys_chroot", true),
        162 => ("sys_sync", true),
        163 => ("sys_acct", true),
        164 => ("sys_settimeofday", true),
        165 => ("linux_mount", false),
        166 => ("linux_umount", false),
        167 => ("sys_swapon", true),
        168 => ("linux_swapoff", false),
        169 => ("linux_reboot", false),
        170 => ("linux_sethostname", false),
        171 => ("linux_setdomainname", false),
        186 => ("linux_gettid", false),
        200 => ("linux_tkill", false),
        201 => ("linux_time", false),
        202 => ("linux_sys_futex", false),
        203 => ("linux_sched_setaffinity", false),
        204 => ("linux_sched_getaffinity", false),
        213 => ("linux_epoll_create", false),
        217 => ("linux_getdents64", false),
        218 => ("linux_set_tid_address", false),
        222 => ("linux_timer_create", false),
        223 => ("linux_timer_settime", false),
        224 => ("linux_timer_gettime", false),
        225 => ("linux_timer_getoverrun", false),
        226 => ("linux_timer_delete", false),
        227 => ("linux_clock_settime", false),
        228 => ("linux_clock_gettime", false),
        229 => ("linux_clock_getres", false),
        230 => ("linux_clock_nanosleep", false),
        231 => ("linux_exit_group", false),
        232 => ("linux_epoll_wait", false),
        233 => ("linux_epoll_ctl", false),
        234 => ("linux_tgkill", false),
        235 => ("linux_utimes", false),
        247 => ("linux_waitid", false),
        257 => ("linux_openat", false),
        258 => ("linux_mkdirat", false),
        259 => ("linux_mknodat", false),
        260 => ("linux_fchownat", false),
        261 => ("linux_futimesat", false),
        262 => ("linux_newfstatat", false),
        263 => ("linux_unlinkat", false),
        264 => ("linux_renameat", false),
        265 => ("linux_linkat", false),
        266 => ("linux_symlinkat", false),
        267 => ("linux_readlinkat", false),
        268 => ("linux_fchmodat", false),
        269 => ("linux_faccessat", false),
        270 => ("linux_pselect6", false),
        271 => ("linux_ppoll", false),
        272 => ("linux_unshare", false),
        273 => ("linux_set_robust_list", false),
        274 => ("linux_get_robust_list", false),
        275 => ("linux_splice", false),
        280 => ("linux_utimensat", false),
        281 => ("linux_epoll_pwait", false),
        283 => ("linux_timerfd_create", false),
        284 => ("linux_eventfd", false),
        285 => ("linux_fallocate", false),
        286 => ("linux_timerfd_settime", false),
        287 => ("linux_timerfd_gettime", false),
        288 => ("linux_accept4", false),
        289 => ("linux_signalfd4", false),
        290 => ("linux_eventfd2", false),
        291 => ("linux_epoll_create1", false),
        292 => ("linux_dup3", false),
        293 => ("linux_pipe2", false),
        294 => ("linux_inotify_init1", false),
        295 => ("linux_preadv", false),
        296 => ("linux_pwritev", false),
        302 => ("linux_prlimit64", false),
        306 => ("linux_syncfs", false),
        316 => ("linux_renameat2", false),
        318 => ("linux_getrandom", false),
        319 => ("linux_memfd_create", false),
        322 => ("linux_execveat", false),
        324 => ("linux_membarrier", false),
        332 => ("linux_statx", false),
        334 => ("linux_rseq", false),
        424 => ("linux_pidfd_send_signal", false),
        425 => ("linux_io_uring_setup", false),
        426 => ("linux_io_uring_enter", false),
        427 => ("linux_io_uring_register", false),
        434 => ("linux_pidfd_open", false),
        435 => ("linux_clone3", false),
        436 => ("linux_close_range", false),
        437 => ("linux_openat2", false),
        438 => ("linux_pidfd_getfd", false),
        439 => ("linux_faccessat2", false),
        441 => ("linux_epoll_pwait2", false),
        449 => ("linux_futex_waitv", false),
        _ => return None,
    };
    Some(FreeBsdReference {
        nr,
        handler,
        is_native_passthrough: native,
    })
}

/// How a Linux syscall should be handled by the SOT process server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslateResult {
    /// Direct SOT primitive invocation. `op` identifies the SOT operation.
    Direct { op: SotOp },
    /// Must be composed from multiple SOT primitives. The process server
    /// interprets the `composite` variant to issue the right sequence.
    Composite { op: SotOp },
    /// Forward to LKL domain for full Linux-kernel emulation.
    ForwardToLkl,
    /// Return a fixed value without any domain interaction (e.g., getpid).
    Immediate { value: i64 },
    /// Stub: return -ENOSYS. The syscall is known but intentionally unsupported.
    Stub,
    /// Unknown syscall number.
    Unknown,
}

/// SOT domain operation identifiers.
///
/// Each variant maps to a specific SOT IPC message or kernel primitive
/// that implements the semantics of one or more Linux syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SotOp {
    // --- File/SO operations (VFS domain IPC) ---
    /// SO read invocation.
    SoRead,
    /// SO write invocation.
    SoWrite,
    /// SO open (create handle to named SO).
    SoOpen,
    /// SO close (drop handle).
    SoClose,
    /// SO stat (query SO metadata).
    SoStat,
    /// SO seek within a stream SO.
    SoSeek,
    /// SO ioctl-equivalent invocation.
    SoInvoke,
    /// SO directory listing.
    SoDirList,
    /// SO create (file, directory, etc.).
    SoCreate,
    /// SO delete (unlink, rmdir).
    SoDelete,
    /// SO rename/move.
    SoRename,
    /// SO link (hard/symbolic).
    SoLink,
    /// SO metadata change (chmod, chown, utimes).
    SoMetadata,
    /// SO truncate.
    SoTruncate,
    /// SO sync (fsync/fdatasync).
    SoSync,
    /// SO duplicate handle (dup/dup2/dup3/fcntl(F_DUPFD)).
    SoDupHandle,
    /// SO splice/copy between two SOs.
    SoSplice,

    // --- Memory operations (VMM domain / kernel) ---
    /// Map anonymous or file-backed pages.
    MemMap,
    /// Change page protection.
    MemProtect,
    /// Unmap pages.
    MemUnmap,
    /// Adjust program break.
    MemBrk,
    /// Remap existing mapping.
    MemRemap,
    /// Memory advice hint.
    MemAdvise,
    /// Lock pages in RAM.
    MemLock,
    /// Create anonymous file (memfd).
    MemAnonFile,

    // --- Process / domain operations ---
    /// Create child domain (fork semantics, CoW page tables).
    DomainFork,
    /// Create thread within current domain (clone with CLONE_THREAD).
    DomainThreadCreate,
    /// Replace domain image (execve semantics).
    DomainExec,
    /// Terminate current thread.
    DomainExit,
    /// Terminate all threads in domain.
    DomainExitGroup,
    /// Wait for child domain state change.
    DomainWait,
    /// Set domain policy (prctl equivalent).
    DomainPolicy,
    /// Set architecture-specific state (arch_prctl).
    DomainArchState,
    /// Set process group / session.
    DomainSetGroup,
    /// Unshare namespaces (no-op in SOT but recognized).
    DomainUnshare,

    // --- Signal operations ---
    /// Register signal handler.
    SigAction,
    /// Modify signal mask.
    SigMask,
    /// Return from signal handler.
    SigReturn,
    /// Send signal to domain/thread.
    SigSend,
    /// Set alternate signal stack.
    SigAltStack,
    /// Wait for signal.
    SigWait,

    // --- Network (net domain IPC) ---
    /// Create socket SO.
    NetSocket,
    /// Connect socket.
    NetConnect,
    /// Bind socket.
    NetBind,
    /// Listen on socket.
    NetListen,
    /// Accept connection.
    NetAccept,
    /// Send data.
    NetSend,
    /// Receive data.
    NetRecv,
    /// Socket option get/set.
    NetSockOpt,
    /// Shutdown socket.
    NetShutdown,
    /// Query socket name/peer.
    NetSockInfo,

    // --- IPC / event notification ---
    /// Create pipe pair.
    IpcPipe,
    /// Channel-based event wait (replaces epoll/select/poll).
    IpcEventWait,
    /// Channel-based event control (replaces epoll_ctl).
    IpcEventCtl,
    /// Create event notification channel (replaces epoll_create).
    IpcEventCreate,
    /// Futex wait/wake.
    IpcFutex,
    /// SysV shared memory.
    IpcShm,
    /// SysV semaphore.
    IpcSem,
    /// SysV message queue.
    IpcMsg,
    /// Eventfd counter.
    IpcEventFd,
    /// Inotify file watch.
    IpcInotify,
    /// Create socket pair.
    IpcSocketPair,

    // --- Scheduling ---
    /// Yield current timeslice.
    SchedYield,
    /// Set/get scheduling parameters.
    SchedParam,
    /// Set/get CPU affinity.
    SchedAffinity,

    // --- Time ---
    /// Read clock.
    TimeGetClock,
    /// Sleep.
    TimeSleep,
    /// Timer create/set/get.
    TimeTimer,
    /// Get/set interval timer.
    TimeItimer,

    // --- System info ---
    /// Query domain identity (pid/tid).
    SysIdentity,
    /// Query system information (uname/sysinfo).
    SysInfo,
    /// Resource limit get/set.
    SysRlimit,
    /// Random bytes.
    SysRandom,
    /// Set tid address / robust list.
    SysTidAddr,
    /// Filesystem stat (statfs/fstatfs).
    SysFsStat,

    // --- Identity / credentials ---
    /// Get/set uid/gid/groups.
    IdentCreds,
    /// Get/set capabilities (SOT caps, not Linux caps).
    IdentCaps,

    // --- Mount ---
    /// Mount/unmount filesystem (VFS domain IPC).
    VfsMount,
}

/// Translate a Linux syscall number + arguments to a SOT operation.
///
/// This is the central dispatch point. The process server calls this to
/// determine how to handle each intercepted Linux syscall.
pub fn translate(nr: u64, _args: &SyscallArgs) -> TranslateResult {
    match syscall_table::lookup(nr) {
        None => TranslateResult::Unknown,
        Some(entry) => translate_known(entry.nr, entry.category),
    }
}

/// Internal: translate a known syscall by number and category.
fn translate_known(nr: u64, cat: SyscallCategory) -> TranslateResult {
    use TranslateResult::*;
    use SotOp::*;

    match nr {
        // ===== File I/O (direct SO operations) =====
        0 => Direct { op: SoRead },       // read
        1 => Direct { op: SoWrite },      // write
        2 => Direct { op: SoOpen },       // open
        3 => Direct { op: SoClose },      // close
        4 | 5 | 6 => Direct { op: SoStat }, // stat/fstat/lstat
        7 => Direct { op: IpcEventWait }, // poll -> event wait
        8 => Direct { op: SoSeek },       // lseek
        16 => Direct { op: SoInvoke },    // ioctl -> SO invocation
        17 => Direct { op: SoRead },      // pread64
        18 => Direct { op: SoWrite },     // pwrite64
        19 => Direct { op: SoRead },      // readv
        20 => Direct { op: SoWrite },     // writev
        21 => Direct { op: SoStat },      // access
        32 | 33 | 292 => Direct { op: SoDupHandle }, // dup/dup2/dup3
        40 => Direct { op: SoSplice },    // sendfile
        72 => Direct { op: SoDupHandle }, // fcntl (mostly F_DUPFD, F_GETFL, etc.)
        73 => Stub,                       // flock
        74 | 75 => Direct { op: SoSync }, // fsync/fdatasync
        76 | 77 => Direct { op: SoTruncate }, // truncate/ftruncate
        78 | 217 => Direct { op: SoDirList }, // getdents/getdents64
        79 => Immediate { value: 0 },     // getcwd (process-local)
        80 | 81 => Direct { op: DomainPolicy }, // chdir/fchdir
        82 => Direct { op: SoRename },    // rename
        83 => Direct { op: SoCreate },    // mkdir
        84 => Direct { op: SoDelete },    // rmdir
        85 => Direct { op: SoCreate },    // creat
        86 => Direct { op: SoLink },      // link
        87 => Direct { op: SoDelete },    // unlink
        88 => Direct { op: SoLink },      // symlink
        89 => Direct { op: SoStat },      // readlink
        90 | 91 | 92 | 93 | 94 => Direct { op: SoMetadata }, // chmod/fchmod/chown/fchown/lchown
        95 => Immediate { value: 0o022 }, // umask
        133 => Stub,                      // mknod
        257 => Direct { op: SoOpen },     // openat
        258 => Direct { op: SoCreate },   // mkdirat
        259 => Stub,                      // mknodat
        260 | 268 => Direct { op: SoMetadata }, // fchownat/fchmodat
        261 | 280 => Direct { op: SoMetadata }, // futimesat/utimensat
        262 => Direct { op: SoStat },     // newfstatat
        263 => Direct { op: SoDelete },   // unlinkat
        264 | 316 => Direct { op: SoRename }, // renameat/renameat2
        265 => Direct { op: SoLink },     // linkat
        266 => Direct { op: SoLink },     // symlinkat
        267 => Direct { op: SoStat },     // readlinkat
        269 | 439 => Direct { op: SoStat }, // faccessat/faccessat2
        275 | 276 | 278 => Direct { op: SoSplice }, // splice/tee/vmsplice
        277 => Direct { op: SoSync },     // sync_file_range
        285 => Stub,                      // fallocate
        295 | 296 | 327 | 328 => Direct { op: SoRead }, // preadv/pwritev/preadv2/pwritev2
        303 | 304 => ForwardToLkl,        // name_to_handle_at, open_by_handle_at
        326 => Direct { op: SoSplice },   // copy_file_range
        332 => Direct { op: SoStat },     // statx

        // ===== Memory =====
        9 => Direct { op: MemMap },
        10 => Direct { op: MemProtect },
        11 => Direct { op: MemUnmap },
        12 => Direct { op: MemBrk },
        25 => Direct { op: MemRemap },
        26 => Stub,                       // msync
        27 => Stub,                       // mincore
        28 => Direct { op: MemAdvise },
        149 | 150 | 151 | 152 | 325 => Direct { op: MemLock }, // mlock/munlock/mlockall/munlockall/mlock2
        216 => ForwardToLkl,              // remap_file_pages (deprecated)
        237 | 238 | 239 | 279 => ForwardToLkl, // NUMA: mbind, set/get_mempolicy, move_pages
        319 => Direct { op: MemAnonFile }, // memfd_create
        329 => Direct { op: MemProtect },  // pkey_mprotect
        330 | 331 => Stub,                 // pkey_alloc/free
        440 => Direct { op: MemAdvise },   // process_madvise
        447 => Direct { op: MemAnonFile }, // memfd_secret
        453 => ForwardToLkl,               // map_shadow_stack
        462 => Direct { op: MemProtect },  // mseal

        // ===== Process / domain =====
        56 => Composite { op: DomainThreadCreate }, // clone (may be fork or thread)
        57 => Composite { op: DomainFork },  // fork
        58 => Composite { op: DomainFork },  // vfork
        59 => Composite { op: DomainExec },  // execve
        60 => Direct { op: DomainExit },     // exit
        61 => Direct { op: DomainWait },     // wait4
        62 => Direct { op: SigSend },        // kill
        109 | 111 | 112 | 121 | 124 => Direct { op: DomainSetGroup }, // setpgid/getpgrp/setsid/getpgid/getsid
        135 => Stub,                         // personality
        157 => Direct { op: DomainPolicy },  // prctl
        158 => Direct { op: DomainArchState }, // arch_prctl
        231 => Direct { op: DomainExitGroup }, // exit_group
        247 => Direct { op: DomainWait },    // waitid
        272 => Stub,                         // unshare
        322 => Composite { op: DomainExec }, // execveat
        435 => Stub,                         // clone3 (return -ENOSYS, fallback to clone)

        // ===== Signals =====
        13 => Direct { op: SigAction },
        14 => Direct { op: SigMask },
        15 => Direct { op: SigReturn },
        34 => Direct { op: SigWait },        // pause
        127 => Direct { op: SigMask },       // rt_sigpending
        128 => Direct { op: SigWait },       // rt_sigtimedwait
        129 => Direct { op: SigSend },       // rt_sigqueueinfo
        130 => Direct { op: SigWait },       // rt_sigsuspend
        131 => Direct { op: SigAltStack },
        200 | 234 => Direct { op: SigSend }, // tkill/tgkill
        282 | 289 => Stub,                   // signalfd/signalfd4
        424 => Direct { op: SigSend },       // pidfd_send_signal

        // ===== Network =====
        41 => Direct { op: NetSocket },
        42 => Direct { op: NetConnect },
        43 | 288 => Direct { op: NetAccept }, // accept/accept4
        44 => Direct { op: NetSend },
        45 => Direct { op: NetRecv },
        46 => Direct { op: NetSend },         // sendmsg
        47 => Direct { op: NetRecv },         // recvmsg
        48 => Direct { op: NetShutdown },
        49 => Direct { op: NetBind },
        50 => Direct { op: NetListen },
        51 | 52 => Direct { op: NetSockInfo }, // getsockname/getpeername
        53 => Direct { op: IpcSocketPair },    // socketpair
        54 | 55 => Direct { op: NetSockOpt },  // setsockopt/getsockopt

        // ===== IPC / event notification =====
        22 | 293 => Direct { op: IpcPipe },    // pipe/pipe2
        23 | 270 => Direct { op: IpcEventWait }, // select/pselect6
        271 => Direct { op: IpcEventWait },    // ppoll
        213 | 291 => Direct { op: IpcEventCreate }, // epoll_create/epoll_create1
        232 | 281 | 441 => Direct { op: IpcEventWait }, // epoll_wait/epoll_pwait/epoll_pwait2
        233 => Direct { op: IpcEventCtl },     // epoll_ctl
        29 | 30 | 31 | 67 => Direct { op: IpcShm }, // shmget/shmat/shmctl/shmdt
        64 | 65 | 66 => Direct { op: IpcSem },      // semget/semop/semctl
        68 | 69 | 70 | 71 => Direct { op: IpcMsg },  // msgget/msgsnd/msgrcv/msgctl
        202 | 449 | 454 | 455 | 456 => Direct { op: IpcFutex }, // futex/futex_waitv/wake/wait/requeue
        284 | 290 => Direct { op: IpcEventFd }, // eventfd/eventfd2
        253 | 254 | 255 | 294 => Direct { op: IpcInotify }, // inotify_*

        // ===== Scheduling =====
        24 => Direct { op: SchedYield },
        142 | 143 | 144 | 145 | 146 | 147 | 148 => Direct { op: SchedParam },
        203 | 204 => Direct { op: SchedAffinity },
        314 | 315 => Direct { op: SchedParam },

        // ===== Time =====
        35 | 230 => Direct { op: TimeSleep },  // nanosleep/clock_nanosleep
        36 | 38 => Direct { op: TimeItimer },  // getitimer/setitimer
        37 => Stub,                            // alarm
        96 | 164 => Direct { op: TimeGetClock }, // gettimeofday/settimeofday
        100 => Direct { op: TimeGetClock },    // times
        159 => ForwardToLkl,                   // adjtimex
        201 => Direct { op: TimeGetClock },    // time
        222 | 223 | 224 | 225 | 226 => Direct { op: TimeTimer }, // timer_*
        227 | 228 | 229 => Direct { op: TimeGetClock }, // clock_settime/gettime/getres
        235 => Direct { op: SoMetadata },      // utimes (file metadata)
        283 | 286 | 287 => Direct { op: TimeTimer }, // timerfd_*
        305 => ForwardToLkl,                   // clock_adjtime

        // ===== System info =====
        39 | 110 | 186 => Immediate { value: 0 }, // getpid/getppid/gettid (filled by caller)
        63 => Direct { op: SysInfo },          // uname
        97 | 160 | 302 => Direct { op: SysRlimit }, // getrlimit/setrlimit/prlimit64
        98 => Direct { op: SysInfo },          // getrusage
        99 => Direct { op: SysInfo },          // sysinfo
        101 => Stub,                           // ptrace
        103 => Stub,                           // syslog
        137 | 138 => Direct { op: SysFsStat }, // statfs/fstatfs
        155 => ForwardToLkl,                   // pivot_root
        161 => Stub,                           // chroot
        165 | 166 => Composite { op: VfsMount }, // mount/umount2
        167 | 168 => Stub,                     // swapon/swapoff
        169 => Stub,                           // reboot
        218 => Direct { op: SysTidAddr },      // set_tid_address
        221 => Stub,                           // fadvise64
        273 | 274 => Direct { op: SysTidAddr }, // set/get_robust_list
        318 => Direct { op: SysRandom },       // getrandom
        334 => Stub,                           // rseq

        // ===== Identity / credentials =====
        102 | 104 | 107 | 108 | 115 | 118 | 120 | 122 | 123 =>
            Immediate { value: 0 },            // getuid/getgid/geteuid/getegid/getgroups/getresuid/getresgid/setfsuid/setfsgid
        105 | 106 | 113 | 114 | 116 | 117 | 119 =>
            Stub,                              // setuid/setgid/setreuid/setregid/setgroups/setresuid/setresgid
        125 | 126 => Stub,                     // capget/capset

        // ===== Misc =====
        188..=199 => ForwardToLkl,             // xattr family
        206..=210 => ForwardToLkl,             // io_setup..io_cancel (AIO)
        212 => ForwardToLkl,                   // lookup_dcookie
        248 | 249 | 250 => ForwardToLkl,       // add_key/request_key/keyctl
        251 | 252 => Stub,                     // ioprio_set/get
        256 => ForwardToLkl,                   // migrate_pages
        425 | 426 | 427 => ForwardToLkl,       // io_uring_*
        434 => ForwardToLkl,                   // pidfd_open
        436 => Direct { op: SoClose },         // close_range
        437 => Direct { op: SoOpen },          // openat2
        438 => ForwardToLkl,                   // pidfd_getfd
        444 | 445 | 446 => Stub,               // landlock_*
        448 => Stub,                           // process_mrelease
        450 => ForwardToLkl,                   // set_mempolicy_home_node
        451 => Stub,                           // cachestat
        452 => Direct { op: SoMetadata },      // fchmodat2

        // ===== Obsolete =====
        _ => match cat {
            SyscallCategory::Obsolete => Stub,
            _ => ForwardToLkl,
        },
    }
}
