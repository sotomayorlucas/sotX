//! Linux syscall to SOT primitive translation layer.
//!
//! Each Linux syscall is mapped to its equivalent SOT domain operation.
//! The translation falls into three tiers:
//!
//! 1. **Direct** -- 1:1 mapping to a SOT primitive (e.g., read/write to SO invocation).
//! 2. **Composite** -- Linux semantics composed from multiple SOT primitives
//!    (e.g., `clone(CLONE_THREAD)` = domain thread creation + shared FD group).
//! 3. **Forwarded** -- no native equivalent; forwarded to LKL domain for emulation.

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
