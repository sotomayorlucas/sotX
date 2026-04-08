//! Linux x86_64 syscall number to name/category mapping.
//!
//! Complete table of all ~335 Linux x86_64 syscall numbers as defined in
//! `arch/x86/entry/syscalls/syscall_64.tbl` (kernel 6.x). Each entry maps
//! a syscall number to its name string and category for dispatch routing.

/// Syscall category for routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallCategory {
    /// File I/O: open, read, write, close, stat, lseek, etc.
    File,
    /// Process lifecycle: fork, clone, execve, exit, wait, etc.
    Process,
    /// Memory management: mmap, munmap, brk, mprotect, etc.
    Memory,
    /// Networking: socket, bind, connect, send, recv, etc.
    Network,
    /// Signals: rt_sigaction, rt_sigprocmask, kill, etc.
    Signal,
    /// IPC: pipe, shmget, semget, msgget, futex, etc.
    Ipc,
    /// Scheduling: sched_setscheduler, yield, etc.
    Scheduler,
    /// Time: clock_gettime, nanosleep, timer_create, etc.
    Time,
    /// System info: uname, sysinfo, getrlimit, etc.
    System,
    /// Identity/credentials: getuid, setuid, capget, etc.
    Identity,
    /// Extended attributes, key management, misc.
    Misc,
    /// Deprecated or obsolete syscalls.
    Obsolete,
}

/// A single syscall table entry.
#[derive(Debug, Clone, Copy)]
pub struct SyscallEntry {
    pub nr: u64,
    pub name: &'static str,
    pub category: SyscallCategory,
}

// ---------------------------------------------------------------------------
// File I/O syscalls
// ---------------------------------------------------------------------------

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_SENDFILE: u64 = 40;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_FLOCK: u64 = 73;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FDATASYNC: u64 = 75;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_GETDENTS: u64 = 78;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_FCHDIR: u64 = 81;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_CREAT: u64 = 85;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_FCHOWN: u64 = 93;
pub const SYS_LCHOWN: u64 = 94;
pub const SYS_UMASK: u64 = 95;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_FALLOCATE: u64 = 285;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_MKNODAT: u64 = 259;
pub const SYS_FCHOWNAT: u64 = 260;
pub const SYS_FUTIMESAT: u64 = 261;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_LINKAT: u64 = 265;
pub const SYS_SYMLINKAT: u64 = 266;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FCHMODAT: u64 = 268;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_SPLICE: u64 = 275;
pub const SYS_TEE: u64 = 276;
pub const SYS_SYNC_FILE_RANGE: u64 = 277;
pub const SYS_VMSPLICE: u64 = 278;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_DUP3: u64 = 292;
pub const SYS_PREADV: u64 = 295;
pub const SYS_PWRITEV: u64 = 296;
pub const SYS_NAME_TO_HANDLE_AT: u64 = 303;
pub const SYS_OPEN_BY_HANDLE_AT: u64 = 304;
pub const SYS_RENAMEAT2: u64 = 316;
pub const SYS_COPY_FILE_RANGE: u64 = 326;
pub const SYS_PREADV2: u64 = 327;
pub const SYS_PWRITEV2: u64 = 328;
pub const SYS_STATX: u64 = 332;
pub const SYS_FACCESSAT2: u64 = 439;

// ---------------------------------------------------------------------------
// Memory management syscalls
// ---------------------------------------------------------------------------

pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_MREMAP: u64 = 25;
pub const SYS_MSYNC: u64 = 26;
pub const SYS_MINCORE: u64 = 27;
pub const SYS_MADVISE: u64 = 28;
pub const SYS_MLOCK: u64 = 149;
pub const SYS_MUNLOCK: u64 = 150;
pub const SYS_MLOCKALL: u64 = 151;
pub const SYS_MUNLOCKALL: u64 = 152;
pub const SYS_REMAP_FILE_PAGES: u64 = 216;
pub const SYS_MBIND: u64 = 237;
pub const SYS_SET_MEMPOLICY: u64 = 238;
pub const SYS_GET_MEMPOLICY: u64 = 239;
pub const SYS_MOVE_PAGES: u64 = 279;
pub const SYS_MEMFD_CREATE: u64 = 319;
pub const SYS_MLOCK2: u64 = 325;
pub const SYS_PROCESS_MADVISE: u64 = 440;

// ---------------------------------------------------------------------------
// Process lifecycle syscalls
// ---------------------------------------------------------------------------

pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_CLONE: u64 = 56;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_WAITID: u64 = 247;
pub const SYS_EXECVEAT: u64 = 322;
pub const SYS_CLONE3: u64 = 435;
pub const SYS_PRCTL: u64 = 157;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_SETSID: u64 = 112;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_GETSID: u64 = 124;
pub const SYS_UNSHARE: u64 = 272;
pub const SYS_PERSONALITY: u64 = 135;

// ---------------------------------------------------------------------------
// Signal syscalls
// ---------------------------------------------------------------------------

pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_RT_SIGRETURN: u64 = 15;
pub const SYS_PAUSE: u64 = 34;
pub const SYS_SIGALTSTACK: u64 = 131;
pub const SYS_RT_SIGPENDING: u64 = 127;
pub const SYS_RT_SIGTIMEDWAIT: u64 = 128;
pub const SYS_RT_SIGQUEUEINFO: u64 = 129;
pub const SYS_RT_SIGSUSPEND: u64 = 130;
pub const SYS_TKILL: u64 = 200;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_SIGNALFD: u64 = 282;
pub const SYS_SIGNALFD4: u64 = 289;
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 424;

// ---------------------------------------------------------------------------
// Network syscalls
// ---------------------------------------------------------------------------

pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SENDMSG: u64 = 46;
pub const SYS_RECVMSG: u64 = 47;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_ACCEPT4: u64 = 288;

// ---------------------------------------------------------------------------
// IPC syscalls
// ---------------------------------------------------------------------------

pub const SYS_PIPE: u64 = 22;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_SELECT: u64 = 23;
pub const SYS_PSELECT6: u64 = 270;
pub const SYS_PPOLL: u64 = 271;
pub const SYS_EPOLL_CREATE: u64 = 213;
pub const SYS_EPOLL_CTL: u64 = 233;
pub const SYS_EPOLL_WAIT: u64 = 232;
pub const SYS_EPOLL_PWAIT: u64 = 281;
pub const SYS_EPOLL_PWAIT2: u64 = 441;
pub const SYS_EPOLL_CREATE1: u64 = 291;
pub const SYS_SHMGET: u64 = 29;
pub const SYS_SHMAT: u64 = 30;
pub const SYS_SHMCTL: u64 = 31;
pub const SYS_SEMGET: u64 = 64;
pub const SYS_SEMOP: u64 = 65;
pub const SYS_SEMCTL: u64 = 66;
pub const SYS_SHMDT: u64 = 67;
pub const SYS_MSGGET: u64 = 68;
pub const SYS_MSGSND: u64 = 69;
pub const SYS_MSGRCV: u64 = 70;
pub const SYS_MSGCTL: u64 = 71;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_EVENTFD: u64 = 284;
pub const SYS_EVENTFD2: u64 = 290;
pub const SYS_INOTIFY_INIT: u64 = 253;
pub const SYS_INOTIFY_ADD_WATCH: u64 = 254;
pub const SYS_INOTIFY_RM_WATCH: u64 = 255;
pub const SYS_INOTIFY_INIT1: u64 = 294;
pub const SYS_FUTEX_WAITV: u64 = 449;

// ---------------------------------------------------------------------------
// Scheduling syscalls
// ---------------------------------------------------------------------------

pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_SCHED_SETPARAM: u64 = 142;
pub const SYS_SCHED_GETPARAM: u64 = 143;
pub const SYS_SCHED_SETSCHEDULER: u64 = 144;
pub const SYS_SCHED_GETSCHEDULER: u64 = 145;
pub const SYS_SCHED_GET_PRIORITY_MAX: u64 = 146;
pub const SYS_SCHED_GET_PRIORITY_MIN: u64 = 147;
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
pub const SYS_SCHED_SETAFFINITY: u64 = 203;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_SCHED_SETATTR: u64 = 314;
pub const SYS_SCHED_GETATTR: u64 = 315;

// ---------------------------------------------------------------------------
// Time syscalls
// ---------------------------------------------------------------------------

pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETITIMER: u64 = 36;
pub const SYS_ALARM: u64 = 37;
pub const SYS_SETITIMER: u64 = 38;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_SETTIMEOFDAY: u64 = 164;
pub const SYS_TIMES: u64 = 100;
pub const SYS_TIME: u64 = 201;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_TIMER_CREATE: u64 = 222;
pub const SYS_TIMER_SETTIME: u64 = 223;
pub const SYS_TIMER_GETTIME: u64 = 224;
pub const SYS_TIMER_GETOVERRUN: u64 = 225;
pub const SYS_TIMER_DELETE: u64 = 226;
pub const SYS_CLOCK_SETTIME: u64 = 227;
pub const SYS_TIMERFD_CREATE: u64 = 283;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;
pub const SYS_CLOCK_ADJTIME: u64 = 305;
pub const SYS_ADJTIMEX: u64 = 159;

// ---------------------------------------------------------------------------
// System info syscalls
// ---------------------------------------------------------------------------

pub const SYS_GETPID: u64 = 39;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETTID: u64 = 186;
pub const SYS_UNAME: u64 = 63;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_GETRLIMIT: u64 = 97;
pub const SYS_SETRLIMIT: u64 = 160;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_GETRUSAGE: u64 = 98;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_RSEQ: u64 = 334;
pub const SYS_SYSLOG: u64 = 103;
pub const SYS_PTRACE: u64 = 101;
pub const SYS_REBOOT: u64 = 169;
pub const SYS_MOUNT: u64 = 165;
pub const SYS_UMOUNT2: u64 = 166;
pub const SYS_PIVOT_ROOT: u64 = 155;
pub const SYS_CHROOT: u64 = 161;
pub const SYS_STATFS: u64 = 137;
pub const SYS_FSTATFS: u64 = 138;
pub const SYS_SWAPON: u64 = 167;
pub const SYS_SWAPOFF: u64 = 168;
pub const SYS_FADVISE64: u64 = 221;

// ---------------------------------------------------------------------------
// Identity / credentials syscalls
// ---------------------------------------------------------------------------

pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETREUID: u64 = 113;
pub const SYS_SETREGID: u64 = 114;
pub const SYS_GETGROUPS: u64 = 115;
pub const SYS_SETGROUPS: u64 = 116;
pub const SYS_SETRESUID: u64 = 117;
pub const SYS_GETRESUID: u64 = 118;
pub const SYS_SETRESGID: u64 = 119;
pub const SYS_GETRESGID: u64 = 120;
pub const SYS_SETFSUID: u64 = 122;
pub const SYS_SETFSGID: u64 = 123;
pub const SYS_CAPGET: u64 = 125;
pub const SYS_CAPSET: u64 = 126;

// ---------------------------------------------------------------------------
// Misc / extended attributes / key management
// ---------------------------------------------------------------------------

pub const SYS_MKNOD: u64 = 133;
pub const SYS_UTIMES: u64 = 235;
pub const SYS_IO_SETUP: u64 = 206;
pub const SYS_IO_DESTROY: u64 = 207;
pub const SYS_IO_GETEVENTS: u64 = 208;
pub const SYS_IO_SUBMIT: u64 = 209;
pub const SYS_IO_CANCEL: u64 = 210;
pub const SYS_LOOKUP_DCOOKIE: u64 = 212;
pub const SYS_GETXATTR: u64 = 191;
pub const SYS_LGETXATTR: u64 = 192;
pub const SYS_FGETXATTR: u64 = 193;
pub const SYS_LISTXATTR: u64 = 194;
pub const SYS_LLISTXATTR: u64 = 195;
pub const SYS_FLISTXATTR: u64 = 196;
pub const SYS_SETXATTR: u64 = 188;
pub const SYS_LSETXATTR: u64 = 189;
pub const SYS_FSETXATTR: u64 = 190;
pub const SYS_REMOVEXATTR: u64 = 197;
pub const SYS_LREMOVEXATTR: u64 = 198;
pub const SYS_FREMOVEXATTR: u64 = 199;
pub const SYS_ADD_KEY: u64 = 248;
pub const SYS_REQUEST_KEY: u64 = 249;
pub const SYS_KEYCTL: u64 = 250;
pub const SYS_IOPRIO_SET: u64 = 251;
pub const SYS_IOPRIO_GET: u64 = 252;
pub const SYS_MIGRATE_PAGES: u64 = 256;
pub const SYS_IO_URING_SETUP: u64 = 425;
pub const SYS_IO_URING_ENTER: u64 = 426;
pub const SYS_IO_URING_REGISTER: u64 = 427;
pub const SYS_PIDFD_OPEN: u64 = 434;
pub const SYS_CLOSE_RANGE: u64 = 436;
pub const SYS_OPENAT2: u64 = 437;
pub const SYS_PIDFD_GETFD: u64 = 438;
pub const SYS_LANDLOCK_CREATE_RULESET: u64 = 444;
pub const SYS_LANDLOCK_ADD_RULE: u64 = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: u64 = 446;
pub const SYS_MEMFD_SECRET: u64 = 447;
pub const SYS_PROCESS_MRELEASE: u64 = 448;
pub const SYS_SET_MEMPOLICY_HOME_NODE: u64 = 450;
pub const SYS_CACHESTAT: u64 = 451;
pub const SYS_FCHMODAT2: u64 = 452;
pub const SYS_MAP_SHADOW_STACK: u64 = 453;
pub const SYS_FUTEX_WAKE: u64 = 454;
pub const SYS_FUTEX_WAIT: u64 = 455;
pub const SYS_FUTEX_REQUEUE: u64 = 456;
pub const SYS_MSEAL: u64 = 462;

// ---------------------------------------------------------------------------
// Obsolete / rarely used
// ---------------------------------------------------------------------------

pub const SYS_USELIB: u64 = 134;
pub const SYS_USTAT: u64 = 136;
pub const SYS_SYSFS: u64 = 139;
pub const SYS_VHANGUP: u64 = 153;
pub const SYS_MODIFY_LDT: u64 = 154;
pub const SYS_ACCT: u64 = 163;
pub const SYS_INIT_MODULE: u64 = 175;
pub const SYS_DELETE_MODULE: u64 = 176;
pub const SYS_QUOTACTL: u64 = 179;
pub const SYS_NFSSERVCTL: u64 = 180;
pub const SYS_GETPMSG: u64 = 181;
pub const SYS_PUTPMSG: u64 = 182;
pub const SYS_AFS_SYSCALL: u64 = 183;
pub const SYS_TUXCALL: u64 = 184;
pub const SYS_SECURITY: u64 = 185;
pub const SYS_READAHEAD: u64 = 187;
pub const SYS_RESTART_SYSCALL: u64 = 219;
pub const SYS_KEXEC_LOAD: u64 = 246;
pub const SYS_PERF_EVENT_OPEN: u64 = 298;
pub const SYS_FANOTIFY_INIT: u64 = 300;
pub const SYS_FANOTIFY_MARK: u64 = 301;
pub const SYS_KCMP: u64 = 312;
pub const SYS_FINIT_MODULE: u64 = 313;
pub const SYS_BPF: u64 = 321;
pub const SYS_USERFAULTFD: u64 = 323;
pub const SYS_SECCOMP: u64 = 317;
pub const SYS_KEXEC_FILE_LOAD: u64 = 320;
pub const SYS_PKEY_MPROTECT: u64 = 329;
pub const SYS_PKEY_ALLOC: u64 = 330;
pub const SYS_PKEY_FREE: u64 = 331;

/// Total number of known Linux x86_64 syscalls (approximate upper bound).
pub const SYSCALL_TABLE_SIZE: usize = 463;

/// Look up syscall metadata by number.
///
/// Returns `Some(SyscallEntry)` for known syscalls, `None` for gaps/unknown.
/// This is a `const fn` usable at compile time for building static dispatch tables.
pub const fn lookup(nr: u64) -> Option<SyscallEntry> {
    // Most frequently used syscalls are handled first for fast common-path dispatch.
    macro_rules! entry {
        ($nr:expr, $name:expr, $cat:expr) => {
            Some(SyscallEntry { nr: $nr, name: $name, category: $cat })
        };
    }

    use SyscallCategory::*;

    match nr {
        // --- File I/O ---
        0 => entry!(0, "read", File),
        1 => entry!(1, "write", File),
        2 => entry!(2, "open", File),
        3 => entry!(3, "close", File),
        4 => entry!(4, "stat", File),
        5 => entry!(5, "fstat", File),
        6 => entry!(6, "lstat", File),
        7 => entry!(7, "poll", File),
        8 => entry!(8, "lseek", File),
        16 => entry!(16, "ioctl", File),
        17 => entry!(17, "pread64", File),
        18 => entry!(18, "pwrite64", File),
        19 => entry!(19, "readv", File),
        20 => entry!(20, "writev", File),
        21 => entry!(21, "access", File),
        32 => entry!(32, "dup", File),
        33 => entry!(33, "dup2", File),
        40 => entry!(40, "sendfile", File),
        72 => entry!(72, "fcntl", File),
        73 => entry!(73, "flock", File),
        74 => entry!(74, "fsync", File),
        75 => entry!(75, "fdatasync", File),
        76 => entry!(76, "truncate", File),
        77 => entry!(77, "ftruncate", File),
        78 => entry!(78, "getdents", File),
        79 => entry!(79, "getcwd", File),
        80 => entry!(80, "chdir", File),
        81 => entry!(81, "fchdir", File),
        82 => entry!(82, "rename", File),
        83 => entry!(83, "mkdir", File),
        84 => entry!(84, "rmdir", File),
        85 => entry!(85, "creat", File),
        86 => entry!(86, "link", File),
        87 => entry!(87, "unlink", File),
        88 => entry!(88, "symlink", File),
        89 => entry!(89, "readlink", File),
        90 => entry!(90, "chmod", File),
        91 => entry!(91, "fchmod", File),
        92 => entry!(92, "chown", File),
        93 => entry!(93, "fchown", File),
        94 => entry!(94, "lchown", File),
        95 => entry!(95, "umask", File),
        133 => entry!(133, "mknod", Misc),
        217 => entry!(217, "getdents64", File),
        257 => entry!(257, "openat", File),
        258 => entry!(258, "mkdirat", File),
        259 => entry!(259, "mknodat", Misc),
        260 => entry!(260, "fchownat", File),
        261 => entry!(261, "futimesat", File),
        262 => entry!(262, "newfstatat", File),
        263 => entry!(263, "unlinkat", File),
        264 => entry!(264, "renameat", File),
        265 => entry!(265, "linkat", File),
        266 => entry!(266, "symlinkat", File),
        267 => entry!(267, "readlinkat", File),
        268 => entry!(268, "fchmodat", File),
        269 => entry!(269, "faccessat", File),
        275 => entry!(275, "splice", File),
        276 => entry!(276, "tee", File),
        277 => entry!(277, "sync_file_range", File),
        278 => entry!(278, "vmsplice", File),
        280 => entry!(280, "utimensat", File),
        285 => entry!(285, "fallocate", File),
        292 => entry!(292, "dup3", File),
        295 => entry!(295, "preadv", File),
        296 => entry!(296, "pwritev", File),
        303 => entry!(303, "name_to_handle_at", File),
        304 => entry!(304, "open_by_handle_at", File),
        316 => entry!(316, "renameat2", File),
        326 => entry!(326, "copy_file_range", File),
        327 => entry!(327, "preadv2", File),
        328 => entry!(328, "pwritev2", File),
        332 => entry!(332, "statx", File),
        439 => entry!(439, "faccessat2", File),

        // --- Memory ---
        9 => entry!(9, "mmap", Memory),
        10 => entry!(10, "mprotect", Memory),
        11 => entry!(11, "munmap", Memory),
        12 => entry!(12, "brk", Memory),
        25 => entry!(25, "mremap", Memory),
        26 => entry!(26, "msync", Memory),
        27 => entry!(27, "mincore", Memory),
        28 => entry!(28, "madvise", Memory),
        149 => entry!(149, "mlock", Memory),
        150 => entry!(150, "munlock", Memory),
        151 => entry!(151, "mlockall", Memory),
        152 => entry!(152, "munlockall", Memory),
        216 => entry!(216, "remap_file_pages", Memory),
        237 => entry!(237, "mbind", Memory),
        238 => entry!(238, "set_mempolicy", Memory),
        239 => entry!(239, "get_mempolicy", Memory),
        279 => entry!(279, "move_pages", Memory),
        319 => entry!(319, "memfd_create", Memory),
        325 => entry!(325, "mlock2", Memory),
        329 => entry!(329, "pkey_mprotect", Memory),
        330 => entry!(330, "pkey_alloc", Memory),
        331 => entry!(331, "pkey_free", Memory),
        440 => entry!(440, "process_madvise", Memory),
        447 => entry!(447, "memfd_secret", Memory),
        453 => entry!(453, "map_shadow_stack", Memory),
        462 => entry!(462, "mseal", Memory),

        // --- Process ---
        56 => entry!(56, "clone", Process),
        57 => entry!(57, "fork", Process),
        58 => entry!(58, "vfork", Process),
        59 => entry!(59, "execve", Process),
        60 => entry!(60, "exit", Process),
        61 => entry!(61, "wait4", Process),
        62 => entry!(62, "kill", Process),
        109 => entry!(109, "setpgid", Process),
        111 => entry!(111, "getpgrp", Process),
        112 => entry!(112, "setsid", Process),
        121 => entry!(121, "getpgid", Process),
        124 => entry!(124, "getsid", Process),
        135 => entry!(135, "personality", Process),
        157 => entry!(157, "prctl", Process),
        158 => entry!(158, "arch_prctl", Process),
        231 => entry!(231, "exit_group", Process),
        247 => entry!(247, "waitid", Process),
        272 => entry!(272, "unshare", Process),
        322 => entry!(322, "execveat", Process),
        435 => entry!(435, "clone3", Process),

        // --- Signals ---
        13 => entry!(13, "rt_sigaction", Signal),
        14 => entry!(14, "rt_sigprocmask", Signal),
        15 => entry!(15, "rt_sigreturn", Signal),
        34 => entry!(34, "pause", Signal),
        127 => entry!(127, "rt_sigpending", Signal),
        128 => entry!(128, "rt_sigtimedwait", Signal),
        129 => entry!(129, "rt_sigqueueinfo", Signal),
        130 => entry!(130, "rt_sigsuspend", Signal),
        131 => entry!(131, "sigaltstack", Signal),
        200 => entry!(200, "tkill", Signal),
        234 => entry!(234, "tgkill", Signal),
        282 => entry!(282, "signalfd", Signal),
        289 => entry!(289, "signalfd4", Signal),
        424 => entry!(424, "pidfd_send_signal", Signal),

        // --- Network ---
        41 => entry!(41, "socket", Network),
        42 => entry!(42, "connect", Network),
        43 => entry!(43, "accept", Network),
        44 => entry!(44, "sendto", Network),
        45 => entry!(45, "recvfrom", Network),
        46 => entry!(46, "sendmsg", Network),
        47 => entry!(47, "recvmsg", Network),
        48 => entry!(48, "shutdown", Network),
        49 => entry!(49, "bind", Network),
        50 => entry!(50, "listen", Network),
        51 => entry!(51, "getsockname", Network),
        52 => entry!(52, "getpeername", Network),
        53 => entry!(53, "socketpair", Network),
        54 => entry!(54, "setsockopt", Network),
        55 => entry!(55, "getsockopt", Network),
        288 => entry!(288, "accept4", Network),

        // --- IPC ---
        22 => entry!(22, "pipe", Ipc),
        23 => entry!(23, "select", Ipc),
        29 => entry!(29, "shmget", Ipc),
        30 => entry!(30, "shmat", Ipc),
        31 => entry!(31, "shmctl", Ipc),
        64 => entry!(64, "semget", Ipc),
        65 => entry!(65, "semop", Ipc),
        66 => entry!(66, "semctl", Ipc),
        67 => entry!(67, "shmdt", Ipc),
        68 => entry!(68, "msgget", Ipc),
        69 => entry!(69, "msgsnd", Ipc),
        70 => entry!(70, "msgrcv", Ipc),
        71 => entry!(71, "msgctl", Ipc),
        202 => entry!(202, "futex", Ipc),
        213 => entry!(213, "epoll_create", Ipc),
        232 => entry!(232, "epoll_wait", Ipc),
        233 => entry!(233, "epoll_ctl", Ipc),
        270 => entry!(270, "pselect6", Ipc),
        271 => entry!(271, "ppoll", Ipc),
        281 => entry!(281, "epoll_pwait", Ipc),
        284 => entry!(284, "eventfd", Ipc),
        290 => entry!(290, "eventfd2", Ipc),
        291 => entry!(291, "epoll_create1", Ipc),
        293 => entry!(293, "pipe2", Ipc),
        253 => entry!(253, "inotify_init", Ipc),
        254 => entry!(254, "inotify_add_watch", Ipc),
        255 => entry!(255, "inotify_rm_watch", Ipc),
        294 => entry!(294, "inotify_init1", Ipc),
        441 => entry!(441, "epoll_pwait2", Ipc),
        449 => entry!(449, "futex_waitv", Ipc),
        454 => entry!(454, "futex_wake", Ipc),
        455 => entry!(455, "futex_wait", Ipc),
        456 => entry!(456, "futex_requeue", Ipc),

        // --- Scheduling ---
        24 => entry!(24, "sched_yield", Scheduler),
        142 => entry!(142, "sched_setparam", Scheduler),
        143 => entry!(143, "sched_getparam", Scheduler),
        144 => entry!(144, "sched_setscheduler", Scheduler),
        145 => entry!(145, "sched_getscheduler", Scheduler),
        146 => entry!(146, "sched_get_priority_max", Scheduler),
        147 => entry!(147, "sched_get_priority_min", Scheduler),
        148 => entry!(148, "sched_rr_get_interval", Scheduler),
        203 => entry!(203, "sched_setaffinity", Scheduler),
        204 => entry!(204, "sched_getaffinity", Scheduler),
        314 => entry!(314, "sched_setattr", Scheduler),
        315 => entry!(315, "sched_getattr", Scheduler),

        // --- Time ---
        35 => entry!(35, "nanosleep", Time),
        36 => entry!(36, "getitimer", Time),
        37 => entry!(37, "alarm", Time),
        38 => entry!(38, "setitimer", Time),
        96 => entry!(96, "gettimeofday", Time),
        100 => entry!(100, "times", Time),
        159 => entry!(159, "adjtimex", Time),
        164 => entry!(164, "settimeofday", Time),
        201 => entry!(201, "time", Time),
        222 => entry!(222, "timer_create", Time),
        223 => entry!(223, "timer_settime", Time),
        224 => entry!(224, "timer_gettime", Time),
        225 => entry!(225, "timer_getoverrun", Time),
        226 => entry!(226, "timer_delete", Time),
        227 => entry!(227, "clock_settime", Time),
        228 => entry!(228, "clock_gettime", Time),
        229 => entry!(229, "clock_getres", Time),
        230 => entry!(230, "clock_nanosleep", Time),
        235 => entry!(235, "utimes", Time),
        283 => entry!(283, "timerfd_create", Time),
        286 => entry!(286, "timerfd_settime", Time),
        287 => entry!(287, "timerfd_gettime", Time),
        305 => entry!(305, "clock_adjtime", Time),

        // --- System info ---
        39 => entry!(39, "getpid", System),
        63 => entry!(63, "uname", System),
        97 => entry!(97, "getrlimit", System),
        98 => entry!(98, "getrusage", System),
        99 => entry!(99, "sysinfo", System),
        101 => entry!(101, "ptrace", System),
        103 => entry!(103, "syslog", System),
        110 => entry!(110, "getppid", System),
        137 => entry!(137, "statfs", System),
        138 => entry!(138, "fstatfs", System),
        155 => entry!(155, "pivot_root", System),
        160 => entry!(160, "setrlimit", System),
        161 => entry!(161, "chroot", System),
        165 => entry!(165, "mount", System),
        166 => entry!(166, "umount2", System),
        167 => entry!(167, "swapon", System),
        168 => entry!(168, "swapoff", System),
        169 => entry!(169, "reboot", System),
        186 => entry!(186, "gettid", System),
        218 => entry!(218, "set_tid_address", System),
        221 => entry!(221, "fadvise64", System),
        273 => entry!(273, "set_robust_list", System),
        274 => entry!(274, "get_robust_list", System),
        302 => entry!(302, "prlimit64", System),
        318 => entry!(318, "getrandom", System),
        334 => entry!(334, "rseq", System),

        // --- Identity / credentials ---
        102 => entry!(102, "getuid", Identity),
        104 => entry!(104, "getgid", Identity),
        105 => entry!(105, "setuid", Identity),
        106 => entry!(106, "setgid", Identity),
        107 => entry!(107, "geteuid", Identity),
        108 => entry!(108, "getegid", Identity),
        113 => entry!(113, "setreuid", Identity),
        114 => entry!(114, "setregid", Identity),
        115 => entry!(115, "getgroups", Identity),
        116 => entry!(116, "setgroups", Identity),
        117 => entry!(117, "setresuid", Identity),
        118 => entry!(118, "getresuid", Identity),
        119 => entry!(119, "setresgid", Identity),
        120 => entry!(120, "getresgid", Identity),
        122 => entry!(122, "setfsuid", Identity),
        123 => entry!(123, "setfsgid", Identity),
        125 => entry!(125, "capget", Identity),
        126 => entry!(126, "capset", Identity),

        // --- Misc ---
        188 => entry!(188, "setxattr", Misc),
        189 => entry!(189, "lsetxattr", Misc),
        190 => entry!(190, "fsetxattr", Misc),
        191 => entry!(191, "getxattr", Misc),
        192 => entry!(192, "lgetxattr", Misc),
        193 => entry!(193, "fgetxattr", Misc),
        194 => entry!(194, "listxattr", Misc),
        195 => entry!(195, "llistxattr", Misc),
        196 => entry!(196, "flistxattr", Misc),
        197 => entry!(197, "removexattr", Misc),
        198 => entry!(198, "lremovexattr", Misc),
        199 => entry!(199, "fremovexattr", Misc),
        206 => entry!(206, "io_setup", Misc),
        207 => entry!(207, "io_destroy", Misc),
        208 => entry!(208, "io_getevents", Misc),
        209 => entry!(209, "io_submit", Misc),
        210 => entry!(210, "io_cancel", Misc),
        212 => entry!(212, "lookup_dcookie", Misc),
        248 => entry!(248, "add_key", Misc),
        249 => entry!(249, "request_key", Misc),
        250 => entry!(250, "keyctl", Misc),
        251 => entry!(251, "ioprio_set", Misc),
        252 => entry!(252, "ioprio_get", Misc),
        256 => entry!(256, "migrate_pages", Misc),
        425 => entry!(425, "io_uring_setup", Misc),
        426 => entry!(426, "io_uring_enter", Misc),
        427 => entry!(427, "io_uring_register", Misc),
        434 => entry!(434, "pidfd_open", Misc),
        436 => entry!(436, "close_range", Misc),
        437 => entry!(437, "openat2", Misc),
        438 => entry!(438, "pidfd_getfd", Misc),
        444 => entry!(444, "landlock_create_ruleset", Misc),
        445 => entry!(445, "landlock_add_rule", Misc),
        446 => entry!(446, "landlock_restrict_self", Misc),
        448 => entry!(448, "process_mrelease", Misc),
        450 => entry!(450, "set_mempolicy_home_node", Misc),
        451 => entry!(451, "cachestat", Misc),
        452 => entry!(452, "fchmodat2", Misc),

        // --- Obsolete ---
        134 => entry!(134, "uselib", Obsolete),
        136 => entry!(136, "ustat", Obsolete),
        139 => entry!(139, "sysfs", Obsolete),
        153 => entry!(153, "vhangup", Obsolete),
        154 => entry!(154, "modify_ldt", Obsolete),
        163 => entry!(163, "acct", Obsolete),
        175 => entry!(175, "init_module", Obsolete),
        176 => entry!(176, "delete_module", Obsolete),
        179 => entry!(179, "quotactl", Obsolete),
        180 => entry!(180, "nfsservctl", Obsolete),
        181 => entry!(181, "getpmsg", Obsolete),
        182 => entry!(182, "putpmsg", Obsolete),
        183 => entry!(183, "afs_syscall", Obsolete),
        184 => entry!(184, "tuxcall", Obsolete),
        185 => entry!(185, "security", Obsolete),
        187 => entry!(187, "readahead", Obsolete),
        219 => entry!(219, "restart_syscall", Obsolete),
        246 => entry!(246, "kexec_load", Obsolete),
        298 => entry!(298, "perf_event_open", Obsolete),
        300 => entry!(300, "fanotify_init", Obsolete),
        301 => entry!(301, "fanotify_mark", Obsolete),
        312 => entry!(312, "kcmp", Obsolete),
        313 => entry!(313, "finit_module", Obsolete),
        317 => entry!(317, "seccomp", Obsolete),
        320 => entry!(320, "kexec_file_load", Obsolete),
        321 => entry!(321, "bpf", Obsolete),
        323 => entry!(323, "userfaultfd", Obsolete),

        _ => None,
    }
}
