//! Linux x86_64 ABI types and constants.
//!
//! All numeric constants sourced from `linux-raw-sys` for guaranteed kernel ABI accuracy.
//! Custom struct types are validated at compile-time against official kernel definitions.

use linux_raw_sys::general as k;

// ---------------------------------------------------------------
// struct stat (144 bytes on x86_64) — validated against kernel headers
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Stat {
    pub st_dev: u64,        // 0
    pub st_ino: u64,        // 8
    pub st_nlink: u64,      // 16
    pub st_mode: u32,       // 24
    pub st_uid: u32,        // 28
    pub st_gid: u32,        // 32
    pub __pad0: u32,        // 36
    pub st_rdev: u64,       // 40
    pub st_size: i64,       // 48
    pub st_blksize: i64,    // 56
    pub st_blocks: i64,     // 64
    pub st_atime: i64,      // 72
    pub st_atime_nsec: i64, // 80
    pub st_mtime: i64,      // 88
    pub st_mtime_nsec: i64, // 96
    pub st_ctime: i64,      // 104
    pub st_ctime_nsec: i64, // 112
    pub __unused: [i64; 3], // 120..144
}

const _: () = assert!(core::mem::size_of::<Stat>() == 144);
const _: () = assert!(core::mem::size_of::<Stat>() == core::mem::size_of::<k::stat>());
const _: () = assert!(core::mem::align_of::<Stat>() == core::mem::align_of::<k::stat>());

impl Stat {
    pub const fn zeroed() -> Self {
        Self {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atime: 0,
            st_atime_nsec: 0,
            st_mtime: 0,
            st_mtime_nsec: 0,
            st_ctime: 0,
            st_ctime_nsec: 0,
            __unused: [0; 3],
        }
    }

    /// Write this stat into guest memory at `ptr`.
    ///
    /// # Safety
    /// `ptr` must point to at least 144 writable bytes in the caller's address space.
    pub unsafe fn write_to(&self, ptr: u64) {
        core::ptr::write(ptr as *mut Stat, *self);
    }
}

// ---------------------------------------------------------------
// File mode bits — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const S_IFMT: u32 = k::S_IFMT;
pub const S_IFREG: u32 = k::S_IFREG;
pub const S_IFDIR: u32 = k::S_IFDIR;
pub const S_IFCHR: u32 = k::S_IFCHR;
pub const S_IFIFO: u32 = k::S_IFIFO;
pub const S_IFLNK: u32 = k::S_IFLNK;

// ---------------------------------------------------------------
// struct termios (44 bytes on x86_64) — validated against kernel headers
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Termios {
    pub c_iflag: u32,   // 0
    pub c_oflag: u32,   // 4
    pub c_cflag: u32,   // 8
    pub c_lflag: u32,   // 12
    pub c_line: u8,     // 16
    pub c_cc: [u8; 19], // 17..36
    pub c_ispeed: u32,  // 36
    pub c_ospeed: u32,  // 40
}

const _: () = assert!(core::mem::size_of::<Termios>() == 44);
// Our Termios matches kernel's termios2 (includes c_ispeed/c_ospeed)
const _: () = assert!(core::mem::size_of::<Termios>() == core::mem::size_of::<k::termios2>());

impl Termios {
    /// Sensible defaults for a dumb terminal (raw-ish mode).
    pub const fn defaults() -> Self {
        let mut cc = [0u8; 19];
        cc[0] = 3; // VINTR  = Ctrl-C
        cc[1] = 28; // VQUIT  = Ctrl-\
        cc[2] = 127; // VERASE = DEL
        cc[4] = 4; // VEOF   = Ctrl-D
        cc[5] = 0; // VTIME
        cc[6] = 1; // VMIN
        cc[11] = 1; // VSTART for XON

        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0o60 | 0o200, // CS8 | CREAD
            c_lflag: 0,
            c_line: 0,
            c_cc: cc,
            c_ispeed: 38400,
            c_ospeed: 38400,
        }
    }
}

// ---------------------------------------------------------------
// ioctl request codes — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const TCGETS: u32 = linux_raw_sys::ioctl::TCGETS;
pub const TCSETS: u32 = linux_raw_sys::ioctl::TCSETS;
pub const TCSETSW: u32 = linux_raw_sys::ioctl::TCSETSW;
pub const TCSETSF: u32 = linux_raw_sys::ioctl::TCSETSF;
pub const TIOCGWINSZ: u32 = linux_raw_sys::ioctl::TIOCGWINSZ;
pub const TIOCSWINSZ: u32 = linux_raw_sys::ioctl::TIOCSWINSZ;
pub const TIOCGPGRP: u32 = linux_raw_sys::ioctl::TIOCGPGRP;
pub const TIOCSPGRP: u32 = linux_raw_sys::ioctl::TIOCSPGRP;
pub const FIONREAD: u32 = linux_raw_sys::ioctl::FIONREAD;

// ---------------------------------------------------------------
// struct winsize (8 bytes) — validated against kernel headers
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

const _: () = assert!(core::mem::size_of::<Winsize>() == 8);
const _: () = assert!(core::mem::size_of::<Winsize>() == core::mem::size_of::<k::winsize>());

impl Winsize {
    pub const fn default_serial() -> Self {
        Self {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

// ---------------------------------------------------------------
// struct linux_dirent64 (variable size, header is 19 bytes)
// ---------------------------------------------------------------

#[repr(C)]
pub struct LinuxDirent64 {
    pub d_ino: u64,    // 0
    pub d_off: i64,    // 8
    pub d_reclen: u16, // 16
    pub d_type: u8,    // 18
                       // d_name follows (null-terminated, variable length)
}

pub const DT_REG: u8 = k::DT_REG as u8;
pub const DT_DIR: u8 = k::DT_DIR as u8;
pub const DT_CHR: u8 = k::DT_CHR as u8;

// ---------------------------------------------------------------
// rt_sigaction (kernel struct, 32 bytes with 8-byte sigset)
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigaction {
    pub sa_handler: u64,  // 0: handler or SIG_IGN/SIG_DFL
    pub sa_flags: u64,    // 8
    pub sa_restorer: u64, // 16
    pub sa_mask: u64,     // 24: sigset_t (8 bytes = 64 signals)
}

const _: () = assert!(core::mem::size_of::<KernelSigaction>() == 32);

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const SA_RESTORER: u64 = k::SA_RESTORER as u64;
pub const SA_SIGINFO: u64 = k::SA_SIGINFO as u64;
pub const SA_RESTART: u64 = k::SA_RESTART as u64;
pub const SA_ONSTACK: u64 = k::SA_ONSTACK as u64;

// sigaltstack constants
pub const SS_ONSTACK: u64 = 1;
pub const SS_DISABLE: u64 = 2;
pub const MINSIGSTKSZ: u64 = 2048;

// ---------------------------------------------------------------
// Signal numbers — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const SIGHUP: u32 = k::SIGHUP;
pub const SIGINT: u32 = k::SIGINT;
pub const SIGQUIT: u32 = k::SIGQUIT;
pub const SIGILL: u32 = k::SIGILL;
pub const SIGABRT: u32 = k::SIGABRT;
pub const SIGFPE: u32 = k::SIGFPE;
pub const SIGKILL: u32 = k::SIGKILL;
pub const SIGSEGV: u32 = k::SIGSEGV;
pub const SIGPIPE: u32 = k::SIGPIPE;
pub const SIGALRM: u32 = k::SIGALRM;
pub const SIGTERM: u32 = k::SIGTERM;
pub const SIGCHLD: u32 = k::SIGCHLD;
pub const SIGCONT: u32 = k::SIGCONT;
pub const SIGSTOP: u32 = k::SIGSTOP;
pub const SIGTSTP: u32 = k::SIGTSTP;
pub const SIGWINCH: u32 = k::SIGWINCH;

// ---------------------------------------------------------------
// errno (positive values — negate before returning to userspace)
// sourced from linux-raw-sys
// ---------------------------------------------------------------

use linux_raw_sys::errno as e;

pub const EPERM: i64 = e::EPERM as i64;
pub const ENOENT: i64 = e::ENOENT as i64;
pub const ESRCH: i64 = e::ESRCH as i64;
pub const EINTR: i64 = e::EINTR as i64;
pub const EIO: i64 = e::EIO as i64;
pub const ENXIO: i64 = e::ENXIO as i64;
pub const EBADF: i64 = e::EBADF as i64;
pub const ECHILD: i64 = e::ECHILD as i64;
pub const EAGAIN: i64 = e::EAGAIN as i64;
pub const ENOMEM: i64 = e::ENOMEM as i64;
pub const EACCES: i64 = e::EACCES as i64;
pub const EFAULT: i64 = e::EFAULT as i64;
pub const EEXIST: i64 = e::EEXIST as i64;
pub const ENODEV: i64 = e::ENODEV as i64;
pub const ENOTDIR: i64 = e::ENOTDIR as i64;
pub const EISDIR: i64 = e::EISDIR as i64;
pub const EINVAL: i64 = e::EINVAL as i64;
pub const EMFILE: i64 = e::EMFILE as i64;
pub const ENOTTY: i64 = e::ENOTTY as i64;
pub const ENOSPC: i64 = e::ENOSPC as i64;
pub const ESPIPE: i64 = e::ESPIPE as i64;
pub const EPIPE: i64 = e::EPIPE as i64;
pub const ERANGE: i64 = e::ERANGE as i64;
pub const ENOSYS: i64 = e::ENOSYS as i64;
pub const ENOTEMPTY: i64 = e::ENOTEMPTY as i64;
pub const EDESTADDRREQ: i64 = e::EDESTADDRREQ as i64;
pub const EAFNOSUPPORT: i64 = e::EAFNOSUPPORT as i64;
pub const EADDRNOTAVAIL: i64 = e::EADDRNOTAVAIL as i64;
pub const ETIMEDOUT: i64 = e::ETIMEDOUT as i64;
pub const ECONNREFUSED: i64 = e::ECONNREFUSED as i64;
pub const ENOTCONN: i64 = e::ENOTCONN as i64;

// ---------------------------------------------------------------
// open(2) / openat(2) flags — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const O_RDONLY: u32 = k::O_RDONLY;
pub const O_WRONLY: u32 = k::O_WRONLY;
pub const O_RDWR: u32 = k::O_RDWR;
pub const O_CREAT: u32 = k::O_CREAT;
pub const O_TRUNC: u32 = k::O_TRUNC;
pub const O_APPEND: u32 = k::O_APPEND;
pub const O_NONBLOCK: u32 = k::O_NONBLOCK;
pub const O_DIRECTORY: u32 = k::O_DIRECTORY;
pub const O_CLOEXEC: u32 = k::O_CLOEXEC;

pub const AT_FDCWD: i64 = k::AT_FDCWD as i64;
pub const AT_EMPTY_PATH: u32 = k::AT_EMPTY_PATH;

// ---------------------------------------------------------------
// mmap(2) flags — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const PROT_READ: u32 = k::PROT_READ;
pub const PROT_WRITE: u32 = k::PROT_WRITE;
pub const PROT_EXEC: u32 = k::PROT_EXEC;
pub const MAP_SHARED: u32 = k::MAP_SHARED;
pub const MAP_PRIVATE: u32 = k::MAP_PRIVATE;
pub const MAP_FIXED: u32 = k::MAP_FIXED;
pub const MAP_ANONYMOUS: u32 = k::MAP_ANONYMOUS;

// ---------------------------------------------------------------
// madvise(2) flags
// ---------------------------------------------------------------

pub const MADV_NORMAL: u32 = 0;
pub const MADV_RANDOM: u32 = 1;
pub const MADV_SEQUENTIAL: u32 = 2;
pub const MADV_WILLNEED: u32 = 3;
pub const MADV_DONTNEED: u32 = 4;
pub const MADV_FREE: u32 = 8;
pub const MADV_HUGEPAGE: u32 = 14;
pub const MADV_NOHUGEPAGE: u32 = 15;

// ---------------------------------------------------------------
// SysV IPC constants
// ---------------------------------------------------------------

pub const IPC_CREAT: u32 = 0o1000;
pub const IPC_EXCL: u32 = 0o2000;
pub const IPC_RMID: u32 = 0;
pub const IPC_SET: u32 = 1;
pub const IPC_STAT: u32 = 2;
pub const SHM_RDONLY: u32 = 0o10000;

// ---------------------------------------------------------------
// fcntl(2) commands — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const F_DUPFD: u32 = k::F_DUPFD;
pub const F_GETFD: u32 = k::F_GETFD;
pub const F_SETFD: u32 = k::F_SETFD;
pub const F_GETFL: u32 = k::F_GETFL;
pub const F_SETFL: u32 = k::F_SETFL;

// ---------------------------------------------------------------
// clone(2) flags — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const CLONE_VM: u64 = k::CLONE_VM as u64;
pub const CLONE_FILES: u64 = k::CLONE_FILES as u64;
pub const CLONE_SIGHAND: u64 = k::CLONE_SIGHAND as u64;
pub const CLONE_THREAD: u64 = k::CLONE_THREAD as u64;
pub const CLONE_SETTLS: u64 = k::CLONE_SETTLS as u64;
pub const CLONE_PARENT_SETTID: u64 = k::CLONE_PARENT_SETTID as u64;
pub const CLONE_CHILD_SETTID: u64 = k::CLONE_CHILD_SETTID as u64;
pub const CLONE_CHILD_CLEARTID: u64 = k::CLONE_CHILD_CLEARTID as u64;

// ---------------------------------------------------------------
// Strongly-typed flag sets via `bitflags`
// ---------------------------------------------------------------

bitflags::bitflags! {
    /// open(2)/openat(2) flags (typed wrapper).
    #[derive(Clone, Copy, Debug)]
    pub struct OFlags: u32 {
        const CREAT     = O_CREAT;
        const TRUNC     = O_TRUNC;
        const APPEND    = O_APPEND;
        const NONBLOCK  = O_NONBLOCK;
        const DIRECTORY = O_DIRECTORY;
        const CLOEXEC   = O_CLOEXEC;
    }

    /// mmap(2) flags (typed wrapper).
    #[derive(Clone, Copy, Debug)]
    pub struct MFlags: u32 {
        const SHARED    = MAP_SHARED;
        const PRIVATE   = MAP_PRIVATE;
        const FIXED     = MAP_FIXED;
        const ANONYMOUS = MAP_ANONYMOUS;
    }

    /// clone(2) flags (typed wrapper).
    #[derive(Clone, Copy, Debug)]
    pub struct CFlags: u64 {
        const VM             = CLONE_VM;
        const FILES          = CLONE_FILES;
        const SIGHAND        = CLONE_SIGHAND;
        const THREAD         = CLONE_THREAD;
        const SETTLS         = CLONE_SETTLS;
        const PARENT_SETTID  = CLONE_PARENT_SETTID;
        const CHILD_CLEARTID = CLONE_CHILD_CLEARTID;
    }
}

// ---------------------------------------------------------------
// Linux syscall numbers (x86_64) — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const SYS_READ: u64 = k::__NR_read as u64;
pub const SYS_WRITE: u64 = k::__NR_write as u64;
pub const SYS_OPEN: u64 = k::__NR_open as u64;
pub const SYS_CLOSE: u64 = k::__NR_close as u64;
pub const SYS_STAT: u64 = k::__NR_stat as u64;
pub const SYS_FSTAT: u64 = k::__NR_fstat as u64;
pub const SYS_LSTAT: u64 = k::__NR_lstat as u64;
pub const SYS_POLL: u64 = k::__NR_poll as u64;
pub const SYS_LSEEK: u64 = k::__NR_lseek as u64;
pub const SYS_MMAP: u64 = k::__NR_mmap as u64;
pub const SYS_MPROTECT: u64 = k::__NR_mprotect as u64;
pub const SYS_MUNMAP: u64 = k::__NR_munmap as u64;
pub const SYS_BRK: u64 = k::__NR_brk as u64;
pub const SYS_RT_SIGACTION: u64 = k::__NR_rt_sigaction as u64;
pub const SYS_RT_SIGPROCMASK: u64 = k::__NR_rt_sigprocmask as u64;
pub const SYS_IOCTL: u64 = k::__NR_ioctl as u64;
pub const SYS_PREAD64: u64 = k::__NR_pread64 as u64;
pub const SYS_READV: u64 = k::__NR_readv as u64;
pub const SYS_WRITEV: u64 = k::__NR_writev as u64;
pub const SYS_ACCESS: u64 = k::__NR_access as u64;
pub const SYS_PIPE: u64 = k::__NR_pipe as u64;
pub const SYS_SELECT: u64 = k::__NR_select as u64;
pub const SYS_MREMAP: u64 = k::__NR_mremap as u64;
pub const SYS_MADVISE: u64 = k::__NR_madvise as u64;
pub const SYS_DUP: u64 = k::__NR_dup as u64;
pub const SYS_DUP2: u64 = k::__NR_dup2 as u64;
pub const SYS_NANOSLEEP: u64 = k::__NR_nanosleep as u64;
pub const SYS_GETPID: u64 = k::__NR_getpid as u64;
pub const SYS_SOCKET: u64 = k::__NR_socket as u64;
pub const SYS_CONNECT: u64 = k::__NR_connect as u64;
pub const SYS_SENDTO: u64 = k::__NR_sendto as u64;
pub const SYS_RECVFROM: u64 = k::__NR_recvfrom as u64;
pub const SYS_SENDMSG: u64 = k::__NR_sendmsg as u64;
pub const SYS_RECVMSG: u64 = k::__NR_recvmsg as u64;
pub const SYS_SHUTDOWN: u64 = k::__NR_shutdown as u64;
pub const SYS_BIND: u64 = k::__NR_bind as u64;
pub const SYS_LISTEN: u64 = k::__NR_listen as u64;
pub const SYS_GETSOCKNAME: u64 = k::__NR_getsockname as u64;
pub const SYS_GETPEERNAME: u64 = k::__NR_getpeername as u64;
pub const SYS_SETSOCKOPT: u64 = k::__NR_setsockopt as u64;
pub const SYS_GETSOCKOPT: u64 = k::__NR_getsockopt as u64;
pub const SYS_CLONE: u64 = k::__NR_clone as u64;
pub const SYS_FORK: u64 = k::__NR_fork as u64;
pub const SYS_EXECVE: u64 = k::__NR_execve as u64;
pub const SYS_EXIT: u64 = k::__NR_exit as u64;
pub const SYS_WAIT4: u64 = k::__NR_wait4 as u64;
pub const SYS_KILL: u64 = k::__NR_kill as u64;
pub const SYS_UNAME: u64 = k::__NR_uname as u64;
pub const SYS_FCNTL: u64 = k::__NR_fcntl as u64;
pub const SYS_FSYNC: u64 = k::__NR_fsync as u64;
pub const SYS_FDATASYNC: u64 = k::__NR_fdatasync as u64;
pub const SYS_FTRUNCATE: u64 = k::__NR_ftruncate as u64;
pub const SYS_GETCWD: u64 = k::__NR_getcwd as u64;
pub const SYS_CHDIR: u64 = k::__NR_chdir as u64;
pub const SYS_RENAME: u64 = k::__NR_rename as u64;
pub const SYS_MKDIR: u64 = k::__NR_mkdir as u64;
pub const SYS_RMDIR: u64 = k::__NR_rmdir as u64;
pub const SYS_UNLINK: u64 = k::__NR_unlink as u64;
pub const SYS_CHMOD: u64 = k::__NR_chmod as u64;
pub const SYS_GETTIMEOFDAY: u64 = k::__NR_gettimeofday as u64;
pub const SYS_GETRLIMIT: u64 = k::__NR_getrlimit as u64;
pub const SYS_SYSINFO: u64 = k::__NR_sysinfo as u64;
pub const SYS_GETUID: u64 = k::__NR_getuid as u64;
pub const SYS_GETGID: u64 = k::__NR_getgid as u64;
pub const SYS_GETEUID: u64 = k::__NR_geteuid as u64;
pub const SYS_GETEGID: u64 = k::__NR_getegid as u64;
pub const SYS_SETPGID: u64 = k::__NR_setpgid as u64;
pub const SYS_GETPPID: u64 = k::__NR_getppid as u64;
pub const SYS_GETPGRP: u64 = k::__NR_getpgrp as u64;
pub const SYS_SETSID: u64 = k::__NR_setsid as u64;
pub const SYS_SETFSUID: u64 = k::__NR_setfsuid as u64;
pub const SYS_SETFSGID: u64 = k::__NR_setfsgid as u64;
pub const SYS_SIGALTSTACK: u64 = k::__NR_sigaltstack as u64;
pub const SYS_PRCTL: u64 = k::__NR_prctl as u64;
pub const SYS_SETRLIMIT: u64 = k::__NR_setrlimit as u64;
pub const SYS_GETTID: u64 = k::__NR_gettid as u64;
pub const SYS_TKILL: u64 = k::__NR_tkill as u64;
pub const SYS_TIME: u64 = k::__NR_time as u64;
pub const SYS_FUTEX: u64 = k::__NR_futex as u64;
pub const SYS_SCHED_SETAFFINITY: u64 = k::__NR_sched_setaffinity as u64;
pub const SYS_SCHED_GETAFFINITY: u64 = k::__NR_sched_getaffinity as u64;
pub const SYS_EPOLL_CREATE: u64 = k::__NR_epoll_create as u64;
pub const SYS_GETDENTS64: u64 = k::__NR_getdents64 as u64;
pub const SYS_SET_TID_ADDRESS: u64 = k::__NR_set_tid_address as u64;
pub const SYS_FADVISE64: u64 = k::__NR_fadvise64 as u64;
pub const SYS_CLOCK_GETTIME: u64 = k::__NR_clock_gettime as u64;
pub const SYS_EXIT_GROUP: u64 = k::__NR_exit_group as u64;
pub const SYS_EPOLL_WAIT: u64 = k::__NR_epoll_wait as u64;
pub const SYS_EPOLL_CTL: u64 = k::__NR_epoll_ctl as u64;
pub const SYS_OPENAT: u64 = k::__NR_openat as u64;
pub const SYS_FSTATAT: u64 = k::__NR_newfstatat as u64;
pub const SYS_READLINKAT: u64 = k::__NR_readlinkat as u64;
pub const SYS_FACCESSAT: u64 = k::__NR_faccessat as u64;
pub const SYS_PSELECT6: u64 = k::__NR_pselect6 as u64;
pub const SYS_PPOLL: u64 = k::__NR_ppoll as u64;
pub const SYS_SET_ROBUST_LIST: u64 = k::__NR_set_robust_list as u64;
pub const SYS_GET_ROBUST_LIST: u64 = k::__NR_get_robust_list as u64;
pub const SYS_EPOLL_PWAIT: u64 = k::__NR_epoll_pwait as u64;
pub const SYS_EPOLL_CREATE1: u64 = k::__NR_epoll_create1 as u64;
pub const SYS_DUP3: u64 = k::__NR_dup3 as u64;
pub const SYS_PIPE2: u64 = k::__NR_pipe2 as u64;
pub const SYS_PRLIMIT64: u64 = k::__NR_prlimit64 as u64;
pub const SYS_GETRANDOM: u64 = k::__NR_getrandom as u64;
pub const SYS_STATX: u64 = k::__NR_statx as u64;
pub const SYS_RSEQ: u64 = k::__NR_rseq as u64;

// Phase A–C: additional syscalls for distro binaries, bash, and Wine
pub const SYS_RT_SIGRETURN: u64 = k::__NR_rt_sigreturn as u64; // 15
pub const SYS_PWRITE64: u64 = k::__NR_pwrite64 as u64; // 18
pub const SYS_SCHED_YIELD: u64 = k::__NR_sched_yield as u64; // 24
pub const SYS_MSYNC: u64 = k::__NR_msync as u64; // 26
pub const SYS_MINCORE: u64 = k::__NR_mincore as u64; // 27
pub const SYS_SHMGET: u64 = k::__NR_shmget as u64; // 29
pub const SYS_SHMAT: u64 = k::__NR_shmat as u64; // 30
pub const SYS_SHMCTL: u64 = k::__NR_shmctl as u64; // 31
pub const SYS_PAUSE: u64 = k::__NR_pause as u64; // 34
pub const SYS_GETITIMER: u64 = k::__NR_getitimer as u64; // 36
pub const SYS_ALARM: u64 = k::__NR_alarm as u64; // 37
pub const SYS_SETITIMER: u64 = k::__NR_setitimer as u64; // 38
pub const SYS_SENDFILE: u64 = k::__NR_sendfile as u64; // 40
pub const SYS_ACCEPT: u64 = k::__NR_accept as u64; // 43
pub const SYS_SOCKETPAIR: u64 = k::__NR_socketpair as u64; // 53
pub const SYS_VFORK: u64 = k::__NR_vfork as u64; // 58
pub const SYS_FLOCK: u64 = k::__NR_flock as u64; // 73
pub const SYS_CREAT: u64 = k::__NR_creat as u64; // 85
pub const SYS_LINK: u64 = k::__NR_link as u64; // 86
pub const SYS_SYMLINK: u64 = k::__NR_symlink as u64; // 88
pub const SYS_READLINK: u64 = k::__NR_readlink as u64; // 89
pub const SYS_FCHMOD: u64 = k::__NR_fchmod as u64; // 91
pub const SYS_FCHOWN: u64 = k::__NR_fchown as u64; // 93
pub const SYS_LCHOWN: u64 = k::__NR_lchown as u64; // 94
pub const SYS_UMASK: u64 = k::__NR_umask as u64; // 95
pub const SYS_GETRUSAGE: u64 = k::__NR_getrusage as u64; // 98
pub const SYS_TIMES: u64 = k::__NR_times as u64; // 100
pub const SYS_SETUID: u64 = k::__NR_setuid as u64; // 105
pub const SYS_SETGID: u64 = k::__NR_setgid as u64; // 106
pub const SYS_SETREUID: u64 = k::__NR_setreuid as u64; // 113
pub const SYS_SETREGID: u64 = k::__NR_setregid as u64; // 114
pub const SYS_GETGROUPS: u64 = k::__NR_getgroups as u64; // 115
pub const SYS_SETGROUPS: u64 = k::__NR_setgroups as u64; // 116
pub const SYS_SETRESUID: u64 = k::__NR_setresuid as u64; // 117
pub const SYS_GETRESUID: u64 = k::__NR_getresuid as u64; // 118
pub const SYS_SETRESGID: u64 = k::__NR_setresgid as u64; // 119
pub const SYS_GETRESGID: u64 = k::__NR_getresgid as u64; // 120
pub const SYS_GETPGID: u64 = k::__NR_getpgid as u64; // 121
pub const SYS_GETSID: u64 = k::__NR_getsid as u64; // 124
pub const SYS_CAPGET: u64 = k::__NR_capget as u64; // 125
pub const SYS_CAPSET: u64 = k::__NR_capset as u64; // 126
pub const SYS_RT_SIGPENDING: u64 = k::__NR_rt_sigpending as u64; // 127
pub const SYS_RT_SIGTIMEDWAIT: u64 = k::__NR_rt_sigtimedwait as u64; // 128
pub const SYS_RT_SIGQUEUEINFO: u64 = k::__NR_rt_sigqueueinfo as u64; // 129
pub const SYS_RT_SIGSUSPEND: u64 = k::__NR_rt_sigsuspend as u64; // 130
pub const SYS_MKNOD: u64 = k::__NR_mknod as u64; // 133
pub const SYS_PERSONALITY: u64 = k::__NR_personality as u64; // 135
pub const SYS_STATFS: u64 = k::__NR_statfs as u64; // 137
pub const SYS_FSTATFS: u64 = k::__NR_fstatfs as u64; // 138
pub const SYS_GETPRIORITY: u64 = k::__NR_getpriority as u64; // 140
pub const SYS_SETPRIORITY: u64 = k::__NR_setpriority as u64; // 141
pub const SYS_SCHED_GETPARAM: u64 = k::__NR_sched_getparam as u64; // 143
pub const SYS_SCHED_SETSCHEDULER: u64 = k::__NR_sched_setscheduler as u64; // 144
pub const SYS_SCHED_GETSCHEDULER: u64 = k::__NR_sched_getscheduler as u64; // 145
pub const SYS_SCHED_GET_PRIORITY_MAX: u64 = k::__NR_sched_get_priority_max as u64; // 146
pub const SYS_SCHED_GET_PRIORITY_MIN: u64 = k::__NR_sched_get_priority_min as u64; // 147
pub const SYS_MLOCK: u64 = k::__NR_mlock as u64; // 149
pub const SYS_MUNLOCK: u64 = k::__NR_munlock as u64; // 150
pub const SYS_MLOCKALL: u64 = k::__NR_mlockall as u64; // 151
pub const SYS_MUNLOCKALL: u64 = k::__NR_munlockall as u64; // 152
pub const SYS_CLOCK_GETRES: u64 = k::__NR_clock_getres as u64; // 229
pub const SYS_CLOCK_NANOSLEEP: u64 = k::__NR_clock_nanosleep as u64; // 230
pub const SYS_TGKILL: u64 = k::__NR_tgkill as u64; // 234
pub const SYS_UTIMES: u64 = k::__NR_utimes as u64; // 235
pub const SYS_WAITID: u64 = k::__NR_waitid as u64; // 247
pub const SYS_MKDIRAT: u64 = k::__NR_mkdirat as u64; // 258
pub const SYS_MKNODAT: u64 = k::__NR_mknodat as u64; // 259
pub const SYS_FCHOWNAT: u64 = k::__NR_fchownat as u64; // 260
pub const SYS_FUTIMESAT: u64 = k::__NR_futimesat as u64; // 261
pub const SYS_UNLINKAT: u64 = k::__NR_unlinkat as u64; // 263
pub const SYS_RENAMEAT: u64 = k::__NR_renameat as u64; // 264
pub const SYS_LINKAT: u64 = k::__NR_linkat as u64; // 265
pub const SYS_SYMLINKAT: u64 = k::__NR_symlinkat as u64; // 266
pub const SYS_FCHMODAT: u64 = k::__NR_fchmodat as u64; // 268
pub const SYS_UNSHARE: u64 = k::__NR_unshare as u64; // 272
pub const SYS_SPLICE: u64 = k::__NR_splice as u64; // 275
pub const SYS_TEE: u64 = k::__NR_tee as u64; // 276
pub const SYS_UTIMENSAT: u64 = k::__NR_utimensat as u64; // 280
pub const SYS_SIGNALFD: u64 = k::__NR_signalfd as u64; // 282
pub const SYS_TIMERFD_CREATE: u64 = k::__NR_timerfd_create as u64; // 283
pub const SYS_EVENTFD: u64 = k::__NR_eventfd as u64; // 284
pub const SYS_FALLOCATE: u64 = k::__NR_fallocate as u64; // 285
pub const SYS_TIMERFD_SETTIME: u64 = k::__NR_timerfd_settime as u64; // 286
pub const SYS_TIMERFD_GETTIME: u64 = k::__NR_timerfd_gettime as u64; // 287
pub const SYS_ACCEPT4: u64 = k::__NR_accept4 as u64; // 288
pub const SYS_SIGNALFD4: u64 = k::__NR_signalfd4 as u64; // 289
pub const SYS_EVENTFD2: u64 = k::__NR_eventfd2 as u64; // 290
pub const SYS_INOTIFY_INIT1: u64 = k::__NR_inotify_init1 as u64; // 294
pub const SYS_PREADV: u64 = k::__NR_preadv as u64; // 295
pub const SYS_PWRITEV: u64 = k::__NR_pwritev as u64; // 296
pub const SYS_RENAMEAT2: u64 = k::__NR_renameat2 as u64; // 316
pub const SYS_MEMFD_CREATE: u64 = k::__NR_memfd_create as u64; // 319
pub const SYS_COPY_FILE_RANGE: u64 = k::__NR_copy_file_range as u64; // 326
pub const SYS_CLONE3: u64 = k::__NR_clone3 as u64; // 435
pub const SYS_FACCESSAT2: u64 = k::__NR_faccessat2 as u64; // 439
pub const SYS_IO_SETUP: u64 = k::__NR_io_setup as u64; // 206
pub const SYS_IO_DESTROY: u64 = k::__NR_io_destroy as u64; // 207
pub const SYS_IO_GETEVENTS: u64 = k::__NR_io_getevents as u64; // 208
pub const SYS_IO_SUBMIT: u64 = k::__NR_io_submit as u64; // 209
pub const SYS_IO_CANCEL: u64 = k::__NR_io_cancel as u64; // 210
pub const SYS_INOTIFY_ADD_WATCH: u64 = k::__NR_inotify_add_watch as u64; // 254
pub const SYS_INOTIFY_RM_WATCH: u64 = k::__NR_inotify_rm_watch as u64; // 255

// ---------------------------------------------------------------
// Auxiliary vector types (for ELF loader) — sourced from linux-raw-sys
// ---------------------------------------------------------------

pub const AT_NULL: u64 = k::AT_NULL as u64;
pub const AT_PHDR: u64 = k::AT_PHDR as u64;
pub const AT_PHENT: u64 = k::AT_PHENT as u64;
pub const AT_PHNUM: u64 = k::AT_PHNUM as u64;
pub const AT_PAGESZ: u64 = k::AT_PAGESZ as u64;
pub const AT_BASE: u64 = k::AT_BASE as u64;
pub const AT_ENTRY: u64 = k::AT_ENTRY as u64;
pub const AT_UID: u64 = k::AT_UID as u64;
pub const AT_EUID: u64 = k::AT_EUID as u64;
pub const AT_GID: u64 = k::AT_GID as u64;
pub const AT_EGID: u64 = k::AT_EGID as u64;
pub const AT_CLKTCK: u64 = k::AT_CLKTCK as u64;
pub const AT_RANDOM: u64 = k::AT_RANDOM as u64;
pub const AT_SYSINFO_EHDR: u64 = k::AT_SYSINFO_EHDR as u64;

// ---------------------------------------------------------------
// Stub syscall bypass table (β₁ aniquilación)
// ---------------------------------------------------------------
// These Linux syscalls always return -ENOSYS. The kernel can
// short-circuit them in the redirect path without IPC round-trip.

pub const STUB_BYPASS_SYSCALLS: &[u64] = &[
    SYS_LINK,                   // 86
    SYS_SYMLINK,                // 88
    SYS_FCHMOD,                 // 91
    SYS_FCHOWN,                 // 93
    SYS_LCHOWN,                 // 94
    SYS_FLOCK,                  // 73
    SYS_FALLOCATE,              // 285
    SYS_UTIMES,                 // 235
    SYS_UTIMENSAT,              // 280
    SYS_LINKAT,                 // 265
    SYS_SYMLINKAT,              // 266
    SYS_FCHMODAT,               // 268
    SYS_FCHOWNAT,               // 260
    SYS_MKNOD,                  // 133
    SYS_MKNODAT,                // 259
    SYS_MSYNC,                  // 26
    SYS_ALARM,                  // 37
    SYS_UNSHARE,                // 272
    SYS_CAPGET,                 // 125
    SYS_CAPSET,                 // 126
    SYS_PERSONALITY,            // 135
    SYS_SCHED_SETSCHEDULER,     // 144
    SYS_SCHED_GETPARAM,         // 143 (also stub)
    SYS_SCHED_GET_PRIORITY_MAX, // 146
    SYS_SCHED_GET_PRIORITY_MIN, // 147
    SYS_SETUID,                 // 105
    SYS_SETGID,                 // 106
    SYS_INOTIFY_ADD_WATCH,      // 254
    SYS_INOTIFY_RM_WATCH,       // 255
];
