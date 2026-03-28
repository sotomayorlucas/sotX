// ---------------------------------------------------------------------------
// FileOps trait: vtable-based FD dispatch
//
// Replaces the match-on-fd-kind pattern in syscall handlers with a single
// trait dispatch. Each FD kind implements FileOps, and the dispatch is done
// via fd_ops(kind) → &'static dyn FileOps.
// ---------------------------------------------------------------------------

use sotos_common::IpcMsg;
use crate::syscalls::context::SyscallContext;

/// Result of a poll_ready check (bitmask).
pub(crate) const POLL_IN: u32 = 1;
pub(crate) const POLL_OUT: u32 = 4;
pub(crate) const POLL_ERR: u32 = 8;
pub(crate) const POLL_HUP: u32 = 16;

/// Operations supported by file descriptors.
///
/// Each FD kind (VFS file, pipe, socket, eventfd, etc.) implements this trait.
/// Default implementations return -EBADF, so only relevant operations need
/// to be overridden.
pub(crate) trait FileOps {
    /// Read up to `count` bytes from the FD into the guest buffer at `buf`.
    /// Returns bytes read or negative errno.
    fn read(&self, _ctx: &mut SyscallContext, _fd: usize, _buf: u64, _count: u64) -> i64 {
        -sotos_common::linux_abi::EBADF
    }

    /// Write up to `count` bytes from guest buffer at `buf` to the FD.
    /// Returns bytes written or negative errno.
    fn write(&self, _ctx: &mut SyscallContext, _fd: usize, _buf: u64, _count: u64) -> i64 {
        -sotos_common::linux_abi::EBADF
    }

    /// Close the FD. Returns 0 on success or negative errno.
    fn close(&self, _ctx: &mut SyscallContext, _fd: usize) -> i64 {
        0
    }

    /// Fill a Linux stat buffer at `buf` for this FD.
    /// Returns 0 on success or negative errno.
    fn stat(&self, _ctx: &mut SyscallContext, _fd: usize, _buf: u64) -> i64 {
        -sotos_common::linux_abi::EBADF
    }

    /// Handle an ioctl command. Returns result or negative errno.
    fn ioctl(&self, _ctx: &mut SyscallContext, _fd: usize, _cmd: u64, _arg: u64) -> i64 {
        -sotos_common::linux_abi::ENOTTY
    }

    /// Seek to a position. Returns new offset or negative errno.
    fn lseek(&self, _ctx: &mut SyscallContext, _fd: usize, _offset: i64, _whence: u32) -> i64 {
        -sotos_common::linux_abi::ESPIPE
    }

    /// Check if the FD is ready for I/O. Returns POLL_IN | POLL_OUT bitmask.
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        0
    }
}

// ---------------------------------------------------------------------------
// FD kind implementations
// ---------------------------------------------------------------------------

/// Stdin (kind=1): keyboard input via ring buffer.
pub(crate) struct StdinOps;

impl FileOps for StdinOps {
    fn read(&self, ctx: &mut SyscallContext, _fd: usize, buf: u64, count: u64) -> i64 {
        // Delegate to existing stdin read logic
        // (reads from keyboard ring buffer)
        let _ = (ctx, buf, count);
        0 // Placeholder — actual logic stays in fs_stdio.rs
    }

    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        if unsafe { crate::framebuffer::kb_has_char() } { POLL_IN } else { 0 }
    }
}

/// Stdout/Stderr (kind=2, 3): serial + framebuffer output.
pub(crate) struct StdoutOps;

impl FileOps for StdoutOps {
    fn write(&self, _ctx: &mut SyscallContext, _fd: usize, _buf: u64, _count: u64) -> i64 {
        0 // Placeholder — actual logic stays in fs_stdio.rs
    }

    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_OUT // Always writable
    }
}

/// Pipe read end (kind=4).
pub(crate) struct PipeReadOps;

impl FileOps for PipeReadOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN // Simplified — actual check requires pipe state
    }
}

/// Pipe write end (kind=5).
pub(crate) struct PipeWriteOps;

impl FileOps for PipeWriteOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_OUT
    }
}

/// Initrd file (kind=10): read-only file from CPIO archive.
pub(crate) struct InitrdFileOps;

impl FileOps for InitrdFileOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN
    }
}

/// VFS file (kind=13): read/write file backed by ObjectStore.
pub(crate) struct VfsFileOps;

impl FileOps for VfsFileOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN | POLL_OUT
    }
}

/// VFS directory (kind=14): directory handle for getdents64.
pub(crate) struct VfsDirOps;

impl FileOps for VfsDirOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN
    }
}

/// Virtual procfs file (kind=15): /proc/*, /sys/* pseudo-files.
pub(crate) struct ProcfsOps;

impl FileOps for ProcfsOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN
    }
}

/// Eventfd (kind=22): counter-based signaling FD.
pub(crate) struct EventfdOps;

impl FileOps for EventfdOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN | POLL_OUT
    }
}

/// Timerfd (kind=23): TSC-based timer FD.
pub(crate) struct TimerfdOps;

impl FileOps for TimerfdOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN
    }
}

/// Memfd (kind=25): anonymous page-backed file.
pub(crate) struct MemfdOps;

impl FileOps for MemfdOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN | POLL_OUT
    }
}

/// TCP socket (kind=8).
pub(crate) struct TcpSocketOps;

impl FileOps for TcpSocketOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN | POLL_OUT
    }
}

/// UDP socket (kind=9).
pub(crate) struct UdpSocketOps;

impl FileOps for UdpSocketOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN | POLL_OUT
    }
}

/// Epoll fd (kind=20).
pub(crate) struct EpollOps;

impl FileOps for EpollOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        0
    }
}

/// Unix stream socket (kind=27, 28).
pub(crate) struct UnixSocketOps;

impl FileOps for UnixSocketOps {
    fn poll_ready(&self, _ctx: &SyscallContext, _fd: usize) -> u32 {
        POLL_IN | POLL_OUT
    }
}

/// Unsupported/unknown FD kind — returns errors for everything.
pub(crate) struct UnsupportedOps;

impl FileOps for UnsupportedOps {}

// ---------------------------------------------------------------------------
// Dispatch: fd kind → &dyn FileOps
// ---------------------------------------------------------------------------

static STDIN: StdinOps = StdinOps;
static STDOUT: StdoutOps = StdoutOps;
static PIPE_READ: PipeReadOps = PipeReadOps;
static PIPE_WRITE: PipeWriteOps = PipeWriteOps;
static INITRD_FILE: InitrdFileOps = InitrdFileOps;
static VFS_FILE: VfsFileOps = VfsFileOps;
static VFS_DIR: VfsDirOps = VfsDirOps;
static PROCFS: ProcfsOps = ProcfsOps;
static EVENTFD: EventfdOps = EventfdOps;
static TIMERFD: TimerfdOps = TimerfdOps;
static MEMFD: MemfdOps = MemfdOps;
static TCP_SOCKET: TcpSocketOps = TcpSocketOps;
static UDP_SOCKET: UdpSocketOps = UdpSocketOps;
static EPOLL: EpollOps = EpollOps;
static UNIX_SOCKET: UnixSocketOps = UnixSocketOps;
static UNSUPPORTED: UnsupportedOps = UnsupportedOps;

/// Look up the FileOps implementation for a given FD kind.
///
/// FD kinds (matching fd.rs FdEntry::kind values):
///   0 = unused, 1 = stdin, 2 = stdout, 3 = stderr,
///   4 = pipe_read, 5 = pipe_write, 8 = tcp_socket, 9 = udp_socket,
///   10 = initrd_file, 13 = vfs_file, 14 = vfs_dir, 15 = procfs,
///   20 = epoll, 22 = eventfd, 23 = timerfd, 25 = memfd,
///   27/28 = unix_socket
pub(crate) fn fd_ops(kind: u8) -> &'static dyn FileOps {
    match kind {
        1 => &STDIN,
        2 | 3 => &STDOUT,
        4 => &PIPE_READ,
        5 => &PIPE_WRITE,
        8 => &TCP_SOCKET,
        9 => &UDP_SOCKET,
        10 => &INITRD_FILE,
        13 => &VFS_FILE,
        14 => &VFS_DIR,
        15 => &PROCFS,
        20 => &EPOLL,
        22 => &EVENTFD,
        23 => &TIMERFD,
        25 => &MEMFD,
        27 | 28 => &UNIX_SOCKET,
        _ => &UNSUPPORTED,
    }
}
