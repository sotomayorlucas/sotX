//! sot-lucas: LUCAS evolution bridge to SOT process server.
//!
//! # Background
//!
//! The existing LUCAS handler (`services/init/src/lucas_handler.rs`) is a
//! monolithic ~8000-line function that intercepts Linux syscalls via IPC
//! redirect and emulates them inline. It maintains per-process state in
//! static arrays (FD tables, CWD, signal masks, thread groups, etc.).
//!
//! # Evolution Path
//!
//! The SOT architecture replaces this monolith with a structured process
//! server that uses the `sot-linuxulator` translation layer. The migration
//! proceeds in three phases:
//!
//! 1. **Bridge phase** (current): The existing LUCAS handler implements
//!    `LucasCompat` to expose its state through a structured interface.
//!    New code can query LUCAS state without reaching into static arrays.
//!
//! 2. **Parallel phase**: New syscalls are handled via the `sot-linuxulator`
//!    translation path. LUCAS handles the long tail of existing syscalls.
//!    Both paths share process state through `ProcessState`.
//!
//! 3. **Replacement phase**: All syscall handling moves to the translation
//!    layer. LUCAS static arrays are replaced by per-domain `ProcessState`
//!    allocated from a domain-local heap. The LUCAS handler is retired.
//!
//! # Usage
//!
//! The existing `services/init/` code can implement `LucasCompat` on its
//! handler struct to expose state to the new process server:
//!
//! ```ignore
//! use sot_lucas::{LucasCompat, ProcessState, FdInfo, FdType};
//!
//! struct LegacyHandler;
//!
//! impl LucasCompat for LegacyHandler {
//!     fn process_state(&self, pid: u32) -> Option<ProcessState> {
//!         // Read from existing static arrays
//!         Some(ProcessState {
//!             pid,
//!             tgid: PROC_TGID[pid as usize],
//!             // ...
//!         })
//!     }
//!     // ...
//! }
//! ```

#![no_std]

/// Maximum number of file descriptors per process (matches LUCAS).
pub const MAX_FDS: usize = 64;

/// Maximum number of processes (matches LUCAS MAX_PROCS).
pub const MAX_PROCS: usize = 32;

/// Maximum path length for CWD.
pub const MAX_CWD_LEN: usize = 128;

/// Maximum number of signal handlers.
pub const MAX_SIGNALS: usize = 64;

// ---------------------------------------------------------------------------
// Process state snapshot
// ---------------------------------------------------------------------------

/// Snapshot of a single process's state, extracted from LUCAS static arrays.
///
/// This is the bridge data structure: LUCAS fills it in from its statics,
/// and the new process server consumes it through `LucasCompat`.
#[derive(Debug, Clone)]
pub struct ProcessState {
    /// Process ID.
    pub pid: u32,
    /// Thread group ID (getpid() returns this).
    pub tgid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// FD group index (shared FD table for CLONE_FILES threads).
    pub fd_group: u32,
    /// Memory group index (shared address space for CLONE_VM threads).
    pub mem_group: u32,
    /// Signal group index (shared signal handlers for CLONE_SIGHAND threads).
    pub sig_group: u32,
    /// Current working directory.
    pub cwd: [u8; MAX_CWD_LEN],
    /// CWD length in bytes.
    pub cwd_len: usize,
    /// Signal mask (blocked signals).
    pub signal_mask: u64,
    /// Whether this process has exited.
    pub exited: bool,
    /// Exit code (if exited).
    pub exit_code: i32,
    /// Whether this is a thread (vs process leader).
    pub is_thread: bool,
    /// Kernel raw thread ID (for signal delivery).
    pub kernel_tid: u64,
    /// Redirect endpoint capability.
    pub redirect_ep: u64,
    /// Clear-child-tid address (for CLONE_CHILD_CLEARTID).
    pub clear_child_tid: u64,
}

/// Information about a single file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct FdInfo {
    /// File descriptor number.
    pub fd: u32,
    /// Type of this fd.
    pub kind: FdType,
    /// Whether close-on-exec is set.
    pub cloexec: bool,
    /// Whether non-blocking is set.
    pub nonblock: bool,
    /// Current file offset (for seekable fds).
    pub offset: u64,
}

/// File descriptor type (mirrors LUCAS FdKind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdType {
    /// Not open.
    Closed,
    /// stdin (serial/keyboard).
    Stdin,
    /// stdout/stderr (serial console).
    Stdout,
    /// Initrd-backed file.
    Initrd,
    /// VFS-backed file.
    VfsFile,
    /// VFS directory.
    VfsDir,
    /// Virtual /proc or /sys file.
    ProcFs,
    /// Pipe read end.
    PipeRead,
    /// Pipe write end.
    PipeWrite,
    /// TCP socket.
    SocketTcp,
    /// UDP socket.
    SocketUdp,
    /// Unix socketpair (A side).
    UnixA,
    /// Unix socketpair (B side).
    UnixB,
    /// Eventfd.
    Eventfd,
    /// Timerfd.
    Timerfd,
    /// Epoll instance.
    Epoll,
    /// Signalfd.
    Signalfd,
    /// Memfd (anonymous file).
    Memfd,
    /// Inotify instance.
    Inotify,
}

// ---------------------------------------------------------------------------
// LucasCompat trait
// ---------------------------------------------------------------------------

/// Trait that the existing LUCAS handler implements to expose its internal
/// state to the new SOT process server.
///
/// Each method extracts state from the LUCAS static arrays without modifying
/// them. The process server calls these methods to read LUCAS state and
/// gradually take over syscall handling.
pub trait LucasCompat {
    /// Get the full process state for a given PID.
    fn process_state(&self, pid: u32) -> Option<ProcessState>;

    /// Get file descriptor info for a (fd_group, fd) pair.
    fn fd_info(&self, fd_group: u32, fd: u32) -> Option<FdInfo>;

    /// Get the number of open fds in a group.
    fn fd_count(&self, fd_group: u32) -> u32;

    /// Check if a process is alive (not exited/zombie).
    fn is_alive(&self, pid: u32) -> bool;

    /// Get the list of child PIDs for a process.
    fn children(&self, pid: u32) -> ChildIter;

    /// Get the signal mask for a process.
    fn signal_mask(&self, pid: u32) -> u64;

    /// Read the CWD for a process's fd group.
    fn cwd(&self, fd_group: u32) -> &[u8];
}

/// Iterator over child PIDs. Fixed-size to avoid allocation.
#[derive(Debug)]
pub struct ChildIter {
    /// PIDs of children (0 = empty slot).
    pids: [u32; MAX_PROCS],
    /// Number of valid entries.
    count: usize,
    /// Current iteration index.
    index: usize,
}

impl ChildIter {
    /// Create an empty iterator.
    pub const fn empty() -> Self {
        Self {
            pids: [0; MAX_PROCS],
            count: 0,
            index: 0,
        }
    }

    /// Create an iterator from a slice of child PIDs.
    pub fn from_slice(children: &[u32]) -> Self {
        let mut pids = [0u32; MAX_PROCS];
        let count = children.len().min(MAX_PROCS);
        let mut i = 0;
        while i < count {
            pids[i] = children[i];
            i += 1;
        }
        Self { pids, count, index: 0 }
    }
}

impl Iterator for ChildIter {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.index < self.count {
            let pid = self.pids[self.index];
            self.index += 1;
            Some(pid)
        } else {
            None
        }
    }
}
