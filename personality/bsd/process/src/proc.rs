//! Process descriptor as a SOT domain wrapper.
//!
//! In SOT there are no "processes" -- only capability domains. This module
//! provides a POSIX-compatible process abstraction on top of domains:
//! - PID is derived from the domain ID
//! - Process states map to domain lifecycle events
//! - Parent-child relationships follow the domain delegation tree

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::posix::Cap;
use crate::signal::SignalSet;

/// Maximum number of file descriptors per process.
const MAX_FDS: usize = 256;

/// Global PID counter. Domain IDs and PIDs are 1:1 but we keep a separate
/// counter so the personality can track its own namespace.
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// Process identifier (maps 1:1 to a SOT domain ID).
pub type Pid = u32;

/// Process group identifier.
pub type Pgid = u32;

/// Session identifier.
pub type Sid = u32;

/// Process states, mapped to domain lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Actively scheduled (domain is runnable).
    Running,
    /// Stopped by a signal (SIGSTOP/SIGTSTP). Domain is suspended.
    Stopped,
    /// Terminated but parent has not yet called wait(). Domain is destroyed
    /// but the PCB is retained so the exit status can be collected.
    Zombie,
}

/// A single file-descriptor slot.
#[derive(Debug, Clone, Copy)]
pub struct FdEntry {
    /// The underlying SOT capability.
    pub cap: Cap,
    /// Close-on-exec flag.
    pub cloexec: bool,
}

/// Process Control Block -- the POSIX view of a SOT domain.
#[derive(Debug)]
pub struct Process {
    /// POSIX PID (derived from domain ID).
    pub pid: Pid,
    /// The SOT domain capability that backs this process.
    pub domain_cap: Cap,
    /// Current state.
    pub state: ProcessState,
    /// Exit status (valid only when state == Zombie).
    pub exit_status: i32,
    /// Parent PID (0 for init).
    pub parent_pid: Pid,
    /// Direct children.
    pub children: Vec<Pid>,
    /// Process group.
    pub pgid: Pgid,
    /// Session.
    pub sid: Sid,
    /// Pending signals (delivered as IPC, see signal.rs).
    pub pending_signals: SignalSet,
    /// Signal channel cap (other processes send signals here).
    pub signal_channel: Cap,
    /// File descriptor table: index is the fd number.
    fds: [Option<FdEntry>; MAX_FDS],
}

impl Process {
    /// Create a new process wrapping a SOT domain.
    pub fn new(domain_cap: Cap, parent_pid: Pid, signal_channel: Cap) -> Self {
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        Self {
            pid,
            domain_cap,
            state: ProcessState::Running,
            exit_status: 0,
            parent_pid,
            children: Vec::new(),
            pgid: pid, // new process group by default
            sid: pid,  // new session by default
            pending_signals: SignalSet::empty(),
            signal_channel,
            fds: [const { None }; MAX_FDS],
        }
    }

    /// Allocate the lowest available fd number for `cap`.
    pub fn fd_alloc(&mut self, cap: Cap, cloexec: bool) -> Option<usize> {
        for (i, slot) in self.fds.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(FdEntry { cap, cloexec });
                return Some(i);
            }
        }
        None // EMFILE
    }

    /// Look up a capability by fd number.
    pub fn fd_get(&self, fd: usize) -> Option<&FdEntry> {
        self.fds.get(fd).and_then(|s| s.as_ref())
    }

    /// Close an fd, returning the cap that was held (for revocation).
    pub fn fd_close(&mut self, fd: usize) -> Option<Cap> {
        let slot = self.fds.get_mut(fd)?;
        let entry = slot.take()?;
        Some(entry.cap)
    }

    /// Duplicate `old_fd` into `new_fd` (dup2 semantics).
    /// If `new_fd` is already open, it is closed first.
    pub fn fd_dup2(&mut self, old_fd: usize, new_fd: usize) -> Option<Cap> {
        let entry = (*self.fds.get(old_fd)?)?;
        if new_fd >= MAX_FDS {
            return None;
        }
        // Close existing fd at new_fd (if any) -- caller should revoke it.
        self.fds[new_fd] = Some(FdEntry {
            cap: entry.cap,
            cloexec: false, // dup2 clears cloexec
        });
        Some(entry.cap)
    }

    /// Close all fds marked close-on-exec. Returns the caps that were closed.
    pub fn close_cloexec_fds(&mut self) -> Vec<Cap> {
        let mut closed = Vec::new();
        for slot in self.fds.iter_mut() {
            if let Some(entry) = slot {
                if entry.cloexec {
                    closed.push(entry.cap);
                    *slot = None;
                }
            }
        }
        closed
    }

    /// Transition to Zombie state with given exit status.
    pub fn exit(&mut self, status: i32) {
        self.state = ProcessState::Zombie;
        self.exit_status = status;
    }

    /// Check whether this process has exited.
    pub fn is_zombie(&self) -> bool {
        self.state == ProcessState::Zombie
    }
}

/// Process table -- maps PIDs to process descriptors.
#[derive(Debug, Default)]
pub struct ProcessTable {
    procs: BTreeMap<Pid, Process>,
}

impl ProcessTable {
    pub const fn new() -> Self {
        Self {
            procs: BTreeMap::new(),
        }
    }

    /// Register a newly created process.
    pub fn insert(&mut self, proc: Process) {
        let pid = proc.pid;
        self.procs.insert(pid, proc);
    }

    /// Look up a process by PID.
    pub fn get(&self, pid: Pid) -> Option<&Process> {
        self.procs.get(&pid)
    }

    /// Look up a process by PID (mutable).
    pub fn get_mut(&mut self, pid: Pid) -> Option<&mut Process> {
        self.procs.get_mut(&pid)
    }

    /// Remove a zombie process (after wait() collects its status).
    pub fn reap(&mut self, pid: Pid) -> Option<Process> {
        self.procs.remove(&pid)
    }

    /// Find zombie children of `parent_pid`. Returns the first zombie found.
    pub fn find_zombie_child(&self, parent_pid: Pid) -> Option<Pid> {
        self.procs.values().find_map(|p| {
            if p.parent_pid == parent_pid && p.is_zombie() {
                Some(p.pid)
            } else {
                None
            }
        })
    }

    /// Re-parent all children of `pid` to `new_parent` (init adoption).
    pub fn reparent_children(&mut self, pid: Pid, new_parent: Pid) {
        let children: Vec<Pid> = self
            .procs
            .values()
            .filter(|p| p.parent_pid == pid)
            .map(|p| p.pid)
            .collect();

        for child_pid in children {
            if let Some(child) = self.procs.get_mut(&child_pid) {
                child.parent_pid = new_parent;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_auto_increments() {
        let a = Process::new(10, 0, 100);
        let b = Process::new(20, 0, 200);
        assert!(b.pid > a.pid);
    }

    #[test]
    fn fd_alloc_returns_lowest_free() {
        let mut p = Process::new(1, 0, 100);
        assert_eq!(p.fd_alloc(10, false), Some(0));
        assert_eq!(p.fd_alloc(20, false), Some(1));
        p.fd_close(0);
        assert_eq!(p.fd_alloc(30, false), Some(0));
    }

    #[test]
    fn fd_dup2_overwrites() {
        let mut p = Process::new(1, 0, 100);
        p.fd_alloc(10, false); // fd 0
        p.fd_alloc(20, false); // fd 1
        p.fd_dup2(0, 1);
        assert_eq!(p.fd_get(1).unwrap().cap, 10);
    }

    #[test]
    fn close_cloexec() {
        let mut p = Process::new(1, 0, 100);
        p.fd_alloc(10, true);  // fd 0, cloexec
        p.fd_alloc(20, false); // fd 1, not cloexec
        let closed = p.close_cloexec_fds();
        assert_eq!(closed, alloc::vec![10]);
        assert!(p.fd_get(0).is_none());
        assert!(p.fd_get(1).is_some());
    }

    #[test]
    fn zombie_and_reap() {
        let mut table = ProcessTable::new();
        let mut p = Process::new(1, 0, 100);
        let pid = p.pid;
        let parent = 0;
        p.parent_pid = parent;
        p.exit(42);
        table.insert(p);

        assert_eq!(table.find_zombie_child(parent), Some(pid));
        let reaped = table.reap(pid).unwrap();
        assert_eq!(reaped.exit_status, 42);
    }
}
