//! Synchronization primitives -- mutex, rwlock, condvar.
//!
//! NetBSD rump exposes kernel-style locks (adaptive mutexes, reader-writer
//! locks, condition variables).  On SOT these map to Secure Objects backed
//! by futex-style waits and SOT IPC notifications.

use crate::{RumpError, SotCap};

/// Maximum number of each primitive we track concurrently.
const MAX_MUTEXES: usize = 256;
const MAX_RWLOCKS: usize = 128;
const MAX_CONDVARS: usize = 128;

// ---------------------------------------------------------------------------
// Handle types
// ---------------------------------------------------------------------------

/// Opaque mutex handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutexHandle(pub u32);

/// Opaque reader-writer lock handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RwLockHandle(pub u32);

/// Opaque condition variable handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CondVarHandle(pub u32);

// ---------------------------------------------------------------------------
// Mutex
// ---------------------------------------------------------------------------

/// Mutex flags (mirrors NetBSD MUTEX_* constants).
pub mod mutex_flags {
    /// Adaptive mutex (may spin briefly before blocking).
    pub const ADAPTIVE: u32 = 0x01;
    /// Spin mutex (never blocks, interrupt-safe).
    pub const SPIN: u32 = 0x02;
}

/// Internal mutex state.
#[derive(Debug)]
#[allow(dead_code)]
struct MutexEntry {
    /// SOT capability representing the lock object.
    cap: SotCap,
    /// Flags passed at init time.
    flags: u32,
    /// Owner thread id (0 = unlocked).
    owner: u32,
}

/// Fixed-size mutex table.
pub struct MutexTable {
    entries: [Option<MutexEntry>; MAX_MUTEXES],
    count: usize,
}

impl MutexTable {
    pub const fn new() -> Self {
        const NONE: Option<MutexEntry> = None;
        Self {
            entries: [NONE; MAX_MUTEXES],
            count: 0,
        }
    }

    /// Allocate a new mutex.
    pub fn init(&mut self, flags: u32) -> Result<MutexHandle, RumpError> {
        // TODO: SOT syscall -- create futex-backed lock object:
        //   let cap = sot_sys::mutex_create(flags)?;
        let cap = SotCap(0); // placeholder

        let entry = MutexEntry {
            cap,
            flags,
            owner: 0,
        };

        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(MutexHandle(i as u32));
            }
        }
        Err(RumpError::OutOfMemory)
    }

    /// Acquire (enter) a mutex.
    pub fn enter(&mut self, h: MutexHandle) -> Result<(), RumpError> {
        let entry = self
            .entries
            .get_mut(h.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(RumpError::InvalidCap)?;

        // TODO: SOT syscall -- futex_wait / spin depending on flags:
        //   sot_sys::mutex_lock(entry.cap)?;
        entry.owner = 1; // placeholder (should be current thread id)
        Ok(())
    }

    /// Release (exit) a mutex.
    pub fn exit(&mut self, h: MutexHandle) -> Result<(), RumpError> {
        let entry = self
            .entries
            .get_mut(h.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(RumpError::InvalidCap)?;

        // TODO: SOT syscall -- futex_wake:
        //   sot_sys::mutex_unlock(entry.cap)?;
        entry.owner = 0;
        Ok(())
    }

    /// Destroy a mutex, releasing the SOT capability.
    pub fn destroy(&mut self, h: MutexHandle) -> Result<(), RumpError> {
        let slot = self
            .entries
            .get_mut(h.0 as usize)
            .ok_or(RumpError::InvalidCap)?;
        if slot.is_some() {
            // TODO: SOT syscall -- revoke capability:
            //   sot_sys::cap_revoke(entry.cap)?;
            *slot = None;
            self.count -= 1;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reader-Writer Lock
// ---------------------------------------------------------------------------

/// Internal rwlock state.
#[derive(Debug)]
#[allow(dead_code)]
struct RwLockEntry {
    cap: SotCap,
    flags: u32,
    /// Positive = reader count, -1 = write-locked.
    state: i32,
}

/// Fixed-size rwlock table.
pub struct RwLockTable {
    entries: [Option<RwLockEntry>; MAX_RWLOCKS],
    count: usize,
}

impl RwLockTable {
    pub const fn new() -> Self {
        const NONE: Option<RwLockEntry> = None;
        Self {
            entries: [NONE; MAX_RWLOCKS],
            count: 0,
        }
    }

    /// Create a new reader-writer lock.
    pub fn init(&mut self, flags: u32) -> Result<RwLockHandle, RumpError> {
        // TODO: SOT syscall -- create rwlock object:
        //   let cap = sot_sys::rwlock_create(flags)?;
        let cap = SotCap(0);

        let entry = RwLockEntry {
            cap,
            flags,
            state: 0,
        };

        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(RwLockHandle(i as u32));
            }
        }
        Err(RumpError::OutOfMemory)
    }

    /// Enter the rwlock for reading (`write=false`) or writing (`write=true`).
    pub fn enter(&mut self, h: RwLockHandle, write: bool) -> Result<(), RumpError> {
        let entry = self
            .entries
            .get_mut(h.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(RumpError::InvalidCap)?;

        if write {
            // TODO: SOT syscall -- acquire write lock:
            //   sot_sys::rwlock_write_lock(entry.cap)?;
            entry.state = -1;
        } else {
            // TODO: SOT syscall -- acquire read lock:
            //   sot_sys::rwlock_read_lock(entry.cap)?;
            entry.state += 1;
        }
        Ok(())
    }

    /// Release the rwlock.
    pub fn exit(&mut self, h: RwLockHandle) -> Result<(), RumpError> {
        let entry = self
            .entries
            .get_mut(h.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(RumpError::InvalidCap)?;

        if entry.state == -1 {
            // TODO: SOT syscall -- release write lock:
            //   sot_sys::rwlock_write_unlock(entry.cap)?;
            entry.state = 0;
        } else if entry.state > 0 {
            // TODO: SOT syscall -- release read lock:
            //   sot_sys::rwlock_read_unlock(entry.cap)?;
            entry.state -= 1;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Condition Variable
// ---------------------------------------------------------------------------

/// Internal condvar state.
#[derive(Debug)]
#[allow(dead_code)]
struct CondVarEntry {
    cap: SotCap,
    /// Number of threads currently waiting.
    waiters: u32,
}

/// Fixed-size condvar table.
pub struct CondVarTable {
    entries: [Option<CondVarEntry>; MAX_CONDVARS],
    count: usize,
}

impl CondVarTable {
    pub const fn new() -> Self {
        const NONE: Option<CondVarEntry> = None;
        Self {
            entries: [NONE; MAX_CONDVARS],
            count: 0,
        }
    }

    /// Create a new condition variable.
    pub fn init(&mut self) -> Result<CondVarHandle, RumpError> {
        // TODO: SOT syscall -- create condvar (futex-backed):
        //   let cap = sot_sys::condvar_create()?;
        let cap = SotCap(0);

        let entry = CondVarEntry { cap, waiters: 0 };

        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(CondVarHandle(i as u32));
            }
        }
        Err(RumpError::OutOfMemory)
    }

    /// Wait on a condvar, atomically releasing `mtx`.
    pub fn wait(
        &mut self,
        cv: CondVarHandle,
        _mtx: &mut MutexTable,
        _mtx_h: MutexHandle,
    ) -> Result<(), RumpError> {
        let entry = self
            .entries
            .get_mut(cv.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(RumpError::InvalidCap)?;

        entry.waiters += 1;

        // TODO: SOT syscalls -- atomically:
        //   1. sot_sys::mutex_unlock(mtx_cap);
        //   2. sot_sys::futex_wait(cv_cap);
        //   3. sot_sys::mutex_lock(mtx_cap);  (re-acquire on wake)

        entry.waiters -= 1;
        Ok(())
    }

    /// Wake one waiter.
    pub fn signal(&mut self, cv: CondVarHandle) -> Result<(), RumpError> {
        let entry = self
            .entries
            .get_mut(cv.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(RumpError::InvalidCap)?;

        if entry.waiters > 0 {
            // TODO: SOT syscall -- futex_wake(cv_cap, 1):
            //   sot_sys::futex_wake(entry.cap, 1)?;
        }
        Ok(())
    }

    /// Wake all waiters.
    pub fn broadcast(&mut self, cv: CondVarHandle) -> Result<(), RumpError> {
        let entry = self
            .entries
            .get_mut(cv.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(RumpError::InvalidCap)?;

        if entry.waiters > 0 {
            // TODO: SOT syscall -- futex_wake(cv_cap, ALL):
            //   sot_sys::futex_wake(entry.cap, entry.waiters)?;
        }
        Ok(())
    }
}
