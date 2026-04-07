//! Thread management -- maps rump threads to SOT domain threads.
//!
//! A rump kernel thread is a lightweight cooperative context.  On SOT
//! every thread lives inside a scheduling domain and is represented by
//! a capability.  This module bridges the two models.

use crate::{DomainHandle, RumpError, SotCap};

/// Maximum concurrent rump threads we track.
const MAX_THREADS: usize = 256;

/// Opaque handle returned by `thread_create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadHandle(pub u32);

/// Per-thread bookkeeping stored in the thread table.
#[derive(Debug)]
pub struct ThreadEntry {
    /// SOT thread capability.
    pub cap: SotCap,
    /// SOT domain this thread belongs to.
    pub domain: DomainHandle,
    /// Human-readable name (for debug).
    pub name: [u8; 32],
    /// Has the thread exited?
    pub exited: bool,
}

/// Thread table -- fixed-size array, no heap allocation needed for the
/// table itself.
pub struct ThreadTable {
    entries: [Option<ThreadEntry>; MAX_THREADS],
    count: usize,
}

impl ThreadTable {
    /// Create an empty thread table.
    pub const fn new() -> Self {
        // const-compatible None initialization
        const NONE: Option<ThreadEntry> = None;
        Self {
            entries: [NONE; MAX_THREADS],
            count: 0,
        }
    }

    /// Allocate a slot and return its index as a `ThreadHandle`.
    pub fn alloc(&mut self, entry: ThreadEntry) -> Result<ThreadHandle, RumpError> {
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(ThreadHandle(i as u32));
            }
        }
        Err(RumpError::OutOfMemory)
    }

    /// Look up a thread by handle.
    pub fn get(&self, h: ThreadHandle) -> Option<&ThreadEntry> {
        self.entries.get(h.0 as usize).and_then(|s| s.as_ref())
    }

    /// Look up a thread mutably.
    pub fn get_mut(&mut self, h: ThreadHandle) -> Option<&mut ThreadEntry> {
        self.entries.get_mut(h.0 as usize).and_then(|s| s.as_mut())
    }

    /// Free a slot after join/exit.
    pub fn free(&mut self, h: ThreadHandle) {
        if let Some(slot) = self.entries.get_mut(h.0 as usize) {
            if slot.is_some() {
                *slot = None;
                self.count -= 1;
            }
        }
    }

    /// Number of live threads.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Public API used by the RumpHypervisor implementation
// ---------------------------------------------------------------------------

/// Create a rump thread backed by a SOT domain thread.
///
/// `func` and `arg` describe the entry point.  `name` is a debug label.
/// `domain` is the SOT domain the thread will be spawned into.
pub fn create(
    table: &mut ThreadTable,
    _func: fn(*mut u8),
    _arg: *mut u8,
    name: &str,
    domain: DomainHandle,
) -> Result<ThreadHandle, RumpError> {
    let mut name_buf = [0u8; 32];
    let len = name.len().min(31);
    name_buf[..len].copy_from_slice(&name.as_bytes()[..len]);

    // TODO: SOT syscall -- spawn thread in `domain`:
    //   let cap = sot_sys::thread_create(domain, func, arg)?;
    let cap = SotCap(0); // placeholder

    let entry = ThreadEntry {
        cap,
        domain,
        name: name_buf,
        exited: false,
    };
    table.alloc(entry)
}

/// Join (block until exit) a rump thread.
pub fn join(table: &mut ThreadTable, handle: ThreadHandle) -> Result<(), RumpError> {
    let entry = table.get(handle).ok_or(RumpError::InvalidCap)?;
    let _cap = entry.cap;

    // TODO: SOT syscall -- join thread:
    //   sot_sys::thread_join(cap)?;

    table.free(handle);
    Ok(())
}

/// Mark current thread as exited (called from the thread itself).
pub fn exit(table: &mut ThreadTable, handle: ThreadHandle) {
    if let Some(entry) = table.get_mut(handle) {
        entry.exited = true;
    }

    // TODO: SOT syscall -- thread_exit() (does not return)
    //   sot_sys::thread_exit();
}
