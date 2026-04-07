//! Rump hypervisor interface -- the ~30 `rumpuser_*` functions.
//!
//! This is the central translation table.  The rump kernel never calls
//! SOT primitives directly; it calls through this trait.  `SotHypervisor`
//! is the concrete implementation that routes each call to SOT domain
//! operations (frame alloc, IPC, caps, scheduling).

use crate::bio::{self, BlockDeviceTable};
use crate::mem::{self, AnonMapTable};
use crate::sync::{CondVarHandle, CondVarTable, MutexHandle, MutexTable, RwLockHandle, RwLockTable};
use crate::thread::{self, ThreadHandle, ThreadTable};
use crate::{DomainHandle, RumpError};

/// The rump hypervisor interface.
///
/// Every function here corresponds to a `rumpuser_*` hypercall that the
/// NetBSD rump kernel issues.  The adaptation layer translates each one
/// into SOT exokernel operations.
pub trait RumpHypervisor {
    // -- Thread management ------------------------------------------------
    fn thread_create(
        &mut self,
        func: fn(*mut u8),
        arg: *mut u8,
        name: &str,
    ) -> Result<ThreadHandle, RumpError>;

    fn thread_join(&mut self, handle: ThreadHandle) -> Result<(), RumpError>;

    fn thread_exit(&mut self, handle: ThreadHandle);

    // -- Synchronization --------------------------------------------------
    fn mutex_init(&mut self, flags: u32) -> Result<MutexHandle, RumpError>;
    fn mutex_enter(&mut self, handle: MutexHandle) -> Result<(), RumpError>;
    fn mutex_exit(&mut self, handle: MutexHandle) -> Result<(), RumpError>;
    fn mutex_destroy(&mut self, handle: MutexHandle) -> Result<(), RumpError>;

    fn rw_init(&mut self, flags: u32) -> Result<RwLockHandle, RumpError>;
    fn rw_enter(&mut self, handle: RwLockHandle, write: bool) -> Result<(), RumpError>;
    fn rw_exit(&mut self, handle: RwLockHandle) -> Result<(), RumpError>;

    fn cv_init(&mut self) -> Result<CondVarHandle, RumpError>;
    fn cv_wait(&mut self, cv: CondVarHandle, mtx: MutexHandle) -> Result<(), RumpError>;
    fn cv_signal(&mut self, cv: CondVarHandle) -> Result<(), RumpError>;
    fn cv_broadcast(&mut self, cv: CondVarHandle) -> Result<(), RumpError>;

    // -- Memory -----------------------------------------------------------
    fn malloc(&mut self, size: usize, align: usize) -> Result<*mut u8, RumpError>;
    fn free(&mut self, ptr: *mut u8, size: usize);
    fn anonmmap(&mut self, size: usize) -> Result<*mut u8, RumpError>;

    // -- Block I/O --------------------------------------------------------
    fn bio_read(&self, dev: u64, offset: u64, buf: &mut [u8]) -> Result<usize, RumpError>;
    fn bio_write(&self, dev: u64, offset: u64, buf: &[u8]) -> Result<usize, RumpError>;

    // -- Clock ------------------------------------------------------------
    fn clock_gettime(&self) -> u64;

    // -- Errno ------------------------------------------------------------
    fn seterrno(&mut self, errno: i32);
    fn geterrno(&self) -> i32;
}

/// Concrete implementation that maps every rumpuser hypercall to SOT
/// exokernel primitives.
pub struct SotHypervisor {
    /// Domain this hypervisor instance runs inside.
    pub domain: DomainHandle,
    /// Thread bookkeeping.
    pub threads: ThreadTable,
    /// Mutex bookkeeping.
    pub mutexes: MutexTable,
    /// Reader-writer lock bookkeeping.
    pub rwlocks: RwLockTable,
    /// Condition variable bookkeeping.
    pub condvars: CondVarTable,
    /// Anonymous memory mapping tracker.
    pub anon_maps: AnonMapTable,
    /// Block device registry.
    pub block_devices: BlockDeviceTable,
    /// Per-thread errno (simplified: single value, not truly per-thread).
    errno: i32,
}

impl SotHypervisor {
    /// Create a new hypervisor instance for the given SOT domain.
    pub const fn new(domain: DomainHandle) -> Self {
        Self {
            domain,
            threads: ThreadTable::new(),
            mutexes: MutexTable::new(),
            rwlocks: RwLockTable::new(),
            condvars: CondVarTable::new(),
            anon_maps: AnonMapTable::new(),
            block_devices: BlockDeviceTable::new(),
            errno: 0,
        }
    }
}

impl RumpHypervisor for SotHypervisor {
    // -- Thread management ------------------------------------------------

    fn thread_create(
        &mut self,
        func: fn(*mut u8),
        arg: *mut u8,
        name: &str,
    ) -> Result<ThreadHandle, RumpError> {
        thread::create(&mut self.threads, func, arg, name, self.domain)
    }

    fn thread_join(&mut self, handle: ThreadHandle) -> Result<(), RumpError> {
        thread::join(&mut self.threads, handle)
    }

    fn thread_exit(&mut self, handle: ThreadHandle) {
        thread::exit(&mut self.threads, handle);
    }

    // -- Synchronization --------------------------------------------------

    fn mutex_init(&mut self, flags: u32) -> Result<MutexHandle, RumpError> {
        self.mutexes.init(flags)
    }

    fn mutex_enter(&mut self, handle: MutexHandle) -> Result<(), RumpError> {
        self.mutexes.enter(handle)
    }

    fn mutex_exit(&mut self, handle: MutexHandle) -> Result<(), RumpError> {
        self.mutexes.exit(handle)
    }

    fn mutex_destroy(&mut self, handle: MutexHandle) -> Result<(), RumpError> {
        self.mutexes.destroy(handle)
    }

    fn rw_init(&mut self, flags: u32) -> Result<RwLockHandle, RumpError> {
        self.rwlocks.init(flags)
    }

    fn rw_enter(&mut self, handle: RwLockHandle, write: bool) -> Result<(), RumpError> {
        self.rwlocks.enter(handle, write)
    }

    fn rw_exit(&mut self, handle: RwLockHandle) -> Result<(), RumpError> {
        self.rwlocks.exit(handle)
    }

    fn cv_init(&mut self) -> Result<CondVarHandle, RumpError> {
        self.condvars.init()
    }

    fn cv_wait(&mut self, cv: CondVarHandle, mtx: MutexHandle) -> Result<(), RumpError> {
        self.condvars.wait(cv, &mut self.mutexes, mtx)
    }

    fn cv_signal(&mut self, cv: CondVarHandle) -> Result<(), RumpError> {
        self.condvars.signal(cv)
    }

    fn cv_broadcast(&mut self, cv: CondVarHandle) -> Result<(), RumpError> {
        self.condvars.broadcast(cv)
    }

    // -- Memory -----------------------------------------------------------

    fn malloc(&mut self, size: usize, align: usize) -> Result<*mut u8, RumpError> {
        mem::malloc(&mut self.anon_maps, size, align)
    }

    fn free(&mut self, ptr: *mut u8, size: usize) {
        mem::free(&mut self.anon_maps, ptr, size);
    }

    fn anonmmap(&mut self, size: usize) -> Result<*mut u8, RumpError> {
        mem::anonmmap(&mut self.anon_maps, size)
    }

    // -- Block I/O --------------------------------------------------------

    fn bio_read(&self, dev: u64, offset: u64, buf: &mut [u8]) -> Result<usize, RumpError> {
        bio::bio_read(&self.block_devices, dev, offset, buf)
    }

    fn bio_write(&self, dev: u64, offset: u64, buf: &[u8]) -> Result<usize, RumpError> {
        bio::bio_write(&self.block_devices, dev, offset, buf)
    }

    // -- Clock ------------------------------------------------------------

    fn clock_gettime(&self) -> u64 {
        // TODO: SOT syscall -- read TSC or LAPIC timer, convert to nanoseconds:
        //   sot_sys::clock_gettime()
        0
    }

    // -- Errno ------------------------------------------------------------

    fn seterrno(&mut self, errno: i32) {
        self.errno = errno;
    }

    fn geterrno(&self) -> i32 {
        self.errno
    }
}
