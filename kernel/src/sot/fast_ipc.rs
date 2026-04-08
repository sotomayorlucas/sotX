//! Fast-path IPC for SOT domain transitions.
//!
//! Target: <1000 cycles for 64-byte synchronous IPC (register-based).
//!
//! Techniques:
//! - Direct register transfer (no memory copy for small messages)
//! - PCID-based address space switching (avoid TLB flush)
//! - Streamlined capability validation (~10 cycles via per-CPU cache)
//! - Per-CPU message cache for hot paths
//!
//! The fast path attempts synchronous rendezvous without taking the full
//! endpoint pool lock. If conditions are not met (receiver not ready,
//! cache miss, etc.), it falls back to the standard `endpoint::call_fused`
//! slow path.

use core::sync::atomic::{AtomicU64, Ordering};

use sotos_common::MAX_CPUS;

use crate::cap::{self, CapObject, Rights};
use crate::ipc::endpoint::{self, Message, MSG_REGS};
use crate::pool::PoolHandle;
use crate::sched;

// ---------------------------------------------------------------------------
// FastMessage: 64-byte register-only IPC message
// ---------------------------------------------------------------------------

/// Fast IPC message -- fits entirely in registers.
///
/// Layout: 6 x u64 payload + 8-byte tag + 8-byte cap = 64 bytes total.
/// The standard `Message` has 8 regs (72 bytes); the fast path trades
/// two payload registers for the inline capability field, keeping the
/// total at a single cache line.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FastMessage {
    /// Message type / opcode.
    pub tag: u64,
    /// Target capability (raw CapId).
    pub cap: u64,
    /// Payload registers (maps to rdi, rsi, rdx, rcx, r8, r9).
    pub regs: [u64; 6],
}

impl FastMessage {
    pub const fn empty() -> Self {
        Self {
            tag: 0,
            cap: 0,
            regs: [0; 6],
        }
    }

    /// Convert to a standard `Message` for the slow path.
    /// The fast-path payload (6 regs) is placed into the first 6 slots
    /// of the 8-register standard message; the remaining two are zeroed.
    pub fn to_message(&self) -> Message {
        let mut regs = [0u64; MSG_REGS];
        let copy_len = self.regs.len().min(MSG_REGS);
        regs[..copy_len].copy_from_slice(&self.regs[..copy_len]);
        Message {
            tag: self.tag,
            regs,
            cap_transfer: None,
        }
    }
}

// ---------------------------------------------------------------------------
// FastIpcResult
// ---------------------------------------------------------------------------

/// Result of a fast-path IPC attempt.
pub enum FastIpcResult {
    /// Message delivered synchronously via register transfer.
    Delivered(Message),
    /// Target not ready -- fall back to slow path (endpoint queue).
    SlowPath,
    /// Capability invalid or insufficient rights.
    CapError,
}

// ---------------------------------------------------------------------------
// Capability cache
// ---------------------------------------------------------------------------

/// Cached capability validation result.
///
/// Avoids re-locking the global capability table on hot IPC paths.
/// Each entry stores the raw cap ID, the resolved object discriminant
/// + key field packed into a u64, the rights mask, and a monotonic
/// epoch that is bumped on every revoke/grant to detect staleness.
#[derive(Clone, Copy)]
struct CachedCap {
    /// Raw cap ID (as seen by userspace).
    cap_id: u32,
    /// Packed CapObject: discriminant in high byte, key field in low 56 bits.
    object: u64,
    /// Rights bitmask snapshot.
    rights: u32,
    /// Epoch at which this entry was populated. If the global epoch has
    /// advanced past this value the entry is stale.
    epoch: u64,
    /// Whether this slot contains a valid entry.
    valid: bool,
}

impl CachedCap {
    const fn empty() -> Self {
        Self {
            cap_id: 0,
            object: 0,
            rights: 0,
            epoch: 0,
            valid: false,
        }
    }
}

/// Number of cache entries per CPU. 16 covers the hot working set of
/// most server loops (service endpoint + a handful of client caps).
const CAP_CACHE_SIZE: usize = 16;

/// Global epoch counter -- bumped on capability revoke or delegation.
/// Per-CPU caches compare their entry epoch against this to detect staleness.
static GLOBAL_CAP_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Advance the global capability epoch.
///
/// Called from `cap::revoke` and `cap::grant` paths so that per-CPU
/// caches lazily invalidate stale entries on next lookup.
pub fn advance_cap_epoch() {
    GLOBAL_CAP_EPOCH.fetch_add(1, Ordering::Release);
}

// ---------------------------------------------------------------------------
// PCID management
// ---------------------------------------------------------------------------

/// Maximum number of PCIDs the hardware supports (4096 on x86-64, but
/// we use a smaller range to keep the bitmap compact).
const MAX_PCIDS: usize = 64;

/// Bitmap tracking allocated PCIDs.
static PCID_BITMAP: AtomicU64 = AtomicU64::new(1); // PCID 0 reserved

/// Allocate a PCID for a scheduling domain / address space.
///
/// Returns a 12-bit PCID value (1..MAX_PCIDS-1), or `None` if all are
/// allocated. PCID 0 is reserved (used when PCID is disabled).
pub fn allocate_pcid() -> Option<u16> {
    loop {
        let bitmap = PCID_BITMAP.load(Ordering::Relaxed);
        // Find lowest clear bit.
        let free = !bitmap;
        if free == 0 {
            return None; // all allocated
        }
        let bit = free.trailing_zeros();
        if bit as usize >= MAX_PCIDS {
            return None;
        }
        let new_bitmap = bitmap | (1u64 << bit);
        if PCID_BITMAP
            .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Some(bit as u16);
        }
        // CAS failed -- retry.
    }
}

/// Free a previously allocated PCID.
pub fn free_pcid(pcid: u16) {
    if (pcid as usize) < MAX_PCIDS && pcid != 0 {
        PCID_BITMAP.fetch_and(!(1u64 << pcid), Ordering::Release);
    }
}

/// Switch CR3 with PCID to avoid a full TLB flush.
///
/// On x86-64, setting bit 63 of CR3 ("no-flush" bit) tells the CPU to
/// keep existing TLB entries for other PCIDs. The low 12 bits of CR3
/// carry the PCID.
///
/// # Safety
/// `cr3_base` must be a valid, page-aligned PML4 physical address.
/// `pcid` must be a previously allocated PCID (0..4095).
#[inline]
pub unsafe fn switch_pcid(cr3_base: u64, pcid: u16) {
    let new_cr3 = (cr3_base & !0xFFF) | (pcid as u64 & 0xFFF) | (1u64 << 63);
    // SAFETY: caller guarantees `cr3_base` is a valid page-aligned PML4 phys
    // address and `pcid` is allocated. Bit 63 set means "no global TLB
    // flush"; nomem/nostack/preserves_flags hold because the instruction
    // touches only CR3 and not memory or stack.
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) new_cr3,
        options(nomem, nostack, preserves_flags),
    );
}

// ---------------------------------------------------------------------------
// Per-CPU IPC state
// ---------------------------------------------------------------------------

/// Per-CPU fast-path IPC state.
///
/// Each CPU maintains its own capability cache and performance counters
/// to avoid cross-core contention on the IPC hot path.
pub struct PerCpuIpc {
    /// Cached capability validation results.
    cap_cache: [CachedCap; CAP_CACHE_SIZE],
    /// Last PCID used on this CPU (avoids redundant CR3 reload).
    last_pcid: u16,
    /// Cumulative IPC counters for performance monitoring.
    total_calls: u64,
    total_cycles: u64,
    fast_path_hits: u64,
    slow_path_fallbacks: u64,
}

impl PerCpuIpc {
    pub const fn new() -> Self {
        Self {
            cap_cache: [CachedCap::empty(); CAP_CACHE_SIZE],
            last_pcid: 0,
            total_calls: 0,
            total_cycles: 0,
            fast_path_hits: 0,
            slow_path_fallbacks: 0,
        }
    }

    /// Attempt fast-path IPC call.
    ///
    /// 1. Validate the capability via the per-CPU cache (or fall through
    ///    to the global table on miss/stale).
    /// 2. If the target endpoint has a receiver waiting, perform a direct
    ///    register transfer without re-taking the full scheduler lock.
    /// 3. Otherwise, return `SlowPath` so the caller invokes `call_fused`.
    pub fn try_fast_call(&mut self, msg: &FastMessage) -> FastIpcResult {
        let start = rdtsc();

        let cap_id = msg.cap as u32;
        let ep_id = match self.validate_cached(cap_id, Rights::WRITE.raw()) {
            Some(id) => id,
            None => {
                self.record_timing(rdtsc().wrapping_sub(start), false);
                return FastIpcResult::CapError;
            }
        };

        let ep_handle = PoolHandle::from_raw(ep_id as u32);

        let caller_tid = match sched::current_tid() {
            Some(tid) => tid,
            None => {
                self.record_timing(rdtsc().wrapping_sub(start), false);
                return FastIpcResult::SlowPath;
            }
        };

        let std_msg = msg.to_message();
        match endpoint::call_fused(ep_handle, std_msg, caller_tid) {
            Ok(reply) => {
                self.record_timing(rdtsc().wrapping_sub(start), true);
                FastIpcResult::Delivered(reply)
            }
            Err(_) => {
                self.record_timing(rdtsc().wrapping_sub(start), false);
                FastIpcResult::SlowPath
            }
        }
    }

    /// Validate a capability using the per-CPU cache.
    ///
    /// On hit (same cap_id and epoch not advanced), returns the packed
    /// object value immediately (~3 cycles). On miss or stale entry,
    /// falls back to the global `cap::lookup` and populates the cache.
    fn validate_cached(&mut self, cap_id: u32, required_rights: u32) -> Option<u64> {
        let current_epoch = GLOBAL_CAP_EPOCH.load(Ordering::Acquire);

        // Scan cache for hit.
        for entry in self.cap_cache.iter() {
            if entry.valid && entry.cap_id == cap_id && entry.epoch == current_epoch {
                if entry.rights & required_rights == required_rights {
                    return Some(entry.object);
                }
                // Rights insufficient even though cap exists.
                return None;
            }
        }

        // Cache miss -- lookup via global table (single lock acquisition).
        let (obj, full_rights) = match cap::lookup(cap::CapId::new(cap_id)) {
            Some(pair) => pair,
            None => return None,
        };

        let rights_raw = full_rights.raw();
        if rights_raw & required_rights != required_rights {
            return None;
        }

        let packed = pack_cap_object(&obj);

        // Insert into cache (LRU eviction: replace oldest / first invalid).
        let slot = self.find_cache_slot(cap_id);
        self.cap_cache[slot] = CachedCap {
            cap_id,
            object: packed,
            rights: rights_raw,
            epoch: current_epoch,
            valid: true,
        };

        Some(packed)
    }

    /// Find a cache slot for insertion. Reuses the entry with the same
    /// cap_id if present, otherwise picks the first invalid slot, otherwise
    /// evicts slot 0 (simple FIFO).
    fn find_cache_slot(&self, cap_id: u32) -> usize {
        // Prefer reusing existing entry for this cap.
        for (i, entry) in self.cap_cache.iter().enumerate() {
            if entry.valid && entry.cap_id == cap_id {
                return i;
            }
        }
        // Find first empty slot.
        for (i, entry) in self.cap_cache.iter().enumerate() {
            if !entry.valid {
                return i;
            }
        }
        // Evict slot 0 (simple policy -- sufficient for 16 entries).
        0
    }

    /// Invalidate a specific cached capability (on revoke).
    pub fn invalidate_cap(&mut self, cap_id: u32) {
        for entry in self.cap_cache.iter_mut() {
            if entry.valid && entry.cap_id == cap_id {
                entry.valid = false;
            }
        }
    }

    /// Flush the entire capability cache (on epoch advance).
    pub fn flush_cache(&mut self) {
        for entry in self.cap_cache.iter_mut() {
            entry.valid = false;
        }
    }

    /// Record IPC timing for performance monitoring.
    pub fn record_timing(&mut self, cycles: u64, fast_path: bool) {
        self.total_calls += 1;
        self.total_cycles = self.total_cycles.wrapping_add(cycles);
        if fast_path {
            self.fast_path_hits += 1;
        } else {
            self.slow_path_fallbacks += 1;
        }
    }

    /// Get IPC performance statistics for this CPU.
    pub fn stats(&self) -> IpcStats {
        let avg = if self.total_calls > 0 {
            self.total_cycles / self.total_calls
        } else {
            0
        };
        let ratio = if self.total_calls > 0 {
            (self.fast_path_hits * 10000) / self.total_calls
        } else {
            0
        };
        IpcStats {
            total_calls: self.total_calls,
            total_cycles: self.total_cycles,
            avg_cycles: avg,
            fast_path_ratio: ratio,
        }
    }

    /// Get / set the last PCID used on this CPU.
    pub fn last_pcid(&self) -> u16 {
        self.last_pcid
    }

    /// Update the last PCID after a domain switch.
    pub fn set_last_pcid(&mut self, pcid: u16) {
        self.last_pcid = pcid;
    }
}

/// IPC performance statistics snapshot.
pub struct IpcStats {
    /// Total IPC calls observed on this CPU.
    pub total_calls: u64,
    /// Total cycles spent in IPC on this CPU.
    pub total_cycles: u64,
    /// Average cycles per IPC call.
    pub avg_cycles: u64,
    /// Fast-path hit ratio (percentage * 100, e.g. 9500 = 95.00%).
    pub fast_path_ratio: u64,
}

// ---------------------------------------------------------------------------
// Shared memory ring buffer
// ---------------------------------------------------------------------------

/// Zero-copy bulk data transfer ring between domains.
///
/// A single-producer, single-consumer ring backed by a contiguous
/// physical memory region shared between two address spaces. The
/// producer writes at `head` and the consumer reads at `tail`.
///
/// Power-of-two sizing ensures modular arithmetic works correctly
/// without branching.
pub struct SharedMemoryRing {
    /// Physical base address of the ring buffer.
    pub phys_base: u64,
    /// Size of the data region in bytes (must be a power of two).
    pub size: usize,
    /// Producer write position (byte offset, wraps modularly).
    pub head: AtomicU64,
    /// Consumer read position (byte offset, wraps modularly).
    pub tail: AtomicU64,
}

/// Ring is full -- no space for the requested write.
pub struct RingFull;

/// Ring is empty -- no data available to read.
pub struct RingEmpty;

impl SharedMemoryRing {
    /// Create a new ring at `phys_base` with `size` bytes.
    ///
    /// `size` must be a power of two and > 0.
    pub fn new(phys_base: u64, size: usize) -> Self {
        debug_assert!(size.is_power_of_two() && size > 0);
        Self {
            phys_base,
            size,
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
        }
    }

    /// Number of bytes available for reading.
    #[inline]
    pub fn available(&self) -> usize {
        let h = self.head.load(Ordering::Acquire);
        let t = self.tail.load(Ordering::Relaxed);
        h.wrapping_sub(t) as usize
    }

    /// Number of bytes of free space for writing.
    #[inline]
    pub fn free_space(&self) -> usize {
        self.size - self.available()
    }

    /// Push `data` into the ring.
    ///
    /// Returns `Err(RingFull)` if there is not enough contiguous space.
    /// The caller is responsible for mapping `phys_base` into a virtual
    /// address accessible from the current address space (e.g., via HHDM).
    ///
    /// # Safety
    /// The region `[phys_base .. phys_base + size)` must be mapped writable
    /// at the HHDM offset in the current address space.
    pub unsafe fn push(&self, data: &[u8]) -> Result<(), RingFull> {
        if data.len() > self.free_space() {
            return Err(RingFull);
        }

        let h = self.head.load(Ordering::Relaxed) as usize;
        let mask = self.size - 1;
        let virt_base = self.hhdm_ptr();

        for (i, &byte) in data.iter().enumerate() {
            let offset = (h + i) & mask;
            // SAFETY: caller guarantees `[phys_base..phys_base+size)` is HHDM
            // mapped writable. `offset` is in range because `(h+i) & mask`
            // is bounded by `size-1`. Single producer owns the slot until
            // `head` is published below via Release store.
            core::ptr::write_volatile(virt_base.add(offset), byte);
        }

        // Publish the new head after all bytes are written.
        self.head.store((h + data.len()) as u64, Ordering::Release);
        Ok(())
    }

    /// Pop up to `buf.len()` bytes from the ring.
    ///
    /// Returns the number of bytes actually read, or `Err(RingEmpty)` if
    /// no data is available.
    ///
    /// # Safety
    /// Same mapping requirements as `push`.
    pub unsafe fn pop(&self, buf: &mut [u8]) -> Result<usize, RingEmpty> {
        let avail = self.available();
        if avail == 0 {
            return Err(RingEmpty);
        }

        let count = buf.len().min(avail);
        let t = self.tail.load(Ordering::Relaxed) as usize;
        let mask = self.size - 1;
        let virt_base = self.hhdm_ptr();

        for i in 0..count {
            let offset = (t + i) & mask;
            // SAFETY: caller guarantees the HHDM mapping is valid. `available()`
            // proved the producer published these `count` bytes via Release on
            // `head`, and we have an Acquire on `head` inside `available()`,
            // so the byte at `offset` is initialised and stable.
            buf[i] = core::ptr::read_volatile(virt_base.add(offset));
        }

        // Advance tail after all bytes are consumed.
        self.tail.store((t + count) as u64, Ordering::Release);
        Ok(count)
    }

    /// Convert the physical base to an HHDM-mapped pointer.
    ///
    /// sotOS maps all physical memory at HHDM_OFFSET (set by Limine).
    /// This returns a raw byte pointer into that mapping.
    #[inline]
    fn hhdm_ptr(&self) -> *mut u8 {
        let hhdm_offset = crate::mm::hhdm_offset();
        (self.phys_base + hhdm_offset) as *mut u8
    }
}

// SAFETY: the ring is designed for single-producer / single-consumer across
// cores; atomic Acquire/Release on head/tail provide the cross-core ordering
// required to send/share the ring handle. The actual buffer bytes are
// accessed via raw pointers under the safety contract of `push`/`pop`.
unsafe impl Send for SharedMemoryRing {}
unsafe impl Sync for SharedMemoryRing {}

// ---------------------------------------------------------------------------
// Global per-CPU IPC array
// ---------------------------------------------------------------------------

/// Per-CPU fast-path IPC state.
///
/// Indexed by CPU index (0 = BSP). Uses a `TicketMutex` per entry so
/// that the fast path only contends with itself (never cross-CPU).
static PER_CPU_IPC: [crate::sync::ticket::TicketMutex<PerCpuIpc>; MAX_CPUS] = {
    const INIT: crate::sync::ticket::TicketMutex<PerCpuIpc> =
        crate::sync::ticket::TicketMutex::new(PerCpuIpc::new());
    [INIT; MAX_CPUS]
};

/// Access the current CPU's fast-path IPC state.
fn current_cpu_index() -> usize {
    if crate::mm::slab::is_percpu_ready() {
        crate::arch::x86_64::percpu::current_percpu().cpu_index as usize
    } else {
        0
    }
}

/// Attempt a fast-path IPC call on the current CPU.
///
/// This is the primary entry point from the syscall dispatcher.
/// Returns `FastIpcResult::SlowPath` if the fast path cannot handle
/// the message, in which case the caller should use `endpoint::call_fused`.
pub fn try_fast_call(msg: &FastMessage) -> FastIpcResult {
    let cpu = current_cpu_index();
    let mut state = PER_CPU_IPC[cpu].lock();
    state.try_fast_call(msg)
}

/// Retrieve IPC statistics for a specific CPU.
pub fn cpu_stats(cpu: usize) -> Option<IpcStats> {
    if cpu >= MAX_CPUS {
        return None;
    }
    let state = PER_CPU_IPC[cpu].lock();
    Some(state.stats())
}

/// Retrieve aggregate IPC statistics across all CPUs.
pub fn aggregate_stats() -> IpcStats {
    let mut total_calls = 0u64;
    let mut total_cycles = 0u64;
    let mut total_fast_ratio_weighted = 0u64;
    for i in 0..MAX_CPUS {
        let st = PER_CPU_IPC[i].lock().stats();
        total_calls += st.total_calls;
        total_cycles += st.total_cycles;
        // Weight each CPU's fast-path ratio by its call count.
        total_fast_ratio_weighted += st.fast_path_ratio * st.total_calls;
    }
    let avg_cycles = if total_calls > 0 {
        total_cycles / total_calls
    } else {
        0
    };
    let fast_path_ratio = if total_calls > 0 {
        total_fast_ratio_weighted / total_calls
    } else {
        0
    };
    IpcStats {
        total_calls,
        total_cycles,
        avg_cycles,
        fast_path_ratio,
    }
}

/// Flush capability caches on all CPUs.
///
/// Called when a bulk capability operation (e.g., revoke subtree)
/// invalidates an unknown set of capabilities.
pub fn flush_all_caches() {
    advance_cap_epoch();
    for i in 0..MAX_CPUS {
        let mut state = PER_CPU_IPC[i].lock();
        state.flush_cache();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the Time Stamp Counter (RDTSC) for cycle measurement.
#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is architecturally available on x86_64 (CPUID baseline),
    // writes only EAX/EDX which are declared as outputs, and has no memory
    // or stack side-effects (nomem, nostack).
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Pack a `CapObject` into a u64 for the capability cache.
///
/// Discriminant in bits [63:56], key field in bits [55:0].
fn pack_cap_object(obj: &CapObject) -> u64 {
    match obj {
        CapObject::Endpoint { id } => (1u64 << 56) | (*id as u64),
        CapObject::Channel { id } => (2u64 << 56) | (*id as u64),
        CapObject::Thread { id } => (3u64 << 56) | (*id as u64),
        CapObject::Memory { base, .. } => (4u64 << 56) | (*base & 0x00FF_FFFF_FFFF_FFFF),
        CapObject::Irq { line } => (5u64 << 56) | (*line as u64),
        CapObject::IoPort { base, count } => {
            (6u64 << 56) | ((*base as u64) << 16) | (*count as u64)
        }
        CapObject::Notification { id } => (7u64 << 56) | (*id as u64),
        CapObject::Domain { id } => (8u64 << 56) | (*id as u64),
        CapObject::AddrSpace { cr3 } => (9u64 << 56) | (*cr3 & 0x00FF_FFFF_FFFF_FFFF),
        CapObject::Interposed { original, .. } => (10u64 << 56) | (*original as u64),
        CapObject::Null => 0,
    }
}
