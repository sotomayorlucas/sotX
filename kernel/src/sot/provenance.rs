//! Per-CPU lock-free SPSC ring buffers for Secure Object provenance logging.
//!
//! Every operation on a Secure Object generates a [`ProvenanceEntry`] that is
//! pushed into the ring for the current CPU.  A provenance-domain consumer on
//! another core drains entries without contention thanks to the SPSC design
//! (cache-line-separated head/tail indices, `Release`/`Acquire` fences).

use core::sync::atomic::{AtomicU64, Ordering};

use sotos_common::MAX_CPUS;

/// A single provenance entry -- records one SO operation.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ProvenanceEntry {
    /// Global epoch at time of operation.
    pub epoch: u64,
    /// Domain that performed the operation.
    pub domain_id: u32,
    /// Operation type (read, write, invoke, grant, revoke, etc.)
    pub operation: u16,
    /// Semantic object type tag (matches `sotos_provenance::types::SoType`
    /// when set; 0 = unknown / not classified).
    pub so_type: u8,
    /// Padding for alignment.
    pub _pad: u8,
    /// Secure Object that was acted upon.
    pub so_id: u64,
    /// Version of the SO after the operation.
    pub version: u64,
    /// Transaction ID (0 if not in a transaction).
    pub tx_id: u64,
    /// Timestamp (TSC value).
    pub timestamp: u64,
}

const _: () = assert!(core::mem::size_of::<ProvenanceEntry>() == 48);

impl ProvenanceEntry {
    pub const fn zeroed() -> Self {
        Self {
            epoch: 0,
            domain_id: 0,
            operation: 0,
            so_type: 0,
            _pad: 0,
            so_id: 0,
            version: 0,
            tx_id: 0,
            timestamp: 0,
        }
    }
}

/// Ring buffer capacity per CPU.
const RING_CAPACITY: usize = 4096;

// Power-of-two required for bitmask indexing.
const _: () = assert!(RING_CAPACITY.is_power_of_two());
const RING_MASK: u64 = (RING_CAPACITY - 1) as u64;

/// Per-CPU provenance ring buffer.
///
/// Producer (kernel hot path) and consumer (provenance domain) run on
/// different cores.  Head and tail live on separate cache lines to avoid
/// false sharing.
#[repr(C, align(64))]
pub struct ProvenanceRing {
    /// Write index (only producer writes; consumer reads for empty check).
    head: AtomicU64,
    _pad0: [u8; 56],
    /// Read index (only consumer writes; producer reads for full check).
    tail: AtomicU64,
    _pad1: [u8; 56],
    /// Ring buffer entries.
    entries: [ProvenanceEntry; RING_CAPACITY],
    /// Number of dropped entries (ring was full).
    dropped: AtomicU64,
}

impl ProvenanceRing {
    pub const fn new() -> Self {
        Self {
            head: AtomicU64::new(0),
            _pad0: [0u8; 56],
            tail: AtomicU64::new(0),
            _pad1: [0u8; 56],
            entries: [ProvenanceEntry::zeroed(); RING_CAPACITY],
            dropped: AtomicU64::new(0),
        }
    }

    /// Non-blocking push.  Returns `true` on success, `false` if the ring
    /// is full (increments the dropped counter on failure).
    pub fn push(&self, entry: ProvenanceEntry) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        if head.wrapping_sub(tail) >= RING_CAPACITY as u64 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let idx = (head & RING_MASK) as usize;
        // SAFETY: single producer owns this slot until head is published.
        unsafe {
            let slot = (self.entries.as_ptr() as *mut ProvenanceEntry).add(idx);
            core::ptr::write_volatile(slot, entry);
        }
        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Non-blocking pop.  Returns `None` if the ring is empty.
    pub fn pop(&self) -> Option<ProvenanceEntry> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        if tail == head {
            return None;
        }

        let idx = (tail & RING_MASK) as usize;
        // SAFETY: producer published this slot via the Release on head.
        let entry = unsafe {
            let slot = self.entries.as_ptr().add(idx);
            core::ptr::read_volatile(slot)
        };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(entry)
    }

    /// Drain up to `buf.len()` entries into `buf`.  Returns the number of
    /// entries copied.  Uses a single tail update for the whole batch.
    pub fn drain_to(&self, buf: &mut [ProvenanceEntry]) -> usize {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        let available = head.wrapping_sub(tail) as usize;
        let count = available.min(buf.len());

        for i in 0..count {
            let idx = (tail.wrapping_add(i as u64) & RING_MASK) as usize;
            // SAFETY: all slots in [tail..tail+count) have been published.
            buf[i] = unsafe {
                let slot = self.entries.as_ptr().add(idx);
                core::ptr::read_volatile(slot)
            };
        }

        if count > 0 {
            self.tail
                .store(tail.wrapping_add(count as u64), Ordering::Release);
        }
        count
    }

    /// Current number of unread entries in the ring.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail) as usize
    }

    /// Total number of entries that were dropped because the ring was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

static PROVENANCE_RINGS: [ProvenanceRing; MAX_CPUS] = {
    const INIT: ProvenanceRing = ProvenanceRing::new();
    [INIT; MAX_CPUS]
};

/// Record a provenance entry on the given CPU's ring.
pub fn record(cpu_id: usize, entry: ProvenanceEntry) {
    if let Some(ring) = PROVENANCE_RINGS.get(cpu_id) {
        ring.push(entry);
    }
}

/// Drain entries from the given CPU's ring into `buf`.
/// Returns the number of entries written.
pub fn drain_cpu(cpu_id: usize, buf: &mut [ProvenanceEntry]) -> usize {
    match PROVENANCE_RINGS.get(cpu_id) {
        Some(ring) => ring.drain_to(buf),
        None => 0,
    }
}
