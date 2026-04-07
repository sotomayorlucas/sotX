//! Write-Ahead Log for Tier 1 (single-object) transactions.
//!
//! Fixed-size ring buffer of `WalEntry`. Each entry captures the old value
//! of a Secure Object region *before* it is mutated, so the transaction can
//! be rolled back by replaying entries in reverse.

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A WAL entry recording a pre-mutation snapshot.
#[derive(Clone, Copy)]
pub struct WalEntry {
    /// Transaction that owns this entry.
    pub tx_id: u64,
    /// Which Secure Object was modified.
    pub so_id: u64,
    /// Byte offset of the modification within the object.
    pub offset: u64,
    /// Length of the old data captured in `old_data`.
    pub old_len: u32,
    /// Inline snapshot of the old value (max 64 bytes).
    pub old_data: [u8; 64],
    /// Whether this entry has been committed (eligible for GC).
    committed: bool,
}

impl WalEntry {
    const EMPTY: Self = Self {
        tx_id: 0,
        so_id: 0,
        offset: 0,
        old_len: 0,
        old_data: [0u8; 64],
        committed: false,
    };
}

/// Errors returned by WAL operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalError {
    /// The ring buffer is full and no committed entries can be reclaimed.
    Full,
}

// ---------------------------------------------------------------------------
// WAL ring buffer
// ---------------------------------------------------------------------------

const WAL_CAPACITY: usize = 1024;

/// Write-Ahead Log backed by a fixed-size ring buffer.
pub struct Wal {
    ring: [WalEntry; WAL_CAPACITY],
    /// Number of live (non-empty) entries in the ring.
    len: usize,
    /// Next write position (wraps around).
    head: usize,
}

impl Wal {
    pub const fn new() -> Self {
        Self {
            ring: [WalEntry::EMPTY; WAL_CAPACITY],
            len: 0,
            head: 0,
        }
    }

    /// Append a new WAL entry. Returns `WalError::Full` if the ring is at
    /// capacity and no committed entries remain to reclaim.
    pub fn append(&mut self, entry: WalEntry) -> Result<(), WalError> {
        if self.len >= WAL_CAPACITY {
            // Try to GC committed entries first.
            self.gc();
            if self.len >= WAL_CAPACITY {
                return Err(WalError::Full);
            }
        }

        self.ring[self.head] = entry;
        self.head = (self.head + 1) % WAL_CAPACITY;
        self.len += 1;
        Ok(())
    }

    /// Roll back all entries belonging to `tx_id` by scanning the ring in
    /// reverse insertion order and clearing matching entries.
    ///
    /// A higher-level layer will wire up actual Secure Object restore once
    /// the object store is integrated.
    pub fn rollback(&mut self, tx_id: u64) {
        if self.len == 0 {
            return;
        }

        let mut removed = 0usize;
        for slot in self.ring.iter_mut() {
            if slot.tx_id == tx_id && !slot.committed {
                *slot = WalEntry::EMPTY;
                removed += 1;
            }
        }

        self.len = self.len.saturating_sub(removed);
    }

    /// Mark all entries for `tx_id` as committed. They become eligible for
    /// garbage collection.
    pub fn commit(&mut self, tx_id: u64) {
        for entry in self.ring.iter_mut() {
            if entry.tx_id == tx_id {
                entry.committed = true;
            }
        }
    }

    /// Garbage-collect committed entries by zeroing them out.
    pub fn gc(&mut self) {
        let mut removed = 0usize;
        for entry in self.ring.iter_mut() {
            if entry.committed && entry.tx_id != 0 {
                *entry = WalEntry::EMPTY;
                removed += 1;
            }
        }
        self.len = self.len.saturating_sub(removed);
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the WAL is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
