//! Transaction group (TXG) integration between SOT Tier 0/1/2 transactions and ZFS.

/// An operation pending in the current transaction group.
#[derive(Clone)]
pub enum TxgOp {
    Write {
        dataset_idx: u32,
        offset: u64,
        len: u32,
    },
    Create {
        dataset_idx: u32,
        name: [u8; 64],
        name_len: usize,
    },
    Delete {
        dataset_idx: u32,
        name: [u8; 64],
        name_len: usize,
    },
    Snapshot {
        dataset_idx: u32,
        snap_name: [u8; 64],
        snap_name_len: usize,
    },
}

/// Bridge between SOT transactions and ZFS transaction groups.
///
/// Accumulates filesystem operations within a TXG and commits them atomically.
pub struct TxgBridge {
    pub current_txg: u64,
    pub pending_ops: [Option<TxgOp>; 128],
    pub pending_count: usize,
}

impl TxgBridge {
    /// Create a new bridge starting at txg 1.
    pub fn new() -> Self {
        Self {
            current_txg: 1,
            pending_ops: core::array::from_fn(|_| None),
            pending_count: 0,
        }
    }

    /// Queue a write operation in the current TXG. Returns false if full.
    pub fn queue_write(&mut self, dataset_idx: u32, offset: u64, len: u32) -> bool {
        self.push(TxgOp::Write {
            dataset_idx,
            offset,
            len,
        })
    }

    /// Queue a create operation. Returns false if full.
    pub fn queue_create(&mut self, dataset_idx: u32, name: &[u8]) -> bool {
        let (buf, name_len) = copy_name(name);
        self.push(TxgOp::Create { dataset_idx, name: buf, name_len })
    }

    /// Queue a delete operation. Returns false if full.
    pub fn queue_delete(&mut self, dataset_idx: u32, name: &[u8]) -> bool {
        let (buf, name_len) = copy_name(name);
        self.push(TxgOp::Delete { dataset_idx, name: buf, name_len })
    }

    /// Queue a snapshot operation. Returns false if full.
    pub fn queue_snapshot(&mut self, dataset_idx: u32, snap_name: &[u8]) -> bool {
        let (buf, len) = copy_name(snap_name);
        self.push(TxgOp::Snapshot { dataset_idx, snap_name: buf, snap_name_len: len })
    }

    /// Commit the current TXG: advance the TXG number and clear pending ops.
    /// Returns (committed_txg, op_count).
    pub fn commit(&mut self) -> (u64, usize) {
        let txg = self.current_txg;
        let count = self.pending_count;
        self.current_txg += 1;
        self.clear_pending();
        (txg, count)
    }

    /// Abort the current TXG: discard all pending ops without advancing.
    /// Returns the number of discarded operations.
    pub fn abort(&mut self) -> usize {
        let count = self.pending_count;
        self.clear_pending();
        count
    }

    /// Number of pending operations.
    pub fn pending(&self) -> usize {
        self.pending_count
    }

    // -- internal helpers --

    fn push(&mut self, op: TxgOp) -> bool {
        if self.pending_count >= 128 {
            return false;
        }
        for slot in self.pending_ops.iter_mut() {
            if slot.is_none() {
                *slot = Some(op);
                self.pending_count += 1;
                return true;
            }
        }
        false
    }

    fn clear_pending(&mut self) {
        for slot in self.pending_ops.iter_mut() {
            *slot = None;
        }
        self.pending_count = 0;
    }
}

/// Copy a byte slice into a fixed-size name buffer.
fn copy_name(src: &[u8]) -> ([u8; 64], usize) {
    let mut buf = [0u8; 64];
    let len = src.len().min(64);
    buf[..len].copy_from_slice(&src[..len]);
    (buf, len)
}
