//! SOT-transactional ZFS snapshots.
//!
//! Every tx_commit() on a filesystem-modifying transaction creates a snapshot,
//! enabling forensic rollback to any prior transaction boundary.

/// Lightweight reference stored in a dataset's snapshot list.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotRef {
    /// Index into the SnapshotManager timeline.
    pub timeline_idx: usize,
    /// ZFS transaction group number.
    pub txg: u64,
}

/// ZFS snapshot tied to a SOT transaction.
#[derive(Clone)]
pub struct TransactionalSnapshot {
    pub name: [u8; 64],
    pub name_len: usize,
    /// ZFS transaction group at creation time.
    pub txg: u64,
    /// SOT transaction ID that triggered this snapshot.
    pub sot_tx_id: u64,
    /// TSC timestamp at creation.
    pub created_at: u64,
    /// Provenance epoch at snapshot time.
    pub provenance_epoch: u64,
    /// Bytes changed since the previous snapshot.
    pub space_delta: i64,
}

impl TransactionalSnapshot {
    /// Return the snapshot name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Manages the ordered timeline of snapshots, tying SOT transactions to ZFS snapshots.
pub struct SnapshotManager {
    /// Ordered timeline of snapshots.
    pub timeline: [Option<TransactionalSnapshot>; 256],
    pub timeline_count: usize,
    /// Automatically snapshot on every Tier 1+ tx_commit.
    pub auto_snapshot: bool,
    /// Maximum snapshots before garbage collection.
    pub max_snapshots: usize,
}

impl SnapshotManager {
    /// Create a new snapshot manager.
    pub fn new(max_snapshots: usize, auto_snapshot: bool) -> Self {
        Self {
            timeline: core::array::from_fn(|_| None),
            timeline_count: 0,
            auto_snapshot,
            max_snapshots: max_snapshots.min(256),
        }
    }

    /// Called on tx_commit: create a snapshot automatically.
    /// Returns the timeline index of the new snapshot, or None if full.
    pub fn on_tx_commit(
        &mut self,
        tx_id: u64,
        epoch: u64,
        txg: u64,
        tsc_now: u64,
    ) -> Option<usize> {
        if !self.auto_snapshot {
            return None;
        }

        // GC if at capacity.
        if self.timeline_count >= self.max_snapshots {
            self.gc();
        }

        // Build auto-snapshot name: "auto-<txg>".
        let mut name = [0u8; 64];
        let prefix = b"auto-";
        name[..prefix.len()].copy_from_slice(prefix);
        let name_len = prefix.len() + write_u64_decimal(&mut name[prefix.len()..], txg);

        self.insert(TransactionalSnapshot {
            name,
            name_len,
            txg,
            sot_tx_id: tx_id,
            created_at: tsc_now,
            provenance_epoch: epoch,
            space_delta: 0,
        })
    }

    /// Called on tx_abort: find the most recent snapshot before this transaction
    /// and return its index for rollback. Does not modify state -- the caller
    /// performs the actual rollback.
    pub fn on_tx_abort(&self, tx_id: u64) -> Option<usize> {
        // Walk backwards to find the last snapshot *before* this tx.
        for i in (0..self.timeline.len()).rev() {
            if let Some(snap) = &self.timeline[i] {
                if snap.sot_tx_id < tx_id {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Explicit rollback to a named snapshot. Returns its index if found.
    pub fn rollback_to(&self, snapshot_name: &[u8]) -> Option<usize> {
        for (i, slot) in self.timeline.iter().enumerate() {
            if let Some(snap) = slot {
                if snap.name_len == snapshot_name.len()
                    && snap.name[..snap.name_len] == snapshot_name[..snapshot_name.len()]
                {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Return indices of snapshots whose provenance_epoch falls within [start, end].
    /// Useful for forensic timeline queries.
    pub fn timeline_between(&self, start_epoch: u64, end_epoch: u64) -> TimelineIter<'_> {
        TimelineIter {
            manager: self,
            pos: 0,
            start_epoch,
            end_epoch,
        }
    }

    /// Garbage collect old snapshots. Keeps the newest `max_snapshots / 2`
    /// entries, removing the oldest first, then compacts in a single pass.
    pub fn gc(&mut self) {
        let keep = self.max_snapshots / 2;
        if self.timeline_count <= keep {
            return;
        }
        let remove = self.timeline_count - keep;
        let mut removed = 0;
        for slot in self.timeline.iter_mut() {
            if removed >= remove {
                break;
            }
            if slot.is_some() {
                *slot = None;
                removed += 1;
            }
        }
        self.timeline_count -= removed;
        // Compact remaining entries to the front.
        let mut write = 0;
        for read in 0..self.timeline.len() {
            if self.timeline[read].is_some() {
                if write != read {
                    let entry = self.timeline[read].take();
                    self.timeline[write] = entry;
                }
                write += 1;
            }
        }
    }

    fn insert(&mut self, snap: TransactionalSnapshot) -> Option<usize> {
        for (i, slot) in self.timeline.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(snap);
                self.timeline_count += 1;
                return Some(i);
            }
        }
        None
    }
}

/// Iterator over snapshots in a provenance epoch range.
pub struct TimelineIter<'a> {
    manager: &'a SnapshotManager,
    pos: usize,
    start_epoch: u64,
    end_epoch: u64,
}

impl<'a> Iterator for TimelineIter<'a> {
    type Item = (usize, &'a TransactionalSnapshot);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.manager.timeline.len() {
            let i = self.pos;
            self.pos += 1;
            if let Some(snap) = &self.manager.timeline[i] {
                if snap.provenance_epoch >= self.start_epoch
                    && snap.provenance_epoch <= self.end_epoch
                {
                    return Some((i, snap));
                }
            }
        }
        None
    }
}

/// Write a u64 as decimal ASCII into `buf`. Returns the number of bytes written.
fn write_u64_decimal(buf: &mut [u8], mut val: u64) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
            return 1;
        }
        return 0;
    }
    // Write digits in reverse, then flip.
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while val > 0 && len < 20 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    let out_len = len.min(buf.len());
    for i in 0..out_len {
        buf[i] = tmp[len - 1 - i];
    }
    out_len
}
