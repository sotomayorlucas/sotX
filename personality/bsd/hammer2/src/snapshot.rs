//! HAMMER2 instant CoW snapshots.
//!
//! Because HAMMER2 is copy-on-write, snapshots cost zero additional space
//! initially. Space grows only as the original data diverges.

/// A HAMMER2 instant snapshot.
#[derive(Clone)]
pub struct Hammer2Snapshot {
    pub name: [u8; 64],
    pub name_len: usize,
    /// HAMMER2 transaction ID at snapshot time.
    pub tid: u64,
    /// Corresponding SOT transaction ID.
    pub sot_tx_id: u64,
    /// Space consumed by divergence from the original (bytes).
    pub space_delta: i64,
    /// TSC timestamp at creation.
    pub created_at: u64,
}

impl Hammer2Snapshot {
    /// Return the snapshot name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Manages HAMMER2 snapshots for a volume.
pub struct Hammer2SnapshotManager {
    pub snapshots: [Option<Hammer2Snapshot>; 256],
    pub count: usize,
    pub max_snapshots: usize,
}

impl Hammer2SnapshotManager {
    /// Create a new snapshot manager.
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            snapshots: core::array::from_fn(|_| None),
            count: 0,
            max_snapshots: max_snapshots.min(256),
        }
    }

    /// Create a snapshot at the given transaction ID.
    /// Returns the snapshot index, or None if full (after GC attempt).
    pub fn create(
        &mut self,
        name_bytes: &[u8],
        tid: u64,
        sot_tx_id: u64,
        tsc_now: u64,
    ) -> Option<usize> {
        if self.count >= self.max_snapshots {
            self.gc();
        }

        let mut name = [0u8; 64];
        let name_len = name_bytes.len().min(64);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let snap = Hammer2Snapshot {
            name,
            name_len,
            tid,
            sot_tx_id,
            space_delta: 0,
            created_at: tsc_now,
        };

        for (i, slot) in self.snapshots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(snap);
                self.count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Find a snapshot by name. Returns its index, or None.
    pub fn find_by_name(&self, name_bytes: &[u8]) -> Option<usize> {
        for (i, slot) in self.snapshots.iter().enumerate() {
            if let Some(snap) = slot {
                if snap.name_len == name_bytes.len()
                    && snap.name[..snap.name_len] == name_bytes[..name_bytes.len()]
                {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Find a snapshot by SOT transaction ID. Returns its index, or None.
    pub fn find_by_tx(&self, sot_tx_id: u64) -> Option<usize> {
        for (i, slot) in self.snapshots.iter().enumerate() {
            if let Some(snap) = slot {
                if snap.sot_tx_id == sot_tx_id {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Delete a snapshot by index. Returns the removed snapshot, or None.
    pub fn delete(&mut self, idx: usize) -> Option<Hammer2Snapshot> {
        if idx >= 256 {
            return None;
        }
        let snap = self.snapshots[idx].take();
        if snap.is_some() {
            self.count -= 1;
        }
        snap
    }

    /// Garbage collect: remove the oldest snapshots to stay within limits.
    /// Keeps the newest `max_snapshots / 2` entries, then compacts in a single pass.
    pub fn gc(&mut self) {
        let keep = self.max_snapshots / 2;
        if self.count <= keep {
            return;
        }
        let remove = self.count - keep;
        let mut removed = 0;
        for slot in self.snapshots.iter_mut() {
            if removed >= remove {
                break;
            }
            if slot.is_some() {
                *slot = None;
                removed += 1;
            }
        }
        self.count -= removed;
        // Compact remaining entries to the front.
        let mut write = 0;
        for read in 0..self.snapshots.len() {
            if self.snapshots[read].is_some() {
                if write != read {
                    let entry = self.snapshots[read].take();
                    self.snapshots[write] = entry;
                }
                write += 1;
            }
        }
    }
}
