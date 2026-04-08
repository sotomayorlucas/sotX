//! ZFS storage pool backed by SOT block device capabilities.

use crate::dataset::Dataset;

/// Pool operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolState {
    Online,
    Degraded,
    Faulted,
    Offline,
}

/// Aggregate pool statistics.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub snapshot_count: u32,
    /// Current transaction group number.
    pub txg_current: u64,
}

/// A ZFS storage pool backed by SOT block device capabilities.
pub struct ZfsPool {
    pub name: [u8; 32],
    pub name_len: usize,
    pub guid: u64,
    /// SOT capability for the underlying block device.
    pub block_cap: u64,
    pub state: PoolState,
    pub stats: PoolStats,
    pub datasets: [Option<Dataset>; 64],
    pub dataset_count: usize,
}

impl ZfsPool {
    /// Create a new pool with the given name and block device capability.
    pub fn new(name_bytes: &[u8], guid: u64, block_cap: u64, total_bytes: u64) -> Self {
        let mut name = [0u8; 32];
        let name_len = name_bytes.len().min(32);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        Self {
            name,
            name_len,
            guid,
            block_cap,
            state: PoolState::Online,
            stats: PoolStats {
                total_bytes,
                used_bytes: 0,
                free_bytes: total_bytes,
                snapshot_count: 0,
                txg_current: 1,
            },
            datasets: core::array::from_fn(|_| None),
            dataset_count: 0,
        }
    }

    /// Add a dataset to this pool. Returns its index, or None if full.
    pub fn add_dataset(&mut self, ds: Dataset) -> Option<usize> {
        if self.dataset_count >= 64 {
            return None;
        }
        for (i, slot) in self.datasets.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(ds);
                self.dataset_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Remove a dataset by index. Returns the removed dataset, or None.
    pub fn remove_dataset(&mut self, idx: usize) -> Option<Dataset> {
        if idx >= 64 {
            return None;
        }
        let ds = self.datasets[idx].take();
        if ds.is_some() {
            self.dataset_count -= 1;
        }
        ds
    }

    /// Look up a dataset by name. Returns its index, or None.
    pub fn find_dataset(&self, name_bytes: &[u8]) -> Option<usize> {
        for (i, slot) in self.datasets.iter().enumerate() {
            if let Some(ds) = slot {
                if ds.name_len == name_bytes.len()
                    && ds.name[..ds.name_len] == name_bytes[..name_bytes.len()]
                {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Advance the transaction group number.
    pub fn advance_txg(&mut self) -> u64 {
        self.stats.txg_current += 1;
        self.stats.txg_current
    }

    /// Return the pool name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}
