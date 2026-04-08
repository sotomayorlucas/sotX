//! ZFS datasets: filesystems, volumes, and snapshots within a pool.

use crate::snapshot::SnapshotRef;

/// Dataset type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetType {
    Filesystem,
    Volume,
    Snapshot,
}

/// Compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Off,
    Lz4,
    Zstd,
    Gzip,
}

/// Per-dataset properties.
#[derive(Debug, Clone)]
pub struct DatasetProperties {
    pub compression: Compression,
    pub atime: bool,
    pub readonly: bool,
    pub mountpoint: [u8; 128],
    pub mountpoint_len: usize,
}

impl DatasetProperties {
    /// Default properties: LZ4 compression, atime on, read-write, no mountpoint.
    pub fn default_fs() -> Self {
        Self {
            compression: Compression::Lz4,
            atime: true,
            readonly: false,
            mountpoint: [0u8; 128],
            mountpoint_len: 0,
        }
    }

    /// Set the mountpoint from a byte slice.
    pub fn set_mountpoint(&mut self, path: &[u8]) {
        let len = path.len().min(128);
        self.mountpoint[..len].copy_from_slice(&path[..len]);
        self.mountpoint_len = len;
    }
}

/// A ZFS dataset (filesystem, volume, or snapshot).
#[derive(Clone)]
pub struct Dataset {
    pub name: [u8; 64],
    pub name_len: usize,
    pub ds_type: DatasetType,
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub snapshots: [Option<SnapshotRef>; 32],
    pub snapshot_count: usize,
    pub properties: DatasetProperties,
}

impl Dataset {
    /// Create a new filesystem dataset with the given name.
    pub fn new_filesystem(name_bytes: &[u8]) -> Self {
        let mut name = [0u8; 64];
        let name_len = name_bytes.len().min(64);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        Self {
            name,
            name_len,
            ds_type: DatasetType::Filesystem,
            used_bytes: 0,
            quota_bytes: 0,
            snapshots: core::array::from_fn(|_| None),
            snapshot_count: 0,
            properties: DatasetProperties::default_fs(),
        }
    }

    /// Create a new volume dataset with the given name and size.
    pub fn new_volume(name_bytes: &[u8], size_bytes: u64) -> Self {
        let mut ds = Self::new_filesystem(name_bytes);
        ds.ds_type = DatasetType::Volume;
        ds.quota_bytes = size_bytes;
        ds
    }

    /// Add a snapshot reference. Returns its index, or None if full.
    pub fn add_snapshot(&mut self, snap: SnapshotRef) -> Option<usize> {
        if self.snapshot_count >= 32 {
            return None;
        }
        for (i, slot) in self.snapshots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(snap);
                self.snapshot_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Return the dataset name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}
