//! Mount point management.
//!
//! The mount table maps path prefixes to filesystem backends. Each backend
//! (ZFS, FFS, tmpfs, etc.) is a sub-domain with its own capabilities. When
//! path resolution crosses a mount boundary, the VFS server delegates to the
//! appropriate backend domain.

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum number of simultaneous mount points.
pub const MAX_MOUNTS: usize = 64;

/// Filesystem backend type — identifies which sub-domain handles storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FsType {
    /// In-memory tmpfs (no backing store).
    Tmpfs = 1,
    /// BSD FFS (UFS2).
    Ffs = 2,
    /// ZFS dataset.
    Zfs = 3,
    /// Device filesystem (/dev).
    Devfs = 4,
    /// Process filesystem (/proc).
    Procfs = 5,
    /// sotFS — graph-structured filesystem with DPO rewriting.
    SotFs = 6,
}

/// A single mount point entry.
#[derive(Debug, Clone)]
pub struct MountEntry {
    /// Unique mount identifier.
    pub mount_id: u32,
    /// Mounted path prefix (e.g., "/", "/tmp", "/dev").
    pub path: String,
    /// Filesystem backend type.
    pub fs_type: FsType,
    /// Capability id granting access to the backend domain.
    pub backend_cap: u64,
    /// Root vnode id within this mount.
    pub root_vnode: u64,
    /// Read-only mount flag.
    pub read_only: bool,
}

/// Mount table — maps path prefixes to filesystem backends.
pub struct MountTable {
    entries: Vec<MountEntry>,
    next_id: u32,
}

impl MountTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 1,
        }
    }

    /// Register a new mount point. Returns the mount id, or `None` if the
    /// path is already mounted or the table is full.
    pub fn mount(
        &mut self,
        path: String,
        fs_type: FsType,
        backend_cap: u64,
        root_vnode: u64,
        read_only: bool,
    ) -> Option<u32> {
        if self.entries.len() >= MAX_MOUNTS {
            return None;
        }
        if self.entries.iter().any(|e| e.path == path) {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(MountEntry {
            mount_id: id,
            path,
            fs_type,
            backend_cap,
            root_vnode,
            read_only,
        });
        Some(id)
    }

    /// Unmount a filesystem by mount id. Returns the entry on success.
    pub fn unmount(&mut self, mount_id: u32) -> Option<MountEntry> {
        let pos = self.entries.iter().position(|e| e.mount_id == mount_id)?;
        Some(self.entries.remove(pos))
    }

    /// Find the deepest (longest-prefix) mount point that covers `path`.
    pub fn resolve(&self, path: &str) -> Option<&MountEntry> {
        let mut best: Option<&MountEntry> = None;
        let mut best_len = 0;
        for entry in &self.entries {
            let prefix = entry.path.as_str();
            let matches = if prefix == "/" {
                true
            } else {
                path == prefix
                    || (path.len() > prefix.len()
                        && path.as_bytes()[prefix.len()] == b'/'
                        && path.starts_with(prefix))
            };
            if matches && prefix.len() >= best_len {
                best = Some(entry);
                best_len = prefix.len();
            }
        }
        best
    }

    /// Look up a mount by its id.
    pub fn get(&self, mount_id: u32) -> Option<&MountEntry> {
        self.entries.iter().find(|e| e.mount_id == mount_id)
    }

    /// Iterate over all mount entries.
    pub fn iter(&self) -> impl Iterator<Item = &MountEntry> {
        self.entries.iter()
    }

    /// Number of active mounts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> MountTable {
        let mut t = MountTable::new();
        t.mount(String::from("/"), FsType::Ffs, 1, 0, false);
        t.mount(String::from("/tmp"), FsType::Tmpfs, 2, 100, false);
        t.mount(String::from("/dev"), FsType::Devfs, 3, 200, true);
        t
    }

    #[test]
    fn resolve_root() {
        let t = make_table();
        let m = t.resolve("/etc/passwd").unwrap();
        assert_eq!(m.path, "/");
    }

    #[test]
    fn resolve_longest_prefix() {
        let t = make_table();
        let m = t.resolve("/tmp/foo").unwrap();
        assert_eq!(m.path, "/tmp");
    }

    #[test]
    fn resolve_exact() {
        let t = make_table();
        let m = t.resolve("/dev").unwrap();
        assert_eq!(m.path, "/dev");
    }

    #[test]
    fn no_duplicate_mounts() {
        let mut t = MountTable::new();
        assert!(t.mount(String::from("/"), FsType::Ffs, 1, 0, false).is_some());
        assert!(t.mount(String::from("/"), FsType::Tmpfs, 2, 0, false).is_none());
    }

    #[test]
    fn unmount_works() {
        let mut t = make_table();
        assert_eq!(t.len(), 3);
        let entry = t.unmount(2).unwrap();
        assert_eq!(entry.path, "/tmp");
        assert_eq!(t.len(), 2);
        assert!(t.unmount(99).is_none());
    }
}
