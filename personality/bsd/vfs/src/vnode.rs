//! Vnode — SecureObject representing a file, directory, or device.
//!
//! Every filesystem object is a vnode with type, permissions, size, data
//! location, and reference count. Vnodes are the unit of access control:
//! the VFS server never exposes raw storage locations to callers.

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum filename length in bytes.
pub const NAME_MAX: usize = 255;

/// Vnode type — mirrors BSD vtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VnodeType {
    Regular = 1,
    Directory = 2,
    Symlink = 3,
    CharDevice = 4,
    BlockDevice = 5,
}

/// POSIX-style permission bits.
#[derive(Debug, Clone, Copy)]
pub struct Permissions {
    pub owner_read: bool,
    pub owner_write: bool,
    pub owner_exec: bool,
    pub group_read: bool,
    pub group_write: bool,
    pub group_exec: bool,
    pub other_read: bool,
    pub other_write: bool,
    pub other_exec: bool,
}

impl Permissions {
    /// 0o755: rwxr-xr-x
    pub const DIR_DEFAULT: Self = Self {
        owner_read: true,
        owner_write: true,
        owner_exec: true,
        group_read: true,
        group_write: false,
        group_exec: true,
        other_read: true,
        other_write: false,
        other_exec: true,
    };

    /// 0o644: rw-r--r--
    pub const FILE_DEFAULT: Self = Self {
        owner_read: true,
        owner_write: true,
        owner_exec: false,
        group_read: true,
        group_write: false,
        group_exec: false,
        other_read: true,
        other_write: false,
        other_exec: false,
    };

    /// Pack into a u16 mode field (standard POSIX octal layout).
    pub fn to_mode(self) -> u16 {
        let mut m: u16 = 0;
        if self.owner_read {
            m |= 0o400;
        }
        if self.owner_write {
            m |= 0o200;
        }
        if self.owner_exec {
            m |= 0o100;
        }
        if self.group_read {
            m |= 0o040;
        }
        if self.group_write {
            m |= 0o020;
        }
        if self.group_exec {
            m |= 0o010;
        }
        if self.other_read {
            m |= 0o004;
        }
        if self.other_write {
            m |= 0o002;
        }
        if self.other_exec {
            m |= 0o001;
        }
        m
    }

    /// Unpack from a u16 mode field.
    pub fn from_mode(m: u16) -> Self {
        Self {
            owner_read: m & 0o400 != 0,
            owner_write: m & 0o200 != 0,
            owner_exec: m & 0o100 != 0,
            group_read: m & 0o040 != 0,
            group_write: m & 0o020 != 0,
            group_exec: m & 0o010 != 0,
            other_read: m & 0o004 != 0,
            other_write: m & 0o002 != 0,
            other_exec: m & 0o001 != 0,
        }
    }
}

/// Stat metadata returned by STAT/FSTAT operations.
#[derive(Debug, Clone, Copy)]
pub struct VnodeStat {
    pub vnode_id: u64,
    pub vtype: VnodeType,
    pub permissions: u16,
    pub size: u64,
    pub link_count: u32,
    pub uid: u32,
    pub gid: u32,
    /// Seconds since epoch.
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

/// A directory entry within a directory vnode.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub vnode_id: u64,
    pub entry_type: VnodeType,
}

/// A vnode — the SecureObject representing any filesystem entity.
///
/// All access must go through the VFS server which validates capabilities
/// before touching vnode internals.
#[derive(Debug, Clone)]
pub struct Vnode {
    pub id: u64,
    pub vtype: VnodeType,
    pub permissions: Permissions,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub link_count: u32,
    pub ref_count: u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    /// For regular files: inline data (small files).
    pub data: Vec<u8>,
    /// For directories: child entries.
    pub children: Vec<DirEntry>,
    /// For symlinks: target path.
    pub symlink_target: Option<String>,
    /// Mount point this vnode belongs to.
    pub mount_id: u32,
}

impl Vnode {
    /// Create a new regular file vnode.
    pub fn new_file(id: u64, mount_id: u32) -> Self {
        Self {
            id,
            vtype: VnodeType::Regular,
            permissions: Permissions::FILE_DEFAULT,
            uid: 0,
            gid: 0,
            size: 0,
            link_count: 1,
            ref_count: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            data: Vec::new(),
            children: Vec::new(),
            symlink_target: None,
            mount_id,
        }
    }

    /// Create a new directory vnode with `.` and `..` entries.
    pub fn new_dir(id: u64, parent_id: u64, mount_id: u32) -> Self {
        let children = alloc::vec![
            DirEntry {
                name: String::from("."),
                vnode_id: id,
                entry_type: VnodeType::Directory,
            },
            DirEntry {
                name: String::from(".."),
                vnode_id: parent_id,
                entry_type: VnodeType::Directory,
            },
        ];
        Self {
            id,
            vtype: VnodeType::Directory,
            permissions: Permissions::DIR_DEFAULT,
            uid: 0,
            gid: 0,
            size: 0,
            link_count: 2,
            ref_count: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            data: Vec::new(),
            children,
            symlink_target: None,
            mount_id,
        }
    }

    /// Build stat metadata from this vnode.
    pub fn stat(&self) -> VnodeStat {
        VnodeStat {
            vnode_id: self.id,
            vtype: self.vtype,
            permissions: self.permissions.to_mode(),
            size: self.size,
            link_count: self.link_count,
            uid: self.uid,
            gid: self.gid,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
        }
    }

    /// Look up a child by name in a directory vnode.
    pub fn find_child(&self, name: &str) -> Option<u64> {
        if self.vtype != VnodeType::Directory {
            return None;
        }
        self.children
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.vnode_id)
    }

    /// Add a child entry to a directory vnode.
    pub fn add_child(&mut self, name: String, vnode_id: u64, entry_type: VnodeType) -> bool {
        if self.vtype != VnodeType::Directory {
            return false;
        }
        if self.find_child(&name).is_some() {
            return false;
        }
        self.children.push(DirEntry {
            name,
            vnode_id,
            entry_type,
        });
        self.link_count += 1;
        true
    }

    /// Remove a child entry by name. Returns the removed vnode id.
    pub fn remove_child(&mut self, name: &str) -> Option<u64> {
        if self.vtype != VnodeType::Directory {
            return None;
        }
        if name == "." || name == ".." {
            return None;
        }
        let pos = self.children.iter().position(|e| e.name == name)?;
        let entry = self.children.remove(pos);
        self.link_count = self.link_count.saturating_sub(1);
        Some(entry.vnode_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_has_dot_entries() {
        let d = Vnode::new_dir(1, 0, 0);
        assert_eq!(d.find_child("."), Some(1));
        assert_eq!(d.find_child(".."), Some(0));
    }

    #[test]
    fn add_remove_child() {
        let mut d = Vnode::new_dir(1, 0, 0);
        assert!(d.add_child(String::from("foo"), 2, VnodeType::Regular));
        assert_eq!(d.find_child("foo"), Some(2));
        assert!(!d.add_child(String::from("foo"), 3, VnodeType::Regular));
        assert_eq!(d.remove_child("foo"), Some(2));
        assert_eq!(d.find_child("foo"), None);
    }

    #[test]
    fn cannot_remove_dot() {
        let mut d = Vnode::new_dir(1, 0, 0);
        assert_eq!(d.remove_child("."), None);
        assert_eq!(d.remove_child(".."), None);
    }

    #[test]
    fn permissions_roundtrip() {
        let p = Permissions::DIR_DEFAULT;
        let mode = p.to_mode();
        assert_eq!(mode, 0o755);
        let p2 = Permissions::from_mode(mode);
        assert_eq!(p2.to_mode(), mode);
    }

    #[test]
    fn file_stat() {
        let f = Vnode::new_file(42, 1);
        let s = f.stat();
        assert_eq!(s.vnode_id, 42);
        assert_eq!(s.permissions, 0o644);
        assert_eq!(s.size, 0);
    }
}
