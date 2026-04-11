//! Inline sotFS type graph engine for the bare-metal service.
//!
//! Simplified version of sotfs-graph optimized for no_std + alloc.
//! Implements the core DPO rules: create, mkdir, rmdir, link, unlink, rename.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// VfsOp codes matching personality/bsd/vfs/src/lib.rs:64-79
#[derive(Debug, Clone, Copy)]
pub enum VfsOp {
    Open,
    Close,
    Read,
    Write,
    Stat,
    Readdir,
    Mkdir,
    Rmdir,
    Unlink,
    Rename,
    Fstat,
    Unknown,
}

impl VfsOp {
    pub fn from_tag(tag: u64) -> Self {
        match tag {
            1 => VfsOp::Open,
            2 => VfsOp::Close,
            3 => VfsOp::Read,
            4 => VfsOp::Write,
            5 => VfsOp::Stat,
            6 => VfsOp::Readdir,
            7 => VfsOp::Mkdir,
            8 => VfsOp::Rmdir,
            9 => VfsOp::Unlink,
            10 => VfsOp::Rename,
            12 => VfsOp::Fstat,
            _ => VfsOp::Unknown,
        }
    }
}

/// POSIX error codes (negative).
pub const ENOENT: i64 = -2;
pub const EIO: i64 = -5;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ENOTEMPTY: i64 = -39;
pub const EPERM: i64 = -1;

/// Inode type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    Regular,
    Directory,
}

/// Inode metadata.
#[derive(Debug, Clone)]
pub struct Inode {
    pub id: u64,
    pub kind: InodeKind,
    pub size: u64,
    pub mode: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Directory entry: (name, inode_id).
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub inode_id: u64,
}

/// The in-memory type graph.
pub struct SotFsGraph {
    pub inodes: BTreeMap<u64, Inode>,
    pub dir_entries: BTreeMap<u64, Vec<DirEntry>>, // inode_id → entries
    pub file_data: BTreeMap<u64, Vec<u8>>,         // inode_id → data
    next_id: u64,
}

impl SotFsGraph {
    /// CREATE-ROOT: initialize with root directory (inode 1).
    pub fn new() -> Self {
        let mut g = Self {
            inodes: BTreeMap::new(),
            dir_entries: BTreeMap::new(),
            file_data: BTreeMap::new(),
            next_id: 2,
        };

        // Root inode
        g.inodes.insert(1, Inode {
            id: 1,
            kind: InodeKind::Directory,
            size: 0,
            mode: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
        });

        // Root dir entries: "." and ".."
        g.dir_entries.insert(1, alloc::vec![
            DirEntry { name: String::from("."), inode_id: 1 },
            DirEntry { name: String::from(".."), inode_id: 1 },
        ]);

        g
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Resolve name in directory inode. Returns target inode id.
    fn lookup(&self, dir_inode: u64, name: &str) -> Option<u64> {
        let entries = self.dir_entries.get(&dir_inode)?;
        entries.iter().find(|e| e.name == name).map(|e| e.inode_id)
    }

    /// Create a regular file in a directory.
    pub fn create_file(&mut self, parent_inode: u64, name: &str) -> Result<u64, i64> {
        if self.lookup(parent_inode, name).is_some() {
            return Err(EEXIST);
        }
        let inode = self.inodes.get(&parent_inode).ok_or(ENOENT)?;
        if inode.kind != InodeKind::Directory {
            return Err(ENOTDIR);
        }

        let id = self.alloc_id();
        self.inodes.insert(id, Inode {
            id,
            kind: InodeKind::Regular,
            size: 0,
            mode: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
        });

        self.dir_entries
            .entry(parent_inode)
            .or_default()
            .push(DirEntry { name: String::from(name), inode_id: id });

        Ok(id)
    }

    /// DPO Rule: MKDIR
    pub fn mkdir(&mut self, parent_inode: u64, name: &str) -> Result<u64, i64> {
        if self.lookup(parent_inode, name).is_some() {
            return Err(EEXIST);
        }
        let inode = self.inodes.get(&parent_inode).ok_or(ENOENT)?;
        if inode.kind != InodeKind::Directory {
            return Err(ENOTDIR);
        }

        let id = self.alloc_id();
        self.inodes.insert(id, Inode {
            id,
            kind: InodeKind::Directory,
            size: 0,
            mode: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
        });

        // New dir entries: "." and ".."
        self.dir_entries.insert(id, alloc::vec![
            DirEntry { name: String::from("."), inode_id: id },
            DirEntry { name: String::from(".."), inode_id: parent_inode },
        ]);

        // Add entry in parent
        self.dir_entries
            .entry(parent_inode)
            .or_default()
            .push(DirEntry { name: String::from(name), inode_id: id });

        Ok(id)
    }

    /// DPO Rule: RMDIR
    pub fn rmdir(&mut self, parent_inode: u64, name: &str) -> Result<(), i64> {
        let target_id = self.lookup(parent_inode, name).ok_or(ENOENT)?;
        let inode = self.inodes.get(&target_id).ok_or(ENOENT)?;
        if inode.kind != InodeKind::Directory {
            return Err(ENOTDIR);
        }

        // Must be empty (only "." and "..")
        if let Some(entries) = self.dir_entries.get(&target_id) {
            if entries.iter().any(|e| e.name != "." && e.name != "..") {
                return Err(ENOTEMPTY);
            }
        }

        // Remove from parent
        if let Some(entries) = self.dir_entries.get_mut(&parent_inode) {
            entries.retain(|e| !(e.name == name && e.inode_id == target_id));
        }

        self.dir_entries.remove(&target_id);
        self.inodes.remove(&target_id);
        Ok(())
    }

    /// DPO Rule: UNLINK
    pub fn unlink(&mut self, parent_inode: u64, name: &str) -> Result<(), i64> {
        let target_id = self.lookup(parent_inode, name).ok_or(ENOENT)?;
        let inode = self.inodes.get(&target_id).ok_or(ENOENT)?;
        if inode.kind == InodeKind::Directory {
            return Err(EISDIR);
        }

        // Remove from parent
        if let Some(entries) = self.dir_entries.get_mut(&parent_inode) {
            entries.retain(|e| !(e.name == name && e.inode_id == target_id));
        }

        // Decrement nlink
        if let Some(inode) = self.inodes.get_mut(&target_id) {
            inode.nlink -= 1;
            if inode.nlink == 0 {
                self.inodes.remove(&target_id);
                self.file_data.remove(&target_id);
            }
        }

        Ok(())
    }

    /// DPO Rule: RENAME
    pub fn rename(
        &mut self,
        src_parent: u64,
        src_name: &str,
        dst_parent: u64,
        dst_name: &str,
    ) -> Result<(), i64> {
        let src_id = self.lookup(src_parent, src_name).ok_or(ENOENT)?;

        // If destination exists, remove it first
        if let Some(dst_id) = self.lookup(dst_parent, dst_name) {
            let dst_inode = self.inodes.get(&dst_id).ok_or(ENOENT)?;
            if dst_inode.kind == InodeKind::Directory {
                self.rmdir(dst_parent, dst_name)?;
            } else {
                self.unlink(dst_parent, dst_name)?;
            }
        }

        // Remove from source dir
        if let Some(entries) = self.dir_entries.get_mut(&src_parent) {
            entries.retain(|e| !(e.name == src_name && e.inode_id == src_id));
        }

        // Add to destination dir
        self.dir_entries
            .entry(dst_parent)
            .or_default()
            .push(DirEntry {
                name: String::from(dst_name),
                inode_id: src_id,
            });

        Ok(())
    }

    /// Write data to a file.
    pub fn write_data(&mut self, inode_id: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
        let inode = self.inodes.get(&inode_id).ok_or(ENOENT)?;
        if inode.kind != InodeKind::Regular {
            return Err(EISDIR);
        }

        let buf = self.file_data.entry(inode_id).or_default();
        let end = offset as usize + data.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[offset as usize..end].copy_from_slice(data);

        if let Some(inode) = self.inodes.get_mut(&inode_id) {
            inode.size = buf.len() as u64;
        }

        Ok(data.len())
    }

    /// Read data from a file.
    pub fn read_data(&self, inode_id: u64, offset: u64, max_len: usize) -> Option<Vec<u8>> {
        let inode = self.inodes.get(&inode_id)?;
        if inode.kind != InodeKind::Regular {
            return None;
        }

        let buf = self.file_data.get(&inode_id)?;
        let start = (offset as usize).min(buf.len());
        let end = (start + max_len).min(buf.len());
        Some(buf[start..end].to_vec())
    }

    /// Stat an inode: (size, mode, nlink, uid, gid).
    pub fn stat(&self, inode_id: u64) -> Option<(u64, u16, u32, u32, u32)> {
        let inode = self.inodes.get(&inode_id)?;
        let mode = match inode.kind {
            InodeKind::Regular => 0o100000 | inode.mode,
            InodeKind::Directory => 0o040000 | inode.mode,
        };
        Some((inode.size, mode, inode.nlink, inode.uid, inode.gid))
    }

    /// Readdir: get the n-th entry in a directory.
    pub fn readdir(&self, dir_inode: u64, offset: usize) -> Option<(u64, String)> {
        let entries = self.dir_entries.get(&dir_inode)?;
        let entry = entries.get(offset)?;
        Some((entry.inode_id, entry.name.clone()))
    }
}
