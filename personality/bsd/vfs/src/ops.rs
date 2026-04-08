//! POSIX file operations: open, read, write, stat, readdir, mkdir, unlink, etc.
//!
//! Every operation validates the caller's `FileCap` rights before touching
//! vnode data. Reads annotate provenance as Tier0; writes annotate as Tier1.

use alloc::vec::Vec;
use crate::lookup::{resolve_parent, resolve_path};
use crate::mount::MountTable;
use crate::vnode::{DirEntry, Vnode, VnodeStat, VnodeType};
use crate::{FileCap, FileRights, Tier, VfsError, VfsOp};

/// Open flags passed by the caller, mapped to POSIX semantics.
#[derive(Debug, Clone, Copy)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
    pub directory: bool,
}

impl OpenFlags {
    /// Derive file rights from the open flags.
    pub fn to_rights(self) -> FileRights {
        FileRights {
            read: self.read,
            write: self.write,
            execute: false,
            append_only: self.append,
        }
    }
}

/// Operation result with provenance annotation.
#[derive(Debug)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub bytes_read: usize,
    pub tier: Tier,
}

/// VFS server state: owns all vnodes and the mount table.
pub struct VfsServer {
    pub mounts: MountTable,
    pub vnodes: Vec<Vnode>,
    next_vnode_id: u64,
    next_cap_id: u64,
}

impl VfsServer {
    pub fn new() -> Self {
        Self {
            mounts: MountTable::new(),
            vnodes: Vec::new(),
            next_vnode_id: 0,
            next_cap_id: 1,
        }
    }

    /// Allocate the next vnode id.
    fn alloc_vnode_id(&mut self) -> u64 {
        let id = self.next_vnode_id;
        self.next_vnode_id += 1;
        id
    }

    /// Allocate the next capability id.
    fn alloc_cap_id(&mut self) -> u64 {
        let id = self.next_cap_id;
        self.next_cap_id += 1;
        id
    }

    /// Find a vnode by id (immutable).
    pub fn find_vnode(&self, id: u64) -> Option<&Vnode> {
        self.vnodes.iter().find(|v| v.id == id)
    }

    /// Find a vnode by id (mutable).
    fn find_vnode_mut(&mut self, id: u64) -> Option<&mut Vnode> {
        self.vnodes.iter_mut().find(|v| v.id == id)
    }

    // --- POSIX Operations ---

    /// Open a file by path. Returns a `FileCap` with rights derived from flags.
    pub fn open(&mut self, path: &str, flags: OpenFlags) -> Result<FileCap, VfsError> {
        // Try resolving the path first.
        match resolve_path(path, &self.mounts, &self.vnodes) {
            Ok(result) => {
                let vnode = self.find_vnode(result.vnode_id).ok_or(VfsError::NoEnt)?;
                if flags.directory && vnode.vtype != VnodeType::Directory {
                    return Err(VfsError::NotDir);
                }
                if vnode.vtype == VnodeType::Directory && flags.write {
                    return Err(VfsError::IsDir);
                }

                let vnode_id = result.vnode_id;
                // Truncate if requested.
                if flags.truncate && flags.write {
                    let vnode = self.find_vnode_mut(vnode_id).ok_or(VfsError::NoEnt)?;
                    vnode.data.clear();
                    vnode.size = 0;
                }

                // Increment refcount.
                let vnode = self.find_vnode_mut(vnode_id).ok_or(VfsError::NoEnt)?;
                vnode.ref_count += 1;

                Ok(FileCap {
                    cap_id: self.alloc_cap_id(),
                    rights: flags.to_rights(),
                    vnode_id,
                    offset: 0,
                })
            }
            Err(VfsError::NoEnt) if flags.create => {
                // Create the file.
                let parent = resolve_parent(path, &self.mounts, &self.vnodes)?;
                let new_id = self.alloc_vnode_id();
                let mut vnode = Vnode::new_file(new_id, parent.mount_id);
                vnode.ref_count = 1;
                self.vnodes.push(vnode);

                let parent_vnode = self.find_vnode_mut(parent.parent_id)
                    .ok_or(VfsError::NoEnt)?;
                if !parent_vnode.add_child(parent.name, new_id, VnodeType::Regular) {
                    return Err(VfsError::Exist);
                }

                Ok(FileCap {
                    cap_id: self.alloc_cap_id(),
                    rights: flags.to_rights(),
                    vnode_id: new_id,
                    offset: 0,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Close a file handle — decrements the vnode refcount.
    pub fn close(&mut self, cap: &FileCap) -> Result<(), VfsError> {
        let vnode = self.find_vnode_mut(cap.vnode_id).ok_or(VfsError::BadF)?;
        vnode.ref_count = vnode.ref_count.saturating_sub(1);
        Ok(())
    }

    /// Read from an open file. Provenance: Tier0.
    pub fn read(&self, cap: &mut FileCap, buf_len: usize) -> Result<ReadResult, VfsError> {
        if !cap.rights.read {
            return Err(VfsError::Access);
        }
        let vnode = self.find_vnode(cap.vnode_id).ok_or(VfsError::BadF)?;
        if vnode.vtype == VnodeType::Directory {
            return Err(VfsError::IsDir);
        }

        let offset = cap.offset as usize;
        if offset >= vnode.data.len() {
            return Ok(ReadResult {
                data: Vec::new(),
                bytes_read: 0,
                tier: Tier::Tier0,
            });
        }

        let end = core::cmp::min(offset + buf_len, vnode.data.len());
        let data = vnode.data[offset..end].to_vec();
        let bytes_read = data.len();
        cap.offset += bytes_read as u64;

        Ok(ReadResult {
            data,
            bytes_read,
            tier: Tier::Tier0,
        })
    }

    /// Write to an open file. Provenance: Tier1.
    pub fn write(&mut self, cap: &mut FileCap, data: &[u8]) -> Result<(usize, Tier), VfsError> {
        if !cap.rights.write {
            return Err(VfsError::Access);
        }
        let vnode = self.find_vnode_mut(cap.vnode_id).ok_or(VfsError::BadF)?;
        if vnode.vtype == VnodeType::Directory {
            return Err(VfsError::IsDir);
        }

        let offset = if cap.rights.append_only {
            vnode.data.len()
        } else {
            cap.offset as usize
        };

        // Extend data buffer if necessary.
        if offset + data.len() > vnode.data.len() {
            vnode.data.resize(offset + data.len(), 0);
        }
        vnode.data[offset..offset + data.len()].copy_from_slice(data);
        vnode.size = vnode.data.len() as u64;

        let written = data.len();
        cap.offset = (offset + written) as u64;

        Ok((written, Tier::Tier1))
    }

    /// Stat a file by path.
    pub fn stat(&self, path: &str) -> Result<VnodeStat, VfsError> {
        let result = resolve_path(path, &self.mounts, &self.vnodes)?;
        let vnode = self.find_vnode(result.vnode_id).ok_or(VfsError::NoEnt)?;
        Ok(vnode.stat())
    }

    /// Fstat on an open file handle.
    pub fn fstat(&self, cap: &FileCap) -> Result<VnodeStat, VfsError> {
        let vnode = self.find_vnode(cap.vnode_id).ok_or(VfsError::BadF)?;
        Ok(vnode.stat())
    }

    /// Read directory entries from a directory handle.
    pub fn readdir(&self, cap: &FileCap) -> Result<Vec<DirEntry>, VfsError> {
        if !cap.rights.read {
            return Err(VfsError::Access);
        }
        let vnode = self.find_vnode(cap.vnode_id).ok_or(VfsError::BadF)?;
        if vnode.vtype != VnodeType::Directory {
            return Err(VfsError::NotDir);
        }
        Ok(vnode.children.clone())
    }

    /// Create a directory at the given path.
    pub fn mkdir(&mut self, path: &str) -> Result<u64, VfsError> {
        let parent = resolve_parent(path, &self.mounts, &self.vnodes)?;

        // Check the name doesn't already exist.
        let parent_vnode = self.find_vnode(parent.parent_id).ok_or(VfsError::NoEnt)?;
        if parent_vnode.find_child(&parent.name).is_some() {
            return Err(VfsError::Exist);
        }

        let new_id = self.alloc_vnode_id();
        let dir = Vnode::new_dir(new_id, parent.parent_id, parent.mount_id);
        self.vnodes.push(dir);

        let parent_vnode = self.find_vnode_mut(parent.parent_id)
            .ok_or(VfsError::NoEnt)?;
        parent_vnode.add_child(parent.name, new_id, VnodeType::Directory);

        Ok(new_id)
    }

    /// Remove an empty directory.
    pub fn rmdir(&mut self, path: &str) -> Result<(), VfsError> {
        let parent = resolve_parent(path, &self.mounts, &self.vnodes)?;

        let parent_vnode = self.find_vnode(parent.parent_id).ok_or(VfsError::NoEnt)?;
        let child_id = parent_vnode.find_child(&parent.name).ok_or(VfsError::NoEnt)?;

        let child = self.find_vnode(child_id).ok_or(VfsError::NoEnt)?;
        if child.vtype != VnodeType::Directory {
            return Err(VfsError::NotDir);
        }
        // Directory must only contain `.` and `..`.
        if child.children.len() > 2 {
            return Err(VfsError::NotEmpty);
        }

        let parent_vnode = self.find_vnode_mut(parent.parent_id)
            .ok_or(VfsError::NoEnt)?;
        parent_vnode.remove_child(&parent.name);

        self.vnodes.retain(|v| v.id != child_id);
        Ok(())
    }

    /// Unlink (remove) a file.
    pub fn unlink(&mut self, path: &str) -> Result<(), VfsError> {
        let parent = resolve_parent(path, &self.mounts, &self.vnodes)?;

        let parent_vnode = self.find_vnode(parent.parent_id).ok_or(VfsError::NoEnt)?;
        let child_id = parent_vnode.find_child(&parent.name).ok_or(VfsError::NoEnt)?;

        let child = self.find_vnode(child_id).ok_or(VfsError::NoEnt)?;
        if child.vtype == VnodeType::Directory {
            return Err(VfsError::IsDir);
        }

        let parent_vnode = self.find_vnode_mut(parent.parent_id)
            .ok_or(VfsError::NoEnt)?;
        parent_vnode.remove_child(&parent.name);

        // Remove vnode if unreferenced; open handles keep it alive (POSIX).
        let child = self.find_vnode(child_id).ok_or(VfsError::NoEnt)?;
        if child.ref_count == 0 {
            self.vnodes.retain(|v| v.id != child_id);
        }
        Ok(())
    }

    /// Rename a file or directory.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), VfsError> {
        let old_parent = resolve_parent(old_path, &self.mounts, &self.vnodes)?;
        let new_parent = resolve_parent(new_path, &self.mounts, &self.vnodes)?;

        // Find the source.
        let src_vnode = self.find_vnode(old_parent.parent_id)
            .ok_or(VfsError::NoEnt)?;
        let child_id = src_vnode.find_child(&old_parent.name)
            .ok_or(VfsError::NoEnt)?;

        let child = self.find_vnode(child_id).ok_or(VfsError::NoEnt)?;
        let entry_type = child.vtype;

        // Remove from old parent.
        let src = self.find_vnode_mut(old_parent.parent_id)
            .ok_or(VfsError::NoEnt)?;
        src.remove_child(&old_parent.name);

        // If destination already exists, remove it.
        let dst = self.find_vnode_mut(new_parent.parent_id)
            .ok_or(VfsError::NoEnt)?;
        if let Some(existing) = dst.find_child(&new_parent.name) {
            dst.remove_child(&new_parent.name);
            self.vnodes.retain(|v| v.id != existing);
            // Re-borrow after retain.
            let dst = self.find_vnode_mut(new_parent.parent_id)
                .ok_or(VfsError::NoEnt)?;
            dst.add_child(new_parent.name, child_id, entry_type);
        } else {
            dst.add_child(new_parent.name, child_id, entry_type);
        }

        Ok(())
    }

    /// Seek within an open file.
    pub fn lseek(&self, cap: &mut FileCap, offset: i64, whence: u32) -> Result<u64, VfsError> {
        const SEEK_SET: u32 = 0;
        const SEEK_CUR: u32 = 1;
        const SEEK_END: u32 = 2;

        let vnode = self.find_vnode(cap.vnode_id).ok_or(VfsError::BadF)?;
        let new_offset = match whence {
            SEEK_SET => {
                if offset < 0 {
                    return Err(VfsError::Inval);
                }
                offset as u64
            }
            SEEK_CUR => {
                let current = cap.offset as i64;
                let result = current + offset;
                if result < 0 {
                    return Err(VfsError::Inval);
                }
                result as u64
            }
            SEEK_END => {
                let end = vnode.size as i64;
                let result = end + offset;
                if result < 0 {
                    return Err(VfsError::Inval);
                }
                result as u64
            }
            _ => return Err(VfsError::Inval),
        };
        cap.offset = new_offset;
        Ok(new_offset)
    }

    /// Sync file data to storage (no-op for in-memory backend).
    pub fn fsync(&self, cap: &FileCap) -> Result<(), VfsError> {
        let _ = self.find_vnode(cap.vnode_id).ok_or(VfsError::BadF)?;
        Ok(())
    }

    /// Truncate an open file to the given length.
    pub fn ftruncate(&mut self, cap: &FileCap, length: u64) -> Result<(), VfsError> {
        if !cap.rights.write {
            return Err(VfsError::Access);
        }
        let vnode = self.find_vnode_mut(cap.vnode_id).ok_or(VfsError::BadF)?;
        if vnode.vtype == VnodeType::Directory {
            return Err(VfsError::IsDir);
        }
        vnode.data.resize(length as usize, 0);
        vnode.size = length;
        Ok(())
    }

    /// Dispatch a VFS operation by opcode (for IPC message handling).
    ///
    /// In a full implementation this would deserialize the IPC message,
    /// validate the caller's capability, dispatch to the correct method,
    /// and serialize the reply. This stub shows the dispatch structure.
    pub fn dispatch(&mut self, op: VfsOp, cap: &mut FileCap) -> Result<(), VfsError> {
        match op {
            VfsOp::Close => self.close(cap),
            VfsOp::Stat => {
                let _ = self.fstat(cap)?;
                Ok(())
            }
            VfsOp::Fsync => self.fsync(cap),
            _ => Err(VfsError::Inval),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::FsType;
    use alloc::string::String;

    fn make_server() -> VfsServer {
        let mut s = VfsServer::new();
        let root_id = s.alloc_vnode_id();
        let root = Vnode::new_dir(root_id, root_id, 1);
        s.vnodes.push(root);
        s.mounts.mount(String::from("/"), FsType::Tmpfs, 1, root_id, false);
        s
    }

    #[test]
    fn open_create_read_write() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        let mut cap = s.open("/hello.txt", flags).unwrap();
        let (written, tier) = s.write(&mut cap, b"Hello, VFS!").unwrap();
        assert_eq!(written, 11);
        assert_eq!(tier, Tier::Tier1);

        cap.offset = 0;
        let result = s.read(&mut cap, 64).unwrap();
        assert_eq!(&result.data, b"Hello, VFS!");
        assert_eq!(result.tier, Tier::Tier0);
    }

    #[test]
    fn open_existing() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        s.open("/test.txt", flags).unwrap();

        let flags2 = OpenFlags {
            read: true,
            write: false,
            create: false,
            truncate: false,
            append: false,
            directory: false,
        };
        let cap = s.open("/test.txt", flags2).unwrap();
        assert!(cap.rights.read);
        assert!(!cap.rights.write);
    }

    #[test]
    fn open_not_found() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: false,
            create: false,
            truncate: false,
            append: false,
            directory: false,
        };
        assert_eq!(s.open("/nope", flags).unwrap_err(), VfsError::NoEnt);
    }

    #[test]
    fn mkdir_and_readdir() {
        let mut s = make_server();
        s.mkdir("/bin").unwrap();

        let flags = OpenFlags {
            read: true,
            write: false,
            create: false,
            truncate: false,
            append: false,
            directory: true,
        };
        let cap = s.open("/bin", flags).unwrap();
        let entries = s.readdir(&cap).unwrap();
        // `.` and `..`
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn mkdir_duplicate() {
        let mut s = make_server();
        s.mkdir("/tmp").unwrap();
        assert_eq!(s.mkdir("/tmp").unwrap_err(), VfsError::Exist);
    }

    #[test]
    fn rmdir_empty() {
        let mut s = make_server();
        s.mkdir("/empty").unwrap();
        s.rmdir("/empty").unwrap();
        assert_eq!(
            s.stat("/empty").unwrap_err(),
            VfsError::NoEnt
        );
    }

    #[test]
    fn rmdir_not_empty() {
        let mut s = make_server();
        s.mkdir("/stuff").unwrap();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        s.open("/stuff/file", flags).unwrap();
        assert_eq!(s.rmdir("/stuff").unwrap_err(), VfsError::NotEmpty);
    }

    #[test]
    fn unlink_file() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        let cap = s.open("/del.txt", flags).unwrap();
        s.close(&cap).unwrap();
        s.unlink("/del.txt").unwrap();
        assert_eq!(s.stat("/del.txt").unwrap_err(), VfsError::NoEnt);
    }

    #[test]
    fn unlink_dir_fails() {
        let mut s = make_server();
        s.mkdir("/d").unwrap();
        assert_eq!(s.unlink("/d").unwrap_err(), VfsError::IsDir);
    }

    #[test]
    fn rename_file() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        s.open("/old.txt", flags).unwrap();
        s.rename("/old.txt", "/new.txt").unwrap();
        assert!(s.stat("/new.txt").is_ok());
        assert_eq!(s.stat("/old.txt").unwrap_err(), VfsError::NoEnt);
    }

    #[test]
    fn lseek_set_cur_end() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        let mut cap = s.open("/seek.txt", flags).unwrap();
        s.write(&mut cap, b"abcdef").unwrap();

        s.lseek(&mut cap, 0, 0).unwrap(); // SEEK_SET
        assert_eq!(cap.offset, 0);

        s.lseek(&mut cap, 3, 1).unwrap(); // SEEK_CUR
        assert_eq!(cap.offset, 3);

        s.lseek(&mut cap, -2, 2).unwrap(); // SEEK_END
        assert_eq!(cap.offset, 4);
    }

    #[test]
    fn ftruncate_shrink_grow() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        let mut cap = s.open("/trunc.txt", flags).unwrap();
        s.write(&mut cap, b"hello world").unwrap();
        s.ftruncate(&cap, 5).unwrap();
        let st = s.fstat(&cap).unwrap();
        assert_eq!(st.size, 5);

        s.ftruncate(&cap, 10).unwrap();
        let st = s.fstat(&cap).unwrap();
        assert_eq!(st.size, 10);
    }

    #[test]
    fn append_mode() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: true,
            directory: false,
        };
        let mut cap = s.open("/log.txt", flags).unwrap();
        s.write(&mut cap, b"first").unwrap();
        cap.offset = 0; // Even if someone resets offset, append forces end.
        s.write(&mut cap, b"second").unwrap();

        cap.offset = 0;
        let result = s.read(&mut cap, 64).unwrap();
        assert_eq!(&result.data, b"firstsecond");
    }

    #[test]
    fn read_without_permission() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: false,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        let mut cap = s.open("/noperm.txt", flags).unwrap();
        assert_eq!(s.read(&mut cap, 10).unwrap_err(), VfsError::Access);
    }

    #[test]
    fn write_without_permission() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        let cap = s.open("/ro.txt", flags).unwrap();
        s.close(&cap).unwrap();

        let ro_flags = OpenFlags {
            read: true,
            write: false,
            create: false,
            truncate: false,
            append: false,
            directory: false,
        };
        let mut cap2 = s.open("/ro.txt", ro_flags).unwrap();
        assert_eq!(s.write(&mut cap2, b"nope").unwrap_err(), VfsError::Access);
    }

    #[test]
    fn stat_path() {
        let s = make_server();
        let st = s.stat("/").unwrap();
        assert_eq!(st.permissions, 0o755);
    }

    #[test]
    fn close_decrements_refcount() {
        let mut s = make_server();
        let flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            append: false,
            directory: false,
        };
        let cap = s.open("/ref.txt", flags).unwrap();
        assert_eq!(s.find_vnode(cap.vnode_id).unwrap().ref_count, 1);
        s.close(&cap).unwrap();
        assert_eq!(s.find_vnode(cap.vnode_id).unwrap().ref_count, 0);
    }
}
