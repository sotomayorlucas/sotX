//! POSIX-like VFS shim on top of the ObjectStore.

use crate::store::ObjectStore;

const MAX_HANDLES: usize = 16;

/// File open flags.
pub const O_RDONLY: u32 = 1;
pub const O_WRONLY: u32 = 2;
pub const O_RDWR: u32 = 3;

#[derive(Clone, Copy)]
struct FileHandle {
    oid: u64,       // 0 = unused
    pos: u64,       // byte offset
    flags: u32,
}

impl FileHandle {
    const fn unused() -> Self {
        Self { oid: 0, pos: 0, flags: 0 }
    }

    fn is_used(&self) -> bool {
        self.oid != 0
    }
}

/// Access permission bits for check_permission().
pub const PERM_READ: u8 = 4;
pub const PERM_WRITE: u8 = 2;
pub const PERM_EXEC: u8 = 1;

pub struct Vfs {
    store: &'static mut ObjectStore,
    handles: [FileHandle; MAX_HANDLES],
    pub cwd: u64,
    /// Current user ID for permission checks (default: 0 = root).
    pub uid: u16,
    /// Current group ID for permission checks (default: 0 = root).
    pub gid: u16,
}


impl Vfs {
    pub fn new(store: &'static mut ObjectStore) -> Self {
        use crate::layout::ROOT_OID;
        Self {
            store,
            handles: [FileHandle::unused(); MAX_HANDLES],
            cwd: ROOT_OID,
            uid: 0,
            gid: 0,
        }
    }

    /// Check if the given uid/gid has the specified access permission on a DirEntry.
    ///
    /// - `access`: bitmask of PERM_READ(4), PERM_WRITE(2), PERM_EXEC(1).
    /// - Returns true if access is granted, false if denied.
    ///
    /// Permission bits in `entry.permissions` follow Unix layout:
    ///   bits 8-6: owner rwx
    ///   bits 5-3: group rwx
    ///   bits 2-0: other rwx
    pub fn check_permission(entry: &crate::layout::DirEntry, uid: u16, gid: u16, access: u8) -> bool {
        // Root (uid 0) always has access.
        if uid == 0 {
            return true;
        }

        let perms = entry.permissions;
        let relevant_bits = if entry.owner_uid == uid {
            // Owner permissions (bits 8-6)
            ((perms >> 6) & 0x7) as u8
        } else if entry.owner_gid == gid {
            // Group permissions (bits 5-3)
            ((perms >> 3) & 0x7) as u8
        } else {
            // Other permissions (bits 2-0)
            (perms & 0x7) as u8
        };

        (relevant_bits & access) == access
    }

    /// Open an existing file by name (path resolved relative to cwd). Returns fd.
    pub fn open(&mut self, name: &[u8], flags: u32) -> Result<u32, &'static str> {
        let oid = self.resolve(name)?;

        // Permission check.
        if let Some(entry) = self.store.stat(oid) {
            let access = match flags {
                O_RDONLY => PERM_READ,
                O_WRONLY => PERM_WRITE,
                O_RDWR => PERM_READ | PERM_WRITE,
                _ => PERM_READ,
            };
            if !Self::check_permission(&entry, self.uid, self.gid, access) {
                return Err("permission denied");
            }
        }

        let fd = self.alloc_handle()?;
        self.handles[fd as usize] = FileHandle { oid, pos: 0, flags };
        Ok(fd)
    }

    /// Create a new file (path resolved relative to cwd). Returns fd (opened for read/write).
    pub fn create(&mut self, name: &[u8]) -> Result<u32, &'static str> {
        // Split into parent path and filename
        let (parent_oid, filename) = self.resolve_parent(name)?;
        let oid = self.store.create_in(filename, &[], parent_oid)?;
        let fd = self.alloc_handle()?;
        self.handles[fd as usize] = FileHandle { oid, pos: 0, flags: O_RDWR };

        Ok(fd)
    }

    /// Read from an open file. Returns bytes read.
    pub fn read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize, &'static str> {
        let h = self.get_handle(fd)?;
        if h.flags == O_WRONLY {
            return Err("not readable");
        }

        let oid = h.oid;
        let pos = h.pos as usize;

        // Permission check.
        if let Some(entry) = self.store.stat(oid) {
            if !Self::check_permission(&entry, self.uid, self.gid, PERM_READ) {
                return Err("permission denied");
            }
        }

        let n = self.store.read_obj_range(oid, pos, buf)?;
        self.handles[fd as usize].pos += n as u64;
        Ok(n)
    }

    /// Write to an open file at the current position.
    pub fn write(&mut self, fd: u32, data: &[u8]) -> Result<usize, &'static str> {
        let h = self.get_handle(fd)?;
        if h.flags == O_RDONLY {
            return Err("not writable");
        }

        let oid = h.oid;
        let pos = h.pos as usize;

        // Permission check.
        if let Some(entry) = self.store.stat(oid) {
            if !Self::check_permission(&entry, self.uid, self.gid, PERM_WRITE) {
                return Err("permission denied");
            }
        }

        self.store.write_obj_range(oid, pos, data)?;

        self.handles[fd as usize].pos += data.len() as u64;

        Ok(data.len())
    }

    /// Seek to a byte position.
    pub fn seek(&mut self, fd: u32, pos: u64) -> Result<(), &'static str> {
        let _ = self.get_handle(fd)?;
        self.handles[fd as usize].pos = pos;
        Ok(())
    }

    /// Close a file handle.
    pub fn close(&mut self, fd: u32) -> Result<(), &'static str> {
        let _ = self.get_handle(fd)?;
        self.handles[fd as usize] = FileHandle::unused();
        Ok(())
    }

    /// Delete a file by name/path (closes no handles — caller should close first).
    pub fn delete(&mut self, name: &[u8]) -> Result<(), &'static str> {
        let oid = self.resolve(name)?;
        self.store.delete(oid)?;

        Ok(())
    }

    /// Get the current file position.
    pub fn tell(&self, fd: u32) -> Result<u64, &'static str> {
        let h = self.get_handle(fd)?;
        Ok(h.pos)
    }

    /// Get the object ID for a file handle (useful as inode number in stat).
    pub fn file_oid(&self, fd: u32) -> Result<u64, &'static str> {
        let h = self.get_handle(fd)?;
        Ok(h.oid)
    }

    /// Get the size of the file behind a handle via store.stat().
    pub fn file_size(&self, fd: u32) -> Result<u64, &'static str> {
        let h = self.get_handle(fd)?;
        let entry = self.store.stat(h.oid).ok_or("stat failed")?;
        Ok(entry.size)
    }

    /// Change working directory.
    pub fn chdir(&mut self, path: &[u8]) -> Result<(), &'static str> {
        let oid = self.resolve(path)?;
        let entry = self.store.stat(oid).ok_or("not found")?;
        if !entry.is_dir() {
            return Err("not a directory");
        }
        self.cwd = oid;
        Ok(())
    }

    /// Get the current working directory path.
    pub fn getcwd(&self, buf: &mut [u8]) -> usize {
        use crate::layout::ROOT_OID;
        if self.cwd == ROOT_OID {
            if !buf.is_empty() {
                buf[0] = b'/';
            }
            return 1;
        }

        // Walk up to root collecting names
        let mut oids = [0u64; 16];
        let mut depth = 0;
        let mut cur = self.cwd;
        while cur != ROOT_OID && depth < 16 {
            oids[depth] = cur;
            depth += 1;
            if let Some(slot) = self.store.find_slot_pub(cur) {
                let parent = self.store.dir[slot].parent_oid;
                cur = if parent == 0 { ROOT_OID } else { parent };
            } else {
                break;
            }
        }

        // Build path from root down
        let mut pos = 0;
        if depth == 0 {
            if pos < buf.len() { buf[pos] = b'/'; pos += 1; }
            return pos;
        }
        let mut i = depth;
        while i > 0 {
            i -= 1;
            if pos < buf.len() { buf[pos] = b'/'; pos += 1; }
            if let Some(slot) = self.store.find_slot_pub(oids[i]) {
                let name = self.store.dir[slot].name_as_str();
                let copy_len = name.len().min(buf.len() - pos);
                buf[pos..pos + copy_len].copy_from_slice(&name[..copy_len]);
                pos += copy_len;
            }
        }
        pos
    }

    /// Create a directory at the given path.
    pub fn mkdir(&mut self, path: &[u8]) -> Result<u64, &'static str> {
        let (parent_oid, name) = self.resolve_parent(path)?;
        self.store.mkdir(name, parent_oid)
    }

    /// Remove a directory at the given path.
    pub fn rmdir(&mut self, path: &[u8]) -> Result<(), &'static str> {
        let oid = self.resolve(path)?;
        self.store.rmdir(oid)
    }

    /// Change permissions on a file/directory by path.
    pub fn chmod(&mut self, path: &[u8], mode: u32) -> Result<(), &'static str> {
        let oid = self.resolve(path)?;
        if let Some(slot) = self.store.find_slot_pub(oid) {
            // Only owner or root can chmod.
            let entry = &self.store.dir[slot];
            if self.uid != 0 && entry.owner_uid != self.uid {
                return Err("permission denied");
            }
            self.store.dir[slot].permissions = mode & 0o777;
            self.store.flush_dir().map_err(|_| "flush dir failed")?;
            Ok(())
        } else {
            Err("not found")
        }
    }

    /// Change ownership of a file/directory by path.
    pub fn chown(&mut self, path: &[u8], uid: u16, gid: u16) -> Result<(), &'static str> {
        let oid = self.resolve(path)?;
        if let Some(slot) = self.store.find_slot_pub(oid) {
            // Only root can chown.
            if self.uid != 0 {
                return Err("permission denied");
            }
            self.store.dir[slot].owner_uid = uid;
            self.store.dir[slot].owner_gid = gid;
            self.store.flush_dir().map_err(|_| "flush dir failed")?;
            Ok(())
        } else {
            Err("not found")
        }
    }

    /// Find a file/dir by path, resolving relative to cwd. Returns OID.
    pub fn find_path(&self, path: &[u8]) -> Option<u64> {
        self.store.resolve_path(path, self.cwd).ok()
    }

    /// Get access to the underlying object store.
    pub fn store(&self) -> &ObjectStore {
        self.store
    }

    /// Get mutable access to the underlying store (for list, etc).
    pub fn store_mut(&mut self) -> &mut ObjectStore {
        self.store
    }

    // ---------------------------------------------------------------
    // Private
    // ---------------------------------------------------------------

    /// Resolve a path to an OID relative to cwd.
    fn resolve(&self, path: &[u8]) -> Result<u64, &'static str> {
        self.store.resolve_path(path, self.cwd)
    }

    /// Resolve the parent directory and return (parent_oid, filename).
    fn resolve_parent<'a>(&self, path: &'a [u8]) -> Result<(u64, &'a [u8]), &'static str> {
        // Find last '/' to split parent/filename
        let mut last_slash = None;
        for (i, &b) in path.iter().enumerate() {
            if b == b'/' {
                last_slash = Some(i);
            }
        }

        match last_slash {
            Some(pos) => {
                let parent_path = &path[..pos];
                let filename = &path[pos + 1..];
                if filename.is_empty() {
                    return Err("empty filename");
                }
                let parent_oid = if parent_path.is_empty() {
                    use crate::layout::ROOT_OID;
                    ROOT_OID
                } else {
                    self.store.resolve_path(parent_path, self.cwd)?
                };
                Ok((parent_oid, filename))
            }
            None => {
                // No slash — file in cwd
                Ok((self.cwd, path))
            }
        }
    }

    fn alloc_handle(&self) -> Result<u32, &'static str> {
        for (i, h) in self.handles.iter().enumerate() {
            if !h.is_used() {
                return Ok(i as u32);
            }
        }
        Err("no free file handles")
    }

    fn get_handle(&self, fd: u32) -> Result<&FileHandle, &'static str> {
        let idx = fd as usize;
        if idx >= MAX_HANDLES || !self.handles[idx].is_used() {
            return Err("invalid fd");
        }
        Ok(&self.handles[idx])
    }
}
