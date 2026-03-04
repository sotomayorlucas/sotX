//! POSIX-like VFS shim on top of the ObjectStore.

use sotos_common::sys;
use crate::store::{ObjectStore, TEMP_BUF_VADDR, MAX_OBJ_SIZE};

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

pub struct Vfs {
    store: &'static mut ObjectStore,
    handles: [FileHandle; MAX_HANDLES],
}

fn dbg(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn dbg_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

/// Get the temp buffer as a mutable slice (1 page at TEMP_BUF_VADDR).
fn temp_buf() -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(TEMP_BUF_VADDR as *mut u8, MAX_OBJ_SIZE) }
}

impl Vfs {
    pub fn new(store: &'static mut ObjectStore) -> Self {
        Self {
            store,
            handles: [FileHandle::unused(); MAX_HANDLES],
        }
    }

    /// Open an existing file by name. Returns fd.
    pub fn open(&mut self, name: &[u8], flags: u32) -> Result<u32, &'static str> {
        let oid = self.store.find(name).ok_or("file not found")?;
        let fd = self.alloc_handle()?;
        self.handles[fd as usize] = FileHandle { oid, pos: 0, flags };
        Ok(fd)
    }

    /// Create a new file. Returns fd (opened for read/write).
    pub fn create(&mut self, name: &[u8]) -> Result<u32, &'static str> {
        let oid = self.store.create(name, &[])?;
        let fd = self.alloc_handle()?;
        self.handles[fd as usize] = FileHandle { oid, pos: 0, flags: O_RDWR };

        dbg(b"VFS: created ");
        dbg(name);
        dbg(b" fd=");
        dbg_u64(fd as u64);
        dbg(b"\n");

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

        // Read full object into temp buffer.
        let tmp = temp_buf();
        let obj_size = self.store.read_obj(oid, tmp)?;

        if pos >= obj_size {
            return Ok(0);
        }

        let available = obj_size - pos;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&tmp[pos..pos + to_read]);

        self.handles[fd as usize].pos += to_read as u64;
        Ok(to_read)
    }

    /// Write to an open file at the current position.
    pub fn write(&mut self, fd: u32, data: &[u8]) -> Result<usize, &'static str> {
        let h = self.get_handle(fd)?;
        if h.flags == O_RDONLY {
            return Err("not writable");
        }

        let oid = h.oid;
        let pos = h.pos as usize;

        // Read existing object into temp buffer.
        let tmp = temp_buf();
        let obj_size = self.store.read_obj(oid, tmp).unwrap_or(0);

        // Calculate new size.
        let new_end = pos + data.len();
        if new_end > MAX_OBJ_SIZE {
            return Err("write exceeds max size");
        }
        let new_size = new_end.max(obj_size);

        // Zero-fill gap if writing past end.
        if pos > obj_size {
            for b in &mut tmp[obj_size..pos] {
                *b = 0;
            }
        }

        // Apply write.
        tmp[pos..pos + data.len()].copy_from_slice(data);

        // Write back full object.
        self.store.write_obj(oid, &tmp[..new_size])?;

        self.handles[fd as usize].pos += data.len() as u64;

        dbg(b"VFS: write ");
        dbg_u64(data.len() as u64);
        dbg(b" bytes\n");

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

        dbg(b"VFS: close fd=");
        dbg_u64(fd as u64);
        dbg(b"\n");

        Ok(())
    }

    /// Delete a file by name (closes no handles — caller should close first).
    pub fn delete(&mut self, name: &[u8]) -> Result<(), &'static str> {
        let oid = self.store.find(name).ok_or("file not found")?;
        self.store.delete(oid)?;

        dbg(b"VFS: deleted ");
        dbg(name);
        dbg(b"\n");

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
