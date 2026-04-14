//! ObjectStore — transactional named blob storage on top of virtio-blk.

use sotos_common::sys;
use sotos_virtio::blk::VirtioBlk;
use crate::layout::*;
use crate::bitmap;
use crate::wal;

/// Virtual address where ObjectStore is placed (320 pages ≈ 1.25 MiB).
const STORE_VADDR: u64 = 0xD00000;
const STORE_PAGES: u64 = 320;
/// WRITABLE flag for map syscall.
const MAP_WRITABLE: u64 = 2;

/// Maximum data size for an object (512 KB practical limit with streaming I/O).
pub const MAX_OBJ_SIZE: usize = 512 * 1024;

/// The in-memory object store state.
#[repr(C)]
pub struct ObjectStore {
    pub blk: VirtioBlk,
    pub sb: Superblock,
    pub dir: [DirEntry; DIR_ENTRY_COUNT],
    pub bitmap: [u8; BITMAP_BYTES],
    pub wal: WalHeader,
    pub wal_buf: [[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
    pub wal_index: wal::WalIndex,
    pub sector_buf: [u8; SECTOR_SIZE],
    pub refcount: [u8; REFCOUNT_ENTRIES],
    pub snap_meta: [SnapMeta; MAX_SNAPSHOTS],
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

/// Track whether pages have been allocated (static flag).
static mut PAGES_INITIALIZED: bool = false;

/// Allocate and map pages for the ObjectStore + temp buffer.
/// Idempotent — only allocates on first call.
fn init_pages() -> Result<(), &'static str> {
    unsafe {
        if PAGES_INITIALIZED {
            return Ok(());
        }
        PAGES_INITIALIZED = true;
    }
    // 5 pages for ObjectStore at 0xD00000.
    for i in 0..STORE_PAGES {
        let frame = sys::frame_alloc().map_err(|_| "frame_alloc for store")?;
        sys::map(STORE_VADDR + i * 4096, frame, MAP_WRITABLE).map_err(|_| "map store page")?;
    }
    Ok(())
}

impl ObjectStore {
    /// Format a new filesystem on the disk and return a reference to the in-memory store.
    pub fn format(blk: VirtioBlk) -> Result<&'static mut Self, &'static str> {
        init_pages()?;

        let store = unsafe { &mut *(STORE_VADDR as *mut ObjectStore) };

        // Initialize all fields.
        store.blk = blk;

        let total_sectors = store.blk.capacity as u32;
        let data_count = if total_sectors > SECTOR_DATA {
            total_sectors - SECTOR_DATA
        } else {
            return Err("disk too small");
        };

        // Initialize superblock.
        store.sb = Superblock::zeroed();
        store.sb.magic = SUPERBLOCK_MAGIC;
        store.sb.version = FS_VERSION;
        store.sb.total_sectors = total_sectors;
        store.sb.data_start = SECTOR_DATA;
        store.sb.data_count = data_count;
        store.sb.bitmap_start = SECTOR_BITMAP;
        store.sb.dir_start = SECTOR_DIR;
        store.sb.dir_sectors = DIR_SECTORS;
        store.sb.next_oid = 2; // 1 is reserved for root dir
        store.sb.obj_count = 1; // root dir counts

        // Clear directory.
        store.dir = [DirEntry::zeroed(); DIR_ENTRY_COUNT];

        // Create root directory entry in slot 0.
        store.dir[0].oid = ROOT_OID;
        store.dir[0].name[0] = b'/';
        store.dir[0].flags = FLAG_DIR;
        store.dir[0].parent_oid = 0; // sentinel: root's parent
        store.dir[0].permissions = DEFAULT_DIR_PERMS;
        let now = crate::layout::get_epoch_seconds();
        store.dir[0].created_time = now;
        store.dir[0].modified_time = now;
        store.dir[0].accessed_time = now;

        // Clear bitmap.
        store.bitmap = [0u8; BITMAP_BYTES];

        // Initialize WAL.
        store.wal = WalHeader::zeroed();
        store.wal.magic = WAL_MAGIC;

        // Clear WAL buffers and index.
        store.wal_buf = [[0u8; SECTOR_SIZE]; WAL_MAX_ENTRIES];
        store.wal_index = wal::WalIndex::new();
        store.sector_buf = [0u8; SECTOR_SIZE];

        // Clear refcount table and snapshot metadata.
        store.refcount = [0u8; REFCOUNT_ENTRIES];
        store.snap_meta = [SnapMeta::zeroed(); MAX_SNAPSHOTS];

        // Write everything to disk.
        store.flush_superblock()?;
        store.flush_bitmap()?;
        store.flush_dir()?;
        store.flush_wal_header()?;
        store.flush_refcount()?;
        store.flush_snap_meta()?;

        dbg(b"OBJSTORE: formatted, ");
        dbg_u64(data_count as u64);
        dbg(b" data blocks\n");

        Ok(store)
    }

    /// Mount an existing filesystem from disk.
    pub fn mount(blk: VirtioBlk) -> Result<&'static mut Self, &'static str> {
        dbg(b"MOUNT: init_pages\n");
        init_pages()?;

        let store = unsafe { &mut *(STORE_VADDR as *mut ObjectStore) };
        store.blk = blk;

        dbg(b"MOUNT: read superblock\n");
        store.blk.read_sector(SECTOR_SUPERBLOCK as u64)?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                store.blk.data_ptr(),
                &mut store.sb as *mut Superblock as *mut u8,
                SECTOR_SIZE,
            );
        }
        dbg(b"MOUNT: superblock magic=");
        dbg_u64(store.sb.magic as u64);
        dbg(b" version=");
        dbg_u64(store.sb.version as u64);
        dbg(b"\n");
        if store.sb.magic != SUPERBLOCK_MAGIC {
            return Err("bad superblock magic");
        }
        // v6 layout has different sector offsets — old versions can't be migrated
        // in-place without data loss. Auto-format instead (mkdisk.py regenerates disk.img).
        if store.sb.version != FS_VERSION {
            dbg(b"OBJSTORE: old version ");
            dbg_u64(store.sb.version as u64);
            dbg(b" -> auto-format to v6\n");
            return Err("old version");
        }

        dbg(b"MOUNT: WAL replay\n");
        let replayed = wal::replay(&mut store.blk, &mut store.wal, &mut store.wal_buf, &mut store.wal_index)?;
        if replayed {
            store.blk.read_sector(SECTOR_SUPERBLOCK as u64)?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    store.blk.data_ptr(),
                    &mut store.sb as *mut Superblock as *mut u8,
                    SECTOR_SIZE,
                );
            }
        }

        dbg(b"MOUNT: read_bitmap\n");
        store.read_bitmap()?;

        dbg(b"MOUNT: read_dir\n");
        store.read_dir()?;

        dbg(b"MOUNT: read_refcount\n");
        store.read_refcount()?;

        dbg(b"MOUNT: read_snap_meta\n");
        store.read_snap_meta()?;

        // Fix next_oid: scan all entries to ensure next_oid > max(existing OIDs).
        // Protects against torn writes when QEMU is killed mid-operation.
        let mut max_oid: u64 = store.sb.next_oid;
        for i in 0..DIR_ENTRY_COUNT {
            if !store.dir[i].is_free() && store.dir[i].oid >= max_oid {
                max_oid = store.dir[i].oid + 1;
            }
        }
        if max_oid != store.sb.next_oid {
            dbg(b"MOUNT: next_oid fixed "); dbg_u64(store.sb.next_oid);
            dbg(b" -> "); dbg_u64(max_oid); dbg(b"\n");
            store.sb.next_oid = max_oid;
        }

        Ok(store)
    }

    /// Create a new object with the given name and data in the root directory. Returns the OID.
    pub fn create(&mut self, name: &[u8], data: &[u8]) -> Result<u64, &'static str> {
        self.create_in(name, data, ROOT_OID)
    }

    /// Create a new object in a specific parent directory. Returns the OID.
    pub fn create_in(&mut self, name: &[u8], data: &[u8], parent_oid: u64) -> Result<u64, &'static str> {
        if name.is_empty() || name.len() >= MAX_NAME_LEN {
            return Err("invalid name length");
        }
        if data.len() > MAX_OBJ_SIZE {
            return Err("data too large");
        }

        // Check for duplicate name in parent.
        if self.find_in(name, parent_oid).is_some() {
            return Err("name already exists");
        }

        // Find free directory slot.
        let slot = self.dir.iter().position(|e| e.is_free())
            .ok_or("directory full")?;

        // Allocate data blocks.
        let sector_count = sectors_for(data.len());
        let sector_start = if sector_count > 0 {
            bitmap::alloc_blocks(&mut self.bitmap, self.sb.data_count, sector_count)
                .ok_or("no space")?
        } else {
            0
        };

        // Set refcount for new blocks.
        self.set_refcount(sector_start, sector_count, 1);

        // Write data sectors.
        self.write_data(sector_start, data)?;

        // Fill directory entry.
        let oid = self.sb.next_oid;
        // DIAG: check for pre-existing OID collision
        if let Some(cslot) = self.find_slot(oid) {
            let ce = &self.dir[cslot];
            dbg(b"OID-COLLISION! next_oid="); dbg_u64(oid);
            dbg(b" collision_slot="); dbg_u64(cslot as u64);
            dbg(b" flags="); dbg_u64(ce.flags as u64);
            dbg(b" parent="); dbg_u64(ce.parent_oid);
            dbg(b" name=["); dbg(ce.name_as_str()); dbg(b"]");
            dbg(b" new_slot="); dbg_u64(slot as u64);
            dbg(b" new_name=["); dbg(name); dbg(b"]\n");
        }
        self.dir[slot] = DirEntry::zeroed();
        self.dir[slot].oid = oid;
        let copy_len = name.len().min(MAX_NAME_LEN - 1);
        self.dir[slot].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.dir[slot].size = data.len() as u64;
        self.dir[slot].sector_start = sector_start;
        self.dir[slot].sector_count = sector_count;
        self.dir[slot].parent_oid = parent_oid;
        self.dir[slot].permissions = DEFAULT_FILE_PERMS;
        let now = crate::layout::get_epoch_seconds();
        self.dir[slot].created_time = now;
        self.dir[slot].modified_time = now;
        self.dir[slot].accessed_time = now;

        // Update superblock.
        self.sb.next_oid += 1;
        self.sb.obj_count += 1;
        // WAL commit: bitmap sector(s) + directory sector + superblock.
        self.wal_commit_metadata(slot)?;
        self.flush_refcount()?;

        Ok(oid)
    }

    /// Create a hardlink: new directory entry sharing the same sector data as `src_oid`.
    /// The new entry has a new OID but points to the same on-disk sectors.
    /// Refcounts are incremented for shared sectors.
    pub fn link_into(&mut self, name: &[u8], src_oid: u64, new_parent: u64) -> Result<u64, &'static str> {
        if name.is_empty() || name.len() >= MAX_NAME_LEN {
            return Err("invalid name");
        }
        if self.find_in(name, new_parent).is_some() {
            return Err("exists");
        }
        let src_slot = self.find_slot(src_oid).ok_or("src not found")?;
        let src = self.dir[src_slot];
        let slot = self.dir.iter().position(|e| e.is_free()).ok_or("dir full")?;

        let oid = self.sb.next_oid;
        self.dir[slot] = DirEntry::zeroed();
        self.dir[slot].oid = oid;
        let n = name.len().min(MAX_NAME_LEN - 1);
        self.dir[slot].name[..n].copy_from_slice(&name[..n]);
        self.dir[slot].size = src.size;
        self.dir[slot].sector_start = src.sector_start;
        self.dir[slot].sector_count = src.sector_count;
        self.dir[slot].flags = src.flags;
        self.dir[slot].parent_oid = new_parent;
        self.dir[slot].permissions = src.permissions;
        self.dir[slot].created_time = src.created_time;
        self.dir[slot].modified_time = src.modified_time;
        self.dir[slot].accessed_time = src.accessed_time;

        // Increment refcounts for shared sectors
        for s in 0..src.sector_count {
            let idx = (src.sector_start + s) as usize;
            if idx < self.refcount.len() && self.refcount[idx] < 255 {
                self.refcount[idx] += 1;
            }
        }

        self.sb.next_oid += 1;
        self.sb.obj_count += 1;
        // Don't flush per-entry — caller should flush_dir() + flush_superblock() after batch.

        Ok(oid)
    }

    /// Read an object by OID into `buf`. Returns bytes read.
    pub fn read_obj(&mut self, oid: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        let slot = self.find_slot(oid).ok_or("object not found")?;
        let entry = &self.dir[slot];
        let size = entry.size as usize;
        if buf.len() < size {
            return Err("buffer too small");
        }

        self.read_data(entry.sector_start, entry.sector_count, &mut buf[..size])?;
        Ok(size)
    }

    /// Overwrite an object's data.
    pub fn write_obj(&mut self, oid: u64, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > MAX_OBJ_SIZE {
            return Err("data too large");
        }

        let slot = self.find_slot(oid).ok_or("object not found")?;

        // CoW-aware free of old blocks.
        let old_start = self.dir[slot].sector_start;
        let old_count = self.dir[slot].sector_count;
        if old_count > 0 {
            self.cow_free_blocks(old_start, old_count);
        }

        // Allocate new blocks.
        let new_count = sectors_for(data.len());
        let new_start = if new_count > 0 {
            bitmap::alloc_blocks(&mut self.bitmap, self.sb.data_count, new_count)
                .ok_or("no space")?
        } else {
            0
        };

        // Set refcount for new blocks.
        self.set_refcount(new_start, new_count, 1);

        // Write new data.
        self.write_data(new_start, data)?;

        // Update directory entry.
        self.dir[slot].size = data.len() as u64;
        self.dir[slot].sector_start = new_start;
        self.dir[slot].sector_count = new_count;
        self.dir[slot].modified_time = crate::layout::get_epoch_seconds();

        // WAL commit.
        self.wal_commit_metadata(slot)?;
        self.flush_refcount()?;

        Ok(())
    }

    /// Read a byte range from an object. Returns bytes actually read.
    pub fn read_obj_range(&mut self, oid: u64, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
        let slot = self.find_slot(oid).ok_or("object not found")?;
        let entry = &self.dir[slot];
        let size = entry.size as usize;

        if offset >= size {
            return Ok(0);
        }
        let end = (offset + buf.len()).min(size);
        let total = end - offset;
        if total == 0 {
            return Ok(0);
        }

        let first_sector = offset / SECTOR_SIZE;
        let last_sector = (end - 1) / SECTOR_SIZE;
        let data_base = self.sb.data_start + entry.sector_start;

        let mut buf_pos = 0;
        let mut s = first_sector;
        while s <= last_sector {
            // Read up to 8 contiguous sectors at once (4KB bulk read)
            let remaining = last_sector - s + 1;
            let chunk = remaining.min(8);
            self.blk.read_sectors_multi((data_base + s as u32) as u64, chunk as u32)?;
            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), chunk * SECTOR_SIZE) };

            for i in 0..chunk {
                let cur = s + i;
                let sec_start = cur * SECTOR_SIZE;
                let copy_from = if cur == first_sector { offset - sec_start } else { 0 };
                let copy_to = if cur == last_sector { end - sec_start } else { SECTOR_SIZE };
                let copy_len = copy_to - copy_from;
                let src_off = i * SECTOR_SIZE + copy_from;
                buf[buf_pos..buf_pos + copy_len].copy_from_slice(&src[src_off..src_off + copy_len]);
                buf_pos += copy_len;
            }
            s += chunk;
        }

        Ok(total)
    }

    /// Write a byte range into an object, growing it if necessary.
    pub fn write_obj_range(&mut self, oid: u64, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        let slot = self.find_slot(oid).ok_or("object not found")?;
        let new_end = offset + data.len();
        if new_end > MAX_OBJ_SIZE {
            return Err("data too large");
        }

        let old_size = self.dir[slot].size as usize;
        let old_start = self.dir[slot].sector_start;
        let old_count = self.dir[slot].sector_count;
        let new_size = new_end.max(old_size);
        let new_count = sectors_for(new_size);

        // CoW: if blocks are shared (refcount > 1), or we need more sectors, reallocate
        let shared = self.blocks_shared(old_start, old_count);
        if new_count > old_count || shared {
            let new_start = bitmap::alloc_blocks(&mut self.bitmap, self.sb.data_count, new_count)
                .ok_or("no space")?;

            // Copy old data sector-by-sector to new location
            for i in 0..old_count {
                let old_abs = self.sb.data_start + old_start + i;
                self.blk.read_sector(old_abs as u64)?;
                let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
                self.sector_buf.copy_from_slice(src);

                let new_abs = self.sb.data_start + new_start + i;
                let dst = unsafe { core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE) };
                dst.copy_from_slice(&self.sector_buf);
                self.blk.write_sector(new_abs as u64)?;
            }

            // Zero new sectors beyond old data
            for i in old_count..new_count {
                self.sector_buf = [0u8; SECTOR_SIZE];
                let abs = self.sb.data_start + new_start + i;
                let dst = unsafe { core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE) };
                dst.copy_from_slice(&self.sector_buf);
                self.blk.write_sector(abs as u64)?;
            }

            // CoW-aware free of old blocks
            if old_count > 0 {
                self.cow_free_blocks(old_start, old_count);
            }

            // Set refcount for new blocks
            self.set_refcount(new_start, new_count, 1);

            self.dir[slot].sector_start = new_start;
            self.dir[slot].sector_count = new_count;
        }

        let sector_start = self.dir[slot].sector_start;

        // Write the data range
        if !data.is_empty() {
            let first_sector = offset / SECTOR_SIZE;
            let last_sector = (new_end - 1) / SECTOR_SIZE;

            let mut data_pos = 0;
            for s in first_sector..=last_sector {
                let abs_sector = self.sb.data_start + sector_start + s as u32;
                let sec_start = s * SECTOR_SIZE;
                let write_from = if s == first_sector { offset - sec_start } else { 0 };
                let write_to = if s == last_sector { new_end - sec_start } else { SECTOR_SIZE };
                let write_len = write_to - write_from;

                // Partial sector: read-modify-write
                if write_from != 0 || write_to != SECTOR_SIZE {
                    self.blk.read_sector(abs_sector as u64)?;
                    let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
                    self.sector_buf.copy_from_slice(src);
                } else {
                    self.sector_buf = [0u8; SECTOR_SIZE];
                }

                self.sector_buf[write_from..write_to].copy_from_slice(&data[data_pos..data_pos + write_len]);
                data_pos += write_len;

                let dst = unsafe { core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE) };
                dst.copy_from_slice(&self.sector_buf);
                self.blk.write_sector(abs_sector as u64)?;
            }
        }

        self.dir[slot].size = new_size as u64;
        self.dir[slot].modified_time = crate::layout::get_epoch_seconds();

        // WAL commit metadata
        self.wal_commit_metadata(slot)?;
        self.flush_refcount()?;

        Ok(())
    }

    /// Delete an object by OID.
    pub fn delete(&mut self, oid: u64) -> Result<(), &'static str> {
        let slot = self.find_slot(oid).ok_or("object not found")?;

        // CoW-aware free of data blocks.
        let start = self.dir[slot].sector_start;
        let count = self.dir[slot].sector_count;
        if count > 0 {
            self.cow_free_blocks(start, count);
        }

        // Clear directory entry.
        self.dir[slot] = DirEntry::zeroed();

        // Update superblock.
        self.sb.obj_count -= 1;

        // WAL commit.
        self.wal_commit_metadata(slot)?;
        self.flush_refcount()?;

        Ok(())
    }

    /// Rename an object: change its name and optionally move it to a new parent.
    pub fn rename(&mut self, old_oid: u64, new_name: &[u8], new_parent: u64) -> Result<(), &'static str> {
        let slot0 = self.find_slot(old_oid).ok_or("object not found")?;
        let flags_before = self.dir[slot0].flags;
        if new_name.is_empty() || new_name.len() >= MAX_NAME_LEN {
            return Err("invalid name");
        }
        // If target name already exists in new_parent, delete it first
        if let Some(existing) = self.find_in(new_name, new_parent) {
            if existing != old_oid {
                self.delete(existing)?;
                // Check if delete corrupted the source entry
                if let Some(s) = self.find_slot(old_oid) {
                    if self.dir[s].flags != flags_before {
                        dbg(b"REN-DEL-CORRUPT: oid=");
                        dbg_u64(old_oid);
                        dbg(b" flags ");
                        dbg_u64(flags_before as u64);
                        dbg(b"->");
                        dbg_u64(self.dir[s].flags as u64);
                        dbg(b" del=");
                        dbg_u64(existing);
                        dbg(b" slot=");
                        dbg_u64(s as u64);
                        dbg(b"/");
                        dbg_u64(slot0 as u64);
                        dbg(b"\n");
                    }
                }
            }
        }
        // Re-find slot (delete may have shifted things, but find_slot uses oid)
        let slot = self.find_slot(old_oid).ok_or("object not found after delete")?;
        // DIAG: snapshot flags at every step
        let flags_after_delete = self.dir[slot].flags;
        if flags_after_delete != flags_before {
            dbg(b"REN-FLAGS-MOVED: oid=");
            dbg_u64(old_oid);
            dbg(b" slot0=");
            dbg_u64(slot0 as u64);
            dbg(b" slot=");
            dbg_u64(slot as u64);
            dbg(b" flags ");
            dbg_u64(flags_before as u64);
            dbg(b"->");
            dbg_u64(flags_after_delete as u64);
            dbg(b"\n");
        }
        self.dir[slot].name = [0u8; MAX_NAME_LEN];
        let copy_len = new_name.len().min(MAX_NAME_LEN - 1);
        self.dir[slot].name[..copy_len].copy_from_slice(&new_name[..copy_len]);
        self.dir[slot].parent_oid = new_parent;
        self.wal_commit_metadata(slot)?;
        // Final check: flags and name must be correct after WAL commit
        if self.dir[slot].flags != flags_before {
            dbg(b"REN-FINAL-CORRUPT: oid=");
            dbg_u64(old_oid);
            dbg(b" flags ");
            dbg_u64(flags_before as u64);
            dbg(b"->");
            dbg_u64(self.dir[slot].flags as u64);
            dbg(b"\n");
        }
        // Verify name was actually changed
        let actual_name = self.dir[slot].name_as_str();
        if actual_name != new_name {
            dbg(b"REN-NAME-MISMATCH: oid=");
            dbg_u64(old_oid);
            dbg(b" slot=");
            dbg_u64(slot as u64);
            dbg(b" expected=[");
            dbg(new_name);
            dbg(b"] got=[");
            dbg(actual_name);
            dbg(b"]\n");
        }
        Ok(())
    }

    /// Find an object by name in the root directory. Returns OID or None.
    pub fn find(&self, name: &[u8]) -> Option<u64> {
        self.find_in(name, ROOT_OID)
    }

    /// Find an object by name within a specific parent directory.
    pub fn find_in(&self, name: &[u8], parent_oid: u64) -> Option<u64> {
        for entry in &self.dir {
            if !entry.is_free() && entry.parent_oid == parent_oid && entry.name_as_str() == name {
                return Some(entry.oid);
            }
        }
        None
    }

    /// Resolve a "/"-separated path relative to a working directory OID.
    /// Absolute paths (starting with "/") resolve from ROOT_OID.
    /// Supports "." (current) and ".." (parent).
    pub fn resolve_path(&self, path: &[u8], cwd_oid: u64) -> Result<u64, &'static str> {
        if path.is_empty() {
            return Ok(cwd_oid);
        }

        let mut current = if path[0] == b'/' { ROOT_OID } else { cwd_oid };

        let mut i = 0;
        while i < path.len() {
            // Skip leading slashes
            while i < path.len() && path[i] == b'/' {
                i += 1;
            }
            if i >= path.len() {
                break;
            }

            // Find end of component
            let start = i;
            while i < path.len() && path[i] != b'/' {
                i += 1;
            }
            let component = &path[start..i];

            if component == b"." {
                continue;
            } else if component == b".." {
                // Go to parent
                let slot = self.find_slot(current).ok_or("path not found")?;
                let parent = self.dir[slot].parent_oid;
                current = if parent == 0 { ROOT_OID } else { parent };
            } else {
                current = self.find_in(component, current).ok_or("path not found")?;
            }
        }

        Ok(current)
    }

    /// Create a directory. Returns the new directory's OID.
    pub fn mkdir(&mut self, name: &[u8], parent_oid: u64) -> Result<u64, &'static str> {
        if name.is_empty() || name.len() >= MAX_NAME_LEN {
            return Err("invalid name length");
        }
        if self.find_in(name, parent_oid).is_some() {
            return Err("name already exists");
        }

        let slot = self.dir.iter().position(|e| e.is_free())
            .ok_or("directory full")?;

        let oid = self.sb.next_oid;
        // DIAG: check for pre-existing OID collision
        if let Some(cslot) = self.find_slot(oid) {
            let ce = &self.dir[cslot];
            dbg(b"OID-COLLISION-MK! next_oid="); dbg_u64(oid);
            dbg(b" collision_slot="); dbg_u64(cslot as u64);
            dbg(b" flags="); dbg_u64(ce.flags as u64);
            dbg(b" parent="); dbg_u64(ce.parent_oid);
            dbg(b" name=["); dbg(ce.name_as_str()); dbg(b"]");
            dbg(b" new_slot="); dbg_u64(slot as u64);
            dbg(b" new_name=["); dbg(name); dbg(b"]\n");
        }
        self.dir[slot] = DirEntry::zeroed();
        self.dir[slot].oid = oid;
        let copy_len = name.len().min(MAX_NAME_LEN - 1);
        self.dir[slot].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.dir[slot].flags = FLAG_DIR;
        self.dir[slot].parent_oid = parent_oid;
        self.dir[slot].permissions = DEFAULT_DIR_PERMS;
        let now = crate::layout::get_epoch_seconds();
        self.dir[slot].created_time = now;
        self.dir[slot].modified_time = now;
        self.dir[slot].accessed_time = now;

        self.sb.next_oid += 1;
        self.sb.obj_count += 1;
        self.wal_commit_metadata(slot)?;

        Ok(oid)
    }

    /// Remove a directory. Fails if it has children.
    pub fn rmdir(&mut self, oid: u64) -> Result<(), &'static str> {
        if oid == ROOT_OID {
            return Err("cannot remove root");
        }
        let slot = self.find_slot(oid).ok_or("directory not found")?;
        if self.dir[slot].flags & FLAG_DIR == 0 {
            return Err("not a directory");
        }

        // Check for children
        for entry in &self.dir {
            if !entry.is_free() && entry.parent_oid == oid {
                return Err("directory not empty");
            }
        }

        self.dir[slot] = DirEntry::zeroed();
        self.sb.obj_count -= 1;
        self.wal_commit_metadata(slot)?;

        Ok(())
    }

    /// List entries in a directory. Returns count written (clamped to out.len()).
    pub fn list_dir(&self, parent_oid: u64, out: &mut [DirEntry]) -> usize {
        let mut n = 0;
        for entry in &self.dir {
            if !entry.is_free() && entry.parent_oid == parent_oid && entry.oid != parent_oid {
                if n < out.len() {
                    out[n] = *entry;
                    n += 1;
                }
            }
        }
        n
    }

    /// Get a copy of a directory entry by OID.
    pub fn stat(&self, oid: u64) -> Option<DirEntry> {
        self.find_slot(oid).map(|i| self.dir[i])
    }

    /// List all live non-root objects. Returns count written (backwards compat).
    pub fn list(&self, out: &mut [DirEntry]) -> usize {
        self.list_dir(ROOT_OID, out)
    }

    /// Get the VirtioBlk device back (consumes the store logically, but since
    /// it's at a fixed address we just return the inner blk by-value equivalent).
    /// Caller must not use the store after this.
    /// Create a named snapshot. Returns the snapshot slot index.
    pub fn snap_create(&mut self, name: &[u8]) -> Result<usize, &'static str> {
        // Find free slot
        let slot = self.snap_meta.iter().position(|s| s.active == 0)
            .ok_or("no free snapshot slots")?;

        // Fill snapshot metadata
        self.snap_meta[slot] = SnapMeta::zeroed();
        self.snap_meta[slot].active = 1;
        self.snap_meta[slot].snap_id = (slot + 1) as u32;
        let copy_len = name.len().min(31);
        self.snap_meta[slot].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.snap_meta[slot].created_tick = crate::layout::get_epoch_seconds() as u32;
        self.snap_meta[slot].obj_count = self.sb.obj_count;
        self.snap_meta[slot].next_oid = self.sb.next_oid;

        // Write directory copy (8 sectors)
        for s in 0..DIR_SECTORS as usize {
            let buf = self.serialize_dir_sector(s);
            let snap_dir_sector = SECTOR_SNAP_DIR + (slot as u32 * DIR_SECTORS) + s as u32;
            let dst = unsafe { core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE) };
            dst.copy_from_slice(&buf);
            self.blk.write_sector(snap_dir_sector as u64)?;
        }

        // Write bitmap copy (2 sectors)
        for i in 0..BITMAP_SECTORS {
            let bmp_offset = i as usize * SECTOR_SIZE;
            let snap_bmp_sector = SECTOR_SNAP_BMP + (slot as u32 * BITMAP_SECTORS) + i;
            let dst = unsafe { core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE) };
            dst.copy_from_slice(&self.bitmap[bmp_offset..bmp_offset + SECTOR_SIZE]);
            self.blk.write_sector(snap_bmp_sector as u64)?;
        }

        // Increment refcount for all currently allocated data blocks
        for entry in &self.dir {
            if !entry.is_free() && entry.sector_count > 0 {
                for b in entry.sector_start..entry.sector_start + entry.sector_count {
                    if (b as usize) < REFCOUNT_ENTRIES {
                        self.refcount[b as usize] = self.refcount[b as usize].saturating_add(1);
                    }
                }
            }
        }

        // Flush snapshot metadata and refcounts
        self.flush_snap_meta()?;
        self.flush_refcount()?;

        dbg(b"OBJSTORE: snapshot created: ");
        dbg(name);
        dbg(b"\n");

        Ok(slot)
    }

    /// Delete a snapshot by slot index, freeing its block references.
    pub fn snap_delete(&mut self, slot: usize) -> Result<(), &'static str> {
        if slot >= MAX_SNAPSHOTS || self.snap_meta[slot].active == 0 {
            return Err("snapshot not found");
        }

        // Process snapshot directory entries sector-by-sector (avoids large stack alloc)
        let mut sector_entries = [DirEntry::zeroed(); DIR_ENTRIES_PER_SECTOR];
        for s in 0..DIR_SECTORS as usize {
            let snap_dir_sector = SECTOR_SNAP_DIR + (slot as u32 * DIR_SECTORS) + s as u32;
            self.blk.read_sector(snap_dir_sector as u64)?;
            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
            for i in 0..DIR_ENTRIES_PER_SECTOR {
                let offset = i * 128;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src[offset..].as_ptr(),
                        &mut sector_entries[i] as *mut DirEntry as *mut u8,
                        128,
                    );
                }
            }
            // Decrement refcounts for this sector's entries
            for entry in &sector_entries {
                if !entry.is_free() && entry.sector_count > 0 {
                    self.cow_free_blocks(entry.sector_start, entry.sector_count);
                }
            }
        }

        // Mark snapshot as inactive
        self.snap_meta[slot].active = 0;

        self.flush_snap_meta()?;
        self.flush_refcount()?;
        self.flush_bitmap()?;

        dbg(b"OBJSTORE: snapshot deleted\n");

        Ok(())
    }

    /// Restore a snapshot: replace current directory and bitmap with snapshot's copies.
    pub fn snap_restore(&mut self, slot: usize) -> Result<(), &'static str> {
        if slot >= MAX_SNAPSHOTS || self.snap_meta[slot].active == 0 {
            return Err("snapshot not found");
        }

        // CoW-free all current blocks first (decrement refcount)
        for i in 0..DIR_ENTRY_COUNT {
            let entry = &self.dir[i];
            if !entry.is_free() && entry.sector_count > 0 {
                let start = entry.sector_start;
                let count = entry.sector_count;
                for b in start..start + count {
                    let idx = b as usize;
                    if idx < REFCOUNT_ENTRIES && self.refcount[idx] > 0 {
                        self.refcount[idx] -= 1;
                        if self.refcount[idx] == 0 {
                            bitmap::free_blocks(&mut self.bitmap, b, 1);
                        }
                    }
                }
            }
        }

        // Read snapshot's directory (directly into self.dir)
        for s in 0..DIR_SECTORS as usize {
            let snap_dir_sector = SECTOR_SNAP_DIR + (slot as u32 * DIR_SECTORS) + s as u32;
            self.blk.read_sector(snap_dir_sector as u64)?;
            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
            let base = s * DIR_ENTRIES_PER_SECTOR;
            for i in 0..DIR_ENTRIES_PER_SECTOR {
                let offset = i * 128;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src[offset..].as_ptr(),
                        &mut self.dir[base + i] as *mut DirEntry as *mut u8,
                        128,
                    );
                }
            }
        }

        // Read snapshot's bitmap
        for i in 0..BITMAP_SECTORS {
            let snap_bmp_sector = SECTOR_SNAP_BMP + (slot as u32 * BITMAP_SECTORS) + i;
            self.blk.read_sector(snap_bmp_sector as u64)?;
            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
            let bmp_offset = i as usize * SECTOR_SIZE;
            self.bitmap[bmp_offset..bmp_offset + SECTOR_SIZE].copy_from_slice(src);
        }

        // Increment refcount for all restored blocks
        for entry in &self.dir {
            if !entry.is_free() && entry.sector_count > 0 {
                for b in entry.sector_start..entry.sector_start + entry.sector_count {
                    if (b as usize) < REFCOUNT_ENTRIES {
                        self.refcount[b as usize] = self.refcount[b as usize].saturating_add(1);
                    }
                }
            }
        }

        // Restore superblock metadata
        self.sb.obj_count = self.snap_meta[slot].obj_count;
        self.sb.next_oid = self.snap_meta[slot].next_oid;

        // Flush everything
        self.flush_superblock()?;
        self.flush_bitmap()?;
        self.flush_dir()?;
        self.flush_refcount()?;

        dbg(b"OBJSTORE: snapshot restored\n");

        Ok(())
    }

    /// List active snapshots. Returns count.
    pub fn snap_list(&self, out: &mut [SnapMeta]) -> usize {
        let mut n = 0;
        for meta in &self.snap_meta {
            if meta.active != 0 {
                if n < out.len() {
                    out[n] = *meta;
                }
                n += 1;
            }
        }
        n
    }

    /// Find a snapshot slot by name.
    pub fn snap_find(&self, name: &[u8]) -> Option<usize> {
        for (i, meta) in self.snap_meta.iter().enumerate() {
            if meta.active != 0 && meta.name_as_str() == name {
                return Some(i);
            }
        }
        None
    }

    pub fn into_blk(&mut self) -> VirtioBlk {
        // Safety: bitwise copy of VirtioBlk; caller must not use `self` afterward.
        let blk_ptr = &self.blk as *const VirtioBlk;
        unsafe { core::ptr::read(blk_ptr) }
    }

    /// Recover the VirtioBlk after a failed mount() or format().
    /// mount/format store blk at the static STORE_VADDR before they can fail,
    /// so this reads it back out for retry.
    pub fn recover_blk() -> VirtioBlk {
        unsafe { core::ptr::read(&(*(STORE_VADDR as *const ObjectStore)).blk) }
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    fn find_slot(&self, oid: u64) -> Option<usize> {
        self.dir.iter().position(|e| e.oid == oid)
    }

    /// Public version of find_slot for VFS getcwd path building.
    pub fn find_slot_pub(&self, oid: u64) -> Option<usize> {
        self.find_slot(oid)
    }

    /// Write data to consecutive sectors in the data region.
    fn write_data(&mut self, start_block: u32, data: &[u8]) -> Result<(), &'static str> {
        let count = sectors_for(data.len());
        for i in 0..count {
            let offset = i as usize * SECTOR_SIZE;
            let end = (offset + SECTOR_SIZE).min(data.len());

            // Clear sector buffer.
            self.sector_buf = [0u8; SECTOR_SIZE];

            if offset < data.len() {
                let len = end - offset;
                self.sector_buf[..len].copy_from_slice(&data[offset..offset + len]);
            }

            let abs_sector = self.sb.data_start + start_block + i;
            let dst = unsafe {
                core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE)
            };
            dst.copy_from_slice(&self.sector_buf);
            self.blk.write_sector(abs_sector as u64)?;
        }
        Ok(())
    }

    /// Read data from consecutive sectors in the data region.
    fn read_data(&mut self, start_block: u32, block_count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        for i in 0..block_count {
            let abs_sector = self.sb.data_start + start_block + i;
            self.blk.read_sector(abs_sector as u64)?;

            let offset = i as usize * SECTOR_SIZE;
            let remaining = buf.len() - offset;
            let copy_len = remaining.min(SECTOR_SIZE);

            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), copy_len) };
            buf[offset..offset + copy_len].copy_from_slice(src);
        }
        Ok(())
    }

    /// WAL-commit metadata changes (superblock + directory entry sector).
    /// Bitmap is flushed separately (too large for WAL with 128 sectors).
    fn wal_commit_metadata(&mut self, dir_slot: usize) -> Result<(), &'static str> {
        // Snapshot flags before WAL
        let flags_pre = self.dir[dir_slot].flags;
        let oid_pre = self.dir[dir_slot].oid;

        wal::begin(&mut self.wal, &mut self.wal_index);

        // Stage superblock.
        let sb_buf = unsafe {
            &*((&self.sb as *const Superblock) as *const [u8; SECTOR_SIZE])
        };
        wal::stage(&mut self.wal, &mut self.wal_buf, &mut self.wal_index, SECTOR_SUPERBLOCK, sb_buf)?;

        // Stage directory sector containing the modified slot.
        let dir_sector_idx = dir_slot / DIR_ENTRIES_PER_SECTOR;
        let dir_abs_sector = SECTOR_DIR + dir_sector_idx as u32;
        let dir_buf = self.serialize_dir_sector(dir_sector_idx);
        wal::stage(&mut self.wal, &mut self.wal_buf, &mut self.wal_index, dir_abs_sector, &dir_buf)?;

        wal::commit(&mut self.blk, &mut self.wal, &self.wal_buf)?;

        // Check if WAL commit corrupted the entry
        if self.dir[dir_slot].flags != flags_pre {
            dbg(b"WAL-CORRUPT: slot=");
            dbg_u64(dir_slot as u64);
            dbg(b" oid=");
            dbg_u64(oid_pre);
            dbg(b" flags ");
            dbg_u64(flags_pre as u64);
            dbg(b"->");
            dbg_u64(self.dir[dir_slot].flags as u64);
            dbg(b"\n");
        }

        // Flush bitmap separately (non-WAL — too many sectors for WAL staging).
        self.flush_bitmap()?;
        Ok(())
    }

    /// Serialize one directory sector (4 entries) into a 512-byte buffer.
    fn serialize_dir_sector(&self, sector_idx: usize) -> [u8; SECTOR_SIZE] {
        let mut buf = [0u8; SECTOR_SIZE];
        let base = sector_idx * DIR_ENTRIES_PER_SECTOR;
        for i in 0..DIR_ENTRIES_PER_SECTOR {
            let entry = &self.dir[base + i];
            let offset = i * 128;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    entry as *const DirEntry as *const u8,
                    buf[offset..].as_mut_ptr(),
                    128,
                );
            }
        }
        buf
    }

    /// Flush superblock to disk (non-WAL, for format).
    pub fn flush_superblock(&mut self) -> Result<(), &'static str> {
        write_sector_struct(&mut self.blk, SECTOR_SUPERBLOCK as u64, &self.sb)
    }

    /// Flush bitmap to disk (non-WAL, for format).
    fn flush_bitmap(&mut self) -> Result<(), &'static str> {
        flush_sectors(&mut self.blk, &self.bitmap, SECTOR_BITMAP, BITMAP_SECTORS)
    }

    /// Flush all directory sectors to disk (non-WAL, for format/chmod/chown).
    pub fn flush_dir(&mut self) -> Result<(), &'static str> {
        for s in 0..DIR_SECTORS as usize {
            let buf = self.serialize_dir_sector(s);
            write_sector_buf(&mut self.blk, (SECTOR_DIR + s as u32) as u64, &buf)?;
        }
        Ok(())
    }

    /// Flush WAL header to disk (non-WAL, for format).
    fn flush_wal_header(&mut self) -> Result<(), &'static str> {
        write_sector_struct(&mut self.blk, SECTOR_WAL_HEADER as u64, &self.wal)
    }

    /// Read bitmap from disk into memory.
    fn read_bitmap(&mut self) -> Result<(), &'static str> {
        read_sectors(&mut self.blk, &mut self.bitmap, SECTOR_BITMAP, BITMAP_SECTORS)
    }

    /// Read all directory sectors from disk into memory.
    fn read_dir(&mut self) -> Result<(), &'static str> {
        for s in 0..DIR_SECTORS as usize {
            // Dense trace for the first 32 sectors (to catch per-sector hangs),
            // then every 256 for progress.
            if s < 32 || s % 256 == 0 {
                dbg(b"MOUNT: read_dir sector ");
                dbg_u64(s as u64);
                dbg(b"/");
                dbg_u64(DIR_SECTORS as u64);
                dbg(b"\n");
            }
            self.blk.read_sector((SECTOR_DIR + s as u32) as u64)?;
            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
            let base = s * DIR_ENTRIES_PER_SECTOR;
            for i in 0..DIR_ENTRIES_PER_SECTOR {
                let offset = i * 128;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src[offset..].as_ptr(),
                        &mut self.dir[base + i] as *mut DirEntry as *mut u8,
                        128,
                    );
                }
            }
        }
        Ok(())
    }

    /// Flush refcount table to disk (8 sectors).
    pub fn flush_refcount(&mut self) -> Result<(), &'static str> {
        flush_sectors(&mut self.blk, &self.refcount, SECTOR_REFCOUNT, REFCOUNT_SECTORS)
    }

    /// Read refcount table from disk.
    fn read_refcount(&mut self) -> Result<(), &'static str> {
        read_sectors(&mut self.blk, &mut self.refcount, SECTOR_REFCOUNT, REFCOUNT_SECTORS)
    }

    /// Flush snapshot metadata to disk (4 sectors).
    fn flush_snap_meta(&mut self) -> Result<(), &'static str> {
        for i in 0..MAX_SNAPSHOTS {
            write_sector_struct(&mut self.blk, (SECTOR_SNAP_META + i as u32) as u64, &self.snap_meta[i])?;
        }
        Ok(())
    }

    /// Read snapshot metadata from disk.
    fn read_snap_meta(&mut self) -> Result<(), &'static str> {
        for i in 0..MAX_SNAPSHOTS {
            self.blk.read_sector((SECTOR_SNAP_META + i as u32) as u64)?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.blk.data_ptr(),
                    &mut self.snap_meta[i] as *mut SnapMeta as *mut u8,
                    SECTOR_SIZE,
                );
            }
        }
        Ok(())
    }

    /// Check if any block in the range has refcount > 1 (shared with snapshot).
    fn blocks_shared(&self, start: u32, count: u32) -> bool {
        for b in start..start + count {
            let idx = b as usize;
            if idx < REFCOUNT_ENTRIES && self.refcount[idx] > 1 {
                return true;
            }
        }
        false
    }

    /// Set refcount for a block range.
    fn set_refcount(&mut self, start: u32, count: u32, val: u8) {
        for b in start..start + count {
            let idx = b as usize;
            if idx < REFCOUNT_ENTRIES {
                self.refcount[idx] = val;
            }
        }
    }

    /// CoW-aware block free: decrement refcount. Only free bitmap bit when refcount reaches 0.
    fn cow_free_blocks(&mut self, start: u32, count: u32) {
        for b in start..start + count {
            let idx = b as usize;
            if idx < REFCOUNT_ENTRIES {
                if self.refcount[idx] > 1 {
                    self.refcount[idx] -= 1;
                    // Block still referenced by a snapshot — don't free bitmap
                } else {
                    self.refcount[idx] = 0;
                    bitmap::free_blocks(&mut self.bitmap, b, 1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone sector I/O helpers (avoid borrow conflicts with &mut self)
// ---------------------------------------------------------------------------

/// Write multiple sectors from a contiguous byte array.
fn flush_sectors(blk: &mut VirtioBlk, data: &[u8], base_sector: u32, count: u32) -> Result<(), &'static str> {
    for i in 0..count {
        let offset = i as usize * SECTOR_SIZE;
        let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), SECTOR_SIZE) };
        dst.copy_from_slice(&data[offset..offset + SECTOR_SIZE]);
        blk.write_sector((base_sector + i) as u64)?;
    }
    Ok(())
}

/// Read multiple sectors into a contiguous byte array (uses bulk reads of 8 sectors).
fn read_sectors(blk: &mut VirtioBlk, data: &mut [u8], base_sector: u32, count: u32) -> Result<(), &'static str> {
    let mut i = 0u32;
    while i < count {
        let chunk = (count - i).min(8);
        blk.read_sectors_multi((base_sector + i) as u64, chunk)?;
        let src = unsafe { core::slice::from_raw_parts(blk.data_ptr(), chunk as usize * SECTOR_SIZE) };
        let offset = i as usize * SECTOR_SIZE;
        data[offset..offset + chunk as usize * SECTOR_SIZE].copy_from_slice(src);
        i += chunk;
    }
    Ok(())
}

/// Write a single sector from a buffer.
fn write_sector_buf(blk: &mut VirtioBlk, sector: u64, buf: &[u8; SECTOR_SIZE]) -> Result<(), &'static str> {
    let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), SECTOR_SIZE) };
    dst.copy_from_slice(buf);
    blk.write_sector(sector)
}

/// Write a struct as a single sector (must fit in SECTOR_SIZE).
fn write_sector_struct<T>(blk: &mut VirtioBlk, sector: u64, val: &T) -> Result<(), &'static str> {
    let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), SECTOR_SIZE) };
    unsafe {
        core::ptr::copy_nonoverlapping(
            val as *const T as *const u8,
            dst.as_mut_ptr(),
            SECTOR_SIZE,
        );
    }
    blk.write_sector(sector)
}

/// Calculate number of sectors needed for `size` bytes.
fn sectors_for(size: usize) -> u32 {
    if size == 0 {
        0
    } else {
        ((size + SECTOR_SIZE - 1) / SECTOR_SIZE) as u32
    }
}
