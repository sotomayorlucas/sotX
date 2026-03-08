//! On-disk layout structures for the sotOS object store.

/// Superblock magic: "SOTOS_FS!" in ASCII.
pub const SUPERBLOCK_MAGIC: u64 = 0x534F544F_53465321;

/// WAL header magic: "WALH" in ASCII.
pub const WAL_MAGIC: u32 = 0x57414C48;

/// Filesystem version.
pub const FS_VERSION: u32 = 6;

/// Directory entry flag: entry is a directory.
pub const FLAG_DIR: u32 = 1;

/// Default permissions: rwxr-xr-x (0o755) for dirs, rw-r--r-- (0o644) for files.
pub const DEFAULT_DIR_PERMS: u32 = 0o755;
pub const DEFAULT_FILE_PERMS: u32 = 0o644;

/// Root directory OID (always 1).
pub const ROOT_OID: u64 = 1;

// Sector layout (v6 — 8192 dir entries for full rootfs injection):
pub const SECTOR_SUPERBLOCK: u32 = 0;
pub const SECTOR_WAL_HEADER: u32 = 1;
pub const SECTOR_WAL_PAYLOAD: u32 = 2;      // 2-5 (4 sectors)
pub const WAL_MAX_ENTRIES: usize = 4;
pub const SECTOR_BITMAP: u32 = 6;            // 6-133 (128 sectors)
pub const BITMAP_SECTORS: u32 = 128;
pub const SECTOR_DIR: u32 = 134;             // 134-2181 (2048 sectors, 8192 entries)
pub const DIR_SECTORS: u32 = 2048;
pub const SECTOR_REFCOUNT: u32 = 2182;       // 2182-2197 (16 sectors, 8192 × u8)
pub const REFCOUNT_SECTORS: u32 = 16;
pub const REFCOUNT_ENTRIES: usize = REFCOUNT_SECTORS as usize * SECTOR_SIZE; // 8192

pub const SECTOR_SNAP_META: u32 = 2198;      // 2198-2201 (4 × SnapMeta)
pub const MAX_SNAPSHOTS: usize = 4;

pub const SECTOR_SNAP_DIR: u32 = 2202;       // 2202-10393 (4 × 2048 sectors)
pub const SECTOR_SNAP_BMP: u32 = 10394;      // 10394-10905 (4 × 128 sectors)

pub const SECTOR_DATA: u32 = 10906;          // 10906+ (data region)

/// Entries per sector (128 bytes each, 4 per 512-byte sector).
pub const DIR_ENTRIES_PER_SECTOR: usize = 4;
/// Total directory entries.
pub const DIR_ENTRY_COUNT: usize = DIR_SECTORS as usize * DIR_ENTRIES_PER_SECTOR; // 8192

/// Bitmap size in bytes (128 sectors × 512 = 65536 bytes = 524288 bits).
pub const BITMAP_BYTES: usize = BITMAP_SECTORS as usize * 512; // 65536

/// v5 layout constants (for migration from previous format).
pub const V5_SECTOR_DIR: u32 = 134;
pub const V5_DIR_SECTORS: u32 = 512;
pub const V5_DIR_ENTRY_COUNT: usize = 2048;
pub const V5_SECTOR_REFCOUNT: u32 = 646;
pub const V5_REFCOUNT_SECTORS: u32 = 16;
pub const V5_SECTOR_SNAP_META: u32 = 662;
pub const V5_SECTOR_SNAP_DIR: u32 = 666;
pub const V5_SECTOR_SNAP_BMP: u32 = 2714;
pub const V5_SECTOR_DATA: u32 = 3226;

/// Size of a sector in bytes.
pub const SECTOR_SIZE: usize = 512;

/// Maximum object name length (null-terminated).
pub const MAX_NAME_LEN: usize = 48;

/// Superblock (512 bytes, sector 0).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Superblock {
    pub magic: u64,
    pub version: u32,
    pub total_sectors: u32,
    pub data_start: u32,
    pub data_count: u32,
    pub bitmap_start: u32,
    pub dir_start: u32,
    pub dir_sectors: u32,
    pub next_oid: u64,
    pub obj_count: u32,
    pub _pad: [u8; 460],  // 512 - 52 (alignment padding before next_oid)
}

impl Superblock {
    pub const fn zeroed() -> Self {
        Self {
            magic: 0,
            version: 0,
            total_sectors: 0,
            data_start: 0,
            data_count: 0,
            bitmap_start: 0,
            dir_start: 0,
            dir_sectors: 0,
            next_oid: 0,
            obj_count: 0,
            _pad: [0; 460],
        }
    }
}

/// WAL header (512 bytes, sector 1).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WalHeader {
    pub magic: u32,
    pub seq: u64,
    pub entry_count: u32,
    pub committed: u32,
    pub targets: [u32; WAL_MAX_ENTRIES],
    pub _pad: [u8; 472],
}

impl WalHeader {
    pub const fn zeroed() -> Self {
        Self {
            magic: 0,
            seq: 0,
            entry_count: 0,
            committed: 0,
            targets: [0; WAL_MAX_ENTRIES],
            _pad: [0; 472],
        }
    }
}

/// Directory entry (128 bytes, 4 per sector).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub oid: u64,
    pub name: [u8; MAX_NAME_LEN],
    pub size: u64,
    pub sector_start: u32,
    pub sector_count: u32,
    pub flags: u32,
    pub created_time: u64,    // Unix timestamp in seconds (was created_tick: u32)
    pub modified_time: u64,   // Unix timestamp in seconds (was modified_tick: u32)
    pub accessed_time: u64,   // Unix timestamp in seconds (atime)
    pub parent_oid: u64,      // parent directory OID (0 = root's parent sentinel)
    pub permissions: u32,     // Unix-style rwxrwxrwx (owner/group/other, 9 bits)
    pub owner_uid: u16,       // owner user ID
    pub owner_gid: u16,       // owner group ID
    pub _pad: [u8; 8],        // pad to 128 total
}

impl DirEntry {
    pub const fn zeroed() -> Self {
        Self {
            oid: 0,
            name: [0; MAX_NAME_LEN],
            size: 0,
            sector_start: 0,
            sector_count: 0,
            flags: 0,
            created_time: 0,
            modified_time: 0,
            accessed_time: 0,
            parent_oid: 0,
            permissions: 0,
            owner_uid: 0,
            owner_gid: 0,
            _pad: [0; 8],
        }
    }

    pub fn is_dir(&self) -> bool {
        self.flags & FLAG_DIR != 0
    }

    pub fn is_free(&self) -> bool {
        self.oid == 0
    }

    pub fn name_as_str(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_NAME_LEN);
        &self.name[..len]
    }
}

/// Snapshot metadata (512 bytes, one per sector).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnapMeta {
    pub active: u32,
    pub snap_id: u32,
    pub name: [u8; 32],
    pub created_tick: u32,
    pub obj_count: u32,
    pub next_oid: u64,
    pub _pad: [u8; 456],   // 512 - 56
}

impl SnapMeta {
    pub const fn zeroed() -> Self {
        Self {
            active: 0,
            snap_id: 0,
            name: [0; 32],
            created_tick: 0,
            obj_count: 0,
            next_oid: 0,
            _pad: [0; 456],
        }
    }

    pub fn name_as_str(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(32);
        &self.name[..len]
    }
}

// Compile-time size assertions.
const _: () = assert!(core::mem::size_of::<Superblock>() == 512);
const _: () = assert!(core::mem::size_of::<WalHeader>() == 512);
const _: () = assert!(core::mem::size_of::<DirEntry>() == 128);
const _: () = assert!(core::mem::size_of::<SnapMeta>() == 512);

/// Approximate TSC frequency for time estimation.
/// Assumes ~2 GHz TSC (common QEMU default). Real hardware would calibrate
/// against PIT/HPET/ACPI PM timer, but this suffices for a development OS.
const TSC_FREQ_HZ: u64 = 2_000_000_000;

/// Approximate Unix epoch base as TSC ticks at boot.
/// We store the TSC value at first call and use it as the reference point.
/// Since we have no RTC, we assume boot time = 2026-01-01 00:00:00 UTC
/// (epoch = 1767225600).
const BOOT_EPOCH_SECS: u64 = 1767225600;

/// TSC value captured at first call to `get_epoch_seconds()`.
static mut BOOT_TSC: u64 = 0;
/// Whether BOOT_TSC has been initialized.
static mut BOOT_TSC_INIT: bool = false;

/// Get an approximate Unix timestamp in seconds.
///
/// Uses RDTSC to estimate wall-clock time relative to an assumed boot epoch.
/// This is approximate — without an RTC or NTP, the timestamp drifts.
pub fn get_epoch_seconds() -> u64 {
    let tsc: u64;
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        tsc = ((hi as u64) << 32) | lo as u64;
    }

    unsafe {
        if !BOOT_TSC_INIT {
            BOOT_TSC = tsc;
            BOOT_TSC_INIT = true;
        }
        let elapsed_ticks = tsc.saturating_sub(BOOT_TSC);
        let elapsed_secs = elapsed_ticks / TSC_FREQ_HZ;
        BOOT_EPOCH_SECS + elapsed_secs
    }
}
