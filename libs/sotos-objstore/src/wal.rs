//! Write-Ahead Log for atomic multi-sector metadata updates.
//!
//! Includes a hash index over WAL entries for O(1) key lookup by target sector.
//! The index uses FNV-1a hashing with open-addressing (linear probing) and a
//! fixed-capacity table — no_std, no_alloc.

use sotos_virtio::blk::VirtioBlk;
use crate::layout::*;

// ---------------------------------------------------------------------------
// FNV-1a hash
// ---------------------------------------------------------------------------

/// FNV-1a hash over a byte slice. Good distribution, simple, no_std-friendly.
pub const fn fnv1a(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < key.len() {
        h ^= key[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}

/// Hash a u32 target-sector value (the WAL key).
pub const fn hash_sector(sector: u32) -> u64 {
    let bytes = sector.to_le_bytes();
    fnv1a(&bytes)
}

// ---------------------------------------------------------------------------
// WalIndex — open-addressing hash table for WAL key → entry offset
// ---------------------------------------------------------------------------

/// Number of buckets in the hash index. Power of 2 for fast modulo.
pub const WAL_INDEX_CAPACITY: usize = 256;

/// Sentinel indicating an empty bucket.
const EMPTY_HASH: u64 = 0;

/// In-memory hash index mapping WAL target sectors to their entry offset.
///
/// Avoids linear scanning during WAL lookups. Uses FNV-1a hash with
/// open-addressing (linear probing) in a fixed-capacity table.
///
/// Invariant: `buckets[i].0 == EMPTY_HASH` means the slot is empty.
/// Since FNV-1a of any real key is astronomically unlikely to be 0,
/// this is safe. We additionally guard against it in `insert`.
pub struct WalIndex {
    /// Open-addressing hash table: (key_hash, log_offset).
    /// key_hash == 0 means empty slot.
    pub buckets: [(u64, u32); WAL_INDEX_CAPACITY],
    /// Number of occupied slots.
    pub len: usize,
}

impl WalIndex {
    /// Create an empty index.
    pub const fn new() -> Self {
        Self {
            buckets: [(EMPTY_HASH, 0); WAL_INDEX_CAPACITY],
            len: 0,
        }
    }

    /// Clear all entries, resetting the index to empty.
    pub fn clear(&mut self) {
        self.len = 0;
        let mut i = 0;
        while i < WAL_INDEX_CAPACITY {
            self.buckets[i] = (EMPTY_HASH, 0);
            i += 1;
        }
    }

    /// Insert or update a mapping from `key_hash` to `offset`.
    ///
    /// If the key already exists, its offset is updated (last-writer-wins).
    /// Returns `Ok(())` on success, `Err` if the table is full.
    pub fn insert(&mut self, key_hash: u64, offset: u32) -> Result<(), &'static str> {
        // Guard against the sentinel value (astronomically unlikely with FNV-1a).
        let h = if key_hash == EMPTY_HASH { key_hash.wrapping_add(1) } else { key_hash };

        let start = (h as usize) & (WAL_INDEX_CAPACITY - 1);
        let mut idx = start;

        loop {
            let slot = &self.buckets[idx];
            if slot.0 == EMPTY_HASH {
                // Empty slot — insert here.
                self.buckets[idx] = (h, offset);
                self.len += 1;
                return Ok(());
            }
            if slot.0 == h {
                // Key already present — update offset (latest WAL entry wins).
                self.buckets[idx].1 = offset;
                return Ok(());
            }
            idx = (idx + 1) & (WAL_INDEX_CAPACITY - 1);
            if idx == start {
                return Err("WalIndex full");
            }
        }
    }

    /// Look up the WAL entry offset for a given key hash.
    ///
    /// Returns `Some(offset)` if found, `None` if the key is not in the index.
    pub fn lookup(&self, key_hash: u64) -> Option<u32> {
        let h = if key_hash == EMPTY_HASH { key_hash.wrapping_add(1) } else { key_hash };

        let start = (h as usize) & (WAL_INDEX_CAPACITY - 1);
        let mut idx = start;

        loop {
            let slot = &self.buckets[idx];
            if slot.0 == EMPTY_HASH {
                return None; // Empty slot — key not present.
            }
            if slot.0 == h {
                return Some(slot.1);
            }
            idx = (idx + 1) & (WAL_INDEX_CAPACITY - 1);
            if idx == start {
                return None; // Wrapped around — not found.
            }
        }
    }

    /// Remove the entry for `key_hash` from the index.
    ///
    /// Uses backward-shift deletion to maintain probe chain integrity.
    /// Returns `true` if the key was found and removed, `false` otherwise.
    pub fn remove(&mut self, key_hash: u64) -> bool {
        let h = if key_hash == EMPTY_HASH { key_hash.wrapping_add(1) } else { key_hash };

        let start = (h as usize) & (WAL_INDEX_CAPACITY - 1);
        let mut idx = start;

        // Phase 1: find the slot.
        loop {
            if self.buckets[idx].0 == EMPTY_HASH {
                return false;
            }
            if self.buckets[idx].0 == h {
                break; // Found at `idx`.
            }
            idx = (idx + 1) & (WAL_INDEX_CAPACITY - 1);
            if idx == start {
                return false;
            }
        }

        // Phase 2: backward-shift deletion.
        // Remove the slot and shift subsequent entries backward to fill the gap,
        // maintaining probe chain invariants.
        self.buckets[idx] = (EMPTY_HASH, 0);
        self.len -= 1;

        let mut empty = idx;
        let mut j = (idx + 1) & (WAL_INDEX_CAPACITY - 1);

        while self.buckets[j].0 != EMPTY_HASH {
            let natural = (self.buckets[j].0 as usize) & (WAL_INDEX_CAPACITY - 1);

            // Check if `j`'s natural position is "at or before" the empty slot,
            // wrapping around the table. If so, move it backward.
            let should_move = if empty <= j {
                // No wraparound: natural is outside (empty, j]
                natural <= empty || natural > j
            } else {
                // Wraparound: natural is in [j+1, empty]
                natural <= empty && natural > j
            };

            if should_move {
                self.buckets[empty] = self.buckets[j];
                self.buckets[j] = (EMPTY_HASH, 0);
                empty = j;
            }

            j = (j + 1) & (WAL_INDEX_CAPACITY - 1);
            if j == idx {
                break; // Full loop — done.
            }
        }

        true
    }

    /// Rebuild the index by scanning all WAL entries.
    ///
    /// Called during recovery after reading the WAL from disk.
    /// Entries are added in order so the latest offset for each key wins.
    pub fn rebuild(&mut self, wal: &WalHeader) {
        self.clear();
        let count = wal.entry_count as usize;
        let limit = if count > WAL_MAX_ENTRIES { WAL_MAX_ENTRIES } else { count };
        for i in 0..limit {
            let h = hash_sector(wal.targets[i]);
            // Ignore errors — WAL_MAX_ENTRIES << WAL_INDEX_CAPACITY.
            let _ = self.insert(h, i as u32);
        }
    }
}

/// Begin a new WAL transaction (in-memory only).
///
/// Also clears the hash index so it reflects only the new transaction.
pub fn begin(wal: &mut WalHeader, index: &mut WalIndex) {
    wal.seq += 1;
    wal.entry_count = 0;
    wal.committed = 0;
    index.clear();
}

/// Stage a sector image into the WAL payload buffer.
/// `data` must be exactly 512 bytes.
///
/// Also updates the hash index so `wal_lookup` can find this entry in O(1).
pub fn stage(
    wal: &mut WalHeader,
    wal_buf: &mut [[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
    index: &mut WalIndex,
    target_sector: u32,
    data: &[u8; SECTOR_SIZE],
) -> Result<(), &'static str> {
    let idx = wal.entry_count as usize;
    if idx >= WAL_MAX_ENTRIES {
        return Err("WAL full");
    }
    wal_buf[idx].copy_from_slice(data);
    wal.targets[idx] = target_sector;
    wal.entry_count += 1;

    // Update index: map this sector's hash to the new entry offset.
    let h = hash_sector(target_sector);
    let _ = index.insert(h, idx as u32);

    Ok(())
}

/// Look up whether a target sector has a staged WAL entry.
///
/// Returns `Some(entry_index)` if the sector is in the current WAL transaction,
/// `None` otherwise. Uses the hash index for O(1) amortized lookup instead of
/// linear scanning.
pub fn wal_lookup(wal: &WalHeader, index: &WalIndex, target_sector: u32) -> Option<usize> {
    let h = hash_sector(target_sector);
    if let Some(offset) = index.lookup(h) {
        let off = offset as usize;
        // Verify the actual target sector matches (hash collision guard).
        if off < wal.entry_count as usize && wal.targets[off] == target_sector {
            return Some(off);
        }
        // Hash collision — fall back to linear scan.
        let count = wal.entry_count as usize;
        for i in 0..count {
            if wal.targets[i] == target_sector {
                return Some(i);
            }
        }
    }
    None
}

/// Linear-scan lookup (for comparison / fallback).
///
/// Scans all WAL entries to find one matching `target_sector`.
pub fn wal_lookup_linear(wal: &WalHeader, target_sector: u32) -> Option<usize> {
    let count = wal.entry_count as usize;
    for i in 0..count {
        if wal.targets[i] == target_sector {
            return Some(i);
        }
    }
    None
}

/// Commit the WAL transaction to disk.
///
/// Phase 1: Write payload sectors (WAL sectors 2-5).
/// Phase 2: Write WAL header with committed=1 (commit point).
/// Phase 3: Apply payload to actual target sectors.
/// Phase 4: Write WAL header with committed=2 (applied).
pub fn commit(
    blk: &mut VirtioBlk,
    wal: &mut WalHeader,
    wal_buf: &[[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
) -> Result<(), &'static str> {
    let count = wal.entry_count as usize;
    if count == 0 {
        return Ok(());
    }

    // Phase 1: Write WAL payload sectors.
    for i in 0..count {
        write_sector_from(blk, SECTOR_WAL_PAYLOAD + i as u32, &wal_buf[i])?;
    }

    // Phase 2: Write WAL header with committed=1.
    wal.committed = 1;
    write_wal_header(blk, wal)?;

    // Phase 3: Apply — write payload to target sectors.
    for i in 0..count {
        write_sector_from(blk, wal.targets[i], &wal_buf[i])?;
    }

    // Phase 4: Mark WAL as applied.
    wal.committed = 2;
    write_wal_header(blk, wal)?;

    Ok(())
}

/// Replay the WAL if a committed-but-not-applied transaction exists.
/// Returns true if a replay was performed.
///
/// After reading the WAL from disk, the hash index is rebuilt so that
/// subsequent `wal_lookup` calls work correctly.
pub fn replay(
    blk: &mut VirtioBlk,
    wal: &mut WalHeader,
    wal_buf: &mut [[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
    index: &mut WalIndex,
) -> Result<bool, &'static str> {
    // Read WAL header from disk.
    read_sector_into(blk, SECTOR_WAL_HEADER, unsafe {
        &mut *(wal as *mut WalHeader as *mut [u8; SECTOR_SIZE])
    })?;

    if wal.magic != WAL_MAGIC {
        // No valid WAL — initialize it.
        *wal = WalHeader::zeroed();
        wal.magic = WAL_MAGIC;
        index.clear();
        return Ok(false);
    }

    match wal.committed {
        0 => {
            // Incomplete — discard.
            index.clear();
            Ok(false)
        }
        1 => {
            // Committed but not applied — replay.
            let count = wal.entry_count as usize;
            // Read WAL payload sectors.
            for i in 0..count {
                read_sector_into(blk, SECTOR_WAL_PAYLOAD + i as u32, &mut wal_buf[i])?;
            }
            // Apply to target sectors.
            for i in 0..count {
                write_sector_from(blk, wal.targets[i], &wal_buf[i])?;
            }
            // Mark applied.
            wal.committed = 2;
            write_wal_header(blk, wal)?;
            // Rebuild index from replayed entries.
            index.rebuild(wal);
            Ok(true)
        }
        _ => {
            // Already applied (2) or unknown — nothing to do.
            index.rebuild(wal);
            Ok(false)
        }
    }
}

/// Write a 512-byte buffer to a sector via the blk data buffer.
fn write_sector_from(
    blk: &mut VirtioBlk,
    sector: u32,
    data: &[u8; SECTOR_SIZE],
) -> Result<(), &'static str> {
    let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), SECTOR_SIZE) };
    dst.copy_from_slice(data);
    blk.write_sector(sector as u64)
}

/// Read a sector into a 512-byte buffer via the blk data buffer.
fn read_sector_into(
    blk: &mut VirtioBlk,
    sector: u32,
    buf: &mut [u8; SECTOR_SIZE],
) -> Result<(), &'static str> {
    blk.read_sector(sector as u64)?;
    let src = unsafe { core::slice::from_raw_parts(blk.data_ptr(), SECTOR_SIZE) };
    buf.copy_from_slice(src);
    Ok(())
}

/// Serialize the WAL header struct and write to disk.
fn write_wal_header(
    blk: &mut VirtioBlk,
    wal: &WalHeader,
) -> Result<(), &'static str> {
    // Copy struct bytes into blk data buffer, then write.
    let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), SECTOR_SIZE) };
    unsafe {
        core::ptr::copy_nonoverlapping(
            wal as *const WalHeader as *const u8,
            dst.as_mut_ptr(),
            SECTOR_SIZE,
        );
    }
    blk.write_sector(SECTOR_WAL_HEADER as u64)
}

// ===========================================================================
// Tests — pure data-structure tests, no I/O required.
// ===========================================================================

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    // -----------------------------------------------------------------------
    // FNV-1a tests
    // -----------------------------------------------------------------------

    #[test]
    fn fnv1a_empty() {
        // FNV-1a of empty input is the offset basis.
        assert_eq!(fnv1a(&[]), 0xcbf29ce484222325);
    }

    #[test]
    fn fnv1a_deterministic() {
        let a = fnv1a(b"sector42");
        let b = fnv1a(b"sector42");
        assert_eq!(a, b);
    }

    #[test]
    fn fnv1a_different_inputs() {
        let a = fnv1a(b"sector0");
        let b = fnv1a(b"sector1");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_sector_deterministic() {
        assert_eq!(hash_sector(100), hash_sector(100));
        assert_ne!(hash_sector(100), hash_sector(200));
    }

    // -----------------------------------------------------------------------
    // WalIndex basic operations
    // -----------------------------------------------------------------------

    #[test]
    fn index_new_is_empty() {
        let idx = WalIndex::new();
        assert_eq!(idx.len, 0);
        assert!(idx.lookup(hash_sector(42)).is_none());
    }

    #[test]
    fn index_insert_and_lookup() {
        let mut idx = WalIndex::new();
        let h = hash_sector(100);
        idx.insert(h, 0).unwrap();
        assert_eq!(idx.lookup(h), Some(0));
        assert_eq!(idx.len, 1);
    }

    #[test]
    fn index_insert_multiple() {
        let mut idx = WalIndex::new();
        for sector in 0..4u32 {
            let h = hash_sector(sector);
            idx.insert(h, sector).unwrap();
        }
        assert_eq!(idx.len, 4);
        for sector in 0..4u32 {
            assert_eq!(idx.lookup(hash_sector(sector)), Some(sector));
        }
    }

    #[test]
    fn index_update_existing_key() {
        let mut idx = WalIndex::new();
        let h = hash_sector(42);
        idx.insert(h, 0).unwrap();
        assert_eq!(idx.lookup(h), Some(0));

        // Update: same key, new offset.
        idx.insert(h, 7).unwrap();
        assert_eq!(idx.lookup(h), Some(7));
        assert_eq!(idx.len, 1); // Length should NOT increase on update.
    }

    #[test]
    fn index_clear() {
        let mut idx = WalIndex::new();
        for sector in 0..10u32 {
            idx.insert(hash_sector(sector), sector).unwrap();
        }
        assert_eq!(idx.len, 10);

        idx.clear();
        assert_eq!(idx.len, 0);
        for sector in 0..10u32 {
            assert!(idx.lookup(hash_sector(sector)).is_none());
        }
    }

    #[test]
    fn index_remove_existing() {
        let mut idx = WalIndex::new();
        let h = hash_sector(42);
        idx.insert(h, 5).unwrap();
        assert_eq!(idx.len, 1);

        assert!(idx.remove(h));
        assert_eq!(idx.len, 0);
        assert!(idx.lookup(h).is_none());
    }

    #[test]
    fn index_remove_nonexistent() {
        let mut idx = WalIndex::new();
        assert!(!idx.remove(hash_sector(999)));
    }

    #[test]
    fn index_remove_preserves_other_entries() {
        let mut idx = WalIndex::new();
        for sector in 0..5u32 {
            idx.insert(hash_sector(sector), sector).unwrap();
        }

        // Remove sector 2.
        idx.remove(hash_sector(2));
        assert_eq!(idx.len, 4);
        assert!(idx.lookup(hash_sector(2)).is_none());

        // Others still present.
        for sector in [0u32, 1, 3, 4] {
            assert_eq!(idx.lookup(hash_sector(sector)), Some(sector));
        }
    }

    // -----------------------------------------------------------------------
    // Hash collision handling (linear probing)
    // -----------------------------------------------------------------------

    #[test]
    fn index_handles_collisions() {
        // Insert many entries to force linear probing collisions.
        let mut idx = WalIndex::new();
        for sector in 0..200u32 {
            let h = hash_sector(sector);
            idx.insert(h, sector).unwrap();
        }
        assert_eq!(idx.len, 200);

        // All entries must be retrievable.
        for sector in 0..200u32 {
            assert_eq!(
                idx.lookup(hash_sector(sector)),
                Some(sector),
                "lookup failed for sector {}",
                sector
            );
        }
    }

    #[test]
    fn index_remove_with_collisions() {
        // Fill to ~75% capacity, then remove half, then verify remaining.
        let mut idx = WalIndex::new();
        let n = 192u32; // 75% of 256
        for sector in 0..n {
            idx.insert(hash_sector(sector), sector).unwrap();
        }

        // Remove even-numbered sectors.
        for sector in (0..n).step_by(2) {
            assert!(idx.remove(hash_sector(sector)));
        }
        assert_eq!(idx.len, (n / 2) as usize);

        // Odd-numbered sectors must still be found.
        for sector in (1..n).step_by(2) {
            assert_eq!(
                idx.lookup(hash_sector(sector)),
                Some(sector),
                "lookup failed for odd sector {} after removing evens",
                sector
            );
        }
        // Even-numbered sectors must be gone.
        for sector in (0..n).step_by(2) {
            assert!(
                idx.lookup(hash_sector(sector)).is_none(),
                "sector {} should have been removed",
                sector
            );
        }
    }

    // -----------------------------------------------------------------------
    // Index rebuild from WAL header
    // -----------------------------------------------------------------------

    #[test]
    fn index_rebuild_matches_fresh_index() {
        let mut wal = WalHeader::zeroed();
        wal.magic = WAL_MAGIC;
        wal.entry_count = 3;
        wal.targets[0] = 10;
        wal.targets[1] = 20;
        wal.targets[2] = 30;

        // Build index manually.
        let mut manual = WalIndex::new();
        manual.insert(hash_sector(10), 0).unwrap();
        manual.insert(hash_sector(20), 1).unwrap();
        manual.insert(hash_sector(30), 2).unwrap();

        // Rebuild index from WAL header.
        let mut rebuilt = WalIndex::new();
        rebuilt.rebuild(&wal);

        assert_eq!(rebuilt.len, manual.len);
        for sector in [10u32, 20, 30] {
            assert_eq!(
                rebuilt.lookup(hash_sector(sector)),
                manual.lookup(hash_sector(sector)),
                "mismatch for sector {}",
                sector
            );
        }
    }

    #[test]
    fn index_rebuild_empty_wal() {
        let wal = WalHeader::zeroed();
        let mut idx = WalIndex::new();
        // Pre-populate.
        idx.insert(hash_sector(99), 0).unwrap();
        assert_eq!(idx.len, 1);

        idx.rebuild(&wal);
        assert_eq!(idx.len, 0);
    }

    // -----------------------------------------------------------------------
    // Indexed lookup produces same results as linear scan
    // -----------------------------------------------------------------------

    #[test]
    fn indexed_lookup_matches_linear_scan() {
        let mut wal = WalHeader::zeroed();
        wal.magic = WAL_MAGIC;
        let mut index = WalIndex::new();

        // Stage 4 entries.
        wal.entry_count = 4;
        wal.targets[0] = 134;  // SECTOR_DIR
        wal.targets[1] = 0;    // SECTOR_SUPERBLOCK
        wal.targets[2] = 6;    // SECTOR_BITMAP
        wal.targets[3] = 2182; // SECTOR_REFCOUNT

        index.rebuild(&wal);

        // Compare indexed vs linear for all targets.
        for &sector in &[134u32, 0, 6, 2182] {
            let linear = wal_lookup_linear(&wal, sector);
            let indexed = wal_lookup(&wal, &index, sector);
            assert_eq!(
                indexed, linear,
                "mismatch for sector {}: indexed={:?} linear={:?}",
                sector, indexed, linear
            );
        }

        // Non-existent sectors.
        for &sector in &[999u32, 135, 7, 1] {
            let linear = wal_lookup_linear(&wal, sector);
            let indexed = wal_lookup(&wal, &index, sector);
            assert_eq!(indexed, linear);
        }
    }

    // -----------------------------------------------------------------------
    // Integration: begin + stage flow
    // -----------------------------------------------------------------------

    #[test]
    fn begin_clears_index() {
        let mut wal = WalHeader::zeroed();
        wal.magic = WAL_MAGIC;
        let mut index = WalIndex::new();

        // Insert something.
        index.insert(hash_sector(42), 0).unwrap();
        assert_eq!(index.len, 1);

        begin(&mut wal, &mut index);
        assert_eq!(index.len, 0);
        assert_eq!(wal.entry_count, 0);
    }

    #[test]
    fn stage_updates_index() {
        let mut wal = WalHeader::zeroed();
        wal.magic = WAL_MAGIC;
        let mut wal_buf = [[0u8; SECTOR_SIZE]; WAL_MAX_ENTRIES];
        let mut index = WalIndex::new();

        begin(&mut wal, &mut index);

        let data = [0xABu8; SECTOR_SIZE];
        stage(&mut wal, &mut wal_buf, &mut index, 134, &data).unwrap();
        stage(&mut wal, &mut wal_buf, &mut index, 0, &data).unwrap();

        assert_eq!(index.len, 2);
        assert_eq!(wal_lookup(&wal, &index, 134), Some(0));
        assert_eq!(wal_lookup(&wal, &index, 0), Some(1));
        assert!(wal_lookup(&wal, &index, 999).is_none());
    }

    // -----------------------------------------------------------------------
    // Index survives WAL compaction (clear + rebuild cycle)
    // -----------------------------------------------------------------------

    #[test]
    fn index_survives_compaction_cycle() {
        let mut wal = WalHeader::zeroed();
        wal.magic = WAL_MAGIC;

        // Simulate a completed transaction.
        wal.entry_count = 3;
        wal.targets[0] = 10;
        wal.targets[1] = 20;
        wal.targets[2] = 30;

        let mut index = WalIndex::new();
        index.rebuild(&wal);
        assert_eq!(index.len, 3);

        // "Compact" — clear and rebuild (e.g., after WAL finalize).
        index.clear();
        assert_eq!(index.len, 0);

        // Rebuild from same WAL state.
        index.rebuild(&wal);
        assert_eq!(index.len, 3);
        assert_eq!(index.lookup(hash_sector(10)), Some(0));
        assert_eq!(index.lookup(hash_sector(20)), Some(1));
        assert_eq!(index.lookup(hash_sector(30)), Some(2));
    }

    // -----------------------------------------------------------------------
    // Stress: fill to near capacity
    // -----------------------------------------------------------------------

    #[test]
    fn index_fill_to_capacity() {
        let mut idx = WalIndex::new();
        // Fill all 256 slots.
        for i in 0..WAL_INDEX_CAPACITY as u32 {
            // Use different sector values that should spread across buckets.
            let h = hash_sector(i * 1000 + 7);
            idx.insert(h, i).unwrap();
        }
        assert_eq!(idx.len, WAL_INDEX_CAPACITY);

        // Verify all entries.
        for i in 0..WAL_INDEX_CAPACITY as u32 {
            let h = hash_sector(i * 1000 + 7);
            assert_eq!(idx.lookup(h), Some(i));
        }

        // One more should fail.
        let h = hash_sector(999999);
        assert!(idx.insert(h, 0).is_err());
    }
}
