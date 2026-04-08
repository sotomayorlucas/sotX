//! Page cache / buffer cache — caches disk sectors in memory.
//!
//! A simple fixed-size cache that stores recently accessed disk sectors.
//! Uses LRU eviction when full. Dirty entries can be flushed via a
//! caller-provided callback.

use crate::kdebug;
use crate::sync::ticket::TicketMutex;

/// Sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

/// Maximum number of cached sectors.
const CACHE_ENTRIES: usize = 64;

/// A single cache entry: one disk sector.
#[derive(Clone, Copy)]
struct CacheEntry {
    /// Device identifier (caller-defined).
    device_id: u32,
    /// Sector number on the device.
    sector: u64,
    /// Cached sector data.
    data: [u8; SECTOR_SIZE],
    /// Whether this entry has been modified since last flush.
    dirty: bool,
    /// Tick count at last access (for LRU eviction).
    lru_tick: u64,
    /// Whether this slot is occupied.
    valid: bool,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self {
            device_id: 0,
            sector: 0,
            data: [0u8; SECTOR_SIZE],
            dirty: false,
            lru_tick: 0,
            valid: false,
        }
    }
}

/// The page cache: a fixed-size array of cached sectors.
struct PageCacheInner {
    entries: [CacheEntry; CACHE_ENTRIES],
    /// Monotonic tick counter for LRU ordering.
    tick: u64,
}

impl PageCacheInner {
    const fn new() -> Self {
        Self {
            entries: [CacheEntry::empty(); CACHE_ENTRIES],
            tick: 0,
        }
    }

    fn advance_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Find an entry matching (device_id, sector). Returns slot index.
    fn find(&self, device_id: u32, sector: u64) -> Option<usize> {
        for i in 0..CACHE_ENTRIES {
            if self.entries[i].valid
                && self.entries[i].device_id == device_id
                && self.entries[i].sector == sector
            {
                return Some(i);
            }
        }
        None
    }

    /// Find the LRU slot: the valid entry with the lowest lru_tick,
    /// or the first invalid (empty) slot.
    fn find_evict_slot(&self) -> usize {
        let mut best = 0;
        let mut best_tick = u64::MAX;
        for i in 0..CACHE_ENTRIES {
            if !self.entries[i].valid {
                return i; // Empty slot — no eviction needed.
            }
            if self.entries[i].lru_tick < best_tick {
                best_tick = self.entries[i].lru_tick;
                best = i;
            }
        }
        best
    }
}

static PAGE_CACHE: TicketMutex<PageCacheInner> = TicketMutex::new(PageCacheInner::new());

/// Look up a cached sector. Returns a copy of the data if found.
///
/// Updates the LRU tick on hit.
pub fn lookup(device_id: u32, sector: u64) -> Option<[u8; SECTOR_SIZE]> {
    let mut cache = PAGE_CACHE.lock();
    if let Some(idx) = cache.find(device_id, sector) {
        let tick = cache.advance_tick();
        cache.entries[idx].lru_tick = tick;
        let data = cache.entries[idx].data;
        return Some(data);
    }
    None
}

/// Insert a sector into the cache (or update if already present).
///
/// If the cache is full, evicts the LRU entry. If the evicted entry is
/// dirty, it is silently dropped (caller should call `flush_dirty` first
/// if durability matters).
pub fn insert(device_id: u32, sector: u64, data: &[u8; SECTOR_SIZE]) {
    let mut cache = PAGE_CACHE.lock();
    let tick = cache.advance_tick();

    // Check if already cached — just update.
    if let Some(idx) = cache.find(device_id, sector) {
        cache.entries[idx].data = *data;
        cache.entries[idx].lru_tick = tick;
        // Don't clear dirty flag — the insert is fresh data, mark clean.
        cache.entries[idx].dirty = false;
        return;
    }

    // Find a slot (empty or LRU victim).
    let slot = cache.find_evict_slot();
    if cache.entries[slot].valid && cache.entries[slot].dirty {
        kdebug!(
            "page_cache: evicting dirty entry dev={} sector={}",
            cache.entries[slot].device_id,
            cache.entries[slot].sector
        );
    }

    cache.entries[slot] = CacheEntry {
        device_id,
        sector,
        data: *data,
        dirty: false,
        lru_tick: tick,
        valid: true,
    };
}

/// Mark a cached sector as dirty (modified in cache, needs writeback).
///
/// Returns `true` if the entry was found and marked, `false` otherwise.
pub fn mark_dirty(device_id: u32, sector: u64) -> bool {
    let mut cache = PAGE_CACHE.lock();
    if let Some(idx) = cache.find(device_id, sector) {
        cache.entries[idx].dirty = true;
        return true;
    }
    false
}

/// Write a sector into the cache and immediately mark it dirty.
///
/// Combines `insert` + `mark_dirty` for write-back semantics.
pub fn write(device_id: u32, sector: u64, data: &[u8; SECTOR_SIZE]) {
    let mut cache = PAGE_CACHE.lock();
    let tick = cache.advance_tick();

    if let Some(idx) = cache.find(device_id, sector) {
        cache.entries[idx].data = *data;
        cache.entries[idx].lru_tick = tick;
        cache.entries[idx].dirty = true;
        return;
    }

    let slot = cache.find_evict_slot();
    cache.entries[slot] = CacheEntry {
        device_id,
        sector,
        data: *data,
        dirty: true,
        lru_tick: tick,
        valid: true,
    };
}

/// Flush all dirty entries by calling `callback(device_id, sector, &data)`
/// for each dirty entry. The callback should write the data back to disk.
///
/// After a successful callback, the entry is marked clean.
/// The callback signature: `fn(device_id: u32, sector: u64, data: &[u8; SECTOR_SIZE]) -> bool`
/// Returns `true` on success (entry marked clean), `false` on failure (stays dirty).
pub fn flush_dirty<F>(mut callback: F)
where
    F: FnMut(u32, u64, &[u8; SECTOR_SIZE]) -> bool,
{
    let mut cache = PAGE_CACHE.lock();
    for i in 0..CACHE_ENTRIES {
        if cache.entries[i].valid && cache.entries[i].dirty {
            let dev = cache.entries[i].device_id;
            let sec = cache.entries[i].sector;
            let data = cache.entries[i].data;
            if callback(dev, sec, &data) {
                cache.entries[i].dirty = false;
            }
        }
    }
}

/// Invalidate all entries for a given device (e.g., on device removal).
pub fn invalidate_device(device_id: u32) {
    let mut cache = PAGE_CACHE.lock();
    for i in 0..CACHE_ENTRIES {
        if cache.entries[i].valid && cache.entries[i].device_id == device_id {
            cache.entries[i].valid = false;
        }
    }
}

/// Return the number of valid (occupied) entries in the cache.
pub fn entry_count() -> usize {
    let cache = PAGE_CACHE.lock();
    cache.entries.iter().filter(|e| e.valid).count()
}

/// Return the number of dirty entries in the cache.
pub fn dirty_count() -> usize {
    let cache = PAGE_CACHE.lock();
    cache.entries.iter().filter(|e| e.valid && e.dirty).count()
}
