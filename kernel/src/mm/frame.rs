//! Bitmap-based physical frame allocator.
//!
//! Each bit in the bitmap represents one 4 KiB physical frame.
//! Bit = 0 → free, Bit = 1 → allocated.
//!
//! The bitmap itself is placed in a usable memory region provided
//! by the bootloader. No heap allocation required.

use crate::kdebug;
use limine::memory_map::EntryType;
use limine::response::MemoryMapResponse;
use spin::Mutex;

pub const FRAME_SIZE: usize = 4096;

/// A physical memory frame (4 KiB aligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysFrame {
    base: u64,
}

impl PhysFrame {
    /// Create a frame from a physical address (must be aligned).
    pub fn from_addr(addr: u64) -> Self {
        assert!(addr % FRAME_SIZE as u64 == 0, "frame address not aligned");
        Self { base: addr }
    }

    /// Physical base address of this frame.
    pub fn addr(&self) -> u64 {
        self.base
    }

    /// Frame index (base / FRAME_SIZE).
    pub fn index(&self) -> usize {
        (self.base / FRAME_SIZE as u64) as usize
    }
}

/// The global frame allocator, protected by a spinlock.
static ALLOCATOR: Mutex<Option<BitmapAllocator>> = Mutex::new(None);

struct BitmapAllocator {
    /// Pointer to the bitmap in the HHDM region.
    bitmap: *mut u8,
    /// Number of bytes in the bitmap.
    #[allow(dead_code)]
    bitmap_len: usize,
    /// Total number of physical frames tracked.
    total_frames: usize,
    /// Number of currently free frames.
    free_frames: usize,
    /// Hint: index of the next potentially free frame.
    search_hint: usize,
}

// SAFETY: The bitmap pointer is only accessed under the ALLOCATOR spinlock.
unsafe impl Send for BitmapAllocator {}

impl BitmapAllocator {
    fn is_set(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        // SAFETY: callers (allocate, free, allocate_contiguous) only pass `idx`
        // values in `0..self.total_frames`, so `byte = idx/8 < bitmap_len`. The
        // bitmap pointer was allocated by `init()` to cover `bitmap_len` bytes
        // and is held under the `ALLOCATOR` Mutex (Send unsafe impl above).
        unsafe { (*self.bitmap.add(byte) >> bit) & 1 == 1 }
    }

    fn set(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        // SAFETY: same as `is_set`. We hold `&mut self` so the ALLOCATOR Mutex
        // is locked exclusively and no concurrent reader/writer exists. `byte`
        // is bounds-checked by the caller's `idx < total_frames` invariant.
        unsafe {
            *self.bitmap.add(byte) |= 1 << bit;
        }
    }

    fn clear(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        // SAFETY: same as `set` — exclusive `&mut self` access via the
        // ALLOCATOR Mutex; `byte` is in range because `idx < total_frames`.
        unsafe {
            *self.bitmap.add(byte) &= !(1 << bit);
        }
    }

    fn allocate(&mut self) -> Option<PhysFrame> {
        // Word-level scan: check 64 bits at a time, then find free bit within word.
        let total = self.total_frames;
        let hint = self.search_hint;
        // First pass: hint..total, second pass: 0..hint
        for pass in 0..2 {
            let (start, end) = if pass == 0 { (hint, total) } else { (0, hint) };
            let mut idx = start;
            while idx < end {
                let byte = idx / 8;
                // Fast skip: if entire byte is full (0xFF), skip 8 frames
                // SAFETY: `idx < end <= total_frames`, so `byte < bitmap_len`.
                // `&mut self` proves the ALLOCATOR mutex is locked.
                let b = unsafe { *self.bitmap.add(byte) };
                if b == 0xFF {
                    idx = (byte + 1) * 8;
                    continue;
                }
                // Found a byte with a free bit — scan within it
                let bit = idx % 8;
                for b_off in bit..8 {
                    let frame_idx = byte * 8 + b_off;
                    if frame_idx >= end {
                        break;
                    }
                    if (b >> b_off) & 1 == 0 {
                        self.set(frame_idx);
                        self.free_frames -= 1;
                        self.search_hint = frame_idx + 1;
                        return Some(PhysFrame::from_addr(frame_idx as u64 * FRAME_SIZE as u64));
                    }
                }
                idx = (byte + 1) * 8;
            }
        }
        None
    }

    fn allocate_contiguous(&mut self, count: usize) -> Option<PhysFrame> {
        if count == 0 {
            return None;
        }
        let total = self.total_frames;
        if count > total {
            return None;
        }
        let limit = total - count + 1;
        let hint = self.search_hint.min(limit);
        // Two passes: hint..limit, then 0..hint
        for pass in 0..2 {
            let (start, end) = if pass == 0 { (hint, limit) } else { (0, hint) };
            let mut idx = start;
            while idx < end {
                // Fast skip full bytes
                let byte = idx / 8;
                // SAFETY: `idx < end <= limit <= total_frames - count + 1`, so
                // `byte < bitmap_len`. Mutex held via `&mut self`.
                let b = unsafe { *self.bitmap.add(byte) };
                if b == 0xFF && idx % 8 == 0 {
                    idx += 8;
                    continue;
                }
                if self.is_set(idx) {
                    idx += 1;
                    continue;
                }
                // Found a free frame — check if count contiguous frames are free
                let mut run = 1;
                while run < count && !self.is_set(idx + run) {
                    run += 1;
                }
                if run >= count {
                    for j in 0..count {
                        self.set(idx + j);
                    }
                    self.free_frames -= count;
                    self.search_hint = idx + count;
                    return Some(PhysFrame::from_addr(idx as u64 * FRAME_SIZE as u64));
                }
                idx += run + 1;
            }
        }
        None
    }

    fn free(&mut self, frame: PhysFrame) {
        let idx = frame.index();
        assert!(self.is_set(idx), "double free of frame {:#x}", frame.addr());
        self.clear(idx);
        self.free_frames += 1;
        if idx < self.search_hint {
            self.search_hint = idx;
        }
    }
}

/// Initialize the frame allocator from the bootloader's memory map.
pub fn init(memory_map: &MemoryMapResponse, hhdm_offset: u64) {
    let entries = memory_map.entries();

    // Find the highest USABLE physical address to determine bitmap size.
    // Only track usable RAM regions — MMIO regions above physical RAM
    // don't need frame allocator tracking (avoids a 32 MB bitmap for 1 TiB).
    let max_addr = entries
        .iter()
        .filter(|e| e.entry_type == EntryType::USABLE)
        .map(|e| e.base + e.length)
        .max()
        .unwrap_or(0);
    let total_frames = (max_addr as usize + FRAME_SIZE - 1) / FRAME_SIZE;
    let bitmap_bytes = (total_frames + 7) / 8;

    // Find a usable region large enough for the bitmap.
    let bitmap_phys = entries
        .iter()
        .filter(|e| e.entry_type == EntryType::USABLE && e.length as usize >= bitmap_bytes)
        .map(|e| e.base)
        .next()
        .expect("no usable region large enough for frame bitmap");

    let bitmap_ptr = (bitmap_phys + hhdm_offset) as *mut u8;

    // Mark all frames as allocated initially.
    // SAFETY: `bitmap_ptr = bitmap_phys + hhdm_offset`, where `bitmap_phys` was
    // selected from the memmap as a USABLE region of length >= `bitmap_bytes`,
    // and the HHDM mapping makes that physical range writable. No other code
    // has touched this region yet (we are early in `init`), so the write of
    // `bitmap_bytes` 0xFF bytes is exclusive and within bounds.
    unsafe {
        core::ptr::write_bytes(bitmap_ptr, 0xFF, bitmap_bytes);
    }

    let mut free_count = 0usize;

    // Build the allocator so we can mark usable regions.
    let mut alloc = BitmapAllocator {
        bitmap: bitmap_ptr,
        bitmap_len: bitmap_bytes,
        total_frames,
        free_frames: 0,
        search_hint: 0,
    };

    // Free all frames in usable regions (except the bitmap itself).
    for entry in entries.iter() {
        if entry.entry_type != EntryType::USABLE {
            continue;
        }

        let start_frame = ((entry.base + FRAME_SIZE as u64 - 1) / FRAME_SIZE as u64) as usize;
        let end_frame = ((entry.base + entry.length) / FRAME_SIZE as u64) as usize;

        for idx in start_frame..end_frame {
            let frame_addr = idx as u64 * FRAME_SIZE as u64;
            // Don't free the bitmap's own memory.
            if frame_addr >= bitmap_phys && frame_addr < bitmap_phys + bitmap_bytes as u64 {
                continue;
            }
            alloc.clear(idx);
            free_count += 1;
        }
    }

    alloc.free_frames = free_count;

    kdebug!(
        "  frames: {} total, {} free ({} MiB usable)",
        total_frames,
        free_count,
        free_count * FRAME_SIZE / (1024 * 1024)
    );

    *ALLOCATOR.lock() = Some(alloc);
}

/// Allocate a single physical frame.
pub fn alloc_frame() -> Option<PhysFrame> {
    ALLOCATOR.lock().as_mut()?.allocate()
}

/// Allocate `count` physically contiguous frames.
/// Returns the base frame (lowest address). All frames are consecutive.
pub fn alloc_contiguous(count: usize) -> Option<PhysFrame> {
    ALLOCATOR.lock().as_mut()?.allocate_contiguous(count)
}

/// Free a previously allocated physical frame.
pub fn free_frame(frame: PhysFrame) {
    if let Some(alloc) = ALLOCATOR.lock().as_mut() {
        alloc.free(frame);
    }
}

/// Return the number of currently free frames.
pub fn free_count() -> usize {
    ALLOCATOR
        .lock()
        .as_ref()
        .map(|a| a.free_frames)
        .unwrap_or(0)
}
