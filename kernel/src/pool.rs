//! Generic slot allocator backed by `Vec` with ABA-safe handles.
//!
//! `Pool<T>` provides O(1) alloc/free via a free list and unlimited growth.
//! Slots are `Option<T>` — `None` means free, `Some` means occupied.
//!
//! Each slot has a generation counter. `PoolHandle` encodes both the slot
//! index and generation, so stale handles (pointing at recycled slots)
//! are detected and rejected.
//!
//! Handle encoding:
//!   bits [19:0]  = slot index (max 1,048,575 slots)
//!   bits [31:20] = generation  (wraps at 4096)

use alloc::vec::Vec;

/// Packed handle: generation (12 bits) | index (20 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolHandle(u32);

const INDEX_BITS: u32 = 20;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const GEN_SHIFT: u32 = INDEX_BITS;
const GEN_MASK: u32 = 0xFFF; // 12 bits, wraps at 4096

impl PoolHandle {
    /// Construct a handle from raw u32 (e.g. from userspace cap ID).
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw u32 representation.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Extract the slot index.
    pub fn index(self) -> usize {
        (self.0 & INDEX_MASK) as usize
    }

    /// Extract the generation.
    fn gen(self) -> u16 {
        ((self.0 >> GEN_SHIFT) & GEN_MASK) as u16
    }

    /// Pack index + generation into a handle.
    fn pack(index: usize, gen: u16) -> Self {
        Self(((gen as u32 & GEN_MASK) << GEN_SHIFT) | (index as u32 & INDEX_MASK))
    }
}

pub struct Pool<T> {
    slots: Vec<Option<T>>,
    generations: Vec<u16>,
    free_list: Vec<usize>,
}

impl<T> Pool<T> {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            generations: Vec::new(),
            free_list: Vec::new(),
        }
    }

    /// Insert a value, returning a generation-checked handle.
    pub fn alloc(&mut self, val: T) -> PoolHandle {
        if let Some(idx) = self.free_list.pop() {
            self.slots[idx] = Some(val);
            PoolHandle::pack(idx, self.generations[idx])
        } else {
            let idx = self.slots.len();
            self.slots.push(Some(val));
            self.generations.push(0);
            PoolHandle::pack(idx, 0)
        }
    }

    /// Remove and return the value at `handle`, recycling the slot.
    /// Returns `None` if the handle is stale or already freed.
    pub fn free(&mut self, handle: PoolHandle) -> Option<T> {
        let idx = handle.index();
        if idx >= self.slots.len() || self.generations[idx] != handle.gen() {
            return None;
        }
        if let Some(val) = self.slots[idx].take() {
            // Bump generation for next occupant.
            self.generations[idx] = self.generations[idx].wrapping_add(1) & (GEN_MASK as u16);
            self.free_list.push(idx);
            return Some(val);
        }
        None
    }

    /// Look up by generation-checked handle.
    pub fn get(&self, handle: PoolHandle) -> Option<&T> {
        let idx = handle.index();
        if idx >= self.slots.len() || self.generations[idx] != handle.gen() {
            return None;
        }
        self.slots[idx].as_ref()
    }

    /// Mutable look up by generation-checked handle.
    pub fn get_mut(&mut self, handle: PoolHandle) -> Option<&mut T> {
        let idx = handle.index();
        if idx >= self.slots.len() || self.generations[idx] != handle.gen() {
            return None;
        }
        self.slots[idx].as_mut()
    }

    // --- Raw index access (for scheduler, which stores indices in percpu) ---

    /// Look up by raw slot index (bypasses generation check).
    /// Only safe when the caller guarantees the slot is live.
    pub fn get_by_index(&self, idx: u32) -> Option<&T> {
        self.slots.get(idx as usize)?.as_ref()
    }

    /// Mutable look up by raw slot index (bypasses generation check).
    pub fn get_mut_by_index(&mut self, idx: u32) -> Option<&mut T> {
        self.slots.get_mut(idx as usize)?.as_mut()
    }

    /// Free by raw slot index. Returns the value and bumps generation.
    pub fn free_by_index(&mut self, idx: u32) -> Option<T> {
        let idx = idx as usize;
        if idx >= self.slots.len() {
            return None;
        }
        if let Some(val) = self.slots[idx].take() {
            self.generations[idx] = self.generations[idx].wrapping_add(1) & (GEN_MASK as u16);
            self.free_list.push(idx);
            return Some(val);
        }
        None
    }

    /// Iterate over occupied slots as `(PoolHandle, &T)`.
    pub fn iter(&self) -> impl Iterator<Item = (PoolHandle, &T)> {
        self.slots.iter().enumerate().filter_map(|(i, slot)| {
            slot.as_ref()
                .map(|val| (PoolHandle::pack(i, self.generations[i]), val))
        })
    }
}
