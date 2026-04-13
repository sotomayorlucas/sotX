//! # Arena Allocator — fixed-capacity, heap-backed, no_std compatible
//!
//! Provides `Arena<T, CAPACITY>`: a dense storage pool with O(1) alloc,
//! dealloc, and lookup. Uses a free-list for slot reuse after deletions
//! (unlink, rmdir) so the arena never fragments.
//!
//! Designed for the sotFS kernel service where heap allocation is
//! unavailable. Tests use smaller CAPACITY (1024), kernel uses 65536+.
//! The backing arrays are heap-allocated (`Box<[T]>`) to avoid stack
//! overflow at large capacities (65K+). Requires `alloc` but not `std`.
//!
//! Default CAPACITY: 65536 for kernel node pools, 131072 for edges.
//! Tests use smaller capacities (1024).

use core::fmt;
use core::mem::MaybeUninit;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Slot index into an Arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArenaId(pub u32);

impl ArenaId {
    /// Convert to usize for array indexing.
    #[inline(always)]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Metadata for each arena slot.
#[derive(Clone, Copy)]
enum SlotState {
    /// Slot is vacant (not occupied).
    Vacant,
    /// Slot is occupied with a live value.
    Occupied,
}

/// Fixed-capacity arena with amortized O(1) push and O(1) removal.
///
/// Uses a heap-allocated backing array of `CAPACITY` elements stored as
/// `MaybeUninit<T>`. A free-list enables O(1) deallocation and slot reuse.
/// When full, `alloc()` returns `None`.
///
/// For the kernel service, `CAPACITY` is set high (65536).
/// For tests, `CAPACITY` can be smaller (1024).
pub struct Arena<T, const CAPACITY: usize> {
    /// Backing storage (heap-allocated). Only slots in `Occupied` state
    /// contain initialized values.
    data: Box<[MaybeUninit<T>]>,
    /// Per-slot state tracking (heap-allocated).
    state: Box<[SlotState]>,
    /// Number of currently occupied slots.
    len: usize,
    /// Free list: stack of recently-freed slot indices for O(1) reuse.
    free_list: Box<[u32]>,
    /// Number of entries in the free list.
    free_count: usize,
    /// Next slot to bump-allocate from (when free list is empty).
    next_bump: usize,
}

/// Create a boxed slice of MaybeUninit<T> with the given length.
fn boxed_uninit_slice<T>(len: usize) -> Box<[MaybeUninit<T>]> {
    let mut v = Vec::with_capacity(len);
    // SAFETY: MaybeUninit<T> does not require initialization.
    unsafe { v.set_len(len) };
    v.into_boxed_slice()
}

impl<T, const CAPACITY: usize> Arena<T, CAPACITY> {
    // SAFETY INVARIANT: `data[i]` is initialized iff `state[i] == Occupied`.

    /// Create a new empty arena.
    ///
    /// All slots start vacant. The free list is empty; allocation proceeds
    /// via bump pointer until the first dealloc.
    pub fn new() -> Self {
        Self {
            data: boxed_uninit_slice(CAPACITY),
            state: vec![SlotState::Vacant; CAPACITY].into_boxed_slice(),
            len: 0,
            free_list: vec![0u32; CAPACITY].into_boxed_slice(),
            free_count: 0,
            next_bump: 0,
        }
    }

    /// Allocate a slot and write `value` into it. Returns the ArenaId
    /// of the new slot, or `None` if the arena is full.
    ///
    /// Prefers the free list (O(1) pop) over bump allocation.
    pub fn alloc(&mut self, value: T) -> Option<ArenaId> {
        let slot = if self.free_count > 0 {
            // Pop from free list.
            self.free_count -= 1;
            self.free_list[self.free_count] as usize
        } else if self.next_bump < CAPACITY {
            // Bump allocate.
            let s = self.next_bump;
            self.next_bump += 1;
            s
        } else {
            return None; // Full.
        };

        debug_assert!(matches!(self.state[slot], SlotState::Vacant));
        self.data[slot] = MaybeUninit::new(value);
        self.state[slot] = SlotState::Occupied;
        self.len += 1;
        Some(ArenaId(slot as u32))
    }

    /// Allocate at a specific slot index (`ArenaId`), writing `value`.
    /// Returns `true` on success, `false` if the slot is already occupied
    /// or out of range.
    ///
    /// This is used when the caller controls ID assignment (e.g., the
    /// `TypeGraph` ID allocators produce sequential IDs that map to slots).
    pub fn insert_at(&mut self, id: ArenaId, value: T) -> bool {
        let slot = id.index();
        if slot >= CAPACITY {
            return false;
        }
        if matches!(self.state[slot], SlotState::Occupied) {
            return false;
        }
        // Advance bump pointer past this slot if needed.
        if slot >= self.next_bump {
            // Mark intermediate slots as vacant (they already are by default).
            self.next_bump = slot + 1;
        }
        self.data[slot] = MaybeUninit::new(value);
        self.state[slot] = SlotState::Occupied;
        self.len += 1;
        true
    }

    /// Convenience: insert at slot index derived from a `u64` key.
    /// Equivalent to `insert_at(ArenaId(key as u32), value)`.
    #[inline]
    pub fn insert(&mut self, key: u64, value: T) -> bool {
        self.insert_at(ArenaId(key as u32), value)
    }

    /// Deallocate the slot at `id`, dropping the value and pushing the
    /// slot onto the free list for reuse.
    ///
    /// Returns `true` if the slot was occupied (and is now freed),
    /// `false` if the slot was already vacant or out of range.
    pub fn dealloc(&mut self, id: ArenaId) -> bool {
        let slot = id.index();
        if slot >= CAPACITY || !matches!(self.state[slot], SlotState::Occupied) {
            return false;
        }
        // SAFETY: state[slot] == Occupied guarantees data[slot] is initialized.
        unsafe { self.data[slot].assume_init_drop() };
        self.state[slot] = SlotState::Vacant;
        self.len -= 1;
        // Push to free list for reuse.
        if self.free_count < CAPACITY {
            self.free_list[self.free_count] = slot as u32;
            self.free_count += 1;
        }
        true
    }

    /// Remove the value at `id`, returning it. Returns `None` if the slot
    /// is vacant or out of range.
    pub fn remove(&mut self, id: ArenaId) -> Option<T> {
        let slot = id.index();
        if slot >= CAPACITY || !matches!(self.state[slot], SlotState::Occupied) {
            return None;
        }
        // SAFETY: slot is Occupied, so data[slot] is initialized.
        let value = unsafe { self.data[slot].assume_init_read() };
        self.state[slot] = SlotState::Vacant;
        self.len -= 1;
        if self.free_count < CAPACITY {
            self.free_list[self.free_count] = slot as u32;
            self.free_count += 1;
        }
        Some(value)
    }

    /// Convenience: remove by `u64` key. Equivalent to `remove(ArenaId(key as u32))`.
    #[inline]
    pub fn remove_by_key(&mut self, key: &u64) -> Option<T> {
        self.remove(ArenaId(*key as u32))
    }

    /// Get a shared reference to the value at `id`.
    /// Returns `None` if the slot is vacant or out of range.
    #[inline]
    pub fn get(&self, id: ArenaId) -> Option<&T> {
        let slot = id.index();
        if slot >= CAPACITY || !matches!(self.state[slot], SlotState::Occupied) {
            return None;
        }
        // SAFETY: slot is Occupied.
        Some(unsafe { self.data[slot].assume_init_ref() })
    }

    /// Convenience: get by `u64` key. Equivalent to `get(ArenaId(key as u32))`.
    #[inline]
    pub fn get_by_key(&self, key: &u64) -> Option<&T> {
        self.get(ArenaId(*key as u32))
    }

    /// Get a mutable reference to the value at `id`.
    /// Returns `None` if the slot is vacant or out of range.
    #[inline]
    pub fn get_mut(&mut self, id: ArenaId) -> Option<&mut T> {
        let slot = id.index();
        if slot >= CAPACITY || !matches!(self.state[slot], SlotState::Occupied) {
            return None;
        }
        // SAFETY: slot is Occupied.
        Some(unsafe { self.data[slot].assume_init_mut() })
    }

    /// Convenience: get_mut by `u64` key. Equivalent to `get_mut(ArenaId(key as u32))`.
    #[inline]
    pub fn get_mut_by_key(&mut self, key: &u64) -> Option<&mut T> {
        self.get_mut(ArenaId(*key as u32))
    }

    /// Check whether the slot at `id` is occupied.
    #[inline]
    pub fn contains(&self, id: ArenaId) -> bool {
        let slot = id.index();
        slot < CAPACITY && matches!(self.state[slot], SlotState::Occupied)
    }

    /// Convenience: check by `u64` key. Equivalent to `contains(ArenaId(key as u32))`.
    #[inline]
    pub fn contains_key(&self, key: &u64) -> bool {
        self.contains(ArenaId(*key as u32))
    }

    /// Number of currently occupied slots.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the arena has no occupied slots.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum number of slots.
    #[inline]
    pub fn capacity(&self) -> usize {
        CAPACITY
    }

    /// Iterate over all occupied slots, yielding `(ArenaId, &T)`.
    pub fn iter(&self) -> ArenaIter<'_, T, CAPACITY> {
        ArenaIter {
            arena: self,
            pos: 0,
        }
    }

    /// Iterate over all occupied slots, yielding `(ArenaId, &mut T)`.
    pub fn iter_mut(&mut self) -> ArenaIterMut<'_, T, CAPACITY> {
        ArenaIterMut {
            data: &mut self.data,
            state: &self.state,
            pos: 0,
            bound: self.next_bump,
        }
    }

    /// Iterate over all occupied slot IDs.
    pub fn keys(&self) -> ArenaKeys<'_, T, CAPACITY> {
        ArenaKeys {
            arena: self,
            pos: 0,
        }
    }

    /// Iterate over all occupied values.
    pub fn values(&self) -> ArenaValues<'_, T, CAPACITY> {
        ArenaValues {
            arena: self,
            pos: 0,
        }
    }
}

impl<T, const CAPACITY: usize> Drop for Arena<T, CAPACITY> {
    fn drop(&mut self) {
        // Drop all occupied values.
        for i in 0..self.next_bump {
            if matches!(self.state[i], SlotState::Occupied) {
                unsafe { self.data[i].assume_init_drop() };
            }
        }
    }
}

impl<T: Clone, const CAPACITY: usize> Clone for Arena<T, CAPACITY> {
    fn clone(&self) -> Self {
        let mut new_data = boxed_uninit_slice(CAPACITY);
        // Clone all occupied values.
        for i in 0..self.next_bump {
            if matches!(self.state[i], SlotState::Occupied) {
                let val = unsafe { self.data[i].assume_init_ref() };
                new_data[i] = MaybeUninit::new(val.clone());
            }
        }
        Self {
            data: new_data,
            state: self.state.clone(),
            len: self.len,
            free_list: self.free_list.clone(),
            free_count: self.free_count,
            next_bump: self.next_bump,
        }
    }
}

impl<T: fmt::Debug, const CAPACITY: usize> fmt::Debug for Arena<T, CAPACITY> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Arena")
            .field("len", &self.len)
            .field("capacity", &CAPACITY)
            .field("next_bump", &self.next_bump)
            .field("free_count", &self.free_count)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Iterators
// ---------------------------------------------------------------------------

/// Iterator over `(ArenaId, &T)` for occupied slots.
pub struct ArenaIter<'a, T, const CAPACITY: usize> {
    arena: &'a Arena<T, CAPACITY>,
    pos: usize,
}

impl<'a, T, const CAPACITY: usize> Iterator for ArenaIter<'a, T, CAPACITY> {
    type Item = (ArenaId, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.arena.next_bump {
            let i = self.pos;
            self.pos += 1;
            if matches!(self.arena.state[i], SlotState::Occupied) {
                let val = unsafe { self.arena.data[i].assume_init_ref() };
                return Some((ArenaId(i as u32), val));
            }
        }
        None
    }
}

/// Mutable iterator over `(ArenaId, &mut T)` for occupied slots.
pub struct ArenaIterMut<'a, T, const CAPACITY: usize> {
    data: &'a mut [MaybeUninit<T>],
    state: &'a [SlotState],
    pos: usize,
    bound: usize,
}

impl<'a, T, const CAPACITY: usize> Iterator for ArenaIterMut<'a, T, CAPACITY> {
    type Item = (ArenaId, &'a mut T);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.bound {
            let i = self.pos;
            self.pos += 1;
            if matches!(self.state[i], SlotState::Occupied) {
                // SAFETY: Each index is yielded at most once (pos is monotonically
                // increasing), and we have &mut access to data.
                let val = unsafe { &mut *self.data[i].as_mut_ptr() };
                return Some((ArenaId(i as u32), val));
            }
        }
        None
    }
}

/// Iterator over `ArenaId` keys of occupied slots.
pub struct ArenaKeys<'a, T, const CAPACITY: usize> {
    arena: &'a Arena<T, CAPACITY>,
    pos: usize,
}

impl<'a, T, const CAPACITY: usize> Iterator for ArenaKeys<'a, T, CAPACITY> {
    type Item = ArenaId;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.arena.next_bump {
            let i = self.pos;
            self.pos += 1;
            if matches!(self.arena.state[i], SlotState::Occupied) {
                return Some(ArenaId(i as u32));
            }
        }
        None
    }
}

/// Iterator over `&T` values of occupied slots.
pub struct ArenaValues<'a, T, const CAPACITY: usize> {
    arena: &'a Arena<T, CAPACITY>,
    pos: usize,
}

impl<'a, T, const CAPACITY: usize> Iterator for ArenaValues<'a, T, CAPACITY> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.arena.next_bump {
            let i = self.pos;
            self.pos += 1;
            if matches!(self.arena.state[i], SlotState::Occupied) {
                let val = unsafe { self.arena.data[i].assume_init_ref() };
                return Some(val);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_get() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        let id = arena.alloc(42).unwrap();
        assert_eq!(*arena.get(id).unwrap(), 42);
        assert_eq!(arena.len(), 1);
    }

    #[test]
    fn alloc_dealloc_reuse() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        let id1 = arena.alloc(10).unwrap();
        let _id2 = arena.alloc(20).unwrap();
        assert_eq!(arena.len(), 2);

        // Dealloc id1, then alloc again should reuse the same slot.
        assert!(arena.dealloc(id1));
        assert_eq!(arena.len(), 1);
        assert!(arena.get(id1).is_none());

        let id3 = arena.alloc(30).unwrap();
        assert_eq!(id3, id1, "free-list should reuse the deallocated slot");
        assert_eq!(*arena.get(id3).unwrap(), 30);
        assert_eq!(arena.len(), 2);
    }

    #[test]
    fn remove_returns_value() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        let id = arena.alloc(99).unwrap();
        let val = arena.remove(id);
        assert_eq!(val, Some(99));
        assert!(arena.get(id).is_none());
        assert_eq!(arena.len(), 0);
    }

    #[test]
    fn capacity_overflow_returns_none() {
        let mut arena: Arena<u32, 4> = Arena::new();
        assert!(arena.alloc(1).is_some());
        assert!(arena.alloc(2).is_some());
        assert!(arena.alloc(3).is_some());
        assert!(arena.alloc(4).is_some());
        assert!(arena.alloc(5).is_none(), "arena should be full");
        assert_eq!(arena.len(), 4);
    }

    #[test]
    fn capacity_overflow_after_free_reuse() {
        let mut arena: Arena<u32, 4> = Arena::new();
        let a = arena.alloc(1).unwrap();
        let _b = arena.alloc(2).unwrap();
        let _c = arena.alloc(3).unwrap();
        let _d = arena.alloc(4).unwrap();

        // Full. Free one slot, then alloc should succeed.
        arena.dealloc(a);
        assert!(arena.alloc(5).is_some());
        assert!(arena.alloc(6).is_none(), "full again");
    }

    #[test]
    fn get_mut_modifies_value() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        let id = arena.alloc(10).unwrap();
        *arena.get_mut(id).unwrap() = 20;
        assert_eq!(*arena.get(id).unwrap(), 20);
    }

    #[test]
    fn contains_check() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        let id = arena.alloc(1).unwrap();
        assert!(arena.contains(id));
        arena.dealloc(id);
        assert!(!arena.contains(id));
        // Out-of-range
        assert!(!arena.contains(ArenaId(9999)));
    }

    #[test]
    fn iter_yields_all_occupied() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        let _a = arena.alloc(10).unwrap();
        let b = arena.alloc(20).unwrap();
        let _c = arena.alloc(30).unwrap();
        arena.dealloc(b);

        let items: Vec<_> = arena.iter().map(|(_, &v)| v).collect();
        assert_eq!(items.len(), 2);
        assert!(items.contains(&10));
        assert!(items.contains(&30));
    }

    #[test]
    fn keys_and_values_iterators() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        arena.alloc(100).unwrap();
        arena.alloc(200).unwrap();

        let keys: Vec<_> = arena.keys().collect();
        assert_eq!(keys.len(), 2);

        let vals: Vec<_> = arena.values().collect();
        assert_eq!(vals.len(), 2);
        assert_eq!(*vals[0], 100);
        assert_eq!(*vals[1], 200);
    }

    #[test]
    fn insert_at_specific_slot() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        assert!(arena.insert_at(ArenaId(5), 50));
        assert!(arena.insert_at(ArenaId(10), 100));
        assert_eq!(*arena.get(ArenaId(5)).unwrap(), 50);
        assert_eq!(*arena.get(ArenaId(10)).unwrap(), 100);
        assert_eq!(arena.len(), 2);
        // Slot 0 should be vacant.
        assert!(arena.get(ArenaId(0)).is_none());
    }

    #[test]
    fn insert_at_duplicate_fails() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        assert!(arena.insert_at(ArenaId(3), 30));
        assert!(!arena.insert_at(ArenaId(3), 31), "slot already occupied");
    }

    #[test]
    fn dealloc_vacant_returns_false() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        assert!(!arena.dealloc(ArenaId(0)));
        assert!(!arena.dealloc(ArenaId(999)));
    }

    #[test]
    fn alloc_dealloc_cycle_stress() {
        let mut arena: Arena<u32, 64> = Arena::new();
        let mut ids = [ArenaId(0); 64];

        // Fill completely.
        for i in 0..64 {
            ids[i] = arena.alloc(i as u32).unwrap();
        }
        assert!(arena.alloc(999).is_none());
        assert_eq!(arena.len(), 64);

        // Free all odd slots.
        for i in (1..64).step_by(2) {
            assert!(arena.dealloc(ids[i]));
        }
        assert_eq!(arena.len(), 32);

        // Reallocate into freed slots.
        for i in 0..32 {
            let new_id = arena.alloc(100 + i).unwrap();
            assert!(arena.contains(new_id));
        }
        assert_eq!(arena.len(), 64);

        // Verify even slots still have original values.
        for i in (0..64).step_by(2) {
            assert_eq!(*arena.get(ids[i]).unwrap(), i as u32);
        }
    }

    #[test]
    fn empty_arena_iter() {
        let arena: Arena<u64, 16> = Arena::new();
        assert_eq!(arena.iter().count(), 0);
        assert_eq!(arena.keys().count(), 0);
        assert_eq!(arena.values().count(), 0);
        assert!(arena.is_empty());
    }

    #[test]
    fn drop_cleans_up() {
        // This test verifies the Drop impl doesn't panic.
        // With types that have drop glue, this would also verify no leaks.
        let mut arena: Arena<[u8; 32], 8> = Arena::new();
        arena.alloc([1u8; 32]).unwrap();
        arena.alloc([2u8; 32]).unwrap();
        let id = arena.alloc([3u8; 32]).unwrap();
        arena.dealloc(id);
        // arena drops here — should not panic
        // arena drops here -- should not panic
    }

    #[test]
    fn convenience_insert_and_get_by_key() {
        let mut arena: Arena<u64, 1024> = Arena::new();
        assert!(arena.insert(5, 50));
        assert!(arena.insert(10, 100));
        assert_eq!(*arena.get_by_key(&5).unwrap(), 50);
        assert_eq!(*arena.get_by_key(&10).unwrap(), 100);
        assert!(arena.contains_key(&5));
        assert!(!arena.contains_key(&999));

        // get_mut_by_key
        *arena.get_mut_by_key(&5).unwrap() = 55;
        assert_eq!(*arena.get_by_key(&5).unwrap(), 55);

        // remove_by_key
        let val = arena.remove_by_key(&10);
        assert_eq!(val, Some(100));
        assert!(!arena.contains_key(&10));
    }
}
