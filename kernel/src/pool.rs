//! Generic slot allocator backed by `Vec`.
//!
//! `Pool<T>` provides O(1) alloc/free via a free list and unlimited growth.
//! Slots are `Option<T>` — `None` means free, `Some` means occupied.
//! IDs are stable `u32` indices, reusable after `free()`.

use alloc::vec::Vec;

pub struct Pool<T> {
    slots: Vec<Option<T>>,
    free_list: Vec<usize>,
}

impl<T> Pool<T> {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_list: Vec::new(),
        }
    }

    /// Insert a value, returning its slot index.
    pub fn alloc(&mut self, val: T) -> u32 {
        if let Some(idx) = self.free_list.pop() {
            self.slots[idx] = Some(val);
            idx as u32
        } else {
            let idx = self.slots.len();
            self.slots.push(Some(val));
            idx as u32
        }
    }

    /// Remove and return the value at `id`, recycling the slot.
    pub fn free(&mut self, id: u32) -> Option<T> {
        let idx = id as usize;
        if idx < self.slots.len() {
            if let Some(val) = self.slots[idx].take() {
                self.free_list.push(idx);
                return Some(val);
            }
        }
        None
    }

    pub fn get(&self, id: u32) -> Option<&T> {
        self.slots.get(id as usize)?.as_ref()
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut T> {
        self.slots.get_mut(id as usize)?.as_mut()
    }

    /// Iterate over occupied slots as `(index, &T)`.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &T)> {
        self.slots.iter().enumerate().filter_map(|(i, slot)| {
            slot.as_ref().map(|val| (i as u32, val))
        })
    }
}
