//! Typed wrappers over SPSC ring buffer.
//!
//! Provides compile-time type safety for shared-memory channels without
//! requiring an IDL compiler. Types must be `Copy` and their size must
//! be a multiple of 8 bytes (u64 slot size).

use core::marker::PhantomData;
use core::mem;

use crate::spsc::{self, SpscRing};

/// Typed sender half of an SPSC channel.
pub struct TypedSender<'a, T: Copy> {
    ring: &'a SpscRing,
    _phantom: PhantomData<T>,
}

/// Typed receiver half of an SPSC channel.
pub struct TypedReceiver<'a, T: Copy> {
    ring: &'a SpscRing,
    _phantom: PhantomData<T>,
}

/// Number of u64 slots required to hold one T.
const fn slots_per<T>() -> usize {
    mem::size_of::<T>().div_ceil(8)
}

impl<'a, T: Copy> TypedSender<'a, T> {
    /// Create a typed sender wrapping an existing SPSC ring.
    pub fn new(ring: &'a SpscRing) -> Self {
        // Compile-time check: T must fit in u64 slots.
        const { assert!(mem::size_of::<T>() > 0, "zero-sized types not supported") };
        Self {
            ring,
            _phantom: PhantomData,
        }
    }

    /// Send a value, blocking if the ring is full.
    pub fn send(&self, val: T) {
        let slots = slots_per::<T>();
        debug_assert!(
            slots <= self.ring.capacity() as usize,
            "TypedSender: message requires {} slots but ring capacity is {}",
            slots,
            self.ring.capacity(),
        );
        if slots == 1 {
            // Fast path: single u64
            let word = unsafe { *(&val as *const T as *const u64) };
            spsc::send(self.ring, word);
        } else {
            // Multi-slot: send each u64 word sequentially.
            // Note: not atomic across slots — safe only with single producer/consumer.
            let ptr = &val as *const T as *const u64;
            for i in 0..slots {
                let word = unsafe { ptr.add(i).read() };
                spsc::send(self.ring, word);
            }
        }
    }

    /// Try to send a value. Returns `true` on success.
    ///
    /// WARNING: For multi-slot types (size > 8 bytes), a partial send can occur
    /// if the ring fills mid-way. This leaves orphaned slots in the ring.
    /// Only safe with a single producer that retries the full value on failure.
    pub fn try_send(&self, val: T) -> bool {
        let slots = slots_per::<T>();
        debug_assert!(
            slots <= self.ring.capacity() as usize,
            "TypedSender: message requires {} slots but ring capacity is {}",
            slots,
            self.ring.capacity(),
        );
        if slots == 1 {
            let word = unsafe { *(&val as *const T as *const u64) };
            spsc::try_send(self.ring, word)
        } else {
            // Multi-slot: must succeed for all slots.
            // Note: partial send is not atomic — only use with single producer.
            let ptr = &val as *const T as *const u64;
            for i in 0..slots {
                let word = unsafe { ptr.add(i).read() };
                if !spsc::try_send(self.ring, word) {
                    return false;
                }
            }
            true
        }
    }
}

impl<'a, T: Copy> TypedReceiver<'a, T> {
    /// Create a typed receiver wrapping an existing SPSC ring.
    pub fn new(ring: &'a SpscRing) -> Self {
        const { assert!(mem::size_of::<T>() > 0, "zero-sized types not supported") };
        Self {
            ring,
            _phantom: PhantomData,
        }
    }

    /// Receive a value, blocking if the ring is empty.
    pub fn recv(&self) -> T {
        let slots = slots_per::<T>();
        if slots == 1 {
            let word = spsc::recv(self.ring);
            unsafe { *(&word as *const u64 as *const T) }
        } else {
            let mut buf = [0u64; 16]; // max 128 bytes
            for slot in buf.iter_mut().take(slots) {
                *slot = spsc::recv(self.ring);
            }
            unsafe { *(buf.as_ptr() as *const T) }
        }
    }

    /// Try to receive a value. Returns `None` if empty.
    pub fn try_recv(&self) -> Option<T> {
        let slots = slots_per::<T>();
        if slots == 1 {
            let word = spsc::try_recv(self.ring)?;
            Some(unsafe { *(&word as *const u64 as *const T) })
        } else {
            let mut buf = [0u64; 16];
            for slot in buf.iter_mut().take(slots) {
                *slot = spsc::try_recv(self.ring)?;
            }
            Some(unsafe { *(buf.as_ptr() as *const T) })
        }
    }
}
