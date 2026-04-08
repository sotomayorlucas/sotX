//! Lock-free single-producer single-consumer ring buffer for shared memory.
//!
//! Layout fits in one 4 KiB page:
//! - Offset 0x00 (cache line 0): head (consumer read index)
//! - Offset 0x40 (cache line 1): tail (producer write index)
//! - Offset 0x80 (cache line 2): capacity, empty_notify_cap, full_notify_cap
//! - Offset 0xC0 (data start):  u64 slots × capacity
//!
//! With capacity=128: 128×8 = 1024 bytes data + 192 bytes header = 1216 bytes.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::sys;

/// Cache-line-aligned head index (consumer side).
#[repr(C, align(64))]
struct Head {
    value: AtomicU32,
}

/// Cache-line-aligned tail index (producer side).
#[repr(C, align(64))]
struct Tail {
    value: AtomicU32,
}

/// Metadata (on its own cache line).
#[repr(C, align(64))]
struct Meta {
    capacity: u32,
    empty_notify_cap: u32,
    full_notify_cap: u32,
}

/// SPSC ring buffer header. The data slots follow immediately after.
#[repr(C)]
pub struct SpscRing {
    head: Head,
    tail: Tail,
    meta: Meta,
    // Data starts at offset 0xC0 (3 × 64-byte cache lines).
    // Slots are u64 values accessed via pointer arithmetic.
}

const DATA_OFFSET: usize = 192; // 3 × 64

impl SpscRing {
    /// Initialize a ring buffer at a memory location. Called once by the setup thread.
    ///
    /// # Safety
    /// `ptr` must point to at least 4096 bytes of writable, shared memory.
    /// `capacity` must be > 0 and `DATA_OFFSET + capacity * 8` must fit in one page.
    pub unsafe fn init(
        ptr: *mut u8,
        capacity: u32,
        empty_cap: u32,
        full_cap: u32,
    ) -> &'static Self {
        // Zero the header
        core::ptr::write_bytes(ptr, 0, DATA_OFFSET);

        let ring = &*(ptr as *const Self);
        ring.head.value.store(0, Ordering::Relaxed);
        ring.tail.value.store(0, Ordering::Relaxed);

        // Write metadata
        let meta = ptr.add(128) as *mut u32;
        meta.write(capacity);
        meta.add(1).write(empty_cap);
        meta.add(2).write(full_cap);

        ring
    }

    /// Get a reference to an existing ring at a memory location.
    ///
    /// # Safety
    /// `ptr` must point to a previously initialized SpscRing in shared memory.
    pub unsafe fn from_ptr(ptr: *mut u8) -> &'static Self {
        &*(ptr as *const Self)
    }

    #[inline(always)]
    pub fn capacity(&self) -> u32 {
        self.meta.capacity
    }

    #[inline(always)]
    fn empty_notify_cap(&self) -> u64 {
        self.meta.empty_notify_cap as u64
    }

    #[inline(always)]
    fn full_notify_cap(&self) -> u64 {
        self.meta.full_notify_cap as u64
    }

    /// Get pointer to data slot at given index.
    #[inline(always)]
    unsafe fn slot_ptr(&self, index: u32) -> *mut u64 {
        let base = (self as *const Self as *const u8 as *mut u8).add(DATA_OFFSET);
        (base as *mut u64).add((index % self.capacity()) as usize)
    }
}

/// Try to send a value. Returns `true` on success, `false` if ring is full.
pub fn try_send(ring: &SpscRing, value: u64) -> bool {
    let tail = ring.tail.value.load(Ordering::Relaxed);
    let head = ring.head.value.load(Ordering::Acquire);

    if tail.wrapping_sub(head) >= ring.capacity() {
        return false;
    }

    unsafe { ring.slot_ptr(tail).write_volatile(value) };
    ring.tail
        .value
        .store(tail.wrapping_add(1), Ordering::Release);

    // If ring was empty, wake the consumer.
    if tail == head {
        sys::notify_signal(ring.empty_notify_cap());
    }

    true
}

/// Send a value, blocking if the ring is full.
pub fn send(ring: &SpscRing, value: u64) {
    loop {
        if try_send(ring, value) {
            return;
        }
        sys::notify_wait(ring.full_notify_cap()); // cold path: block until space
    }
}

/// Try to receive a value. Returns `None` if ring is empty.
pub fn try_recv(ring: &SpscRing) -> Option<u64> {
    let head = ring.head.value.load(Ordering::Relaxed);
    let tail = ring.tail.value.load(Ordering::Acquire);

    if head == tail {
        return None;
    }

    let value = unsafe { ring.slot_ptr(head).read_volatile() };
    ring.head
        .value
        .store(head.wrapping_add(1), Ordering::Release);

    // If ring was full, wake the producer.
    if tail.wrapping_sub(head) == ring.capacity() {
        sys::notify_signal(ring.full_notify_cap());
    }

    Some(value)
}

/// Receive a value, blocking if the ring is empty.
pub fn recv(ring: &SpscRing) -> u64 {
    loop {
        if let Some(v) = try_recv(ring) {
            return v;
        }
        sys::notify_wait(ring.empty_notify_cap()); // cold path: block until data
    }
}
