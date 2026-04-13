//! Shared ring buffer for mouse events.
//!
//! Same pattern as the keyboard KB ring buffer used in sotX.
//! A single physical page is shared between the mouse driver process
//! and the consumer process (e.g., init or a windowing server).

use crate::event::MouseEvent;

/// Number of mouse event slots in the ring buffer.
/// Sized to fit in a portion of a 4 KiB page alongside the header.
/// Header = 8 bytes (head: u32 + tail: u32), events = 8 bytes each.
/// (4096 - 8) / 8 = 511 events, but use a power-of-2-friendly count.
pub const RING_CAPACITY: usize = 256;

/// Mouse event ring buffer header.
///
/// Layout at the start of the shared page:
/// - offset 0: head (u32) — next slot the producer writes to.
/// - offset 4: tail (u32) — next slot the consumer reads from.
/// - offset 8: events[0..RING_CAPACITY] — mouse event slots.
///
/// Total size: 8 + 256 * 8 = 2056 bytes, fits in one 4 KiB page.
#[repr(C)]
pub struct MouseRing {
    /// Producer write index (written by mouse driver).
    pub head: u32,
    /// Consumer read index (written by consumer).
    pub tail: u32,
    /// Event slots.
    pub events: [MouseEvent; RING_CAPACITY],
}

const _: () = assert!(core::mem::size_of::<MouseRing>() <= 4096);

impl MouseRing {
    /// Initialize the ring buffer (zero head/tail, zero events).
    ///
    /// # Safety
    /// `ptr` must point to a valid, writable, page-aligned region of at least 4096 bytes.
    pub unsafe fn init_at(ptr: *mut MouseRing) {
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<MouseRing>());
        }
    }

    /// Check if the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Check if the ring is full.
    pub fn is_full(&self) -> bool {
        ((self.head + 1) % RING_CAPACITY as u32) == self.tail
    }

    /// Number of events available to read.
    pub fn len(&self) -> u32 {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            RING_CAPACITY as u32 - self.tail + self.head
        }
    }
}

/// Producer side — pushes mouse events into the ring.
pub struct MouseRingProducer {
    ring: *mut MouseRing,
}

impl MouseRingProducer {
    /// Create a new producer for a ring at the given address.
    ///
    /// # Safety
    /// `ring_ptr` must point to a valid, properly initialized `MouseRing`.
    pub unsafe fn new(ring_ptr: *mut MouseRing) -> Self {
        Self { ring: ring_ptr }
    }

    /// Push a mouse event into the ring. Returns false if the ring is full.
    pub fn push(&mut self, event: MouseEvent) -> bool {
        let ring = unsafe { &mut *self.ring };
        let next_head = (ring.head + 1) % RING_CAPACITY as u32;

        // Read tail with volatile to see consumer's updates.
        let tail = unsafe { core::ptr::read_volatile(&ring.tail) };
        if next_head == tail {
            return false; // Ring full.
        }

        // Write event.
        unsafe {
            core::ptr::write_volatile(
                &mut ring.events[ring.head as usize] as *mut MouseEvent,
                event,
            );
        }

        // Update head with volatile write.
        unsafe {
            core::ptr::write_volatile(&mut ring.head as *mut u32, next_head);
        }

        true
    }
}

/// Consumer side — reads mouse events from the ring.
pub struct MouseRingConsumer {
    ring: *mut MouseRing,
}

impl MouseRingConsumer {
    /// Create a new consumer for a ring at the given address.
    ///
    /// # Safety
    /// `ring_ptr` must point to a valid, properly initialized `MouseRing`.
    pub unsafe fn new(ring_ptr: *mut MouseRing) -> Self {
        Self { ring: ring_ptr }
    }

    /// Pop a mouse event from the ring. Returns None if empty.
    pub fn pop(&mut self) -> Option<MouseEvent> {
        let ring = unsafe { &mut *self.ring };

        // Read head with volatile to see producer's updates.
        let head = unsafe { core::ptr::read_volatile(&ring.head) };
        let tail = ring.tail;

        if head == tail {
            return None; // Empty.
        }

        // Read event.
        let event = unsafe {
            core::ptr::read_volatile(&ring.events[tail as usize] as *const MouseEvent)
        };

        // Update tail with volatile write.
        let next_tail = (tail + 1) % RING_CAPACITY as u32;
        unsafe {
            core::ptr::write_volatile(&mut ring.tail as *mut u32, next_tail);
        }

        Some(event)
    }

    /// Peek at the next event without consuming it.
    pub fn peek(&self) -> Option<MouseEvent> {
        let ring = unsafe { &*self.ring };
        let head = unsafe { core::ptr::read_volatile(&ring.head) };
        let tail = ring.tail;

        if head == tail {
            return None;
        }

        let event = unsafe {
            core::ptr::read_volatile(&ring.events[tail as usize] as *const MouseEvent)
        };

        Some(event)
    }

    /// Check if there are events available.
    pub fn has_events(&self) -> bool {
        let ring = unsafe { &*self.ring };
        let head = unsafe { core::ptr::read_volatile(&ring.head) };
        head != ring.tail
    }

    /// Drain all available events, calling `f` for each.
    pub fn drain<F: FnMut(MouseEvent)>(&mut self, mut f: F) {
        while let Some(event) = self.pop() {
            f(event);
        }
    }
}
