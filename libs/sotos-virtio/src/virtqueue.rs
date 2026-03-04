//! Split virtqueue implementation for virtio legacy (v0.9.5) transport.
//!
//! Memory layout (for queue_size=128):
//!   Descriptor table: 128 * 16 = 2048 bytes
//!   Available ring:   6 + 128*2 = 262 bytes
//!   (padding to 4096 boundary)
//!   Used ring:        6 + 128*8 = 1030 bytes
//!
//! Total for queue_size=128: ~2 pages (fits in 8192 bytes).

use core::sync::atomic::{fence, Ordering};
use core::ptr::{read_volatile, write_volatile};

/// Virtqueue descriptor flags.
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;

/// A single virtqueue descriptor (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VringDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// Available ring header.
#[repr(C)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] follows
}

/// Used ring header.
#[repr(C)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] of VringUsedElem follows
}

/// Used ring element (8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VringUsedElem {
    pub id: u32,
    pub len: u32,
}

/// A split virtqueue backed by contiguous physical memory.
pub struct Virtqueue {
    /// Virtual address of the descriptor table.
    desc_va: *mut VringDesc,
    /// Virtual address of the available ring.
    avail_va: *mut VringAvail,
    /// Virtual address of the used ring.
    used_va: *mut VringUsed,
    /// Queue size (number of descriptors).
    queue_size: u16,
    /// Physical page frame number (for legacy transport queue_address register).
    phys_pfn: u32,
    /// Free list head (linked via desc.next).
    free_head: u16,
    /// Number of free descriptors.
    num_free: u16,
    /// Last seen used ring index (for polling).
    last_used_idx: u16,
}

impl Virtqueue {
    /// Calculate the total byte size needed for a virtqueue of given size.
    pub fn byte_size(queue_size: u16) -> usize {
        let qs = queue_size as usize;
        // Descriptor table + available ring, aligned to 4096
        let desc_avail = qs * 16 + (6 + qs * 2);
        let aligned = (desc_avail + 4095) & !4095;
        // Used ring
        let used = 6 + qs * 8;
        aligned + used
    }

    /// Initialize a virtqueue using pre-allocated contiguous physical pages.
    ///
    /// `vaddr_base`: virtual address where the pages are mapped.
    /// `phys_base`: physical address of the contiguous pages.
    /// `queue_size`: number of descriptors.
    pub fn new(vaddr_base: u64, phys_base: u64, queue_size: u16) -> Self {
        let qs = queue_size as usize;

        // Zero ALL allocated pages (not just byte_size) using volatile writes.
        // This ensures QEMU's device model sees zeros when we hand it the PFN.
        // Round up to full pages since the kernel allocates whole pages.
        let total = (Self::byte_size(queue_size) + 4095) & !4095;
        let base = vaddr_base as *mut u8;
        for i in 0..total {
            unsafe { write_volatile(base.add(i), 0u8); }
        }
        // Explicit mfence: guarantee every zero byte is globally visible
        // before any subsequent PIO (port_out32 for PFN) exits to QEMU.
        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }

        // Layout pointers.
        let desc_va = vaddr_base as *mut VringDesc;
        let avail_offset = qs * 16;
        let avail_va = (vaddr_base + avail_offset as u64) as *mut VringAvail;
        let used_offset = (avail_offset + 6 + qs * 2 + 4095) & !4095;
        let used_va = (vaddr_base + used_offset as u64) as *mut VringUsed;

        // Build the free descriptor chain.
        for i in 0..qs {
            let desc = unsafe { &mut *desc_va.add(i) };
            desc.next = if i + 1 < qs { (i + 1) as u16 } else { 0xFFFF };
            desc.flags = 0;
            desc.addr = 0;
            desc.len = 0;
        }

        let phys_pfn = (phys_base / 4096) as u32;

        Virtqueue {
            desc_va,
            avail_va,
            used_va,
            queue_size,
            phys_pfn,
            free_head: 0,
            num_free: queue_size,
            last_used_idx: 0,
        }
    }

    /// Physical page frame number (for legacy queue_address register).
    pub fn phys_pfn(&self) -> u32 {
        self.phys_pfn
    }

    /// Return the queue size.
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Allocate a single descriptor from the free list.
    pub fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let idx = self.free_head;
        let desc = unsafe { &*self.desc_va.add(idx as usize) };
        self.free_head = desc.next;
        self.num_free -= 1;
        Some(idx)
    }

    /// Free a single descriptor back to the free list.
    pub fn free_desc(&mut self, idx: u16) {
        let desc = unsafe { &mut *self.desc_va.add(idx as usize) };
        desc.flags = 0;
        desc.next = self.free_head;
        self.free_head = idx;
        self.num_free += 1;
    }

    /// Free a descriptor chain starting from `head`.
    pub fn free_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            let desc = unsafe { &*self.desc_va.add(idx as usize) };
            let next = desc.next;
            let has_next = desc.flags & VRING_DESC_F_NEXT != 0;
            self.free_desc(idx);
            if has_next {
                idx = next;
            } else {
                break;
            }
        }
    }

    /// Set up a descriptor as a read-only buffer (device reads from it).
    pub fn set_buf_ro(&mut self, idx: u16, phys: u64, len: u32) {
        let desc = self.desc_va.wrapping_add(idx as usize);
        unsafe {
            write_volatile(&raw mut (*desc).addr, phys);
            write_volatile(&raw mut (*desc).len, len);
            write_volatile(&raw mut (*desc).flags, 0);
        }
    }

    /// Set up a descriptor as a write-only buffer (device writes to it).
    pub fn set_buf_wo(&mut self, idx: u16, phys: u64, len: u32) {
        let desc = self.desc_va.wrapping_add(idx as usize);
        unsafe {
            write_volatile(&raw mut (*desc).addr, phys);
            write_volatile(&raw mut (*desc).len, len);
            write_volatile(&raw mut (*desc).flags, VRING_DESC_F_WRITE);
        }
    }

    /// Chain two descriptors: prev.next = next, set NEXT flag on prev.
    pub fn chain(&mut self, prev: u16, next: u16) {
        let desc = self.desc_va.wrapping_add(prev as usize);
        unsafe {
            let flags = read_volatile(&raw const (*desc).flags);
            write_volatile(&raw mut (*desc).flags, flags | VRING_DESC_F_NEXT);
            write_volatile(&raw mut (*desc).next, next);
        }
    }

    /// Submit a descriptor chain head to the available ring.
    pub fn submit(&mut self, head: u16) {
        // Read current avail index (volatile — device-shared memory).
        let idx = unsafe { read_volatile(&raw const (*self.avail_va).idx) };
        // Write head into ring[idx % queue_size].
        let ring_ptr = unsafe {
            (self.avail_va as *mut u8).add(4) as *mut u16
        };
        unsafe {
            write_volatile(ring_ptr.add((idx % self.queue_size) as usize), head);
        }
        // Ensure ring entry is visible before updating idx.
        fence(Ordering::Release);
        unsafe {
            write_volatile(&raw mut (*self.avail_va).idx, idx.wrapping_add(1));
        }
    }

    /// Poll the used ring for completed requests.
    /// Returns `Some((descriptor_id, bytes_written))` if a new entry is available.
    pub fn poll_used(&mut self) -> Option<(u32, u32)> {
        fence(Ordering::Acquire);
        let used_idx = unsafe { read_volatile(&raw const (*self.used_va).idx) };
        if self.last_used_idx == used_idx {
            return None;
        }
        let ring_ptr = unsafe {
            (self.used_va as *mut u8).add(4) as *const VringUsedElem
        };
        let elem = unsafe {
            read_volatile(ring_ptr.add((self.last_used_idx % self.queue_size) as usize))
        };
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((elem.id, elem.len))
    }
}
