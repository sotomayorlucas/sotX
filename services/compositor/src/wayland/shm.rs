//! wl_shm -- shared memory buffer management.
//!
//! Events:
//!   0 = format(format: uint) -- advertise supported pixel formats
//!
//! Requests:
//!   0 = create_pool(id: new_id, fd: fd, size: int) -- create a wl_shm_pool
//!
//! wl_shm_pool requests:
//!   0 = create_buffer(id: new_id, offset: int, width: int, height: int,
//!                     stride: int, format: uint)
//!   1 = destroy
//!   2 = resize(size: int)

use super::{WlEvent, WlMessage};

/// Pixel format constants (Wayland enum).
pub const WL_SHM_FORMAT_ARGB8888: u32 = 0;
pub const WL_SHM_FORMAT_XRGB8888: u32 = 1;

/// Send format advertisements when wl_shm is bound.
pub fn send_formats(shm_id: u32, events: &mut [WlEvent; 16], event_count: &mut usize) {
    for &fmt in &[WL_SHM_FORMAT_ARGB8888, WL_SHM_FORMAT_XRGB8888] {
        if *event_count >= events.len() {
            break;
        }
        let mut ev = WlEvent::new();
        ev.begin(shm_id, 0); // wl_shm::format
        ev.put_u32(fmt);
        ev.finish();
        events[*event_count] = ev;
        *event_count += 1;
    }
}

/// Maximum pages per pool (256 pages = 1 MiB).
pub const MAX_POOL_PAGES: usize = 256;

/// A shared memory pool backed by kernel SHM.
pub struct ShmPool {
    pub pool_id: u32,
    /// Kernel SHM handle (from SYS_SHM_CREATE).
    pub shm_handle: u64,
    /// Number of pages allocated.
    pub page_count: u32,
    /// Size in bytes.
    pub size: u32,
    /// Virtual address where the pool is mapped in compositor's AS.
    pub mapped_vaddr: u64,
    pub active: bool,
}

impl ShmPool {
    pub const fn empty() -> Self {
        Self {
            pool_id: 0,
            shm_handle: 0,
            page_count: 0,
            size: 0,
            mapped_vaddr: 0,
            active: false,
        }
    }
}

/// A buffer created from a pool.
pub struct ShmBuffer {
    pub buffer_id: u32,
    pub pool_idx: usize,
    pub offset: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub active: bool,
}

impl ShmBuffer {
    pub const fn empty() -> Self {
        Self {
            buffer_id: 0,
            pool_idx: 0,
            offset: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: 0,
            active: false,
        }
    }
}

/// Handle wl_shm::create_pool request.
/// Returns (pool_id, fd_or_shm_handle, size) for the caller to set up.
///
/// Wire format: new_id(u32) + fd(i32) + size(i32)
/// In sotX IPC transport, the fd field carries the kernel SHM handle
/// if the client pre-created the shared memory object (>= 0).
/// A value of -1 means the compositor should create the SHM itself.
pub fn handle_create_pool(msg: &WlMessage) -> Option<(u32, i32, u32)> {
    if msg.opcode != 0 {
        return None;
    }
    let pool_id = msg.arg_u32(0);
    let fd = msg.arg_i32(4); // SHM handle or -1
    let size = msg.arg_u32(8) as u32;
    Some((pool_id, fd, size))
}

/// Handle wl_shm_pool::create_buffer request.
/// Returns buffer parameters.
pub fn handle_create_buffer(msg: &WlMessage) -> Option<ShmBuffer> {
    if msg.opcode != 0 {
        return None;
    }
    Some(ShmBuffer {
        buffer_id: msg.arg_u32(0),
        pool_idx: 0, // caller fills in
        offset: msg.arg_u32(4) as u32,
        width: msg.arg_u32(8) as u32,
        height: msg.arg_u32(12) as u32,
        stride: msg.arg_u32(16) as u32,
        format: msg.arg_u32(20),
        active: true,
    })
}
