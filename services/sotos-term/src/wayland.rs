//! Minimal Wayland client helpers -- wire protocol wrangling for sotos-term.
//!
//! This mirrors the layout hello-gui uses (`services/hello-gui/src/main.rs`):
//! one IpcMsg per wire message, 8 regs * 8 bytes = 64 bytes of payload, with
//! a `tag` that encodes the op type + wire size.
//!
//! The compositor side is defined by `services/compositor/src/wayland/` and
//! `services/compositor/src/main.rs`.

use sotos_common::{sys, IpcMsg};

/// Tag for plain Wayland requests (IPC-wrapped wire bytes).
pub const WL_MSG_TAG: u64 = 0x574C;
/// Tag for the initial CONNECT handshake.
pub const WL_CONNECT_TAG: u64 = 0x574C_434F;
/// Tag for the shm_pool-creation confirmation reply (carries shm handle).
pub const WL_SHM_POOL_TAG: u64 = 0x574C_5348;

/// Maximum bytes per IPC payload = 8 regs * 8 bytes.
pub const IPC_DATA_MAX: usize = 64;

/// Wayland object IDs (wl_display is always 1).
pub const WL_DISPLAY_ID: u32 = 1;

// Client-allocated object IDs. Keeping them as plain constants keeps the
// code flat -- sotos-term only ever needs one of each.
pub const REGISTRY_ID: u32 = 2;
pub const SHM_ID: u32 = 3;
pub const COMPOSITOR_ID: u32 = 4;
pub const XDG_WM_BASE_ID: u32 = 5;
pub const SEAT_ID: u32 = 6;
pub const POOL_ID: u32 = 7;
pub const BUFFER_ID: u32 = 8;
pub const SURFACE_ID: u32 = 9;
pub const XDG_SURFACE_ID: u32 = 10;
pub const XDG_TOPLEVEL_ID: u32 = 11;
pub const KEYBOARD_ID: u32 = 12;
pub const POINTER_ID: u32 = 13;

/// Build a Wayland wire message in a byte buffer.
pub struct WireBuilder {
    buf: [u8; IPC_DATA_MAX],
    len: usize,
}

impl WireBuilder {
    pub fn new(object_id: u32, opcode: u16) -> Self {
        let mut b = Self {
            buf: [0u8; IPC_DATA_MAX],
            len: 8, // header reserved
        };
        b.buf[0..4].copy_from_slice(&object_id.to_ne_bytes());
        let op = (opcode as u32).to_ne_bytes();
        b.buf[4..8].copy_from_slice(&op);
        b
    }

    pub fn put_u32(&mut self, val: u32) {
        self.buf[self.len..self.len + 4].copy_from_slice(&val.to_ne_bytes());
        self.len += 4;
    }

    pub fn put_i32(&mut self, val: i32) {
        self.put_u32(val as u32);
    }

    pub fn put_string(&mut self, s: &[u8]) {
        let len_with_nul = s.len() + 1;
        self.put_u32(len_with_nul as u32);
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.buf[self.len + s.len()] = 0;
        let padded = (len_with_nul + 3) & !3;
        self.len += padded;
    }

    /// Finalize -- pack header+payload into an IpcMsg ready for `sys::call`.
    pub fn finish(&mut self) -> IpcMsg {
        // Write the (size << 16) | opcode word.
        let op_lo =
            u32::from_ne_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]) & 0xFFFF;
        let size_opcode = ((self.len as u32) << 16) | op_lo;
        self.buf[4..8].copy_from_slice(&size_opcode.to_ne_bytes());

        let mut msg = IpcMsg::empty();
        msg.tag = WL_MSG_TAG | ((self.len as u64) << 16);
        let dst = &mut msg.regs as *mut u64 as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(self.buf.as_ptr(), dst, self.len);
        }
        msg
    }
}

/// Send a Wayland message synchronously; returns empty IpcMsg on error.
pub fn wl_call(ep: u64, msg: &IpcMsg) -> IpcMsg {
    match sys::call(ep, msg) {
        Ok(reply) => reply,
        Err(_) => IpcMsg::empty(),
    }
}

/// Fire-and-forget -- used when we know the reply is discardable.
pub fn wl_call_noreply(ep: u64, msg: &IpcMsg) {
    let _ = sys::call(ep, msg);
}

/// Extract raw wire bytes from an IPC message.
///
/// Returns the number of valid bytes extracted. The wire data is stored
/// in the IPC registers as raw bytes; the message tag encodes the byte
/// count in bits 16..31.
pub fn ipc_to_wire(msg: &IpcMsg, out: &mut [u8; IPC_DATA_MAX]) -> usize {
    let n = ((msg.tag >> 16) & 0xFFFF) as usize;
    let n = n.min(IPC_DATA_MAX);
    let src = &msg.regs as *const u64 as *const u8;
    unsafe {
        core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), n);
    }
    n
}
