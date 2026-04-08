//! Block I/O -- maps rump bio requests to SOT device Secure Object invocation.
//!
//! The rump kernel issues block I/O via `rumpuser_bio(dev, offset, buf, len,
//! flags)`.  On SOT this becomes an IPC call to the appropriate block-device
//! service (virtio-blk, NVMe, AHCI) identified by a device capability.

use crate::{RumpError, SotCap};

/// Maximum registered block devices.
const MAX_DEVICES: usize = 16;

/// Transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    Read,
    Write,
}

/// A registered block device with its SOT capability.
#[derive(Debug, Clone, Copy)]
pub struct BlockDevice {
    /// Rump-side device number (used as lookup key).
    pub dev: u64,
    /// SOT capability for the block-device service endpoint.
    pub cap: SotCap,
    /// Sector size in bytes (typically 512).
    pub sector_size: u32,
}

/// Block device table.
pub struct BlockDeviceTable {
    devices: [Option<BlockDevice>; MAX_DEVICES],
    count: usize,
}

impl BlockDeviceTable {
    pub const fn new() -> Self {
        const NONE: Option<BlockDevice> = None;
        Self {
            devices: [NONE; MAX_DEVICES],
            count: 0,
        }
    }

    /// Register a block device that rump can issue I/O against.
    pub fn register(&mut self, dev: BlockDevice) -> Result<(), RumpError> {
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(dev);
                self.count += 1;
                return Ok(());
            }
        }
        Err(RumpError::OutOfMemory)
    }

    /// Look up a device by its rump dev number.
    pub fn lookup(&self, dev: u64) -> Option<&BlockDevice> {
        for slot in &self.devices {
            if let Some(ref d) = slot {
                if d.dev == dev {
                    return Some(d);
                }
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Maximum bytes per single IPC-based I/O transfer.
///
/// Larger requests are split into multiple IPC calls.  This matches the
/// SOT IPC inline data limit for block I/O (one page at a time via
/// shared-memory windows in practice, but the interface is byte-oriented).
const MAX_TRANSFER: usize = 4096;

/// Perform a block read via SOT IPC.
///
/// Reads `buf.len()` bytes starting at byte `offset` on device `dev`.
pub fn bio_read(
    devices: &BlockDeviceTable,
    dev: u64,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, RumpError> {
    let device = devices.lookup(dev).ok_or(RumpError::IoError(6))?; // ENXIO
    let _cap = device.cap;

    let mut done: usize = 0;
    while done < buf.len() {
        let chunk = (buf.len() - done).min(MAX_TRANSFER);
        let _chunk_offset = offset + done as u64;

        // TODO: SOT IPC call to block-device service:
        //   let reply = sot_sys::ipc_call(cap, &BioRequest {
        //       op: BioOp::Read,
        //       offset: chunk_offset,
        //       len: chunk,
        //   })?;
        //   buf[done..done+chunk].copy_from_slice(&reply.data[..chunk]);

        done += chunk;
    }

    Ok(done)
}

/// Perform a block write via SOT IPC.
///
/// Writes `buf.len()` bytes starting at byte `offset` on device `dev`.
pub fn bio_write(
    devices: &BlockDeviceTable,
    dev: u64,
    offset: u64,
    buf: &[u8],
) -> Result<usize, RumpError> {
    let device = devices.lookup(dev).ok_or(RumpError::IoError(6))?; // ENXIO
    let _cap = device.cap;

    let mut done: usize = 0;
    while done < buf.len() {
        let chunk = (buf.len() - done).min(MAX_TRANSFER);
        let _chunk_offset = offset + done as u64;

        // TODO: SOT IPC call to block-device service:
        //   sot_sys::ipc_call(cap, &BioRequest {
        //       op: BioOp::Write,
        //       offset: chunk_offset,
        //       data: &buf[done..done+chunk],
        //   })?;

        done += chunk;
    }

    Ok(done)
}
