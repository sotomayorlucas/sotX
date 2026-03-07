//! FAT32 filesystem support via the `embedded-sdmmc` crate.
//!
//! Provides a `VirtioBlkDevice` adapter implementing the `BlockDevice` trait,
//! enabling standard FAT32 read/write on the MBR boot partition.

use sotos_virtio::blk::VirtioBlk;
use embedded_sdmmc::{Block, BlockCount, BlockDevice, BlockIdx, TimeSource, Timestamp};

// Re-export types needed by consumers.
pub use embedded_sdmmc::{self, VolumeManager, VolumeIdx};

/// FAT32 boot partition starts at LBA 2048 (1 MiB aligned, set by mkimage.py).
pub const BOOT_PARTITION_LBA: u64 = 2048;

/// Error type for block I/O.
#[derive(Debug, Clone, Copy)]
pub struct FatIoError;

/// Block device adapter wrapping VirtioBlk for embedded-sdmmc.
/// Uses a raw pointer to VirtioBlk for interior mutability (`BlockDevice::read` takes `&self`).
pub struct VirtioBlkDevice {
    blk: *mut VirtioBlk,
    capacity: u64,
}

impl VirtioBlkDevice {
    /// Create a new FAT block device adapter.
    ///
    /// # Safety
    /// `blk` must point to a valid, initialized VirtioBlk that remains valid
    /// for the lifetime of this struct. Caller must ensure no concurrent access.
    pub unsafe fn new(blk: *mut VirtioBlk) -> Self {
        let capacity = (*blk).capacity;
        Self { blk, capacity }
    }
}

impl BlockDevice for VirtioBlkDevice {
    type Error = FatIoError;

    fn read(
        &self,
        blocks: &mut [Block],
        start_block_idx: BlockIdx,
        _reason: &str,
    ) -> Result<(), Self::Error> {
        let blk = unsafe { &mut *self.blk };
        for (i, block) in blocks.iter_mut().enumerate() {
            let sector = start_block_idx.0 as u64 + i as u64;
            blk.read_sector(sector).map_err(|_| FatIoError)?;
            let src = unsafe { core::slice::from_raw_parts(blk.data_ptr(), 512) };
            block.contents.copy_from_slice(src);
        }
        Ok(())
    }

    fn write(&self, blocks: &[Block], start_block_idx: BlockIdx) -> Result<(), Self::Error> {
        let blk = unsafe { &mut *self.blk };
        for (i, block) in blocks.iter().enumerate() {
            let sector = start_block_idx.0 as u64 + i as u64;
            let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), 512) };
            dst.copy_from_slice(&block.contents);
            blk.write_sector(sector).map_err(|_| FatIoError)?;
        }
        Ok(())
    }

    fn num_blocks(&self) -> Result<BlockCount, Self::Error> {
        Ok(BlockCount(self.capacity as u32))
    }
}

/// Fixed timestamp source (2026-01-01 00:00:00) for FAT directory entries.
pub struct FixedTimeSource;

impl TimeSource for FixedTimeSource {
    fn get_timestamp(&self) -> Timestamp {
        Timestamp {
            year_since_1970: 56, // 2026
            zero_indexed_month: 0,
            zero_indexed_day: 0,
            hours: 0,
            minutes: 0,
            seconds: 0,
        }
    }
}
