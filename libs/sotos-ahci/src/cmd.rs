//! AHCI Command List and Command Table structures.
//!
//! Each AHCI port has a Command List (up to 32 Command Headers) and
//! each header points to a Command Table containing the FIS and PRDT.

use crate::fis::FisRegH2D;

// ---------------------------------------------------------------------------
// Command Header (32 bytes each, 32 per Command List = 1 KiB)
// ---------------------------------------------------------------------------

/// AHCI Command Header (32 bytes).
///
/// Resides in the Command List. Each header describes one command slot.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommandHeader {
    /// DW0: Various flags and Command FIS Length.
    /// Bits 4:0 = CFL (Command FIS Length in DWORDs, e.g., 5 for H2D FIS).
    /// Bit 5 = A (ATAPI).
    /// Bit 6 = W (Write — 1 for device-write, 0 for device-read).
    /// Bit 7 = P (Prefetchable).
    /// Bit 8 = R (Reset).
    /// Bit 9 = B (BIST).
    /// Bit 10 = C (Clear Busy upon R_OK).
    /// Bits 15:11 = Reserved.
    /// Bits 20:16 = PRDTL (Physical Region Descriptor Table Length).
    pub flags_cfl_prdtl: u32,
    /// DW1: PRDBC — Physical Region Descriptor Byte Count (updated by HBA).
    pub prdbc: u32,
    /// DW2: CTBA — Command Table Base Address (128-byte aligned, lower 32 bits).
    pub ctba: u32,
    /// DW3: CTBA Upper — Command Table Base Address upper 32 bits.
    pub ctbau: u32,
    /// DW4-7: Reserved.
    pub _rsv: [u32; 4],
}

const _: () = assert!(core::mem::size_of::<CommandHeader>() == 32);

/// CFL (Command FIS Length) for a standard H2D Register FIS = 5 DWORDs (20 bytes).
pub const CFL_H2D: u32 = 5;

// Flag bits in `flags_cfl_prdtl` (AHCI 1.3.1 §4.2.2).
/// A (ATAPI) — command is an ATAPI PACKET command.
pub const CH_FLAG_ATAPI: u32 = 1 << 5;
/// W (Write) — data moves host-to-device.
pub const CH_FLAG_WRITE: u32 = 1 << 6;
/// P (Prefetchable) — HBA may prefetch PRDs.
pub const CH_FLAG_PREFETCH: u32 = 1 << 7;
/// R (Reset) — command is part of a device reset sequence.
pub const CH_FLAG_RESET: u32 = 1 << 8;
/// B (BIST) — command is a BIST sequence.
pub const CH_FLAG_BIST: u32 = 1 << 9;
/// C (Clear BSY on R_OK) — HBA should clear BSY on successful completion.
pub const CH_FLAG_CLEAR_BSY: u32 = 1 << 10;

impl CommandHeader {
    /// Create a zeroed command header.
    pub const fn zeroed() -> Self {
        Self {
            flags_cfl_prdtl: 0,
            prdbc: 0,
            ctba: 0,
            ctbau: 0,
            _rsv: [0; 4],
        }
    }

    /// Build a command header for a read operation.
    ///
    /// - `ctba_phys`: Physical address of the Command Table (128-byte aligned).
    /// - `prdtl`: Number of PRD entries in the table.
    pub fn new_read(ctba_phys: u64, prdtl: u16) -> Self {
        Self {
            flags_cfl_prdtl: CFL_H2D | ((prdtl as u32) << 16),
            prdbc: 0,
            ctba: ctba_phys as u32,
            ctbau: (ctba_phys >> 32) as u32,
            _rsv: [0; 4],
        }
    }

    /// Build a command header for a write operation.
    ///
    /// - `ctba_phys`: Physical address of the Command Table (128-byte aligned).
    /// - `prdtl`: Number of PRD entries in the table.
    pub fn new_write(ctba_phys: u64, prdtl: u16) -> Self {
        Self {
            flags_cfl_prdtl: CFL_H2D | CH_FLAG_WRITE | ((prdtl as u32) << 16),
            prdbc: 0,
            ctba: ctba_phys as u32,
            ctbau: (ctba_phys >> 32) as u32,
            _rsv: [0; 4],
        }
    }

    /// Extract PRDTL (number of PRDT entries) from this header.
    pub const fn prdtl(&self) -> u16 {
        ((self.flags_cfl_prdtl >> 16) & 0xFFFF) as u16
    }

    /// Get the 64-bit Command Table base address.
    pub const fn ctba_addr(&self) -> u64 {
        (self.ctba as u64) | ((self.ctbau as u64) << 32)
    }
}

// ---------------------------------------------------------------------------
// Command List (array of 32 Command Headers = 1024 bytes)
// ---------------------------------------------------------------------------

/// Maximum command slots per port.
pub const MAX_CMD_SLOTS: usize = 32;

/// Command List — array of command headers (1024 bytes, 1024-byte aligned).
#[repr(C, align(1024))]
pub struct CommandList {
    /// The 32 slot entries. `headers[i]` is programmed before
    /// issuing command `i` via `PORT_CI`.
    pub headers: [CommandHeader; MAX_CMD_SLOTS],
}

const _: () = assert!(core::mem::size_of::<CommandList>() == 1024);

impl CommandList {
    /// All-zeros Command List — used to initialize the per-port
    /// CLB page before setting `PORT_CLB`.
    pub const fn zeroed() -> Self {
        Self {
            headers: [CommandHeader::zeroed(); MAX_CMD_SLOTS],
        }
    }
}

// ---------------------------------------------------------------------------
// PRDT Entry (Physical Region Descriptor Table Entry, 16 bytes)
// ---------------------------------------------------------------------------

/// PRDT Entry — describes one scatter/gather DMA region (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrdtEntry {
    /// Data Base Address (lower 32 bits, 2-byte aligned).
    pub dba: u32,
    /// Data Base Address Upper 32 bits.
    pub dbau: u32,
    /// Reserved.
    pub _rsv: u32,
    /// DW3: Byte count (bits 21:0, 0-based: actual bytes - 1).
    /// Bit 31 = I (Interrupt on Completion).
    pub dbc_i: u32,
}

const _: () = assert!(core::mem::size_of::<PrdtEntry>() == 16);

/// Interrupt On Completion flag in PRDT DBC field.
pub const PRDT_IOC: u32 = 1 << 31;

/// Maximum bytes per PRDT entry (4 MB, 22 bits: 0x3FFFFF + 1 = 4194304).
pub const PRDT_MAX_BYTES: u32 = 4 * 1024 * 1024;

impl PrdtEntry {
    /// Create a zeroed PRDT entry.
    pub const fn zeroed() -> Self {
        Self { dba: 0, dbau: 0, _rsv: 0, dbc_i: 0 }
    }

    /// Create a PRDT entry.
    ///
    /// - `phys`: Physical address of the data buffer (2-byte aligned).
    /// - `byte_count`: Number of bytes in this region (must be even, max 4 MB).
    /// - `ioc`: Generate interrupt on completion of this entry.
    pub fn new(phys: u64, byte_count: u32, ioc: bool) -> Self {
        let mut dbc = (byte_count - 1) & 0x3FFFFF; // 22 bits, 0-based
        if ioc {
            dbc |= PRDT_IOC;
        }
        Self {
            dba: phys as u32,
            dbau: (phys >> 32) as u32,
            _rsv: 0,
            dbc_i: dbc,
        }
    }

    /// Extract byte count (1-based) from this entry.
    pub const fn byte_count(&self) -> u32 {
        (self.dbc_i & 0x3FFFFF) + 1
    }
}

// ---------------------------------------------------------------------------
// Command Table (128-byte aligned, variable size)
// ---------------------------------------------------------------------------

/// Maximum PRDT entries per command (enough for multi-page transfers).
pub const MAX_PRDT_ENTRIES: usize = 8;

/// AHCI Command Table.
///
/// Contains the Command FIS (up to 64 bytes), ATAPI Command (16 bytes),
/// reserved area, and the Physical Region Descriptor Table.
///
/// Must be 128-byte aligned. Size = 128 + PRDTL * 16.
#[repr(C, align(128))]
pub struct CommandTable {
    /// Command FIS (up to 64 bytes, only first 20 used for H2D Register FIS).
    pub cfis: [u8; 64],
    /// ATAPI Command (12-16 bytes, padded to 16).
    pub acmd: [u8; 16],
    /// Reserved.
    pub _rsv: [u8; 48],
    /// Physical Region Descriptor Table entries.
    pub prdt: [PrdtEntry; MAX_PRDT_ENTRIES],
}

const _: () = assert!(core::mem::size_of::<CommandTable>() == 128 + MAX_PRDT_ENTRIES * 16);

impl CommandTable {
    /// Create a zeroed command table.
    pub const fn zeroed() -> Self {
        Self {
            cfis: [0; 64],
            acmd: [0; 16],
            _rsv: [0; 48],
            prdt: [PrdtEntry::zeroed(); MAX_PRDT_ENTRIES],
        }
    }

    /// Write a Host-to-Device Register FIS into the CFIS area.
    pub fn set_cfis(&mut self, fis: &FisRegH2D) {
        let src = fis as *const FisRegH2D as *const u8;
        let dst = self.cfis.as_mut_ptr();
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst, core::mem::size_of::<FisRegH2D>());
        }
    }

    /// Set a single PRDT entry at the given index.
    pub fn set_prdt(&mut self, index: usize, entry: PrdtEntry) {
        if index < MAX_PRDT_ENTRIES {
            self.prdt[index] = entry;
        }
    }
}
