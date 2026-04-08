//! Frame Information Structure (FIS) types for SATA communication.
//!
//! FIS structures are used for communication between the host and device
//! in the AHCI command protocol.

// ---------------------------------------------------------------------------
// FIS Type identifiers
// ---------------------------------------------------------------------------

/// Register FIS — Host to Device.
pub const FIS_TYPE_REG_H2D: u8 = 0x27;
/// Register FIS — Device to Host.
pub const FIS_TYPE_REG_D2H: u8 = 0x34;
/// DMA Activate FIS — Device to Host.
pub const FIS_TYPE_DMA_ACT: u8 = 0x39;
/// DMA Setup FIS — Bidirectional.
pub const FIS_TYPE_DMA_SETUP: u8 = 0x41;
/// Data FIS — Bidirectional.
pub const FIS_TYPE_DATA: u8 = 0x46;
/// BIST Activate FIS — Bidirectional.
pub const FIS_TYPE_BIST: u8 = 0x58;
/// PIO Setup FIS — Device to Host.
pub const FIS_TYPE_PIO_SETUP: u8 = 0x5F;
/// Set Device Bits FIS — Device to Host.
pub const FIS_TYPE_DEV_BITS: u8 = 0xA1;

// ---------------------------------------------------------------------------
// ATA Commands
// ---------------------------------------------------------------------------

/// IDENTIFY DEVICE command.
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
/// READ DMA EXT (48-bit LBA).
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// WRITE DMA EXT (48-bit LBA).
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
/// FLUSH CACHE EXT.
pub const ATA_CMD_FLUSH_EXT: u8 = 0xEA;
/// SET FEATURES.
pub const ATA_CMD_SET_FEATURES: u8 = 0xEF;
/// READ SECTORS EXT (PIO, 48-bit LBA).
pub const ATA_CMD_READ_SECTORS_EXT: u8 = 0x24;
/// WRITE SECTORS EXT (PIO, 48-bit LBA).
pub const ATA_CMD_WRITE_SECTORS_EXT: u8 = 0x34;

// ---------------------------------------------------------------------------
// Register FIS — Host to Device (20 bytes, padded to DWORD boundary)
// ---------------------------------------------------------------------------

/// Host-to-Device Register FIS (20 bytes).
///
/// Used to send ATA commands from the host to the device.
/// Stored in the Command FIS area of the Command Table.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FisRegH2D {
    /// FIS Type = 0x27.
    pub fis_type: u8,
    /// Bit 7 = C (command/control), bits 3:0 = port multiplier.
    pub pm_c: u8,
    /// ATA Command register.
    pub command: u8,
    /// ATA Features register (7:0).
    pub features_lo: u8,

    /// LBA bits 7:0.
    pub lba0: u8,
    /// LBA bits 15:8.
    pub lba1: u8,
    /// LBA bits 23:16.
    pub lba2: u8,
    /// Device register (bit 6 = LBA mode).
    pub device: u8,

    /// LBA bits 31:24 (for 48-bit LBA).
    pub lba3: u8,
    /// LBA bits 39:32 (for 48-bit LBA).
    pub lba4: u8,
    /// LBA bits 47:40 (for 48-bit LBA).
    pub lba5: u8,
    /// ATA Features register (15:8).
    pub features_hi: u8,

    /// Sector Count (7:0).
    pub count_lo: u8,
    /// Sector Count (15:8).
    pub count_hi: u8,
    /// Reserved.
    pub _rsv0: u8,
    /// ATA Control register.
    pub control: u8,

    /// Reserved (pad to 20 bytes).
    pub _rsv1: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<FisRegH2D>() == 20);

impl FisRegH2D {
    /// Create a zeroed H2D FIS.
    pub const fn zeroed() -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            pm_c: 0,
            command: 0,
            features_lo: 0,
            lba0: 0, lba1: 0, lba2: 0,
            device: 0,
            lba3: 0, lba4: 0, lba5: 0,
            features_hi: 0,
            count_lo: 0, count_hi: 0,
            _rsv0: 0,
            control: 0,
            _rsv1: [0; 4],
        }
    }

    /// Create an IDENTIFY DEVICE command FIS.
    pub const fn identify() -> Self {
        let mut fis = Self::zeroed();
        fis.pm_c = 0x80; // C bit = 1 (command)
        fis.command = ATA_CMD_IDENTIFY;
        fis.device = 0; // Master device
        fis
    }

    /// Create a READ DMA EXT command FIS.
    ///
    /// - `lba`: 48-bit logical block address.
    /// - `count`: Number of sectors to read (0 = 65536).
    pub const fn read_dma_ext(lba: u64, count: u16) -> Self {
        let mut fis = Self::zeroed();
        fis.pm_c = 0x80; // C bit = 1 (command)
        fis.command = ATA_CMD_READ_DMA_EXT;
        fis.device = 1 << 6; // LBA mode

        fis.lba0 = (lba & 0xFF) as u8;
        fis.lba1 = ((lba >> 8) & 0xFF) as u8;
        fis.lba2 = ((lba >> 16) & 0xFF) as u8;
        fis.lba3 = ((lba >> 24) & 0xFF) as u8;
        fis.lba4 = ((lba >> 32) & 0xFF) as u8;
        fis.lba5 = ((lba >> 40) & 0xFF) as u8;

        fis.count_lo = (count & 0xFF) as u8;
        fis.count_hi = ((count >> 8) & 0xFF) as u8;
        fis
    }

    /// Create a WRITE DMA EXT command FIS.
    ///
    /// - `lba`: 48-bit logical block address.
    /// - `count`: Number of sectors to write (0 = 65536).
    pub const fn write_dma_ext(lba: u64, count: u16) -> Self {
        let mut fis = Self::zeroed();
        fis.pm_c = 0x80; // C bit = 1 (command)
        fis.command = ATA_CMD_WRITE_DMA_EXT;
        fis.device = 1 << 6; // LBA mode

        fis.lba0 = (lba & 0xFF) as u8;
        fis.lba1 = ((lba >> 8) & 0xFF) as u8;
        fis.lba2 = ((lba >> 16) & 0xFF) as u8;
        fis.lba3 = ((lba >> 24) & 0xFF) as u8;
        fis.lba4 = ((lba >> 32) & 0xFF) as u8;
        fis.lba5 = ((lba >> 40) & 0xFF) as u8;

        fis.count_lo = (count & 0xFF) as u8;
        fis.count_hi = ((count >> 8) & 0xFF) as u8;
        fis
    }

    /// Create a FLUSH CACHE EXT command FIS.
    pub const fn flush_ext() -> Self {
        let mut fis = Self::zeroed();
        fis.pm_c = 0x80;
        fis.command = ATA_CMD_FLUSH_EXT;
        fis.device = 1 << 6;
        fis
    }

    /// Extract 48-bit LBA from this FIS.
    pub const fn lba(&self) -> u64 {
        (self.lba0 as u64)
            | ((self.lba1 as u64) << 8)
            | ((self.lba2 as u64) << 16)
            | ((self.lba3 as u64) << 24)
            | ((self.lba4 as u64) << 32)
            | ((self.lba5 as u64) << 40)
    }

    /// Extract sector count from this FIS.
    pub const fn sector_count(&self) -> u16 {
        (self.count_lo as u16) | ((self.count_hi as u16) << 8)
    }
}

// ---------------------------------------------------------------------------
// Register FIS — Device to Host (20 bytes)
// ---------------------------------------------------------------------------

/// Device-to-Host Register FIS (20 bytes).
///
/// Received from the device in response to a command.
/// Stored in the Received FIS area (RFIS offset 0x40).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FisRegD2H {
    /// FIS Type = 0x34.
    pub fis_type: u8,
    /// Bit 6 = I (interrupt), bits 3:0 = port multiplier.
    pub pm_i: u8,
    /// ATA Status register.
    pub status: u8,
    /// ATA Error register.
    pub error: u8,

    /// LBA bits 7:0.
    pub lba0: u8,
    /// LBA bits 15:8.
    pub lba1: u8,
    /// LBA bits 23:16.
    pub lba2: u8,
    /// Device register.
    pub device: u8,

    /// LBA bits 31:24.
    pub lba3: u8,
    /// LBA bits 39:32.
    pub lba4: u8,
    /// LBA bits 47:40.
    pub lba5: u8,
    /// Reserved.
    pub _rsv0: u8,

    /// Sector Count (7:0).
    pub count_lo: u8,
    /// Sector Count (15:8).
    pub count_hi: u8,
    /// Reserved.
    pub _rsv1: [u8; 6],
}

const _: () = assert!(core::mem::size_of::<FisRegD2H>() == 20);

// ---------------------------------------------------------------------------
// PIO Setup FIS — Device to Host (20 bytes)
// ---------------------------------------------------------------------------

/// PIO Setup FIS — Device to Host (20 bytes).
///
/// Used for PIO data transfers (e.g., IDENTIFY DEVICE response).
/// Stored in the Received FIS area (RFIS offset 0x20).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FisPioSetup {
    /// FIS Type = 0x5F.
    pub fis_type: u8,
    /// Bit 6 = I (interrupt), bit 5 = D (direction), bits 3:0 = PM port.
    pub pm_id: u8,
    /// ATA Status register.
    pub status: u8,
    /// ATA Error register.
    pub error: u8,

    /// LBA bits 7:0.
    pub lba0: u8,
    /// LBA bits 15:8.
    pub lba1: u8,
    /// LBA bits 23:16.
    pub lba2: u8,
    /// Device register.
    pub device: u8,

    /// LBA bits 31:24.
    pub lba3: u8,
    /// LBA bits 39:32.
    pub lba4: u8,
    /// LBA bits 47:40.
    pub lba5: u8,
    /// Reserved.
    pub _rsv0: u8,

    /// Sector Count (7:0).
    pub count_lo: u8,
    /// Sector Count (15:8).
    pub count_hi: u8,
    /// Reserved.
    pub _rsv1: u8,
    /// New value of ATA Status register (E_Status).
    pub e_status: u8,

    /// Transfer Count (bytes to transfer in this PIO burst).
    pub tc: u16,
    /// Reserved.
    pub _rsv2: [u8; 2],
}

const _: () = assert!(core::mem::size_of::<FisPioSetup>() == 20);

// ---------------------------------------------------------------------------
// DMA Setup FIS — Bidirectional (28 bytes)
// ---------------------------------------------------------------------------

/// DMA Setup FIS (28 bytes).
///
/// Used to initiate DMA transfers. Contains DMA buffer identifiers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FisDmaSetup {
    /// FIS Type = 0x41.
    pub fis_type: u8,
    /// Bits: PM port (3:0), reserved, D (direction), I (interrupt), A (auto-activate).
    pub pm_dia: u8,
    /// Reserved.
    pub _rsv0: [u8; 2],

    /// DMA Buffer Identifier Low.
    pub dma_buf_id_lo: u32,
    /// DMA Buffer Identifier High.
    pub dma_buf_id_hi: u32,
    /// Reserved.
    pub _rsv1: u32,
    /// DMA Buffer Offset.
    pub dma_buf_offset: u32,
    /// DMA Transfer Count.
    pub dma_transfer_count: u32,
    /// Reserved.
    pub _rsv2: u32,
}

const _: () = assert!(core::mem::size_of::<FisDmaSetup>() == 28);

// ---------------------------------------------------------------------------
// Set Device Bits FIS — Device to Host (8 bytes)
// ---------------------------------------------------------------------------

/// Set Device Bits FIS — Device to Host (8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FisDevBits {
    /// FIS Type = 0xA1.
    pub fis_type: u8,
    /// Bit 6 = I (interrupt), bit 5 = N (notification), bits 3:0 = PM port.
    pub pm_in: u8,
    /// Status Low (bits 2:0) | Status High (bits 6:4).
    pub status: u8,
    /// Error register.
    pub error: u8,
    /// Protocol specific (SActive for NCQ).
    pub protocol: u32,
}

const _: () = assert!(core::mem::size_of::<FisDevBits>() == 8);

// ---------------------------------------------------------------------------
// Received FIS structure (256 bytes, per port)
// ---------------------------------------------------------------------------

/// Received FIS area for a port (256 bytes).
///
/// The HBA writes incoming FIS data to this structure.
/// Must be 256-byte aligned.
#[repr(C, align(256))]
pub struct ReceivedFis {
    /// DMA Setup FIS (offset 0x00, 28 bytes + 4 reserved).
    pub dma_setup: [u8; 32],
    /// PIO Setup FIS (offset 0x20, 20 bytes + 12 reserved).
    pub pio_setup: [u8; 32],
    /// D2H Register FIS (offset 0x40, 20 bytes + 12 reserved).
    pub d2h_reg: [u8; 32],
    /// Set Device Bits FIS (offset 0x58... but for alignment we place at 0x60).
    pub dev_bits: [u8; 8],
    /// Unknown FIS (offset 0x60, up to 64 bytes).
    pub unknown: [u8; 64],
    /// Reserved (pad to 256 bytes).
    pub _reserved: [u8; 88],
}

const _: () = assert!(core::mem::size_of::<ReceivedFis>() == 256);

impl ReceivedFis {
    /// All-zeros 256-byte Received FIS area — use to initialize the
    /// backing page before handing it to the HBA.
    pub const fn zeroed() -> Self {
        Self {
            dma_setup: [0; 32],
            pio_setup: [0; 32],
            d2h_reg: [0; 32],
            dev_bits: [0; 8],
            unknown: [0; 64],
            _reserved: [0; 88],
        }
    }
}
