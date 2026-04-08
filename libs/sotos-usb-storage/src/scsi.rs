//! SCSI command builders for USB Mass Storage.
//!
//! Implements the SCSI Transparent Command Set commands commonly used
//! with USB Mass Storage devices.

// ---------------------------------------------------------------------------
// SCSI opcodes
// ---------------------------------------------------------------------------

/// TEST UNIT READY — check if device is ready.
pub const SCSI_TEST_UNIT_READY: u8 = 0x00;
/// REQUEST SENSE — retrieve sense data after an error.
pub const SCSI_REQUEST_SENSE: u8 = 0x03;
/// INQUIRY — retrieve device identification.
pub const SCSI_INQUIRY: u8 = 0x12;
/// READ CAPACITY (10) — retrieve device capacity.
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;
/// READ (10) — read data from device.
pub const SCSI_READ_10: u8 = 0x28;
/// WRITE (10) — write data to device.
pub const SCSI_WRITE_10: u8 = 0x2A;
/// SYNCHRONIZE CACHE (10) — flush write cache.
pub const SCSI_SYNC_CACHE_10: u8 = 0x35;
/// MODE SENSE (6) — retrieve mode parameters.
pub const SCSI_MODE_SENSE_6: u8 = 0x1A;
/// PREVENT/ALLOW MEDIUM REMOVAL.
pub const SCSI_PREVENT_ALLOW_REMOVAL: u8 = 0x1E;
/// START STOP UNIT.
pub const SCSI_START_STOP_UNIT: u8 = 0x1B;

// ---------------------------------------------------------------------------
// SCSI CDB builders — each returns (cdb_bytes, cdb_length)
// ---------------------------------------------------------------------------

/// Build a TEST UNIT READY CDB (6 bytes).
pub fn test_unit_ready() -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_TEST_UNIT_READY;
    // Bytes 1-5 are zero.
    (cdb, 6)
}

/// Build a REQUEST SENSE CDB (6 bytes).
///
/// - `alloc_len`: Number of bytes to allocate for response (typically 18).
pub fn request_sense(alloc_len: u8) -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_REQUEST_SENSE;
    cdb[4] = alloc_len;
    (cdb, 6)
}

/// Build an INQUIRY CDB (6 bytes).
///
/// - `alloc_len`: Allocation length (typically 36 for standard inquiry).
pub fn inquiry(alloc_len: u8) -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_INQUIRY;
    cdb[4] = alloc_len;
    (cdb, 6)
}

/// Build a READ CAPACITY (10) CDB (10 bytes).
pub fn read_capacity_10() -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_READ_CAPACITY_10;
    (cdb, 10)
}

/// Build a READ (10) CDB (10 bytes).
///
/// - `lba`: Logical Block Address (32-bit).
/// - `count`: Number of blocks to read (16-bit).
pub fn read_10(lba: u32, count: u16) -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_READ_10;
    // LBA in bytes 2-5 (big-endian).
    cdb[2] = ((lba >> 24) & 0xFF) as u8;
    cdb[3] = ((lba >> 16) & 0xFF) as u8;
    cdb[4] = ((lba >> 8) & 0xFF) as u8;
    cdb[5] = (lba & 0xFF) as u8;
    // Transfer length in bytes 7-8 (big-endian).
    cdb[7] = ((count >> 8) & 0xFF) as u8;
    cdb[8] = (count & 0xFF) as u8;
    (cdb, 10)
}

/// Build a WRITE (10) CDB (10 bytes).
///
/// - `lba`: Logical Block Address (32-bit).
/// - `count`: Number of blocks to write (16-bit).
pub fn write_10(lba: u32, count: u16) -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_WRITE_10;
    // LBA in bytes 2-5 (big-endian).
    cdb[2] = ((lba >> 24) & 0xFF) as u8;
    cdb[3] = ((lba >> 16) & 0xFF) as u8;
    cdb[4] = ((lba >> 8) & 0xFF) as u8;
    cdb[5] = (lba & 0xFF) as u8;
    // Transfer length in bytes 7-8 (big-endian).
    cdb[7] = ((count >> 8) & 0xFF) as u8;
    cdb[8] = (count & 0xFF) as u8;
    (cdb, 10)
}

/// Build a SYNCHRONIZE CACHE (10) CDB (10 bytes).
pub fn sync_cache_10() -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_SYNC_CACHE_10;
    (cdb, 10)
}

// ---------------------------------------------------------------------------
// SCSI response parsers
// ---------------------------------------------------------------------------

/// Standard INQUIRY response data (36 bytes minimum).
#[derive(Clone, Copy)]
pub struct InquiryResponse {
    /// Peripheral device type (bits 4:0 of byte 0).
    pub device_type: u8,
    /// Removable media (bit 7 of byte 1).
    pub removable: bool,
    /// Vendor identification (bytes 8-15, ASCII).
    pub vendor: [u8; 8],
    /// Product identification (bytes 16-31, ASCII).
    pub product: [u8; 16],
    /// Product revision level (bytes 32-35, ASCII).
    pub revision: [u8; 4],
}

impl InquiryResponse {
    /// Parse an INQUIRY response from a byte buffer (min 36 bytes).
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 36 {
            return None;
        }
        let mut vendor = [0u8; 8];
        let mut product = [0u8; 16];
        let mut revision = [0u8; 4];
        vendor.copy_from_slice(&buf[8..16]);
        product.copy_from_slice(&buf[16..32]);
        revision.copy_from_slice(&buf[32..36]);
        Some(Self {
            device_type: buf[0] & 0x1F,
            removable: buf[1] & 0x80 != 0,
            vendor,
            product,
            revision,
        })
    }
}

// SCSI peripheral device types (SPC-3 Table 82).
/// Direct access block device (e.g. HDD/SSD/USB stick) — `0x00`.
pub const PDT_DIRECT_ACCESS: u8 = 0x00;
/// CD/DVD-ROM device — `0x05`.
pub const PDT_CDROM: u8 = 0x05;
/// Optical memory device — `0x07`.
pub const PDT_OPTICAL: u8 = 0x07;

/// READ CAPACITY (10) response (8 bytes).
#[derive(Clone, Copy)]
pub struct ReadCapacity10Response {
    /// Last logical block address (0-based, so total blocks = last_lba + 1).
    pub last_lba: u32,
    /// Logical block length in bytes (typically 512).
    pub block_length: u32,
}

impl ReadCapacity10Response {
    /// Parse from an 8-byte buffer (big-endian).
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let last_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let block_length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(Self { last_lba, block_length })
    }

    /// Total capacity in bytes.
    pub fn total_bytes(&self) -> u64 {
        (self.last_lba as u64 + 1) * self.block_length as u64
    }

    /// Total number of blocks.
    pub fn total_blocks(&self) -> u64 {
        self.last_lba as u64 + 1
    }
}

/// REQUEST SENSE response (18 bytes minimum).
#[derive(Clone, Copy)]
pub struct SenseData {
    /// Response code (bits 6:0 of byte 0).
    pub response_code: u8,
    /// Sense key (bits 3:0 of byte 2).
    pub sense_key: u8,
    /// Additional sense code (byte 12).
    pub asc: u8,
    /// Additional sense code qualifier (byte 13).
    pub ascq: u8,
}

impl SenseData {
    /// Parse from a byte buffer (min 14 bytes for ASC/ASCQ).
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 14 {
            return None;
        }
        Some(Self {
            response_code: buf[0] & 0x7F,
            sense_key: buf[2] & 0x0F,
            asc: buf[12],
            ascq: buf[13],
        })
    }
}

// SCSI Sense Keys (SPC-3 §4.5.6).
/// `0x0` — no specific sense information.
pub const SENSE_NO_SENSE: u8 = 0x00;
/// `0x1` — command completed after automatic recovery.
pub const SENSE_RECOVERED_ERROR: u8 = 0x01;
/// `0x2` — logical unit not ready (e.g. spinning up, no medium).
pub const SENSE_NOT_READY: u8 = 0x02;
/// `0x3` — unrecoverable medium error (bad sector).
pub const SENSE_MEDIUM_ERROR: u8 = 0x03;
/// `0x4` — hardware failure detected by the device.
pub const SENSE_HARDWARE_ERROR: u8 = 0x04;
/// `0x5` — illegal CDB field or parameter.
pub const SENSE_ILLEGAL_REQUEST: u8 = 0x05;
/// `0x6` — unit attention (medium change, reset, etc.).
pub const SENSE_UNIT_ATTENTION: u8 = 0x06;
/// `0x7` — write attempted on write-protected medium.
pub const SENSE_DATA_PROTECT: u8 = 0x07;
