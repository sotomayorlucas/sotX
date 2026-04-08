//! Bulk-Only Transport (BBB) protocol structures.
//!
//! The USB Mass Storage Bulk-Only Transport uses three stages:
//! 1. Command stage — host sends CBW on Bulk-OUT endpoint.
//! 2. Data stage — optional data transfer on Bulk-IN or Bulk-OUT.
//! 3. Status stage — device sends CSW on Bulk-IN endpoint.

// ---------------------------------------------------------------------------
// Command Block Wrapper (CBW) — 31 bytes
// ---------------------------------------------------------------------------

/// CBW Signature: "USBC" = 0x43425355 (little-endian).
pub const CBW_SIGNATURE: u32 = 0x43425355;

/// Maximum command block length in a CBW.
pub const CBW_MAX_CB_LEN: usize = 16;

/// CBW size in bytes.
pub const CBW_SIZE: usize = 31;

/// Command Block Wrapper — sent from host to device on Bulk-OUT.
///
/// Note: This is 31 bytes, which is not naturally aligned. We use
/// a byte-serializable representation.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Cbw {
    /// Signature — must be `CBW_SIGNATURE` (0x43425355).
    pub signature: u32,
    /// Tag — unique per-command identifier, echoed back in CSW.
    pub tag: u32,
    /// Data Transfer Length — number of bytes host expects to transfer.
    pub data_transfer_length: u32,
    /// Flags — bit 7: 0 = Data-Out (host-to-device), 1 = Data-In (device-to-host).
    pub flags: u8,
    /// LUN — Logical Unit Number (bits 3:0).
    pub lun: u8,
    /// CB Length — length of the command block (1-16).
    pub cb_length: u8,
    /// Command Block — SCSI CDB (up to 16 bytes).
    pub cb: [u8; CBW_MAX_CB_LEN],
}

const _: () = assert!(core::mem::size_of::<Cbw>() == CBW_SIZE);

// CBW direction flags (USB MSC 1.0 §5.1).
/// `bmCBWFlags` bit 7 set: data moves device-to-host (IN).
pub const CBW_FLAG_DATA_IN: u8 = 0x80;
/// `bmCBWFlags` bit 7 clear: data moves host-to-device (OUT).
pub const CBW_FLAG_DATA_OUT: u8 = 0x00;

impl Cbw {
    /// Create a zeroed CBW with the signature pre-set.
    pub const fn new() -> Self {
        Self {
            signature: CBW_SIGNATURE,
            tag: 0,
            data_transfer_length: 0,
            flags: 0,
            lun: 0,
            cb_length: 0,
            cb: [0; CBW_MAX_CB_LEN],
        }
    }

    /// Create a CBW for a Data-In (device-to-host) command.
    ///
    /// - `tag`: Unique command tag.
    /// - `data_len`: Expected number of bytes to read.
    /// - `lun`: Logical unit number.
    /// - `cdb`: SCSI Command Descriptor Block bytes.
    /// - `cdb_len`: Length of the CDB.
    pub fn data_in(tag: u32, data_len: u32, lun: u8, cdb: &[u8], cdb_len: u8) -> Self {
        let mut cbw = Self::new();
        cbw.tag = tag;
        cbw.data_transfer_length = data_len;
        cbw.flags = CBW_FLAG_DATA_IN;
        cbw.lun = lun & 0x0F;
        cbw.cb_length = cdb_len;
        let len = if cdb.len() > CBW_MAX_CB_LEN { CBW_MAX_CB_LEN } else { cdb.len() };
        cbw.cb[..len].copy_from_slice(&cdb[..len]);
        cbw
    }

    /// Create a CBW for a Data-Out (host-to-device) command.
    pub fn data_out(tag: u32, data_len: u32, lun: u8, cdb: &[u8], cdb_len: u8) -> Self {
        let mut cbw = Self::new();
        cbw.tag = tag;
        cbw.data_transfer_length = data_len;
        cbw.flags = CBW_FLAG_DATA_OUT;
        cbw.lun = lun & 0x0F;
        cbw.cb_length = cdb_len;
        let len = if cdb.len() > CBW_MAX_CB_LEN { CBW_MAX_CB_LEN } else { cdb.len() };
        cbw.cb[..len].copy_from_slice(&cdb[..len]);
        cbw
    }

    /// Create a CBW for a command with no data phase.
    pub fn no_data(tag: u32, lun: u8, cdb: &[u8], cdb_len: u8) -> Self {
        let mut cbw = Self::new();
        cbw.tag = tag;
        cbw.data_transfer_length = 0;
        cbw.flags = CBW_FLAG_DATA_IN; // Direction doesn't matter for no-data.
        cbw.lun = lun & 0x0F;
        cbw.cb_length = cdb_len;
        let len = if cdb.len() > CBW_MAX_CB_LEN { CBW_MAX_CB_LEN } else { cdb.len() };
        cbw.cb[..len].copy_from_slice(&cdb[..len]);
        cbw
    }

    /// Serialize the CBW to a byte array for transmission.
    pub fn to_bytes(&self) -> [u8; CBW_SIZE] {
        let mut buf = [0u8; CBW_SIZE];
        let sig = self.signature.to_le_bytes();
        let tag = self.tag.to_le_bytes();
        let dtl = self.data_transfer_length.to_le_bytes();
        buf[0..4].copy_from_slice(&sig);
        buf[4..8].copy_from_slice(&tag);
        buf[8..12].copy_from_slice(&dtl);
        buf[12] = self.flags;
        buf[13] = self.lun;
        buf[14] = self.cb_length;
        buf[15..31].copy_from_slice(&self.cb);
        buf
    }
}

// ---------------------------------------------------------------------------
// Command Status Wrapper (CSW) — 13 bytes
// ---------------------------------------------------------------------------

/// CSW Signature: "USBS" = 0x53425355 (little-endian).
pub const CSW_SIGNATURE: u32 = 0x53425355;

/// CSW size in bytes.
pub const CSW_SIZE: usize = 13;

// CSW Status values (USB MSC 1.0 §5.2).
/// Command Passed (`bCSWStatus = 0x00`).
pub const CSW_STATUS_PASSED: u8 = 0x00;
/// Command Failed (`bCSWStatus = 0x01`).
pub const CSW_STATUS_FAILED: u8 = 0x01;
/// Phase Error (`bCSWStatus = 0x02`) — host must reset the device.
pub const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

/// Command Status Wrapper — received from device on Bulk-IN.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Csw {
    /// Signature — must be `CSW_SIGNATURE` (0x53425355).
    pub signature: u32,
    /// Tag — must match the tag from the corresponding CBW.
    pub tag: u32,
    /// Data Residue — difference between expected and actual data transferred.
    pub data_residue: u32,
    /// Status — 0x00 = passed, 0x01 = failed, 0x02 = phase error.
    pub status: u8,
}

const _: () = assert!(core::mem::size_of::<Csw>() == CSW_SIZE);

impl Csw {
    /// Create a zeroed CSW.
    pub const fn zeroed() -> Self {
        Self {
            signature: 0,
            tag: 0,
            data_residue: 0,
            status: 0,
        }
    }

    /// Parse a CSW from a 13-byte buffer.
    pub fn from_bytes(buf: &[u8; CSW_SIZE]) -> Self {
        Self {
            signature: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            tag: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            data_residue: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            status: buf[12],
        }
    }

    /// Validate the CSW against an expected tag.
    pub fn validate(&self, expected_tag: u32) -> Result<(), CswError> {
        if self.signature != CSW_SIGNATURE {
            return Err(CswError::BadSignature);
        }
        if self.tag != expected_tag {
            return Err(CswError::TagMismatch);
        }
        match self.status {
            CSW_STATUS_PASSED => Ok(()),
            CSW_STATUS_FAILED => Err(CswError::CommandFailed),
            CSW_STATUS_PHASE_ERROR => Err(CswError::PhaseError),
            _ => Err(CswError::UnknownStatus(self.status)),
        }
    }

    /// Check if the command passed.
    pub fn passed(&self) -> bool {
        self.status == CSW_STATUS_PASSED
    }
}

/// CSW validation error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CswError {
    /// CSW signature is invalid.
    BadSignature,
    /// CSW tag does not match CBW tag.
    TagMismatch,
    /// Device reported command failure.
    CommandFailed,
    /// Phase error — requires reset recovery.
    PhaseError,
    /// Unknown status byte.
    UnknownStatus(u8),
}

// ---------------------------------------------------------------------------
// Bulk-Only Mass Storage Reset
// ---------------------------------------------------------------------------

/// USB class-specific request: Bulk-Only Mass Storage Reset.
/// bmRequestType = 0x21 (class, interface, host-to-device).
/// bRequest = 0xFF.
/// wValue = 0, wIndex = interface number, wLength = 0.
pub const BOMSR_REQUEST_TYPE: u8 = 0x21;
/// `bRequest` byte for Bulk-Only Mass Storage Reset.
pub const BOMSR_REQUEST: u8 = 0xFF;

/// USB standard request: Clear Feature (ENDPOINT_HALT).
/// Used to clear a stalled bulk endpoint after an error.
pub const CLEAR_FEATURE_REQUEST_TYPE: u8 = 0x02; // standard, endpoint, host-to-device
/// `bRequest` byte for `CLEAR_FEATURE`.
pub const CLEAR_FEATURE_REQUEST: u8 = 0x01;      // CLEAR_FEATURE
/// `wValue` for clearing the `ENDPOINT_HALT` feature on a stalled bulk endpoint.
pub const FEATURE_ENDPOINT_HALT: u16 = 0x0000;

/// USB class-specific request: Get Max LUN.
/// bmRequestType = 0xA1 (class, interface, device-to-host).
/// bRequest = 0xFE.
pub const GET_MAX_LUN_REQUEST_TYPE: u8 = 0xA1;
/// `bRequest` byte for Get Max LUN.
pub const GET_MAX_LUN_REQUEST: u8 = 0xFE;
