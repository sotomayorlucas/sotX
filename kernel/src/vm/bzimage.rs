//! Phase F.4 — bzImage parser for the in-kernel Linux loader.
//!
//! Parses the Linux x86 boot setup header (kernel.org Documentation/
//! arch/x86/boot.rst) and extracts the fields the loader needs to lay
//! out the guest:
//!
//!   - `setup_sects` — number of 512-byte sectors of real-mode setup
//!     code that prefix the protected-mode kernel.
//!   - `init_size` — bytes the kernel needs to be loaded into (code +
//!     bss + stack reserved by the decompressor).
//!   - `relocatable_kernel` — 1 if we may load anywhere, 0 if we must
//!     respect `pref_address`.
//!   - `pref_address` — preferred load address (typically 0x100000).
//!   - `cmd_line_size` — max length of `cmd_line_ptr`.
//!   - `version` — protocol version (we require >= 2.0c for the
//!     64-bit handoff path).
//!
//! ## Layout
//!
//! ```text
//!   offset    field                       size
//!   ──────    ─────                       ────
//!   0x000     Real-mode setup code        setup_sects * 512 bytes
//!             (boot sector + setup)
//!   ──────
//!   0x1F1     setup_sects                 1
//!   0x202     header magic 'HdrS'         4
//!   0x206     version (le)                2
//!   0x210     loadflags                   1
//!   0x218     ramdisk_image (we set)      4
//!   0x21C     ramdisk_size  (we set)      4
//!   0x228     cmd_line_ptr  (we set)      4
//!   0x230     kernel_alignment            4
//!   0x234     relocatable_kernel          1
//!   0x238     cmdline_size                4
//!   0x260     init_size                   4
//!   0x264     handover_offset             4
//!   ──────
//!   (setup_sects + 1) * 512 onward:
//!             Compressed protected-mode kernel (vmlinux)
//!             — at boot we copy this to `pref_address` (0x100000)
//! ```
//!
//! After parse(), the loader knows:
//!   - the offset within the bzImage where the protected-mode payload
//!     starts (`prot_payload_offset`)
//!   - the byte length of that payload (`prot_payload_len`)
//!   - the load address (`pref_address`)
//!   - the bss reserve size (`init_size - prot_payload_len`)

use core::mem::size_of;

const HDR_MAGIC: &[u8; 4] = b"HdrS";

const OFF_SETUP_SECTS: usize = 0x1F1;
const OFF_MAGIC: usize = 0x202;
const OFF_VERSION: usize = 0x206;
#[allow(dead_code)] const OFF_LOADFLAGS: usize = 0x211;
#[allow(dead_code)] const OFF_RAMDISK_IMAGE: usize = 0x218;
#[allow(dead_code)] const OFF_RAMDISK_SIZE: usize = 0x21C;
#[allow(dead_code)] const OFF_CMD_LINE_PTR: usize = 0x228;
const OFF_KERNEL_ALIGNMENT: usize = 0x230;
const OFF_RELOCATABLE: usize = 0x234;
const OFF_CMDLINE_SIZE: usize = 0x238;
const OFF_PAYLOAD_OFFSET: usize = 0x248;
const OFF_PAYLOAD_LENGTH: usize = 0x24C;
const OFF_PREF_ADDRESS: usize = 0x258;
const OFF_INIT_SIZE: usize = 0x260;
const OFF_HANDOVER_OFFSET: usize = 0x264;

/// Errors raised while parsing or laying out a bzImage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BzImageError {
    /// Image is too small to even contain a setup header.
    Truncated,
    /// `HdrS` magic at offset 0x202 didn't match.
    BadMagic,
    /// Boot protocol version below 2.06 — too old for our 64-bit
    /// handoff path.
    UnsupportedProtocol(u16),
    /// `setup_sects + 1` * 512 doesn't fit inside the file.
    TruncatedSetup,
    /// `init_size` is unreasonably large (> 64 MiB).
    InitSizeTooLarge(u32),
}

/// Parsed bzImage descriptor. Contains everything the Phase F.4
/// loader needs to lay out the guest's memory and program the entry
/// state.
#[derive(Debug, Clone, Copy)]
pub struct BzImage<'a> {
    /// Whole bzImage byte slice (CPIO-mapped, lives for the kernel
    /// lifetime).
    pub bytes: &'a [u8],
    /// Number of 512-byte real-mode setup sectors. The
    /// protected-mode kernel starts at `(setup_sects + 1) * 512`.
    pub setup_sects: u32,
    /// Boot protocol version, packed as `(major << 8) | minor`.
    pub version: u16,
    /// 1 if the kernel can be loaded at any address (we still
    /// prefer `pref_address` for cleanliness).
    pub relocatable: bool,
    /// Required alignment of the load address (bytes, power of 2).
    pub kernel_alignment: u32,
    /// Maximum bytes of cmdline the kernel will accept.
    pub cmdline_size: u32,
    /// Preferred guest physical load address — 0x100000 (1 MiB) on
    /// every modern x86 kernel.
    pub pref_address: u64,
    /// Bytes the kernel needs to be loaded into. This is `>= the
    /// payload size` because of the BSS + decompressor scratch.
    pub init_size: u32,
    /// EFI handover entry offset (we don't use the EFI path, so this
    /// is informational only).
    #[allow(dead_code)]
    pub handover_offset: u32,
    /// Offset within `bytes` of the protected-mode kernel payload.
    pub prot_payload_offset: usize,
    /// Length of the protected-mode kernel payload.
    pub prot_payload_len: usize,
}

impl<'a> BzImage<'a> {
    /// Parse a Linux bzImage from a byte slice (typically returned by
    /// `vm::bzimage_slice()` after `load_initrd` finds the file).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BzImageError> {
        if bytes.len() < OFF_HANDOVER_OFFSET + size_of::<u32>() {
            return Err(BzImageError::Truncated);
        }
        // Validate magic.
        if &bytes[OFF_MAGIC..OFF_MAGIC + 4] != HDR_MAGIC {
            return Err(BzImageError::BadMagic);
        }
        let version = read_u16(bytes, OFF_VERSION);
        // 2.06 = 0x0206. Anything older lacks the relocatable +
        // 64-bit handoff fields we depend on.
        if version < 0x0206 {
            return Err(BzImageError::UnsupportedProtocol(version));
        }

        let setup_sects_raw = bytes[OFF_SETUP_SECTS] as u32;
        // Per the boot protocol: 0 means 4 (legacy default).
        let setup_sects = if setup_sects_raw == 0 { 4 } else { setup_sects_raw };

        let prot_payload_offset = (setup_sects as usize + 1) * 512;
        if prot_payload_offset >= bytes.len() {
            return Err(BzImageError::TruncatedSetup);
        }
        let prot_payload_len = bytes.len() - prot_payload_offset;

        let init_size = read_u32(bytes, OFF_INIT_SIZE);
        if init_size > 64 * 1024 * 1024 {
            return Err(BzImageError::InitSizeTooLarge(init_size));
        }

        let kernel_alignment = read_u32(bytes, OFF_KERNEL_ALIGNMENT);
        let pref_address = read_u64(bytes, OFF_PREF_ADDRESS);
        let cmdline_size = read_u32(bytes, OFF_CMDLINE_SIZE);
        let handover_offset = read_u32(bytes, OFF_HANDOVER_OFFSET);
        let relocatable = bytes[OFF_RELOCATABLE] != 0;

        // Sanity check: payload offset / length stored in the header
        // should match what we computed from setup_sects. We don't
        // hard-fail on a mismatch — Linux's own bzImage tooling has
        // been known to leave these zero on tiny test builds —
        // but we log it.
        let header_payload_offset = read_u32(bytes, OFF_PAYLOAD_OFFSET) as usize;
        let header_payload_length = read_u32(bytes, OFF_PAYLOAD_LENGTH) as usize;
        if header_payload_offset != 0 && header_payload_offset != prot_payload_offset {
            crate::kdebug!(
                "  bzImage: header.payload_offset={:#x} != computed {:#x}",
                header_payload_offset,
                prot_payload_offset
            );
        }
        if header_payload_length != 0 && header_payload_length != prot_payload_len {
            crate::kdebug!(
                "  bzImage: header.payload_length={:#x} != computed {:#x}",
                header_payload_length,
                prot_payload_len
            );
        }

        Ok(Self {
            bytes,
            setup_sects,
            version,
            relocatable,
            kernel_alignment,
            cmdline_size,
            pref_address,
            init_size,
            handover_offset,
            prot_payload_offset,
            prot_payload_len,
        })
    }

    /// Slice of the protected-mode kernel payload — what the loader
    /// copies to `pref_address` in guest physical memory.
    #[allow(dead_code)]
    pub fn prot_payload(&self) -> &'a [u8] {
        &self.bytes[self.prot_payload_offset..self.prot_payload_offset + self.prot_payload_len]
    }

    /// Slice of the real-mode setup code (boot sector + setup
    /// sectors). The 64-bit boot path doesn't run this code, but the
    /// header in its first sector is what we copy into `boot_params`.
    pub fn real_mode_setup(&self) -> &'a [u8] {
        &self.bytes[..self.prot_payload_offset]
    }

    /// Pretty-print the parsed fields to the boot log. Used as a
    /// one-time sanity check on the first SYS_VM_RUN.
    pub fn dump(&self) {
        crate::kprintln!(
            "  bzImage: ver={:#06x} setup_sects={} prot_payload={:#x}+{:#x} pref_addr={:#x} init_size={:#x} reloc={} align={:#x} cmdline_max={}",
            self.version,
            self.setup_sects,
            self.prot_payload_offset,
            self.prot_payload_len,
            self.pref_address,
            self.init_size,
            self.relocatable as u32,
            self.kernel_alignment,
            self.cmdline_size,
        );
    }
}

#[inline]
fn read_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

#[inline]
fn read_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

#[inline]
fn read_u64(bytes: &[u8], off: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[off..off + 8]);
    u64::from_le_bytes(buf)
}
