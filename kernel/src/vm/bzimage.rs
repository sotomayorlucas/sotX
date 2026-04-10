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

// ---------------------------------------------------------------------------
// Phase F.4.2 — boot_params builder
// ---------------------------------------------------------------------------
//
// `boot_params` is the contract between the bootloader (us) and the
// Linux 64-bit entry point: a 4 KiB blob whose first 0x1F1 bytes hold
// legacy fields we set to zero, then a copy of the bzImage's setup
// header at 0x1F1, then E820 entries starting at 0x2D0.
//
// Linux's bootparam.h is the canonical reference; field offsets are
// stable across kernel versions because they're part of the boot ABI.

/// Offset of `screen_info.ext_mem_k` (u16) — legacy BIOS-88 mem size.
const BP_SCREEN_EXT_MEM_K: usize = 0x002;
/// Offset of `alt_mem_k` (u32) — legacy BIOS-e801 alternate mem size.
const BP_ALT_MEM_K: usize = 0x1E0;
/// Offset of `e820_entries` (u8) inside boot_params.
const BP_E820_ENTRIES: usize = 0x1E8;
/// Offset of `sentinel` (u8) — must be 0 for newer kernels.
#[allow(dead_code)] const BP_SENTINEL: usize = 0x1EF;
/// Offset where the bzImage setup header starts inside boot_params.
const BP_HDR_OFFSET: usize = 0x1F1;
/// Length of the setup_header copy. boot_params reserves up to
/// 0x290 - 0x1F1 = 0x9F bytes; we copy that many from the bzImage.
const BP_HDR_LEN: usize = 0x290 - 0x1F1;
/// Offset of `e820_table` inside boot_params.
const BP_E820_TABLE: usize = 0x2D0;
/// Each E820 entry is 20 bytes: addr u64, size u64, type u32.
const E820_ENTRY_SIZE: usize = 20;
/// Maximum number of E820 entries we'll write.
pub const BP_E820_MAX: usize = 32;

// setup_header offsets (relative to BP_HDR_OFFSET / 0x1F1).
const HDR_OFF_TYPE_OF_LOADER: usize = 0x210 - BP_HDR_OFFSET;
const HDR_OFF_RAMDISK_IMAGE: usize = 0x218 - BP_HDR_OFFSET;
const HDR_OFF_RAMDISK_SIZE: usize = 0x21C - BP_HDR_OFFSET;
const HDR_OFF_CMD_LINE_PTR: usize = 0x228 - BP_HDR_OFFSET;
#[allow(dead_code)] const HDR_OFF_LOADFLAGS: usize = 0x211 - BP_HDR_OFFSET;

/// Linux E820 type constants.
#[allow(dead_code)]
pub mod e820_type {
    pub const USABLE: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIMABLE: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const BAD_MEMORY: u32 = 5;
}

/// One E820 entry as the kernel expects it on the wire (20 bytes).
#[derive(Debug, Clone, Copy)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub typ: u32,
}

/// Populate a 4 KiB `boot_params` blob in `dst`, copying the setup
/// header from `bz`, installing the supplied E820 entries, and
/// pointing the cmdline at `cmd_line_gpa`.
///
/// `dst` must be at least 4096 bytes long; it is fully zeroed first
/// so the caller doesn't need to worry about uninitialised legacy
/// fields.
///
/// Linux requires:
///   - `setup_header.type_of_loader` to be non-zero (we set 0xFF =
///     "undefined" which Linux accepts unconditionally)
///   - `cmd_line_ptr` to be in low memory (< 4 GiB) and point at a
///     NUL-terminated string
///   - At least one E820 entry covering the kernel's load address
pub fn build_boot_params(
    dst: &mut [u8],
    bz: &BzImage<'_>,
    cmd_line_gpa: u32,
    e820: &[E820Entry],
    ramdisk_gpa: u32,
    ramdisk_size: u32,
) -> Result<(), BzImageError> {
    if dst.len() < 4096 {
        return Err(BzImageError::Truncated);
    }
    if e820.len() > BP_E820_MAX {
        return Err(BzImageError::Truncated);
    }

    // 1. Zero the buffer so legacy fields stay quiet.
    for b in dst.iter_mut().take(4096) {
        *b = 0;
    }

    // 2. Copy the bzImage setup header (0x1F1..0x290) into
    //    boot_params at the same offset. This brings across the
    //    entire setup_header (jump, header magic, version,
    //    setup_sects, kernel_alignment, init_size, etc.) which
    //    Linux's 64-bit entry validates before doing anything else.
    let hdr_src = &bz.bytes[BP_HDR_OFFSET..BP_HDR_OFFSET + BP_HDR_LEN];
    dst[BP_HDR_OFFSET..BP_HDR_OFFSET + BP_HDR_LEN].copy_from_slice(hdr_src);

    // 3. Patch fields the bootloader controls.
    //    type_of_loader: 0xFF = "undefined" (accepted everywhere)
    dst[BP_HDR_OFFSET + HDR_OFF_TYPE_OF_LOADER] = 0xFF;
    //    Phase F.6.3 — ramdisk GPA + size (0 = no initramfs).
    write_u32_at(dst, BP_HDR_OFFSET + HDR_OFF_RAMDISK_IMAGE, ramdisk_gpa);
    write_u32_at(dst, BP_HDR_OFFSET + HDR_OFF_RAMDISK_SIZE, ramdisk_size);
    //    cmd_line_ptr is a 32-bit GPA (Linux's setup_header field
    //    is 4 bytes; only legal in low memory but our cmdline lives
    //    at GPA 0x20000 which fits comfortably).
    write_u32_at(dst, BP_HDR_OFFSET + HDR_OFF_CMD_LINE_PTR, cmd_line_gpa);

    // 4. Install the E820 map.
    dst[BP_E820_ENTRIES] = e820.len() as u8;
    let mut off = BP_E820_TABLE;
    for entry in e820.iter() {
        write_u64_at(dst, off, entry.addr);
        write_u64_at(dst, off + 8, entry.size);
        write_u32_at(dst, off + 16, entry.typ);
        off += E820_ENTRY_SIZE;
    }

    // F.6 — also populate the legacy BIOS-e801 / BIOS-88 fields as a
    // safety net. Linux's `e820__memory_setup_default` falls back to
    // these if for some reason `append_e820_table` returns -1
    // (overflow check, > 128 entries, etc). Compute the total RAM
    // size in KB above 1 MB by summing all USABLE entries that
    // extend past 0x100000.
    let mut high_mem_kb: u64 = 0;
    for entry in e820.iter() {
        if entry.typ != e820_type::USABLE {
            continue;
        }
        let end = entry.addr.saturating_add(entry.size);
        if end > 0x100000 {
            let start = if entry.addr > 0x100000 { entry.addr } else { 0x100000 };
            high_mem_kb += (end - start) / 1024;
        }
    }
    // alt_mem_k is u32 — cap at u32::MAX to handle huge guests, though
    // tinyconfig never reaches that size.
    let alt_kb = if high_mem_kb > u32::MAX as u64 {
        u32::MAX
    } else {
        high_mem_kb as u32
    };
    write_u32_at(dst, BP_ALT_MEM_K, alt_kb);
    // ext_mem_k is u16 — capped at 64 MB on real PCs, just store the
    // capped value so the BIOS-88 path also works.
    let ext_kb = if high_mem_kb > 0xFFFF {
        0xFFFFu16
    } else {
        high_mem_kb as u16
    };
    let ext_kb_bytes = ext_kb.to_le_bytes();
    dst[BP_SCREEN_EXT_MEM_K..BP_SCREEN_EXT_MEM_K + 2].copy_from_slice(&ext_kb_bytes);

    Ok(())
}

#[inline]
fn write_u32_at(buf: &mut [u8], off: usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[off..off + 4].copy_from_slice(&bytes);
}

#[inline]
fn write_u64_at(buf: &mut [u8], off: usize, value: u64) {
    let bytes = value.to_le_bytes();
    buf[off..off + 8].copy_from_slice(&bytes);
}
