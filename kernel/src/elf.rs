//! Minimal ELF64 loader for static executables.
//!
//! Parses an ELF64 ET_EXEC binary and maps its PT_LOAD segments into
//! a user address space. Returns the entry point virtual address.

use crate::mm::{self, hhdm_offset};
use crate::mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

// ELF64 header field offsets
const EI_MAG: usize = 0;        // 4 bytes: \x7fELF
const EI_CLASS: usize = 4;      // 1 byte: 2 = 64-bit
const EI_DATA: usize = 5;       // 1 byte: 1 = little-endian
const E_TYPE: usize = 16;       // 2 bytes: 2 = ET_EXEC
const E_MACHINE: usize = 18;    // 2 bytes: 62 = x86_64
const E_ENTRY: usize = 24;      // 8 bytes: entry point
const E_PHOFF: usize = 32;      // 8 bytes: program header offset
const E_PHENTSIZE: usize = 54;  // 2 bytes: program header entry size
const E_PHNUM: usize = 56;      // 2 bytes: number of program headers

// Program header field offsets (relative to phdr start)
const P_TYPE: usize = 0;        // 4 bytes: 1 = PT_LOAD
const P_FLAGS: usize = 4;       // 4 bytes: PF_X=1, PF_W=2, PF_R=4
const P_OFFSET: usize = 8;      // 8 bytes: file offset
const P_VADDR: usize = 16;      // 8 bytes: virtual address
const P_FILESZ: usize = 32;     // 8 bytes: size in file
const P_MEMSZ: usize = 40;      // 8 bytes: size in memory

const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off], data[off + 1], data[off + 2], data[off + 3],
        data[off + 4], data[off + 5], data[off + 6], data[off + 7],
    ])
}

/// Load an ELF64 ET_EXEC binary into the given address space.
///
/// Maps each PT_LOAD segment, copying file data and zeroing BSS regions.
/// Returns the entry point address on success.
pub fn load(data: &[u8], addr_space: &AddressSpace) -> Result<u64, &'static str> {
    // --- Validate ELF header ---
    if data.len() < 64 {
        return Err("ELF too small");
    }
    if &data[EI_MAG..EI_MAG + 4] != b"\x7fELF" {
        return Err("bad ELF magic");
    }
    if data[EI_CLASS] != 2 {
        return Err("not ELF64");
    }
    if data[EI_DATA] != 1 {
        return Err("not little-endian");
    }
    if read_u16(data, E_TYPE) != 2 {
        return Err("not ET_EXEC");
    }
    if read_u16(data, E_MACHINE) != 62 {
        return Err("not x86_64");
    }

    let entry = read_u64(data, E_ENTRY);
    let phoff = read_u64(data, E_PHOFF) as usize;
    let phentsize = read_u16(data, E_PHENTSIZE) as usize;
    let phnum = read_u16(data, E_PHNUM) as usize;

    let hhdm = hhdm_offset();

    // --- Process PT_LOAD segments ---
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if ph + phentsize > data.len() {
            return Err("phdr out of bounds");
        }

        let p_type = read_u32(data, ph + P_TYPE);
        if p_type != PT_LOAD {
            continue;
        }

        let p_flags = read_u32(data, ph + P_FLAGS);
        let p_offset = read_u64(data, ph + P_OFFSET) as usize;
        let p_vaddr = read_u64(data, ph + P_VADDR);
        let p_filesz = read_u64(data, ph + P_FILESZ) as usize;
        let p_memsz = read_u64(data, ph + P_MEMSZ) as usize;

        if p_memsz == 0 {
            continue;
        }

        // Page range covering this segment
        let seg_start = p_vaddr & !0xFFF;
        let seg_end = (p_vaddr + p_memsz as u64 + 0xFFF) & !0xFFF;

        // Determine page flags
        let mut flags = PAGE_PRESENT | PAGE_USER;
        if p_flags & PF_W != 0 {
            flags |= PAGE_WRITABLE;
        }

        // Map each page
        let mut page_vaddr = seg_start;
        while page_vaddr < seg_end {
            // Allocate and zero a physical frame
            let frame = mm::alloc_frame().expect("ELF loader: out of frames");
            let phys = frame.addr();
            unsafe {
                core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
            }

            // Copy overlapping file data into this page
            // The segment occupies [p_vaddr, p_vaddr + p_filesz) in the file data region,
            // but we need to figure out which bytes land on this specific page.
            let page_start = page_vaddr;
            let page_end = page_vaddr + 4096;

            // File data covers [p_vaddr, p_vaddr + p_filesz) in virtual space
            let file_region_start = p_vaddr;
            let file_region_end = p_vaddr + p_filesz as u64;

            // Overlap between this page and the file data region
            let copy_start = page_start.max(file_region_start);
            let copy_end = page_end.min(file_region_end);

            if copy_start < copy_end {
                let dst_offset = (copy_start - page_start) as usize;
                let src_offset = p_offset + (copy_start - p_vaddr) as usize;
                let count = (copy_end - copy_start) as usize;

                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data[src_offset..].as_ptr(),
                        ((phys + hhdm) as *mut u8).add(dst_offset),
                        count,
                    );
                }
            }

            addr_space.map_page(page_vaddr, phys, flags);
            page_vaddr += 4096;
        }
    }

    Ok(entry)
}
