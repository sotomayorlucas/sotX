//! ELF64 loader for static executables.
//!
//! Uses the `elf` crate for validated parsing. Maps PT_LOAD segments
//! into a user address space with W^X enforcement.

use crate::mm::{self, hhdm_offset};
use crate::mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE, PAGE_NO_EXECUTE};

use elf::ElfBytes;
use elf::endian::LittleEndian;
use elf::abi;

/// Load an ELF64 ET_EXEC binary into the given address space.
///
/// Maps each PT_LOAD segment, copying file data and zeroing BSS regions.
/// Returns the entry point address on success.
pub fn load(data: &[u8], addr_space: &AddressSpace) -> Result<u64, &'static str> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(data)
        .map_err(|_| "ELF parse error")?;

    if file.ehdr.e_type != abi::ET_EXEC {
        return Err("not ET_EXEC");
    }
    if file.ehdr.e_machine != abi::EM_X86_64 {
        return Err("not x86_64");
    }

    let entry = file.ehdr.e_entry;
    let hhdm = hhdm_offset();

    let segments = file.segments().ok_or("no program headers")?;

    for phdr in segments {
        if phdr.p_type != abi::PT_LOAD || phdr.p_memsz == 0 {
            continue;
        }

        let p_vaddr = phdr.p_vaddr;
        let p_offset = phdr.p_offset as usize;
        let p_filesz = phdr.p_filesz as usize;
        let p_memsz = phdr.p_memsz as usize;

        // Page range covering this segment
        let seg_start = p_vaddr & !0xFFF;
        let seg_end = (p_vaddr + p_memsz as u64 + 0xFFF) & !0xFFF;

        // W^X: writable pages are never executable
        let mut flags = PAGE_PRESENT | PAGE_USER;
        if phdr.p_flags & abi::PF_W != 0 {
            flags |= PAGE_WRITABLE;
        }
        if phdr.p_flags & abi::PF_X == 0 {
            flags |= PAGE_NO_EXECUTE;
        }

        // Map each page
        let mut page_vaddr = seg_start;
        while page_vaddr < seg_end {
            let frame = mm::alloc_frame().expect("ELF loader: out of frames");
            let phys = frame.addr();
            unsafe {
                core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
            }

            // Copy overlapping file data into this page
            let page_end = page_vaddr + 4096;
            let file_region_end = p_vaddr + p_filesz as u64;
            let copy_start = page_vaddr.max(p_vaddr);
            let copy_end = page_end.min(file_region_end);

            if copy_start < copy_end {
                let dst_offset = (copy_start - page_vaddr) as usize;
                let src_offset = p_offset + (copy_start - p_vaddr) as usize;
                let count = (copy_end - copy_start) as usize;

                if src_offset + count <= data.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data[src_offset..].as_ptr(),
                            ((phys + hhdm) as *mut u8).add(dst_offset),
                            count,
                        );
                    }
                }
            }

            addr_space.map_page(page_vaddr, phys, flags);
            page_vaddr += 4096;
        }
    }

    Ok(entry)
}
