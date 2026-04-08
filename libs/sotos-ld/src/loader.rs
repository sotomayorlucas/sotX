//! Segment loader: maps ELF PT_LOAD segments into the current address space.

use sotos_common::elf::LoadSegment;
use sotos_common::sys;

use crate::tls::TlsBlock;

/// Maximum mapped regions per shared library.
pub const MAX_REGIONS: usize = 8;

/// A mapped memory region (base vaddr + page count).
#[derive(Clone, Copy)]
pub struct MappedRegion {
    pub base: u64,
    pub pages: u64,
}

/// Tracks all mapped regions for a loaded shared library.
#[derive(Clone, Copy)]
pub struct Mapping {
    pub regions: [MappedRegion; MAX_REGIONS],
    pub count: usize,
}

/// Handle to a loaded shared library.
pub struct DlHandle {
    /// Base address where the library was loaded.
    pub base: u64,
    /// Adjusted entry point (base + ELF entry).
    pub entry: u64,
    /// Offset of .dynsym in the ELF (virtual address from DT_SYMTAB).
    pub symtab_off: u64,
    /// Offset of .dynstr in the ELF (virtual address from DT_STRTAB).
    pub strtab_off: u64,
    /// Size of .dynstr.
    pub strsz: u64,
    /// Offset of .gnu.hash (virtual address from DT_GNU_HASH).
    pub gnu_hash_off: u64,
    /// Memory mapping info for cleanup.
    pub mapping: Mapping,
    /// Pointer to the original ELF data (for reference).
    pub elf_data_ptr: u64,
    /// Length of the original ELF data.
    pub elf_data_len: usize,
    /// Static TLS block for this library (empty when no PT_TLS).
    pub tls: TlsBlock,
}

const MAP_WRITABLE: u64 = 2;

/// Load PT_LOAD segments at the given base address.
/// Returns a Mapping describing all allocated pages.
pub fn load_segments(
    elf_data: &[u8],
    segments: &[LoadSegment],
    base: u64,
) -> Result<Mapping, &'static str> {
    let mut mapping = Mapping {
        regions: [MappedRegion { base: 0, pages: 0 }; MAX_REGIONS],
        count: 0,
    };

    for seg in segments {
        if seg.memsz == 0 {
            continue;
        }

        // For ET_DYN, vaddr starts at 0; we load at base + vaddr.
        let seg_vaddr = base + seg.vaddr;
        let seg_start = seg_vaddr & !0xFFF;
        let seg_end = (seg_vaddr + seg.memsz as u64 + 0xFFF) & !0xFFF;
        let num_pages = (seg_end - seg_start) / 0x1000;

        // All segments are initially mapped writable so we can copy file
        // data into them; `protect_segments` below drops the write bit
        // on non-writable segments once loading is done.
        let mut page = seg_start;
        while page < seg_end {
            let frame_cap = sys::frame_alloc().map_err(|_| "frame_alloc failed")?;
            sys::map(page, frame_cap, MAP_WRITABLE).map_err(|_| "map failed")?;

            // Zero the page.
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, 4096);
            }

            // Copy file data that overlaps this page.
            let page_start = page;
            let page_end = page + 4096;
            let file_region_start = seg_vaddr;
            let file_region_end = seg_vaddr + seg.filesz as u64;
            let copy_start = page_start.max(file_region_start);
            let copy_end = page_end.min(file_region_end);

            if copy_start < copy_end {
                let dst_offset = (copy_start - page_start) as usize;
                let src_offset = seg.offset + (copy_start - seg_vaddr) as usize;
                let count = (copy_end - copy_start) as usize;
                if src_offset + count <= elf_data.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            elf_data.as_ptr().add(src_offset),
                            (page as *mut u8).add(dst_offset),
                            count,
                        );
                    }
                }
            }

            page += 0x1000;
        }

        // Record the mapping.
        if mapping.count < MAX_REGIONS {
            mapping.regions[mapping.count] = MappedRegion {
                base: seg_start,
                pages: num_pages,
            };
            mapping.count += 1;
        }
    }

    Ok(mapping)
}

/// After loading and relocations, change code segment pages from RW to R+X.
/// This calls SYS_PROTECT on each page of segments that have PF_X but not PF_W.
pub fn protect_segments(segments: &[LoadSegment], base: u64) {
    for seg in segments {
        if seg.memsz == 0 {
            continue;
        }
        let is_exec = (seg.flags & 1) != 0; // PF_X
        let is_write = (seg.flags & 2) != 0; // PF_W
        if !is_exec || is_write {
            // Data segments stay RW (already correct), skip.
            continue;
        }
        // Code segment: change from RW (needed for loading) to R+X.
        // flags = 0 means: not writable, not NX → read + execute.
        let seg_vaddr = base + seg.vaddr;
        let seg_start = seg_vaddr & !0xFFF;
        let seg_end = (seg_vaddr + seg.memsz as u64 + 0xFFF) & !0xFFF;
        let mut page = seg_start;
        while page < seg_end {
            let _ = sys::protect(page, 0); // 0 = R+X (no writable, no NX)
            page += 0x1000;
        }
    }
}

/// Unmap all regions of a loaded library.
pub fn unmap_segments(mapping: &Mapping) {
    for i in 0..mapping.count {
        let region = &mapping.regions[i];
        for p in 0..region.pages {
            let _ = sys::unmap(region.base + p * 0x1000);
        }
    }
}
