//! Userspace dynamic linker for sotOS.
//!
//! Loads ELF shared objects (.so, ET_DYN), performs relocations,
//! and resolves symbols. Uses the `sotos-common` ELF parser for
//! header parsing.

#![no_std]

mod loader;
mod reloc;
mod symbol;

pub use loader::DlHandle;

use sotos_common::elf::{self, LoadSegment, MAX_LOAD_SEGMENTS};

/// Open a shared library from raw ELF data already in memory.
///
/// The caller must provide the ELF data at `elf_data`. The linker
/// will allocate pages (frame_alloc + map) to load segments starting
/// at `base_addr`, perform relocations, and return a handle.
pub fn dl_open(elf_data: &[u8], base_addr: u64) -> Result<DlHandle, &'static str> {
    // Parse ELF header.
    let info = elf::parse(elf_data)?;
    if info.elf_type != 3 {
        return Err("not ET_DYN");
    }

    // Extract load segments.
    let mut segments = [const { LoadSegment { offset: 0, vaddr: 0, filesz: 0, memsz: 0, flags: 0 } }; MAX_LOAD_SEGMENTS];
    let seg_count = elf::load_segments(elf_data, &info, &mut segments);

    // Load segments into memory at base_addr.
    let mapping = loader::load_segments(elf_data, &segments[..seg_count], base_addr)?;

    // Parse dynamic section.
    let dyn_info = elf::parse_dynamic(elf_data, &info)
        .ok_or("no PT_DYNAMIC")?;

    // Apply relocations.
    reloc::apply_relocations(base_addr, elf_data, &dyn_info)?;

    // W^X: change code pages from RW (needed for loading) to R+X.
    loader::protect_segments(&segments[..seg_count], base_addr);

    Ok(DlHandle {
        base: base_addr,
        entry: info.entry.wrapping_add(base_addr), // ET_DYN entry is relative
        symtab_off: dyn_info.symtab,
        strtab_off: dyn_info.strtab,
        strsz: dyn_info.strsz,
        gnu_hash_off: dyn_info.gnu_hash,
        mapping,
        elf_data_ptr: elf_data.as_ptr() as u64,
        elf_data_len: elf_data.len(),
    })
}

/// Look up a symbol by name in a loaded shared library.
/// Returns the symbol's virtual address.
pub fn dl_sym(handle: &DlHandle, name: &[u8]) -> Option<u64> {
    // The symtab/strtab offsets from DynamicInfo are virtual addresses
    // relative to the ELF's load base (0 for PIC). After loading at
    // handle.base, they become handle.base + offset.
    let symtab_addr = handle.base + handle.symtab_off;
    let strtab_addr = handle.base + handle.strtab_off;
    let gnu_hash_addr = if handle.gnu_hash_off != 0 {
        handle.base + handle.gnu_hash_off
    } else {
        0
    };

    symbol::find_symbol(name, symtab_addr, strtab_addr, handle.strsz, gnu_hash_addr, handle.base)
}

/// Unmap a loaded shared library. After this, the handle is invalid.
pub fn dl_close(handle: &DlHandle) {
    loader::unmap_segments(&handle.mapping);
}
