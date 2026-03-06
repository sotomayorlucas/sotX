//! ELF relocation engine.
//!
//! Processes .rela.dyn and .rela.plt sections, applying relocations
//! for position-independent shared objects.

use sotos_common::elf::DynamicInfo;

// x86_64 relocation types.
const R_X86_64_RELATIVE: u32 = 8;  // base + addend
const R_X86_64_64: u32 = 1;        // S + A
const R_X86_64_GLOB_DAT: u32 = 6;  // S
const R_X86_64_JUMP_SLOT: u32 = 7; // S

fn read_u64(addr: u64) -> u64 {
    unsafe { core::ptr::read(addr as *const u64) }
}

fn write_u64(addr: u64, val: u64) {
    unsafe { core::ptr::write(addr as *mut u64, val) }
}

/// Apply all relocations for a loaded shared library.
///
/// `base` is the load base address. `elf_data` is the original file data
/// (used for reading symbol tables before they're loaded). `dyn_info` has
/// the parsed PT_DYNAMIC entries.
pub fn apply_relocations(
    base: u64,
    _elf_data: &[u8],
    dyn_info: &DynamicInfo,
) -> Result<(), &'static str> {
    // Process .rela.dyn
    if dyn_info.rela != 0 && dyn_info.relasz > 0 {
        let entry_size = if dyn_info.relaent > 0 { dyn_info.relaent } else { 24 };
        let count = dyn_info.relasz / entry_size;
        process_rela(base, base + dyn_info.rela, count as usize, entry_size as usize)?;
    }

    // Process .rela.plt
    if dyn_info.jmprel != 0 && dyn_info.pltrelsz > 0 {
        let entry_size = 24; // Elf64_Rela is always 24 bytes
        let count = dyn_info.pltrelsz / entry_size;
        process_rela(base, base + dyn_info.jmprel, count as usize, entry_size as usize)?;
    }

    Ok(())
}

/// Process a .rela section (array of Elf64_Rela entries).
fn process_rela(
    base: u64,
    rela_addr: u64,
    count: usize,
    entry_size: usize,
) -> Result<(), &'static str> {
    for i in 0..count {
        let entry = rela_addr + (i * entry_size) as u64;

        // Elf64_Rela: { r_offset: u64, r_info: u64, r_addend: i64 }
        let r_offset = read_u64(entry);
        let r_info = read_u64(entry + 8);
        let r_addend = read_u64(entry + 16) as i64;

        let r_type = (r_info & 0xFFFFFFFF) as u32;
        let _r_sym = (r_info >> 32) as u32;

        let target = base + r_offset;

        match r_type {
            R_X86_64_RELATIVE => {
                // base + addend — most common in PIC code.
                let val = (base as i64 + r_addend) as u64;
                write_u64(target, val);
            }
            R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                // These need symbol resolution (S + A or S).
                // If sym index is 0 (no symbol), use base + addend (relative reloc).
                if _r_sym == 0 {
                    let val = (base as i64 + r_addend) as u64;
                    write_u64(target, val);
                }
                // Non-zero sym: would need symbol lookup from .dynsym.
                // For simple PIC libs without external deps, sym=0 suffices.
            }
            _ => {
                // Unknown relocation type — skip.
            }
        }
    }
    Ok(())
}
