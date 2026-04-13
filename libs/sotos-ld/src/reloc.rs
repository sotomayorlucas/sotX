//! ELF relocation engine.
//!
//! Processes `.rela.dyn` and `.rela.plt` sections, applying relocations
//! for position-independent shared objects loaded by [`crate::dl_open`].
//!
//! Implemented relocation types (x86_64 ABI):
//!
//! | id | name              | computation               |
//! |----|-------------------|---------------------------|
//! |  1 | R_X86_64_64       | `S + A`                   |
//! |  2 | R_X86_64_PC32     | `S + A - P` (32-bit)      |
//! |  4 | R_X86_64_PLT32    | `S + A - P` (32-bit)      |
//! |  6 | R_X86_64_GLOB_DAT | `S`                       |
//! |  7 | R_X86_64_JUMP_SLOT| `S`                       |
//! |  8 | R_X86_64_RELATIVE | `B + A`                   |
//! |  9 | R_X86_64_GOTPCREL | `G + GOT + A - P` (32-bit)|
//! | 16 | R_X86_64_DTPMOD64 | TLS module id (always 1)  |
//! | 17 | R_X86_64_DTPOFF64 | TLS template offset       |
//! | 18 | R_X86_64_TPOFF64  | TLS thread-pointer offset |
//! | 37 | R_X86_64_IRELATIVE| resolver()                |

use core::sync::atomic::{AtomicU64, Ordering};

use sotos_common::elf::DynamicInfo;

use crate::tls::{tp_offset, TlsBlock};

// x86_64 relocation types (subset we implement).
const R_X86_64_64: u32 = 1;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;
const R_X86_64_GOTPCREL: u32 = 9;
const R_X86_64_DTPMOD64: u32 = 16;
const R_X86_64_DTPOFF64: u32 = 17;
const R_X86_64_TPOFF64: u32 = 18;
const R_X86_64_IRELATIVE: u32 = 37;

/// Total relocations the engine encountered but did not know how to apply.
///
/// A successful glibc-style load should leave this at 0; bumps indicate a
/// missing relocation type.
static SKIPPED_RELOCS: AtomicU64 = AtomicU64::new(0);
/// Total relocations successfully applied across all `apply_relocations` calls.
static APPLIED_RELOCS: AtomicU64 = AtomicU64::new(0);

/// Reset both counters. Tests call this before exercising the loader.
pub fn reset_counters() {
    SKIPPED_RELOCS.store(0, Ordering::Relaxed);
    APPLIED_RELOCS.store(0, Ordering::Relaxed);
}

/// Number of relocations skipped since the last [`reset_counters`].
pub fn skipped_count() -> u64 {
    SKIPPED_RELOCS.load(Ordering::Relaxed)
}

/// Number of relocations applied since the last [`reset_counters`].
pub fn applied_count() -> u64 {
    APPLIED_RELOCS.load(Ordering::Relaxed)
}

/// Per-load context shared with the relocation engine.
///
/// `tls_block` is `TlsBlock::empty()` for libraries without PT_TLS.
/// `tls_module_id` is `1` for the main executable, `> 1` for shared libs;
/// for now we only ever pass `1` because sotX doesn't have a real DTV.
///
/// `symtab_addr` / `strtab_addr` point at the loaded `.dynsym` / `.dynstr`
/// (already adjusted by `base`) so the engine can resolve symbols defined
/// **inside** the same shared object. External symbol lookup is not yet
/// implemented — undefined symbols still bump `SKIPPED_RELOCS`.
#[derive(Clone, Copy)]
pub struct RelocCtx {
    pub base: u64,
    pub got_base: u64,
    pub tls_block: TlsBlock,
    pub tls_module_id: u64,
    pub symtab_addr: u64,
    pub symtab_count: u64,
    pub strtab_addr: u64,
    pub strsz: u64,
}

impl RelocCtx {
    pub const fn new(base: u64) -> Self {
        Self {
            base,
            got_base: 0,
            tls_block: TlsBlock::empty(),
            tls_module_id: 1,
            symtab_addr: 0,
            symtab_count: 0,
            strtab_addr: 0,
            strsz: 0,
        }
    }

    pub fn with_tls(mut self, tls: TlsBlock) -> Self {
        self.tls_block = tls;
        self
    }

    pub fn with_got(mut self, got_base: u64) -> Self {
        self.got_base = got_base;
        self
    }

    pub fn with_symtab(
        mut self,
        symtab_addr: u64,
        count: u64,
        strtab_addr: u64,
        strsz: u64,
    ) -> Self {
        self.symtab_addr = symtab_addr;
        self.symtab_count = count;
        self.strtab_addr = strtab_addr;
        self.strsz = strsz;
        self
    }
}

/// Result of resolving a symbol referenced by a relocation.
#[derive(Clone, Copy)]
struct ResolvedSymbol {
    /// Absolute virtual address of the symbol (0 = undefined).
    value: u64,
    /// True when `st_shndx == SHN_UNDEF`, i.e. the symbol is imported.
    undefined: bool,
}

// Elf64_Sym layout: { st_name: u32, st_info: u8, st_other: u8, st_shndx: u16,
//                     st_value: u64, st_size: u64 }  — 24 bytes total.
const SYM_SIZE: u64 = 24;
const ST_SHNDX: u64 = 6;
const ST_VALUE: u64 = 8;

fn read_u16(addr: u64) -> u16 {
    unsafe { core::ptr::read(addr as *const u16) }
}

fn read_u64(addr: u64) -> u64 {
    unsafe { core::ptr::read(addr as *const u64) }
}

fn write_u64(addr: u64, val: u64) {
    unsafe { core::ptr::write(addr as *mut u64, val) }
}

fn write_i32(addr: u64, val: i32) {
    unsafe { core::ptr::write(addr as *mut i32, val) }
}

/// Look up `r_sym` in the loaded `.dynsym` table.
///
/// Returns `None` if the context has no symtab or the index is out of
/// range. A defined symbol returns `(value = base + st_value, undefined = false)`,
/// an imported symbol returns `(0, true)`.
fn resolve_symbol(ctx: &RelocCtx, r_sym: u32) -> Option<ResolvedSymbol> {
    if ctx.symtab_addr == 0 || r_sym == 0 {
        return None;
    }
    if ctx.symtab_count != 0 && (r_sym as u64) >= ctx.symtab_count {
        return None;
    }
    let sym = ctx.symtab_addr + r_sym as u64 * SYM_SIZE;
    if read_u16(sym + ST_SHNDX) == 0 {
        return Some(ResolvedSymbol {
            value: 0,
            undefined: true,
        });
    }
    Some(ResolvedSymbol {
        value: ctx.base.wrapping_add(read_u64(sym + ST_VALUE)),
        undefined: false,
    })
}

/// Apply all relocations for a loaded shared library.
///
/// `base` is the load base address. `elf_data` is the original file data
/// (kept for symmetry with the rest of the loader; the engine itself
/// reads relocation entries directly from memory). `dyn_info` carries the
/// parsed PT_DYNAMIC entries.
pub fn apply_relocations(
    base: u64,
    _elf_data: &[u8],
    dyn_info: &DynamicInfo,
) -> Result<(), &'static str> {
    apply_relocations_ctx(&RelocCtx::new(base), _elf_data, dyn_info)
}

/// Apply relocations using a fully-populated [`RelocCtx`] (TLS, GOT base, …).
pub fn apply_relocations_ctx(
    ctx: &RelocCtx,
    _elf_data: &[u8],
    dyn_info: &DynamicInfo,
) -> Result<(), &'static str> {
    // Process .rela.dyn
    if dyn_info.rela != 0 && dyn_info.relasz > 0 {
        let entry_size = if dyn_info.relaent > 0 {
            dyn_info.relaent
        } else {
            24
        };
        let count = dyn_info.relasz / entry_size;
        process_rela(
            ctx,
            ctx.base + dyn_info.rela,
            count as usize,
            entry_size as usize,
        )?;
    }

    // Process .rela.plt
    if dyn_info.jmprel != 0 && dyn_info.pltrelsz > 0 {
        let entry_size = 24; // Elf64_Rela is always 24 bytes.
        let count = dyn_info.pltrelsz / entry_size;
        process_rela(
            ctx,
            ctx.base + dyn_info.jmprel,
            count as usize,
            entry_size as usize,
        )?;
    }

    Ok(())
}

/// Process a `.rela` section (array of `Elf64_Rela` entries).
fn process_rela(
    ctx: &RelocCtx,
    rela_addr: u64,
    count: usize,
    entry_size: usize,
) -> Result<(), &'static str> {
    let base = ctx.base;

    for i in 0..count {
        let entry = rela_addr + (i * entry_size) as u64;

        // Elf64_Rela: { r_offset: u64, r_info: u64, r_addend: i64 }
        let r_offset = read_u64(entry);
        let r_info = read_u64(entry + 8);
        let r_addend = read_u64(entry + 16) as i64;

        let r_type = (r_info & 0xFFFFFFFF) as u32;
        let r_sym = (r_info >> 32) as u32;

        let target = base + r_offset;

        match r_type {
            R_X86_64_RELATIVE => {
                // B + A — most common in PIC code.
                let val = (base as i64 + r_addend) as u64;
                write_u64(target, val);
                APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
            }

            R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                // S + A (or S). For undefined symbols (sym==0) this collapses
                // to a pure relative reloc. Otherwise we walk the loaded
                // .dynsym; symbols defined inside the same .so resolve, but
                // imports from other modules still bump SKIPPED_RELOCS.
                if r_sym == 0 {
                    let val = (base as i64 + r_addend) as u64;
                    write_u64(target, val);
                    APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
                } else if let Some(sym) = resolve_symbol(ctx, r_sym) {
                    if sym.undefined {
                        SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let val = (sym.value as i64 + r_addend) as u64;
                        write_u64(target, val);
                        APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                }
            }

            R_X86_64_PC32 | R_X86_64_PLT32 => {
                // S + A - P (32-bit). For sym==0 we resolve S as the load
                // base (relative form). PLT32 is identical because we have
                // no real PLT — it's a direct jump to the resolved symbol.
                let s = if r_sym == 0 {
                    base as i64
                } else {
                    match resolve_symbol(ctx, r_sym) {
                        Some(sym) if !sym.undefined => sym.value as i64,
                        _ => {
                            SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                };
                let p = target as i64;
                let val = s + r_addend - p;
                if val < i32::MIN as i64 || val > i32::MAX as i64 {
                    return Err("PC32 relocation overflows i32");
                }
                write_i32(target, val as i32);
                APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
            }

            R_X86_64_GOTPCREL => {
                // GOTPCREL needs per-symbol GOT slot tracking, not yet implemented.
                // Writing G+GOT+A-P with G=0 would store a wrong displacement at
                // the relocation site, so we skip and let the caller notice via
                // SKIPPED_RELOCS instead of silently corrupting the load.
                SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            R_X86_64_IRELATIVE => {
                // The addend is the offset (relative to load base) of an
                // ifunc resolver. Call it and store the returned address in
                // the GOT slot. The resolver returns the implementation it
                // wants the loader to use.
                let resolver_addr = (base as i64 + r_addend) as u64;
                if resolver_addr == 0 {
                    SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let resolver: extern "C" fn() -> u64 =
                    unsafe { core::mem::transmute(resolver_addr as usize) };
                let resolved = resolver();
                write_u64(target, resolved);
                APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
            }

            R_X86_64_DTPMOD64 => {
                // TLS module id. We only support a single module, id 1
                // (the main executable / first dl_open). External TLS
                // modules from sysdeps libraries would need a real DTV.
                write_u64(target, ctx.tls_module_id);
                APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
            }

            R_X86_64_DTPOFF64 => {
                // Offset within the module's TLS block. For sym==0 the
                // result is just the addend; for a defined TLS symbol it's
                // `st_value + addend` (st_value is the template offset).
                let mut val = r_addend as u64;
                if r_sym != 0 {
                    if let Some(sym) = resolve_symbol(ctx, r_sym) {
                        if sym.undefined {
                            SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        // sym.value here is `base + st_value`; the TLS
                        // template offset itself is st_value, so subtract
                        // the base back out.
                        val = (sym.value.wrapping_sub(ctx.base) as i64 + r_addend) as u64;
                    } else {
                        SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                write_u64(target, val);
                APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
            }

            R_X86_64_TPOFF64 => {
                // Negative offset from the thread pointer (FS_BASE) to
                // the variable. The template offset is the symbol's
                // `st_value` (or 0 for sym==0); the result is
                // `addend + st_value - static_size`.
                let static_size = ctx.tls_block.size;
                if static_size == 0 {
                    SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut sym_off: u64 = 0;
                if r_sym != 0 {
                    if let Some(sym) = resolve_symbol(ctx, r_sym) {
                        if sym.undefined {
                            SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        sym_off = sym.value.wrapping_sub(ctx.base);
                    } else {
                        SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                let off = tp_offset(static_size, sym_off + r_addend as u64);
                write_u64(target, off as u64);
                APPLIED_RELOCS.fetch_add(1, Ordering::Relaxed);
            }

            _ => {
                // Unknown relocation type — track it.
                SKIPPED_RELOCS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tp_offset_basic() {
        assert_eq!(tp_offset(64, 0), -64);
        assert_eq!(tp_offset(64, 16), -48);
        assert_eq!(tp_offset(8, 4), -4);
    }

    #[test]
    fn counters_round_trip() {
        reset_counters();
        SKIPPED_RELOCS.fetch_add(3, Ordering::Relaxed);
        APPLIED_RELOCS.fetch_add(5, Ordering::Relaxed);
        assert_eq!(skipped_count(), 3);
        assert_eq!(applied_count(), 5);
        reset_counters();
        assert_eq!(skipped_count(), 0);
        assert_eq!(applied_count(), 0);
    }

    #[test]
    fn ctx_with_tls_and_got() {
        let mut tls = TlsBlock::empty();
        tls.size = 32;
        let ctx = RelocCtx::new(0x1000)
            .with_tls(tls)
            .with_got(0x2000)
            .with_symtab(0x3000, 16, 0x4000, 256);
        assert_eq!(ctx.base, 0x1000);
        assert_eq!(ctx.got_base, 0x2000);
        assert_eq!(ctx.tls_block.size, 32);
        assert_eq!(ctx.symtab_addr, 0x3000);
        assert_eq!(ctx.symtab_count, 16);
        assert_eq!(ctx.strtab_addr, 0x4000);
        assert_eq!(ctx.strsz, 256);
    }
}
