//! Static TLS allocator for loaded shared objects.
//!
//! Layout (musl/glibc style for x86_64):
//!
//!     low addr ─►  [ ──── static TLS area ──── ][ TCB ][ DTV ptr ][ … ]
//!                  ↑                            ↑
//!                  base                         tp (FS_BASE)
//!
//! `tp` (the value loaded into FS_BASE) points one byte past the end of the
//! static TLS area, so a TLS variable at template offset `N` is read with
//! `mov rax, fs:[-(static_size - N)]`. R_X86_64_TPOFF64 stores that negative
//! offset directly into the GOT slot.
//!
//! For sotX we keep things simple: a single static TLS block per loaded
//! library, allocated with `sys::frame_alloc`/`sys::map`. There's no DTV
//! and no `__tls_get_addr`, so dynamic TLS access (DTPMOD64/DTPOFF64) is
//! supported only for the trivial "module 1" case where the dtv slot is
//! never actually consulted at runtime.

use core::sync::atomic::{AtomicU64, Ordering};

use sotos_common::elf::PtTls;
use sotos_common::sys;

/// Default base virtual address for the first TLS block.
///
/// Located between the dynamic linker scratch region and INTERP_BUF_BASE.
/// We bump-allocate from this base on every successful `init_tls` call so
/// repeated `dl_open` invocations don't collide.
const TLS_AREA_BASE: u64 = 0x7000000;
/// Maximum static TLS bytes we will install for one library.
pub const MAX_TLS_BYTES: usize = 64 * 1024;
/// Maximum 4 KiB pages a single TLS block may span.
pub const MAX_TLS_PAGES: usize = MAX_TLS_BYTES / 4096;

const MAP_WRITABLE: u64 = 2;

/// A live TLS block ready to be installed via `set_fs_base`.
#[derive(Clone, Copy)]
pub struct TlsBlock {
    /// Lowest virtual address of the static TLS area.
    pub base: u64,
    /// Total static TLS bytes (memsz, rounded to alignment).
    pub size: usize,
    /// Alignment in bytes (power of two).
    pub align: usize,
    /// Value to write into FS_BASE: one byte past the end of the static area.
    pub tp: u64,
    /// Number of 4 KiB pages mapped (so the loader can later unmap them).
    pub pages: u64,
}

impl TlsBlock {
    /// Empty (zero-sized) block — used when an ELF has no PT_TLS.
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            align: 1,
            tp: 0,
            pages: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pages == 0
    }
}

static NEXT_TLS_BASE: AtomicU64 = AtomicU64::new(TLS_AREA_BASE);

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

fn align_up_u64(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Reserve a fresh `pages * 4 KiB` page-aligned slot from the bump allocator.
fn reserve_tls_slot(pages: u64) -> u64 {
    let mut prev = NEXT_TLS_BASE.load(Ordering::Relaxed);
    loop {
        let aligned = align_up_u64(prev, 4096);
        let next = aligned + pages * 0x1000;
        match NEXT_TLS_BASE.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return aligned,
            Err(actual) => prev = actual,
        }
    }
}

/// Allocate the static TLS area for `pt_tls`, copy `.tdata` from `elf_data`,
/// and zero the trailing `.tbss`.
///
/// Returns a [`TlsBlock`] with `tp` ready to feed into `install_tls`.
pub fn init_tls(elf_data: &[u8], pt_tls: &PtTls) -> Result<TlsBlock, &'static str> {
    if pt_tls.memsz == 0 {
        return Ok(TlsBlock::empty());
    }
    if pt_tls.memsz > MAX_TLS_BYTES {
        return Err("TLS template too large");
    }
    if pt_tls.filesz > pt_tls.memsz {
        return Err("tls: filesz > memsz (malformed ELF)");
    }

    let align = (pt_tls.align as usize).max(1);
    let static_size = align_up(pt_tls.memsz, align);
    let pages = static_size.div_ceil(4096) as u64;
    if pages == 0 {
        return Ok(TlsBlock::empty());
    }
    if pages > MAX_TLS_PAGES as u64 {
        return Err("tls: too many pages");
    }

    // Bump-allocate a fresh page-aligned region.
    let base = reserve_tls_slot(pages);

    for i in 0..pages {
        let frame_cap = sys::frame_alloc().map_err(|_| "tls: frame_alloc failed")?;
        sys::map(base + i * 0x1000, frame_cap, MAP_WRITABLE).map_err(|_| "tls: map failed")?;
        unsafe {
            core::ptr::write_bytes((base + i * 0x1000) as *mut u8, 0, 4096);
        }
    }

    // Copy .tdata into the start of the static area.
    if pt_tls.filesz > 0 {
        let end = pt_tls
            .offset
            .checked_add(pt_tls.filesz)
            .ok_or("tls: filesz overflow")?;
        if end > elf_data.len() {
            return Err("tls: tdata out of range");
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                elf_data.as_ptr().add(pt_tls.offset),
                base as *mut u8,
                pt_tls.filesz,
            );
        }
    }

    // tp points one byte past the end of the static TLS area (musl x86_64).
    let tp = base + static_size as u64;

    Ok(TlsBlock {
        base,
        size: static_size,
        align,
        tp,
        pages,
    })
}

/// Install the TLS block into FS_BASE for the current thread.
///
/// No-op for empty blocks (ELF without PT_TLS).
pub fn install_tls(block: &TlsBlock) -> Result<(), &'static str> {
    if block.is_empty() {
        return Ok(());
    }
    sys::set_fs_base(block.tp).map_err(|_| "tls: set_fs_base failed")
}

/// Unmap every page that backs this TLS block. No-op for empty blocks.
///
/// Mirrors `loader::unmap_segments` — calls `sys::unmap` per page so the
/// virtual range is freed even though the underlying frame caps remain
/// owned by the caller (consistent with how PT_LOAD regions are torn down).
pub fn unmap_tls(block: &TlsBlock) {
    if block.is_empty() {
        return;
    }
    for i in 0..block.pages {
        let _ = sys::unmap(block.base + i * 0x1000);
    }
}

/// Compute the negative TPOFF for a TLS symbol whose template offset is
/// `sym_offset` in a block of `static_size` bytes.
///
/// This is the value written by R_X86_64_TPOFF64 (added to the addend to
/// produce a `mov rax, fs:[tpoff]` displacement).
#[inline]
pub fn tp_offset(static_size: usize, sym_offset: u64) -> i64 {
    -(static_size as i64) + sym_offset as i64
}
