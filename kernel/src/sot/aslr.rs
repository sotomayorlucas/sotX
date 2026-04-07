//! Address Space Layout Randomization for SOT domains.
//!
//! Inspired by OpenBSD's KARL (Kernel Address Randomized Link) and per-process
//! ASLR. Each domain gets randomized code/data/stack/mmap placement, making
//! exploitation of memory corruption bugs significantly harder.
//!
//! Uses the SOT ChaCha20 CSPRNG (`super::crypto::SotRandom`) for all
//! random address generation.

use super::crypto::SotRandom;

/// Alignment for randomized regions (4 KiB page boundary).
const PAGE_SIZE: u64 = 0x1000;

/// Maximum user address (below kernel space).
const USER_MAX: u64 = 0x7FFF_FFFF_F000;

/// Default randomization entropy (bits of jitter per region).
const CODE_JITTER_PAGES: u64 = 256;     // 1 MiB range
const DATA_JITTER_PAGES: u64 = 256;     // 1 MiB range
const HEAP_JITTER_PAGES: u64 = 512;     // 2 MiB range
const STACK_JITTER_PAGES: u64 = 1024;   // 4 MiB range
const MMAP_JITTER_PAGES: u64 = 4096;    // 16 MiB range
const VDSO_JITTER_PAGES: u64 = 256;     // 1 MiB range

/// Randomized memory layout for a new domain.
///
/// Each field represents the base address of a region, randomized
/// within its designated virtual address range.
pub struct DomainLayout {
    /// Randomized .text base.
    pub code_base: u64,
    /// Randomized .data/.bss base.
    pub data_base: u64,
    /// Randomized heap start.
    pub heap_base: u64,
    /// Randomized stack top (grows downward).
    pub stack_top: u64,
    /// Randomized mmap region base.
    pub mmap_base: u64,
    /// Randomized vDSO page address.
    pub vdso_base: u64,
}

impl DomainLayout {
    /// Generate a new randomized layout using the SOT CSPRNG.
    ///
    /// `code_size` is the size of the code segment in bytes (rounded up to pages).
    /// `needs_heap` controls whether heap_base is allocated (some domains are heap-free).
    ///
    /// Layout strategy:
    ///   Code:  0x200000 + random jitter
    ///   Data:  immediately after code + gap + jitter
    ///   Heap:  0x2000000 region + jitter
    ///   Stack: high addresses (below 0x800000000000) - jitter
    ///   Mmap:  0x7F0000000000 region - jitter
    ///   vDSO:  near stack region + jitter
    pub fn randomize(rng: &mut SotRandom, code_size: u64, needs_heap: bool) -> Self {
        let code_pages = (code_size + PAGE_SIZE - 1) / PAGE_SIZE;

        // Code: base at 0x200000 + random offset
        let code_jitter = random_page_offset(rng, CODE_JITTER_PAGES);
        let code_base = 0x20_0000 + code_jitter;

        // Data: after code with a guard gap + random offset
        let data_jitter = random_page_offset(rng, DATA_JITTER_PAGES);
        let data_base = code_base + (code_pages * PAGE_SIZE) + (2 * PAGE_SIZE) + data_jitter;

        // Heap: 0x2000000 region + jitter
        let heap_base = if needs_heap {
            let heap_jitter = random_page_offset(rng, HEAP_JITTER_PAGES);
            0x200_0000 + heap_jitter
        } else {
            0
        };

        // Stack: high address, grows down. Top near 0x7FFFFFFFE000 - jitter.
        let stack_jitter = random_page_offset(rng, STACK_JITTER_PAGES);
        let stack_top = align_down(USER_MAX - stack_jitter, PAGE_SIZE);

        // Mmap: large region for dynamic allocations
        let mmap_jitter = random_page_offset(rng, MMAP_JITTER_PAGES);
        let mmap_base = 0x7F00_0000_0000_u64.saturating_sub(mmap_jitter);

        // vDSO: near stack area
        let vdso_jitter = random_page_offset(rng, VDSO_JITTER_PAGES);
        let vdso_base = stack_top.saturating_sub(0x10_0000 + vdso_jitter);
        // Ensure page-aligned
        let vdso_base = align_down(vdso_base, PAGE_SIZE);

        DomainLayout {
            code_base,
            data_base,
            heap_base,
            stack_top,
            mmap_base,
            vdso_base,
        }
    }
}

/// Generate a random page-aligned offset within [0, max_pages * PAGE_SIZE).
fn random_page_offset(rng: &mut SotRandom, max_pages: u64) -> u64 {
    let page = rng.uniform(max_pages as u32) as u64;
    page * PAGE_SIZE
}

/// Align `addr` down to the nearest multiple of `align`.
const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

/// Generate a per-domain stack canary value from the CSPRNG.
///
/// This provides a unique canary for each domain, unlike the compile-time
/// sentinel used at kernel level. The canary should be placed in the domain's
/// TLS or a well-known address for the stack protector to reference.
pub fn generate_stack_canary(rng: &mut SotRandom) -> u64 {
    let mut buf = [0u8; 8];
    rng.fill(&mut buf);
    let canary = u64::from_le_bytes(buf);
    // Force NUL bytes in positions 0 and 7 to frustrate string-based
    // overflows, following glibc/OpenBSD convention.
    canary & 0x00FF_FFFF_FFFF_FF00
}
