//! Symbol lookup via linear scan of .dynsym.
//!
//! GNU hash is supported for faster lookup when available,
//! but falls back to linear scan.

/// Elf64_Sym size.
const SYM_SIZE: u64 = 24;
// Elf64_Sym field offsets.
const ST_NAME: u64 = 0; // u32: offset into strtab
const ST_INFO: u64 = 4; // u8: binding + type
const ST_VALUE: u64 = 8; // u64: symbol value

fn read_u32(addr: u64) -> u32 {
    unsafe { core::ptr::read(addr as *const u32) }
}

fn read_u64(addr: u64) -> u64 {
    unsafe { core::ptr::read(addr as *const u64) }
}

fn read_u8(addr: u64) -> u8 {
    unsafe { core::ptr::read(addr as *const u8) }
}

/// Compare a name against a NUL-terminated string at addr.
fn str_eq(name: &[u8], addr: u64) -> bool {
    for (i, &b) in name.iter().enumerate() {
        let c = read_u8(addr + i as u64);
        if c != b {
            return false;
        }
    }
    // Check NUL terminator.
    read_u8(addr + name.len() as u64) == 0
}

/// GNU hash function.
fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

/// Find a symbol by name in the .dynsym table.
///
/// `symtab_addr`: virtual address of .dynsym (loaded in memory).
/// `strtab_addr`: virtual address of .dynstr.
/// `strsz`: size of .dynstr.
/// `gnu_hash_addr`: virtual address of .gnu.hash (0 if unavailable).
/// `base`: load base address (added to symbol value for ET_DYN).
///
/// Returns the symbol's absolute virtual address, or None.
pub fn find_symbol(
    name: &[u8],
    symtab_addr: u64,
    strtab_addr: u64,
    strsz: u64,
    gnu_hash_addr: u64,
    base: u64,
) -> Option<u64> {
    if gnu_hash_addr != 0 {
        if let Some(val) = find_symbol_gnu_hash(name, symtab_addr, strtab_addr, gnu_hash_addr, base)
        {
            return Some(val);
        }
    }

    // Fallback: linear scan. We don't know the exact count, so scan
    // until we find a match or hit a reasonable limit.
    find_symbol_linear(name, symtab_addr, strtab_addr, strsz, base)
}

/// Linear scan of .dynsym.
fn find_symbol_linear(
    name: &[u8],
    symtab_addr: u64,
    strtab_addr: u64,
    strsz: u64,
    base: u64,
) -> Option<u64> {
    // Estimate max symbols from strtab size (conservative upper bound).
    let max_syms = if strsz > 0 {
        (strsz / 2).min(4096)
    } else {
        256
    };

    for i in 1..max_syms {
        let sym = symtab_addr + i * SYM_SIZE;
        let st_name = read_u32(sym + ST_NAME) as u64;
        let st_info = read_u8(sym + ST_INFO);
        let st_value = read_u64(sym + ST_VALUE);

        // Skip undefined symbols (value == 0) and non-function/object types.
        let st_type = st_info & 0xF;
        if st_value == 0 || (st_type != 1 && st_type != 2) {
            // type 1 = STT_OBJECT, type 2 = STT_FUNC
            continue;
        }

        if st_name > 0 && st_name < strsz && str_eq(name, strtab_addr + st_name) {
            return Some(base + st_value);
        }
    }

    None
}

/// GNU hash table lookup.
fn find_symbol_gnu_hash(
    name: &[u8],
    symtab_addr: u64,
    strtab_addr: u64,
    gnu_hash_addr: u64,
    base: u64,
) -> Option<u64> {
    // GNU hash table layout:
    // u32 nbuckets, u32 symoffset, u32 bloom_size, u32 bloom_shift
    // u64[bloom_size] bloom filter
    // u32[nbuckets] buckets
    // u32[] chain values (one per symbol starting at symoffset)
    let nbuckets = read_u32(gnu_hash_addr) as u64;
    let symoffset = read_u32(gnu_hash_addr + 4) as u64;
    let bloom_size = read_u32(gnu_hash_addr + 8) as u64;
    let _bloom_shift = read_u32(gnu_hash_addr + 12);

    if nbuckets == 0 {
        return None;
    }

    let bloom_start = gnu_hash_addr + 16;
    let buckets_start = bloom_start + bloom_size * 8;
    let chains_start = buckets_start + nbuckets * 4;

    let h = gnu_hash(name);
    let bucket_idx = (h as u64) % nbuckets;
    let sym_idx = read_u32(buckets_start + bucket_idx * 4) as u64;

    if sym_idx == 0 {
        return None; // Empty bucket.
    }

    // Walk the chain.
    let mut idx = sym_idx;
    loop {
        let chain_val = read_u32(chains_start + (idx - symoffset) * 4);

        // Check if hash matches (ignoring bit 0 which is the stop bit).
        if (chain_val | 1) == (h | 1) {
            let sym = symtab_addr + idx * SYM_SIZE;
            let st_name = read_u32(sym + ST_NAME) as u64;
            let st_value = read_u64(sym + ST_VALUE);

            if st_name > 0 && str_eq(name, strtab_addr + st_name) {
                return Some(base + st_value);
            }
        }

        // Bit 0 of chain value = end of chain.
        if chain_val & 1 != 0 {
            break;
        }
        idx += 1;
    }

    None
}
