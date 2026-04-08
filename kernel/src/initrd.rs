//! CPIO newc archive parser.
//!
//! Finds a named file inside a CPIO newc archive loaded by the bootloader.
//! Used to extract the init ELF binary from the initramfs.

use core::sync::atomic::{AtomicU64, Ordering};

/// Physical base address of the initrd (set once at boot).
static INITRD_PHYS_BASE: AtomicU64 = AtomicU64::new(0);
/// Size of the initrd in bytes.
static INITRD_SIZE: AtomicU64 = AtomicU64::new(0);

/// Store initrd location for later syscall access.
pub fn set_initrd(base_phys: u64, size: u64) {
    INITRD_PHYS_BASE.store(base_phys, Ordering::Release);
    INITRD_SIZE.store(size, Ordering::Release);
}

/// Get the initrd physical base and size (if set).
pub fn initrd_base_size() -> Option<(u64, u64)> {
    let base = INITRD_PHYS_BASE.load(Ordering::Acquire);
    let size = INITRD_SIZE.load(Ordering::Acquire);
    if base != 0 && size != 0 {
        Some((base, size))
    } else {
        None
    }
}

/// Parse 8 hex ASCII characters at `offset` within `data`.
fn parse_hex8(data: &[u8], offset: usize) -> u32 {
    let mut val: u32 = 0;
    for i in 0..8 {
        let c = data[offset + i];
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        };
        val = (val << 4) | digit as u32;
    }
    val
}

/// Round up to the next 4-byte boundary.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Find a file by name in a CPIO newc archive.
///
/// Returns a sub-slice of `data` containing the file contents, or `None`
/// if the file is not found.
pub fn find<'a>(data: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let mut pos = 0;

    loop {
        // Need at least the 110-byte header.
        if pos + 110 > data.len() {
            return None;
        }

        // Verify magic "070701" — compare byte-by-byte to avoid memcmp UB checks.
        let magic_ok = data[pos] == b'0'
            && data[pos + 1] == b'7'
            && data[pos + 2] == b'0'
            && data[pos + 3] == b'7'
            && data[pos + 4] == b'0'
            && data[pos + 5] == b'1';
        if !magic_ok {
            return None;
        }

        let namesize = parse_hex8(data, pos + 94) as usize; // offset 94: namesize
        let filesize = parse_hex8(data, pos + 54) as usize; // offset 54: filesize

        // Name starts right after the 110-byte header.
        let name_start = pos + 110;
        let name_end = name_start + namesize;
        if name_end > data.len() {
            return None;
        }

        // Name includes NUL terminator — compare without it.
        let entry_name = &data[name_start..name_end - 1];

        // Data starts after name + padding to 4-byte boundary.
        let data_start = align4(name_end);
        let data_end = data_start + filesize;
        if data_end > data.len() {
            return None;
        }

        // Check for trailer sentinel — byte-by-byte.
        if entry_name.len() == 10
            && entry_name[0] == b'T'
            && entry_name[1] == b'R'
            && entry_name[2] == b'A'
            && entry_name[3] == b'I'
            && entry_name[4] == b'L'
            && entry_name[5] == b'E'
            && entry_name[6] == b'R'
            && entry_name[7] == b'!'
            && entry_name[8] == b'!'
            && entry_name[9] == b'!'
        {
            return None;
        }

        // Match? — byte-by-byte to avoid compiler_builtins memcmp UB checks.
        let target = name.as_bytes();
        let matched = if entry_name.len() == target.len() {
            let mut eq = true;
            for i in 0..entry_name.len() {
                if entry_name[i] != target[i] {
                    eq = false;
                    break;
                }
            }
            eq
        } else {
            false
        };

        if matched {
            return Some(&data[data_start..data_end]);
        }

        // Advance to next entry (data + padding).
        pos = align4(data_end);
    }
}

/// Find multiple files by name in a single CPIO pass.
/// Returns an array of Option<&[u8]> pairs corresponding
/// to each name in `names`. Reduces O(n*k) to O(n) for k lookups.
pub fn find_all<'a, const N: usize>(data: &'a [u8], names: &[&str; N]) -> [Option<&'a [u8]>; N] {
    let mut results: [Option<&'a [u8]>; N] = [None; N];
    let mut found_count = 0usize;
    let mut pos = 0;

    loop {
        if found_count == N {
            break;
        }
        if pos + 110 > data.len() {
            break;
        }

        // Verify magic "070701" byte-by-byte.
        let magic_ok = data[pos] == b'0'
            && data[pos + 1] == b'7'
            && data[pos + 2] == b'0'
            && data[pos + 3] == b'7'
            && data[pos + 4] == b'0'
            && data[pos + 5] == b'1';
        if !magic_ok {
            break;
        }

        let namesize = parse_hex8(data, pos + 94) as usize;
        let filesize = parse_hex8(data, pos + 54) as usize;

        let name_start = pos + 110;
        let name_end = name_start + namesize;
        if name_end > data.len() {
            break;
        }

        let entry_name = &data[name_start..name_end - 1]; // strip NUL

        let data_start = align4(name_end);
        let data_end = data_start + filesize;
        if data_end > data.len() {
            break;
        }

        // Check for trailer — byte-by-byte.
        if entry_name.len() == 10
            && entry_name[0] == b'T'
            && entry_name[1] == b'R'
            && entry_name[2] == b'A'
            && entry_name[3] == b'I'
            && entry_name[4] == b'L'
            && entry_name[5] == b'E'
            && entry_name[6] == b'R'
            && entry_name[7] == b'!'
            && entry_name[8] == b'!'
            && entry_name[9] == b'!'
        {
            break;
        }

        // Check against all target names.
        for i in 0..N {
            if results[i].is_some() {
                continue;
            }
            let target = names[i].as_bytes();
            if entry_name.len() == target.len() {
                let mut eq = true;
                for j in 0..entry_name.len() {
                    if entry_name[j] != target[j] {
                        eq = false;
                        break;
                    }
                }
                if eq {
                    results[i] = Some(&data[data_start..data_end]);
                    found_count += 1;
                    break;
                }
            }
        }

        pos = align4(data_end);
    }

    results
}
