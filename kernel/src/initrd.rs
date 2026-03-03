//! CPIO newc archive parser.
//!
//! Finds a named file inside a CPIO newc archive loaded by the bootloader.
//! Used to extract the init ELF binary from the initramfs.

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

        // Verify magic "070701".
        if &data[pos..pos + 6] != b"070701" {
            return None;
        }

        let namesize = parse_hex8(data, pos + 94) as usize; // offset 94: namesize
        let filesize = parse_hex8(data, pos + 54) as usize;  // offset 54: filesize

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

        // Check for trailer sentinel.
        if entry_name == b"TRAILER!!!" {
            return None;
        }

        // Match?
        if entry_name == name.as_bytes() {
            return Some(&data[data_start..data_end]);
        }

        // Advance to next entry (data + padding).
        pos = align4(data_end);
    }
}
