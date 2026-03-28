// ---------------------------------------------------------------------------
// XKB path → initrd name mapping
//
// Maps /usr/share/X11/xkb/{subdir}/{file} to initrd entry "xkb_{subdir}_{file}".
// Used by the open/openat handlers to serve XKB files as initrd files (kind=12),
// which supports arbitrarily large files (unlike virtual files capped at 4KB).
// ---------------------------------------------------------------------------

use crate::exec::starts_with;

/// Check if a path is an XKB file and return the initrd name if so.
/// Returns Some((initrd_name, name_len)) if the path maps to an XKB initrd entry.
pub(crate) fn xkb_initrd_name(path: &[u8]) -> Option<([u8; 64], usize)> {
    if !starts_with(path, b"/usr/share/X11/xkb/") {
        return None;
    }
    let suffix = &path[19..]; // after "/usr/share/X11/xkb/"
    if suffix.is_empty() {
        return None;
    }

    // Build initrd lookup name: "xkb_{subdir}_{file}"
    let mut name = [0u8; 64];
    name[0..4].copy_from_slice(b"xkb_");
    let mut i = 4;
    for &b in suffix {
        if i >= 63 { break; }
        if b == b'/' {
            name[i] = b'_';
        } else {
            name[i] = b;
        }
        i += 1;
    }
    Some((name, i))
}
