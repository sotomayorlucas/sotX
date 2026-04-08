//! Secure string operations -- ported from OpenBSD.
//!
//! These prevent buffer overflows in kernel string handling by always
//! NUL-terminating and reporting truncation via the return value.
//!
//! Ported from `vendor/openbsd-crypto/string/strlcpy.c` and `strlcat.c`.
//!
//! Original copyright:
//!   Copyright (c) 1998, 2015 Todd C. Miller <millert@openbsd.org> (ISC license).
//!   explicit_bzero: Public domain, Matthew Dempsky.

/// Securely zero memory. The compiler cannot optimize this away because
/// each byte is written via `write_volatile`, followed by a compiler fence.
///
/// Ported from OpenBSD `explicit_bzero` (`vendor/openbsd-crypto/string/explicit_bzero.c`).
pub fn explicit_bzero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid `&mut u8` from the slice iterator, so the
        // pointer is non-null, properly aligned, and exclusively owned for
        // the duration of the write. `write_volatile` prevents the optimiser
        // from eliding the secret-zeroing.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Copy `src` to `dst`, guaranteeing NUL-termination.
///
/// At most `dst.len() - 1` bytes are copied from `src` (stopping at the first
/// NUL in `src`). The result is always NUL-terminated unless `dst` is empty.
/// Returns the length of `src` (up to its first NUL). If the return value
/// is >= `dst.len()`, truncation occurred.
///
/// Unlike C `strncpy`, this always NUL-terminates and does not zero-pad.
///
/// Faithful port of OpenBSD `strlcpy` (`vendor/openbsd-crypto/string/strlcpy.c`).
pub fn strlcpy(dst: &mut [u8], src: &[u8]) -> usize {
    let dsize = dst.len();
    if dsize == 0 {
        // Still need to count src length
        let mut src_len = 0;
        while src_len < src.len() && src[src_len] != 0 {
            src_len += 1;
        }
        return src_len;
    }

    let mut si = 0; // source index
    let mut di = 0; // dest index
    let nleft = dsize - 1; // space for data (excluding NUL)

    // Copy as many bytes as will fit
    while di < nleft {
        if si >= src.len() || src[si] == 0 {
            break;
        }
        dst[di] = src[si];
        di += 1;
        si += 1;
    }

    // NUL-terminate
    dst[di] = 0;

    // If we stopped early due to dst full, traverse rest of src to get total length
    while si < src.len() && src[si] != 0 {
        si += 1;
    }

    si // length of src (not including NUL)
}

/// Append `src` to NUL-terminated string in `dst`.
///
/// `dst.len()` is the full size of the `dst` buffer (not space remaining).
/// At most `dst.len() - strlen(dst) - 1` bytes from `src` are appended.
/// Always NUL-terminates (unless `dst.len() <= strlen(dst)`).
///
/// Returns `strlen(src) + min(dst.len(), strlen(initial dst))`.
/// If the return value >= `dst.len()`, truncation occurred.
///
/// Faithful port of OpenBSD `strlcat` (`vendor/openbsd-crypto/string/strlcat.c`).
pub fn strlcat(dst: &mut [u8], src: &[u8]) -> usize {
    let dsize = dst.len();

    // Find the end of the existing string in dst
    let mut dlen = 0;
    while dlen < dsize && dst[dlen] != 0 {
        dlen += 1;
    }

    // No room to append (dst not properly NUL-terminated within dsize, or full)
    let n = dsize.saturating_sub(dlen);
    if n == 0 {
        // Count src length and return
        let mut src_len = 0;
        while src_len < src.len() && src[src_len] != 0 {
            src_len += 1;
        }
        return dlen + src_len;
    }

    let space = n - 1; // space for data (excluding NUL)
    let mut si = 0;
    let mut di = dlen;

    while si < src.len() && src[si] != 0 {
        if si < space {
            dst[di] = src[si];
            di += 1;
        }
        si += 1;
    }

    dst[di] = 0;

    dlen + si // total length attempted
}
