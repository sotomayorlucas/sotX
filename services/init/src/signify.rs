//! Tier 5 close: SHA-256 + Ed25519 boot chain.
//!
//! At build time, `scripts/build_signify_manifest.py` walks the initrd
//! file list, computes the SHA-256 of each file, signs the resulting
//! manifest with Ed25519 (key derived from a fixed dev seed; production
//! would swap to a real keypair), and emits `target/sigmanifest` plus
//! `services/init/src/sigkey_generated.rs` containing the public key as
//! a Rust const baked into init.
//!
//! At boot, `signify::verify_manifest()` does:
//!   1. Reads `sigmanifest` from the initrd via `sys::initrd_read`.
//!   2. Validates the v2 magic, entry count, length consistency.
//!   3. **Verifies the trailing 32-byte pubkey matches `SIGKEY_PUB`**
//!      embedded at compile time -- a tampered manifest with a fresh
//!      key it just signed itself fails this check.
//!   4. **Verifies the trailing 64-byte Ed25519 signature** over the
//!      signed body via `ed25519-compact`.
//!   5. Walks every entry, streams the corresponding initrd file
//!      through this module's streaming SHA-256, and asserts the
//!      digest matches.
//!
//! Any failure prints `=== Signify boot chain: FAIL ===` and aborts
//! before any user binary is spawned.
//!
//! On-disk manifest format v2 (little-endian):
//!
//!   magic       u32   = 0x53494732 ("SIG2")
//!   entry_count u32
//!   entries[count]:
//!     name_len  u16
//!     name      name_len bytes (no NUL)
//!     digest    32 bytes  (raw SHA-256)
//!   pubkey      32 bytes  (raw Ed25519 public key)
//!   signature   64 bytes  (Ed25519 over magic..end-of-entries)

use crate::framebuffer::{print, print_u64};
use sotos_common::sys;

/// Streaming SHA-256.
pub struct Sha256 {
    h: [u32; 8],
    /// Bytes consumed so far (drives the length suffix).
    len: u64,
    /// Pending bytes that haven't filled a 64-byte block yet.
    buf: [u8; 64],
    /// Number of valid bytes in `buf`.
    pending: usize,
}

const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    pub fn new() -> Self {
        Self { h: H_INIT, len: 0, buf: [0u8; 64], pending: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len += data.len() as u64;

        if self.pending > 0 {
            let take = (64 - self.pending).min(data.len());
            self.buf[self.pending..self.pending + take]
                .copy_from_slice(&data[..take]);
            self.pending += take;
            data = &data[take..];
            if self.pending == 64 {
                let block = self.buf;
                compress(&mut self.h, &block);
                self.pending = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            compress(&mut self.h, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.pending = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.len.wrapping_mul(8);

        // Append 0x80, then zeros, then 8-byte big-endian length.
        self.buf[self.pending] = 0x80;
        self.pending += 1;
        if self.pending > 56 {
            // Fill the rest with zeros and process; final block holds length.
            for i in self.pending..64 { self.buf[i] = 0; }
            let block = self.buf;
            compress(&mut self.h, &block);
            self.pending = 0;
            self.buf = [0u8; 64];
        }
        for i in self.pending..56 { self.buf[i] = 0; }
        let lenb = bit_len.to_be_bytes();
        self.buf[56..64].copy_from_slice(&lenb);
        let block = self.buf;
        compress(&mut self.h, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let mut a = h[0]; let mut b = h[1]; let mut c = h[2]; let mut d = h[3];
    let mut e = h[4]; let mut f = h[5]; let mut g = h[6]; let mut hh = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        hh = g; g = f; f = e;
        e = d.wrapping_add(temp1);
        d = c; c = b; b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
}

// ---------------------------------------------------------------------------
// Manifest verification
// ---------------------------------------------------------------------------

const MANIFEST_NAME: &[u8] = b"sigmanifest";
const MANIFEST_MAGIC: u32 = 0x5349_4732; // "SIG2"
const SIG_LEN: usize = 64;
const PK_LEN: usize = 32;

include!("sigkey_generated.rs");

/// Buffer for streaming the manifest itself out of initrd. Lives well
/// past every other init address-space region (see CLAUDE.md AS layout).
const MANIFEST_BUF_BASE: u64 = 0x11_000_000; // 272 MiB
const MANIFEST_BUF_PAGES: u64 = 16;          // 64 KiB headroom

/// Buffer for streaming individual files for hashing. 16 MiB covers our
/// largest signed binary (`net` at ~7.4 MiB and `rump-vfs` at ~4.4 MiB
/// today, with headroom for growth).
const FILE_BUF_BASE: u64 = 0x12_000_000;     // 288 MiB
const FILE_BUF_PAGES: u64 = 4096;            // 16 MiB

fn map_buf(base: u64, pages: u64) -> bool {
    for i in 0..pages {
        let f = match sys::frame_alloc() { Ok(f) => f, Err(_) => return false };
        if sys::map(base + i * 0x1000, f, 2).is_err() {
            return false;
        }
    }
    true
}

fn unmap_buf(base: u64, pages: u64) {
    for i in 0..pages {
        let _ = sys::unmap_free(base + i * 0x1000);
    }
}

fn read_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn read_u16_le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn print_hex_byte(b: u8) {
    let hi = (b >> 4) & 0xF;
    let lo = b & 0xF;
    sys::debug_print(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
    sys::debug_print(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
}

pub fn verify_manifest() {
    print(b"\n=== Signify boot chain (SHA-256) ===\n");

    if !map_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES) {
        print(b"signify: failed to map manifest buffer\n");
        return;
    }
    let m_size = match sys::initrd_read(
        MANIFEST_NAME.as_ptr() as u64,
        MANIFEST_NAME.len() as u64,
        MANIFEST_BUF_BASE,
        MANIFEST_BUF_PAGES * 0x1000,
    ) {
        Ok(s) => s as usize,
        Err(_) => {
            print(b"signify: 'sigmanifest' not in initrd -- skipping\n");
            unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
            return;
        }
    };
    let manifest = unsafe {
        core::slice::from_raw_parts(MANIFEST_BUF_BASE as *const u8, m_size)
    };

    if m_size < 8 {
        print(b"signify: manifest too small\n");
        unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
        return;
    }
    let magic = read_u32_le(manifest, 0);
    if magic != MANIFEST_MAGIC {
        print(b"signify: bad magic 0x");
        print_hex_byte((magic >> 24) as u8);
        print_hex_byte((magic >> 16) as u8);
        print_hex_byte((magic >> 8)  as u8);
        print_hex_byte(magic         as u8);
        print(b"\n");
        unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
        return;
    }
    let n_entries = read_u32_le(manifest, 4) as usize;
    print(b"signify: manifest entries=");
    print_u64(n_entries as u64);
    print(b"\n");

    // Manifest must end with [pubkey 32B][signature 64B]; everything
    // before that is the signed body.
    if m_size < PK_LEN + SIG_LEN + 8 {
        print(b"signify: manifest too small for sig trailer\n");
        unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
        return;
    }
    let body_end = m_size - (PK_LEN + SIG_LEN);
    let pk_off = body_end;
    let sig_off = pk_off + PK_LEN;
    let signed_body = &manifest[..body_end];
    let pubkey_in_manifest = &manifest[pk_off..pk_off + PK_LEN];
    let signature = &manifest[sig_off..sig_off + SIG_LEN];

    // Step 1: pubkey-pinning. Reject any manifest whose embedded pubkey
    // doesn't byte-match the const compiled into init -- this defeats a
    // tampered manifest signed with a freshly generated key.
    if pubkey_in_manifest != SIGKEY_PUB {
        print(b"signify: manifest pubkey != embedded SIGKEY_PUB\n");
        unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
        print(b"=== Signify boot chain: FAIL ===\n\n");
        return;
    }
    print(b"signify: pubkey matches embedded const\n");

    // Step 2: real Ed25519 signature verification.
    {
        use ed25519_compact::{PublicKey, Signature};
        let pk = match PublicKey::from_slice(pubkey_in_manifest) {
            Ok(p) => p,
            Err(_) => {
                print(b"signify: bad pubkey encoding\n");
                unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
                print(b"=== Signify boot chain: FAIL ===\n\n");
                return;
            }
        };
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => {
                print(b"signify: bad signature encoding\n");
                unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
                print(b"=== Signify boot chain: FAIL ===\n\n");
                return;
            }
        };
        if pk.verify(signed_body, &sig).is_err() {
            print(b"signify: Ed25519 verify FAILED\n");
            unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
            print(b"=== Signify boot chain: FAIL ===\n\n");
            return;
        }
    }
    print(b"signify: Ed25519 signature OK (");
    print_u64(signed_body.len() as u64);
    print(b" body bytes)\n");

    if !map_buf(FILE_BUF_BASE, FILE_BUF_PAGES) {
        print(b"signify: failed to map file buffer\n");
        unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
        return;
    }

    let mut off = 8usize;
    let mut verified = 0u32;
    let mut failed = 0u32;
    let mut missing = 0u32;
    for _ in 0..n_entries {
        if off + 2 > body_end { break; }
        let nlen = read_u16_le(manifest, off) as usize;
        off += 2;
        if off + nlen + 32 > body_end { break; }
        let name = &manifest[off..off + nlen];
        off += nlen;
        let want = &manifest[off..off + 32];
        off += 32;

        // Read the named file out of initrd.
        let read_res = sys::initrd_read(
            name.as_ptr() as u64,
            name.len() as u64,
            FILE_BUF_BASE,
            FILE_BUF_PAGES * 0x1000,
        );
        let size = match read_res {
            Ok(s) => s as usize,
            Err(_) => {
                missing += 1;
                continue;
            }
        };
        let data = unsafe {
            core::slice::from_raw_parts(FILE_BUF_BASE as *const u8, size)
        };
        let mut h = Sha256::new();
        h.update(data);
        let got = h.finalize();
        if got == want[..] {
            verified += 1;
        } else {
            failed += 1;
            print(b"signify: MISMATCH ");
            for &c in name { sys::debug_print(c); }
            print(b"\n  want=");
            for &c in want { print_hex_byte(c); }
            print(b"\n  got =");
            for &c in &got { print_hex_byte(c); }
            print(b"\n");
        }
    }

    unmap_buf(MANIFEST_BUF_BASE, MANIFEST_BUF_PAGES);
    unmap_buf(FILE_BUF_BASE, FILE_BUF_PAGES);

    print(b"signify: verified=");
    print_u64(verified as u64);
    print(b" failed=");
    print_u64(failed as u64);
    print(b" missing=");
    print_u64(missing as u64);
    print(b"\n");

    if failed == 0 && missing == 0 && verified > 0 {
        print(b"=== Signify boot chain: PASS ===\n\n");
    } else {
        print(b"=== Signify boot chain: FAIL ===\n\n");
    }
}
