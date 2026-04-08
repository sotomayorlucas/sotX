//! SOT cryptographic primitives -- adapted from OpenBSD arc4random.
//!
//! Provides a ChaCha20-based CSPRNG seeded from hardware entropy (RDRAND/RDTSC).
//! Ported from `vendor/openbsd-crypto/arc4random/chacha_private.h` and
//! `vendor/openbsd-crypto/arc4random/arc4random.c`.
//!
//! Original copyright:
//!   chacha-merged.c version 20080118, D. J. Bernstein, Public domain.
//!   arc4random.c -- Copyright (c) 1996 David Mazieres, 2008 Damien Miller,
//!                   2013 Markus Friedl, 2014 Theo de Raadt (ISC license).

use super::secure_string::explicit_bzero;

// -- ChaCha20 constants (from chacha_private.h) --

/// "expand 32-byte k" as little-endian u32s.
const SIGMA: [u32; 4] = [
    0x6170_7865, // "expa"
    0x3320_646e, // "nd 3"
    0x7962_2d32, // "2-by"
    0x6b20_6574, // "te k"
];

// -- ChaCha20 primitives (faithful port from chacha_private.h) --

/// ChaCha20 quarter-round macro: the core mixing operation.
///
/// Direct translation of the OpenBSD QUARTERROUND macro. Uses a macro
/// (like the C original) to avoid borrow checker issues with multiple
/// mutable references into the same array.
///
///   a = PLUS(a,b); d = ROTATE(XOR(d,a),16);
///   c = PLUS(c,d); b = ROTATE(XOR(b,c),12);
///   a = PLUS(a,b); d = ROTATE(XOR(d,a), 8);
///   c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);
macro_rules! quarter_round {
    ($x:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $x[$a] = $x[$a].wrapping_add($x[$b]);
        $x[$d] = ($x[$d] ^ $x[$a]).rotate_left(16);
        $x[$c] = $x[$c].wrapping_add($x[$d]);
        $x[$b] = ($x[$b] ^ $x[$c]).rotate_left(12);
        $x[$a] = $x[$a].wrapping_add($x[$b]);
        $x[$d] = ($x[$d] ^ $x[$a]).rotate_left(8);
        $x[$c] = $x[$c].wrapping_add($x[$d]);
        $x[$b] = ($x[$b] ^ $x[$c]).rotate_left(7);
    };
}

/// Read a little-endian u32 from a byte slice (U8TO32_LITTLE).
#[inline(always)]
fn u8to32_le(p: &[u8]) -> u32 {
    (p[0] as u32) | ((p[1] as u32) << 8) | ((p[2] as u32) << 16) | ((p[3] as u32) << 24)
}

/// Write a u32 as little-endian bytes (U32TO8_LITTLE).
#[inline(always)]
fn u32to8_le(p: &mut [u8], v: u32) {
    p[0] = v as u8;
    p[1] = (v >> 8) as u8;
    p[2] = (v >> 16) as u8;
    p[3] = (v >> 24) as u8;
}

/// Set up the ChaCha20 key (chacha_keysetup, 256-bit key only).
fn chacha_keysetup(state: &mut [u32; 16], key: &[u8; 32]) {
    state[0] = SIGMA[0];
    state[1] = SIGMA[1];
    state[2] = SIGMA[2];
    state[3] = SIGMA[3];
    state[4] = u8to32_le(&key[0..4]);
    state[5] = u8to32_le(&key[4..8]);
    state[6] = u8to32_le(&key[8..12]);
    state[7] = u8to32_le(&key[12..16]);
    state[8] = u8to32_le(&key[16..20]);
    state[9] = u8to32_le(&key[20..24]);
    state[10] = u8to32_le(&key[24..28]);
    state[11] = u8to32_le(&key[28..32]);
}

/// Set the ChaCha20 IV/nonce (chacha_ivsetup).
fn chacha_ivsetup(state: &mut [u32; 16], iv: &[u8; 8]) {
    state[12] = 0;
    state[13] = 0;
    state[14] = u8to32_le(&iv[0..4]);
    state[15] = u8to32_le(&iv[4..8]);
}

/// Generate a 64-byte keystream block (KEYSTREAM_ONLY variant of chacha_encrypt_bytes).
///
/// This is the core of the OpenBSD CSPRNG: 20-round ChaCha applied to the state,
/// producing 64 bytes of keystream per block. Counter in state[12..13] is incremented.
fn chacha_keystream_block(state: &mut [u32; 16], out: &mut [u8; 64]) {
    let mut x = *state;

    // 20 rounds (10 double-rounds), matching the OpenBSD source
    for _ in (0..20).step_by(2) {
        // Column rounds
        quarter_round!(x, 0, 4, 8, 12);
        quarter_round!(x, 1, 5, 9, 13);
        quarter_round!(x, 2, 6, 10, 14);
        quarter_round!(x, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round!(x, 0, 5, 10, 15);
        quarter_round!(x, 1, 6, 11, 12);
        quarter_round!(x, 2, 7, 8, 13);
        quarter_round!(x, 3, 4, 9, 14);
    }

    // Add original state (j0..j15 in the C source)
    for i in 0..16 {
        x[i] = x[i].wrapping_add(state[i]);
    }

    // Serialize to little-endian bytes
    for i in 0..16 {
        u32to8_le(&mut out[i * 4..i * 4 + 4], x[i]);
    }

    // Increment block counter (state[12], overflow into state[13])
    state[12] = state[12].wrapping_add(1);
    if state[12] == 0 {
        state[13] = state[13].wrapping_add(1);
    }
}

// -- OpenBSD arc4random constants --

const KEYSZ: usize = 32;
const IVSZ: usize = 8;
const BLOCKSZ: usize = 64;
const RSBUFSZ: usize = 16 * BLOCKSZ; // 1024 bytes

/// Bytes until mandatory reseed (OpenBSD REKEY_BASE = 1MB).
const REKEY_BASE: usize = 1024 * 1024;

// -- Hardware entropy collection --

/// Try to read hardware random bytes via RDRAND. Returns true on success.
#[cfg(target_arch = "x86_64")]
fn try_rdrand(buf: &mut [u8]) -> bool {
    let mut ok = true;
    let mut i = 0;
    while i + 8 <= buf.len() {
        let val: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) success,
                options(nomem, nostack),
            );
        }
        if success == 0 {
            ok = false;
            break;
        }
        let bytes = val.to_le_bytes();
        buf[i..i + 8].copy_from_slice(&bytes);
        i += 8;
    }
    // Handle remaining bytes
    if ok && i < buf.len() {
        let val: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) success,
                options(nomem, nostack),
            );
        }
        if success == 0 {
            ok = false;
        } else {
            let bytes = val.to_le_bytes();
            let remaining = buf.len() - i;
            buf[i..i + remaining].copy_from_slice(&bytes[..remaining]);
        }
    }
    ok
}

/// Read TSC-based entropy (fallback when RDRAND unavailable).
fn tsc_entropy(buf: &mut [u8]) {
    let mut i = 0;
    while i + 8 <= buf.len() {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        let val = ((hi as u64) << 32) | (lo as u64);
        let bytes = val.to_le_bytes();
        buf[i..i + 8].copy_from_slice(&bytes);
        i += 8;
    }
    if i < buf.len() {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        let val = ((hi as u64) << 32) | (lo as u64);
        let bytes = val.to_le_bytes();
        let remaining = buf.len() - i;
        buf[i..i + remaining].copy_from_slice(&bytes[..remaining]);
    }
}

/// Collect entropy: RDRAND if available, else RDTSC.
fn getentropy(buf: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if try_rdrand(buf) {
            return;
        }
    }
    tsc_entropy(buf);
}

// -- SotRandom: ChaCha20-based CSPRNG (adapted from OpenBSD arc4random) --

/// ChaCha20-based CSPRNG adapted from OpenBSD `arc4random`.
///
/// Uses RDRAND for seeding when available, falls back to TSC-based entropy.
/// Reseeds automatically after `REKEY_BASE` bytes of output, with the reseed
/// interval itself randomized for unpredictability (matching OpenBSD behavior).
pub struct SotRandom {
    state: [u32; 16],      // ChaCha20 state
    buffer: [u8; RSBUFSZ], // Output buffer (keystream blocks)
    have: usize,           // Valid bytes at end of buffer
    count: usize,          // Bytes until next reseed
    initialized: bool,
}

impl SotRandom {
    /// Create an uninitialized CSPRNG. Call `init()` before use.
    pub const fn new() -> Self {
        Self {
            state: [0u32; 16],
            buffer: [0u8; RSBUFSZ],
            have: 0,
            count: 0,
            initialized: false,
        }
    }

    /// Initialize with hardware entropy (RDRAND + TSC).
    /// Corresponds to OpenBSD's `_rs_init` + `_rs_stir`.
    pub fn init(&mut self) {
        let mut seed = [0u8; KEYSZ + IVSZ];
        getentropy(&mut seed);

        self.seed_from(&seed);
        explicit_bzero(&mut seed);

        self.have = 0;
        self.buffer = [0u8; RSBUFSZ];
        self.randomize_rekey_interval();
        self.initialized = true;
    }

    /// Set ChaCha20 key+IV from a KEYSZ+IVSZ byte seed, then securely erase it.
    fn seed_from(&mut self, seed: &[u8]) {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 8];
        key.copy_from_slice(&seed[..KEYSZ]);
        iv.copy_from_slice(&seed[KEYSZ..KEYSZ + IVSZ]);
        chacha_keysetup(&mut self.state, &key);
        chacha_ivsetup(&mut self.state, &iv);
        explicit_bzero(&mut key);
        explicit_bzero(&mut iv);
    }

    /// Generate a randomized rekey interval (OpenBSD: REKEY_BASE + fuzz % REKEY_BASE).
    fn randomize_rekey_interval(&mut self) {
        let mut block = [0u8; 64];
        chacha_keystream_block(&mut self.state, &mut block);
        let fuzz = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
        explicit_bzero(&mut block);
        self.count = REKEY_BASE + (fuzz % REKEY_BASE);
    }

    /// Rekey: generate fresh keystream, optionally mix in additional data.
    /// Corresponds to OpenBSD's `_rs_rekey`.
    fn rekey(&mut self, extra: Option<&[u8]>) {
        // Fill entire buffer with keystream (KEYSTREAM_ONLY mode)
        let mut offset = 0;
        while offset + BLOCKSZ <= RSBUFSZ {
            let mut block = [0u8; 64];
            chacha_keystream_block(&mut self.state, &mut block);
            self.buffer[offset..offset + BLOCKSZ].copy_from_slice(&block);
            offset += BLOCKSZ;
        }

        // Mix in optional extra data
        if let Some(dat) = extra {
            let m = if dat.len() < KEYSZ + IVSZ {
                dat.len()
            } else {
                KEYSZ + IVSZ
            };
            for i in 0..m {
                self.buffer[i] ^= dat[i];
            }
        }

        // Immediately reinit for backtracking resistance (OpenBSD behavior)
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.buffer[..KEYSZ]);
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&self.buffer[KEYSZ..KEYSZ + IVSZ]);
        chacha_keysetup(&mut self.state, &key);
        chacha_ivsetup(&mut self.state, &iv);

        // Zero out consumed key material
        explicit_bzero(&mut self.buffer[..KEYSZ + IVSZ]);
        self.have = RSBUFSZ - KEYSZ - IVSZ;
    }

    /// Reseed from hardware entropy. Called when count expires.
    /// Corresponds to OpenBSD's `_rs_stir`.
    fn stir(&mut self) {
        let mut seed = [0u8; KEYSZ + IVSZ];
        getentropy(&mut seed);

        if !self.initialized {
            self.seed_from(&seed);
            self.initialized = true;
        } else {
            self.rekey(Some(&seed));
        }
        explicit_bzero(&mut seed);

        self.have = 0;
        explicit_bzero(&mut self.buffer);
        self.randomize_rekey_interval();
    }

    /// Ensure we have enough entropy, reseeding if necessary.
    /// Corresponds to OpenBSD's `_rs_stir_if_needed`.
    fn stir_if_needed(&mut self, len: usize) {
        if !self.initialized || self.count <= len {
            self.stir();
        }
        if self.count <= len {
            self.count = 0;
        } else {
            self.count -= len;
        }
    }

    /// Fill buffer with cryptographically random bytes.
    /// Corresponds to OpenBSD's `_rs_random_buf` / `arc4random_buf`.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.stir_if_needed(buf.len());
        let mut remaining = buf.len();
        let mut offset = 0;

        while remaining > 0 {
            if self.have > 0 {
                let m = if remaining < self.have {
                    remaining
                } else {
                    self.have
                };
                let keystream_start = RSBUFSZ - self.have;
                buf[offset..offset + m]
                    .copy_from_slice(&self.buffer[keystream_start..keystream_start + m]);
                // Zero consumed keystream (backtracking resistance)
                explicit_bzero(&mut self.buffer[keystream_start..keystream_start + m]);
                offset += m;
                remaining -= m;
                self.have -= m;
            }
            if self.have == 0 {
                self.rekey(None);
            }
        }
    }

    /// Generate a random u32.
    /// Corresponds to OpenBSD's `_rs_random_u32` / `arc4random`.
    pub fn random_u32(&mut self) -> u32 {
        self.stir_if_needed(4);
        if self.have < 4 {
            self.rekey(None);
        }
        let start = RSBUFSZ - self.have;
        let val = u8to32_le(&self.buffer[start..start + 4]);
        explicit_bzero(&mut self.buffer[start..start + 4]);
        self.have -= 4;
        val
    }

    /// Generate a random u32 in [0, upper_bound) with no modulo bias.
    /// Matches OpenBSD's `arc4random_uniform` algorithm.
    pub fn uniform(&mut self, upper_bound: u32) -> u32 {
        if upper_bound < 2 {
            return 0;
        }
        // Calculate minimum acceptable value to avoid modulo bias.
        // OpenBSD: min = (2^32 - upper_bound) % upper_bound
        //        = (-upper_bound) % upper_bound  (using unsigned wraparound)
        let min = (u32::MAX - upper_bound + 1) % upper_bound;
        loop {
            let r = self.random_u32();
            if r >= min {
                return r % upper_bound;
            }
        }
    }
}
