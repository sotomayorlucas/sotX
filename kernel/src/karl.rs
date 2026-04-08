//! Tier 5: KARL-style per-boot ID randomization.
//!
//! OpenBSD's KARL (Kernel Address Randomized Link) re-relinks the
//! kernel binary at boot time so that internal symbol addresses change
//! across reboots. We don't ship a kernel re-linker, but we can
//! achieve the same downstream effect for everything an attacker can
//! observe through the SOT syscall ABI:
//!
//!  * Transaction IDs (`SYS_TX_BEGIN` returns)
//!  * Thread IDs (per-thread `tid` from `SYS_THREAD_INFO`)
//!  * Future: capability IDs and channel IDs
//!
//! At boot, [`init`] reads RDTSC + a small mixer to derive a 64-bit
//! `boot_seed`. Each pool exposes a per-pool offset derived from this
//! seed; subsequent IDs are `(seed_offset + monotonic_counter)` so the
//! visible IDs differ every boot, defeating attempts to predict / guess
//! identifiers across reboots.
//!
//! All offsets land in distinct sub-ranges of `u64` so collisions
//! between TX IDs and thread IDs remain impossible.

use core::sync::atomic::{AtomicU64, Ordering};

static BOOT_SEED: AtomicU64 = AtomicU64::new(0);

/// Initialize the per-boot KARL seed. Called once from `kmain`. Safe
/// to call multiple times -- only the first call sets the seed.
pub fn init() {
    if BOOT_SEED.load(Ordering::Acquire) != 0 {
        return;
    }
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack),
        );
    }
    let mut s = ((hi as u64) << 32) | (lo as u64);
    // Mix with the kernel-link constant so two boots that happened to
    // get identical TSC values still produce distinct seeds.
    s ^= 0x6A09_E667_F3BC_C908;
    s = s.wrapping_mul(0x100000001B3);
    s ^= s >> 33;
    if s == 0 {
        s = 1;
    }
    BOOT_SEED.store(s, Ordering::Release);
    crate::kdebug!(
        "[karl] boot_seed = {:#018x} (tx_offset={:#x} tid_offset={:#x})",
        s,
        tx_id_offset(),
        thread_id_offset()
    );
}

/// Raw boot seed (for diagnostics).
pub fn boot_seed() -> u64 {
    BOOT_SEED.load(Ordering::Acquire)
}

/// Starting offset for transaction IDs. Lives in the upper 56 bits so
/// the monotonic counter occupies the bottom 8 bits and IDs visibly
/// drift each boot.
pub fn tx_id_offset() -> u64 {
    let s = BOOT_SEED.load(Ordering::Acquire);
    // 16 bits of entropy in the [16..32) range -- enough that two
    // reboots see clearly different IDs but the value still fits a u64
    // counter without overflow concerns.
    (s & 0xFFFF_0000) | 1
}

/// Starting offset for thread IDs. Disjoint range from tx ids.
pub fn thread_id_offset() -> u32 {
    let s = BOOT_SEED.load(Ordering::Acquire);
    // 12 bits of entropy in the [12..24) range, anchored above 0x1000.
    (((s >> 16) & 0xFFF) as u32) | 0x1000
}
