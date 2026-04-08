//! Per-port virtual NIC.
//!
//! A `Vnic` is a tiny POD record stored inline in
//! `VirtualSwitch::ports[port]`. It carries the locally-administered
//! MAC, the bandwidth cap (in kbps), the owning domain, and a TSC
//! timestamp captured at provisioning time. The switch keeps the
//! token-bucket counters separately so the `Vnic` itself stays
//! `Copy + Eq` and easy to inspect.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::DomainId;

/// Default TSC frequency assumed by the rate limiter (2 GHz).
///
/// This matches the value `services/init/src/vdso.rs`'s
/// `__vdso_clock_gettime` already bakes in. If a board ships with a
/// different invariant TSC, the init service can call
/// [`set_tsc_hz`] before provisioning any VNIC.
pub const DEFAULT_TSC_HZ: u64 = 2_000_000_000;

/// Process-wide TSC frequency. Atomic so the kernel-test harness can
/// rewrite it from a different thread without holding a spinlock.
static TSC_HZ: AtomicU64 = AtomicU64::new(DEFAULT_TSC_HZ);

/// Override the assumed TSC frequency. Affects all subsequent
/// `route()` calls (in-flight token buckets keep their stale window
/// until the next refill, which is harmless).
pub fn set_tsc_hz(hz: u64) {
    if hz != 0 {
        TSC_HZ.store(hz, Ordering::Relaxed);
    }
}

/// Read the currently configured TSC frequency.
pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

/// A virtual NIC plugged into a `VirtualSwitch` port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vnic {
    /// 6-byte MAC address. The first octet always has bit 1 set
    /// (locally administered) and bit 0 clear (unicast).
    pub mac: [u8; 6],
    /// Bandwidth ceiling in kbps. Token bucket capacity = this
    /// value scaled into bytes per second.
    pub bw_limit_kbps: u32,
    /// The domain that owns this VNIC.
    pub domain: DomainId,
    /// TSC at provisioning time -- also stirred into the MAC so two
    /// VNICs for the same domain (revoke + re-provision) get
    /// different addresses.
    pub provisioned_at_tsc: u64,
}

/// Compute the locally-administered MAC for `(domain, tsc)`.
///
/// Layout:
/// - byte 0: `0x02 | ((mix >> 2) & 0xFC)` -- LAA bit set, unicast.
/// - bytes 1..5: successive bytes of a 64-bit mix word.
///
/// The mix word is built so that `domain` and `tsc` each contribute
/// to *every* output byte: `mix = (domain.wrapping_mul(0x9E37_79B9_7F4A_7C15))
/// ^ tsc.rotate_left(17) ^ (domain.rotate_left(31))`. This means
/// adjacent domain ids produce visibly different MACs (the test
/// `mac_changes_when_domain_changes` exercises this) and revoking and
/// re-provisioning the same domain in the same nanosecond still yields
/// a fresh address as long as the TSC has advanced.
pub fn mac_for_domain(domain: DomainId, tsc: u64) -> [u8; 6] {
    // Knuth's golden-ratio multiplier spreads single-bit input
    // changes across all 64 output bits.
    const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
    let mix = domain.wrapping_mul(GOLDEN) ^ tsc.rotate_left(17) ^ domain.rotate_left(31);
    let b0 = (((mix >> 2) as u8) & 0xFC) | 0x02;
    [
        b0,
        (mix >> 8) as u8,
        (mix >> 16) as u8,
        (mix >> 24) as u8,
        (mix >> 32) as u8,
        (mix >> 40) as u8,
    ]
}

impl Vnic {
    /// Allocate a fresh VNIC record. The TSC is captured both as a
    /// timestamp field *and* mixed into the MAC.
    pub fn new(domain: DomainId, bw_limit_kbps: u32, tsc: u64) -> Self {
        Self {
            mac: mac_for_domain(domain, tsc),
            bw_limit_kbps,
            domain,
            provisioned_at_tsc: tsc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_sync::TSC_HZ_GUARD;

    #[test]
    fn mac_is_locally_administered_unicast() {
        let mac = mac_for_domain(7, 0xDEAD_BEEF);
        // bit 1 set (LAA), bit 0 clear (unicast).
        assert_eq!(mac[0] & 0x03, 0x02);
    }

    #[test]
    fn mac_changes_when_tsc_changes() {
        let a = mac_for_domain(42, 1_000);
        let b = mac_for_domain(42, 2_000);
        assert_ne!(a, b, "two TSC values for same domain must differ");
    }

    #[test]
    fn mac_changes_when_domain_changes() {
        let a = mac_for_domain(1, 1_000);
        let b = mac_for_domain(2, 1_000);
        assert_ne!(a, b);
    }

    #[test]
    fn vnic_constructor_records_inputs() {
        let v = Vnic::new(9, 5_000, 0xCAFE);
        assert_eq!(v.domain, 9);
        assert_eq!(v.bw_limit_kbps, 5_000);
        assert_eq!(v.provisioned_at_tsc, 0xCAFE);
        assert_eq!(v.mac[0] & 0x03, 0x02);
    }

    #[test]
    fn tsc_hz_round_trip() {
        let _g = TSC_HZ_GUARD.lock().unwrap();
        set_tsc_hz(1_000_000_000);
        assert_eq!(tsc_hz(), 1_000_000_000);
        set_tsc_hz(DEFAULT_TSC_HZ);
        assert_eq!(tsc_hz(), DEFAULT_TSC_HZ);
    }

    #[test]
    fn set_tsc_hz_zero_is_noop() {
        let _g = TSC_HZ_GUARD.lock().unwrap();
        set_tsc_hz(DEFAULT_TSC_HZ);
        set_tsc_hz(0);
        assert_eq!(tsc_hz(), DEFAULT_TSC_HZ);
    }
}
