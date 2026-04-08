//! Virtual switch with per-port token-bucket rate limiting.
//!
//! The switch is a flat array of `Option<Vnic>` slots: provisioning
//! is the first free slot, revocation is `slot = None`. Both
//! operations are O(1) by direct port index, so even with thousands
//! of provision/revoke cycles per second the switch never walks more
//! than `MAX_VSWITCH_PORTS` entries.
//!
//! Rate limiting is a one-second TSC window. On every `route()`:
//!
//! 1. If the current TSC is in a fresh window (>= last + tsc_hz),
//!    reset the byte counter to zero and remember the new window.
//! 2. If `byte_counter + pkt_len` would exceed the per-second
//!    budget (`bw_limit_kbps * 125` bytes), return `RateLimited`.
//! 3. Otherwise, charge the bytes and return `Forward(port)`.
//!
//! `bw_limit_kbps * 125` is the per-second byte budget:
//! `kbps * 1000 bits / 8 bits-per-byte = kbps * 125 bytes`.

use crate::vnic::{tsc_hz, Vnic};
use crate::{DomainId, MAX_VSWITCH_PORTS};

/// Reasons a switch operation can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossbowError {
    /// All `MAX_VSWITCH_PORTS` slots are in use.
    PortsExhausted,
    /// `lookup_domain()` could not find the requested domain.
    DomainNotFound,
    /// `route()` was called with a port index that is either out of
    /// range or refers to a slot that is currently unprovisioned.
    InvalidPort,
}

/// What the switch decided to do with a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchDecision {
    /// Forward the packet on the given port.
    Forward(u8),
    /// Drop because the source port is invalid / unprovisioned.
    Drop,
    /// Drop because the per-port bandwidth budget is exhausted.
    RateLimited,
}

/// The Crossbow virtual switch.
///
/// Holds up to `MAX_VSWITCH_PORTS` VNICs and their token-bucket
/// state. Constructed with `VirtualSwitch::new()` (`const fn`, so
/// it can sit in a `static` if a service ever needs that).
pub struct VirtualSwitch {
    ports: [Option<Vnic>; MAX_VSWITCH_PORTS],
    byte_counters: [u64; MAX_VSWITCH_PORTS],
    last_window_tsc: [u64; MAX_VSWITCH_PORTS],
}

impl VirtualSwitch {
    /// Build an empty switch with no ports provisioned.
    pub const fn new() -> Self {
        Self {
            ports: [None; MAX_VSWITCH_PORTS],
            byte_counters: [0; MAX_VSWITCH_PORTS],
            last_window_tsc: [0; MAX_VSWITCH_PORTS],
        }
    }

    /// Allocate a port for `domain` with a `bw_kbps` bandwidth cap.
    ///
    /// Returns the port index on success, or
    /// `CrossbowError::PortsExhausted` if every slot is in use.
    pub fn provision(
        &mut self,
        domain: DomainId,
        bw_kbps: u32,
    ) -> Result<u8, CrossbowError> {
        let tsc = read_tsc();
        for i in 0..MAX_VSWITCH_PORTS {
            if self.ports[i].is_none() {
                self.ports[i] = Some(Vnic::new(domain, bw_kbps, tsc));
                self.byte_counters[i] = 0;
                self.last_window_tsc[i] = tsc;
                return Ok(i as u8);
            }
        }
        Err(CrossbowError::PortsExhausted)
    }

    /// Free a port. No-op if the port is out of range or already
    /// unprovisioned, so callers can revoke optimistically.
    pub fn revoke(&mut self, port: u8) {
        let p = port as usize;
        if p < MAX_VSWITCH_PORTS {
            self.ports[p] = None;
            self.byte_counters[p] = 0;
            self.last_window_tsc[p] = 0;
        }
    }

    /// Charge `pkt_len` bytes against the source port and decide
    /// whether to forward or drop.
    ///
    /// `now_tsc` is the current TSC reading; the caller passes it in
    /// (instead of the switch reading it itself) so unit tests can
    /// drive the rate limiter deterministically without RDTSC.
    pub fn route(
        &mut self,
        src_port: u8,
        pkt_len: usize,
        now_tsc: u64,
    ) -> SwitchDecision {
        let p = src_port as usize;
        if p >= MAX_VSWITCH_PORTS {
            return SwitchDecision::Drop;
        }
        let vnic = match self.ports[p] {
            Some(v) => v,
            None => return SwitchDecision::Drop,
        };

        // Refill the bucket once per one-second TSC window.
        let window = tsc_hz();
        if now_tsc.wrapping_sub(self.last_window_tsc[p]) >= window {
            self.byte_counters[p] = 0;
            self.last_window_tsc[p] = now_tsc;
        }

        // bw_limit_kbps * 125 = bytes/second budget.
        let budget_bytes = (vnic.bw_limit_kbps as u64).saturating_mul(125);
        let new_total = self.byte_counters[p].saturating_add(pkt_len as u64);
        if new_total > budget_bytes {
            return SwitchDecision::RateLimited;
        }
        self.byte_counters[p] = new_total;
        SwitchDecision::Forward(src_port)
    }

    /// Find the first port (in index order) that owns `domain`.
    pub fn lookup_domain(&self, domain: DomainId) -> Option<u8> {
        for i in 0..MAX_VSWITCH_PORTS {
            if let Some(v) = &self.ports[i] {
                if v.domain == domain {
                    return Some(i as u8);
                }
            }
        }
        None
    }

    /// Inspect the VNIC at `port`, if any.
    pub fn vnic(&self, port: u8) -> Option<&Vnic> {
        let p = port as usize;
        if p >= MAX_VSWITCH_PORTS {
            return None;
        }
        self.ports[p].as_ref()
    }

    /// Number of currently provisioned ports.
    pub fn live_port_count(&self) -> usize {
        self.ports.iter().filter(|p| p.is_some()).count()
    }
}

impl Default for VirtualSwitch {
    fn default() -> Self {
        Self::new()
    }
}

/// Read the TSC. On `x86_64` (kernel + std targets) this is the real
/// rdtsc instruction; on every other target we return zero -- the
/// only callers on non-x86 are unit tests, which always pass an
/// explicit `now_tsc` to `route()` and never observe this value.
#[inline(always)]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: rdtsc has no preconditions and no side effects.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_sync::TSC_HZ_GUARD;
    use crate::vnic::{set_tsc_hz, DEFAULT_TSC_HZ};
    use crate::DEFAULT_BW_LIMIT_KBPS;
    use std::sync::MutexGuard;

    /// Returns a fresh switch *and* a held guard on the global
    /// TSC_HZ. Tests that touch `route()` must keep the guard alive
    /// for their duration so the vnic-module tests can't yank
    /// `TSC_HZ` out from underneath the rate-limiter math.
    fn fresh_switch() -> (VirtualSwitch, MutexGuard<'static, ()>) {
        let guard = TSC_HZ_GUARD.lock().unwrap();
        set_tsc_hz(DEFAULT_TSC_HZ);
        (VirtualSwitch::new(), guard)
    }

    #[test]
    fn provision_returns_sequential_ports() {
        let (mut sw, _g) = fresh_switch();
        assert_eq!(sw.provision(1, DEFAULT_BW_LIMIT_KBPS), Ok(0));
        assert_eq!(sw.provision(2, DEFAULT_BW_LIMIT_KBPS), Ok(1));
        assert_eq!(sw.provision(3, DEFAULT_BW_LIMIT_KBPS), Ok(2));
        assert_eq!(sw.live_port_count(), 3);
    }

    #[test]
    fn provision_exhausts_after_max_ports() {
        let (mut sw, _g) = fresh_switch();
        for i in 0..MAX_VSWITCH_PORTS {
            assert!(sw.provision(i as DomainId, DEFAULT_BW_LIMIT_KBPS).is_ok());
        }
        assert_eq!(
            sw.provision(9999, DEFAULT_BW_LIMIT_KBPS),
            Err(CrossbowError::PortsExhausted),
        );
    }

    #[test]
    fn revoke_then_reprovision_returns_same_port() {
        let (mut sw, _g) = fresh_switch();
        let p0 = sw.provision(7, DEFAULT_BW_LIMIT_KBPS).unwrap();
        let _p1 = sw.provision(8, DEFAULT_BW_LIMIT_KBPS).unwrap();
        sw.revoke(p0);
        let p_again = sw.provision(7, DEFAULT_BW_LIMIT_KBPS).unwrap();
        assert_eq!(p0, p_again);
    }

    #[test]
    fn revoke_invalid_port_is_noop() {
        let (mut sw, _g) = fresh_switch();
        sw.revoke(255);
        assert_eq!(sw.live_port_count(), 0);
    }

    #[test]
    fn route_invalid_port_drops() {
        let (mut sw, _g) = fresh_switch();
        assert_eq!(sw.route(0, 64, 0), SwitchDecision::Drop);
    }

    #[test]
    fn route_revoked_port_drops() {
        let (mut sw, _g) = fresh_switch();
        let p = sw.provision(1, DEFAULT_BW_LIMIT_KBPS).unwrap();
        sw.revoke(p);
        assert_eq!(sw.route(p, 64, 0), SwitchDecision::Drop);
    }

    #[test]
    fn route_forwards_inside_budget() {
        let (mut sw, _g) = fresh_switch();
        let p = sw.provision(1, DEFAULT_BW_LIMIT_KBPS).unwrap();
        // 10 Mbps * 125 = 1_250_000 bytes/sec budget; 1500 bytes is fine.
        assert_eq!(sw.route(p, 1500, 0), SwitchDecision::Forward(p));
    }

    #[test]
    fn route_rate_limits_when_budget_exhausted() {
        let (mut sw, _g) = fresh_switch();
        // Tiny cap: 8 kbps -> 1000 bytes/sec.
        let p = sw.provision(1, 8).unwrap();
        assert_eq!(sw.route(p, 800, 0), SwitchDecision::Forward(p));
        // 800 + 800 = 1600 > 1000 budget -> rate-limited.
        assert_eq!(sw.route(p, 800, 0), SwitchDecision::RateLimited);
    }

    #[test]
    fn route_refills_after_window_advances() {
        let (mut sw, _g) = fresh_switch();
        let p = sw.provision(1, 8).unwrap();
        assert_eq!(sw.route(p, 1000, 0), SwitchDecision::Forward(p));
        assert_eq!(sw.route(p, 1, 0), SwitchDecision::RateLimited);
        // Advance past the one-second TSC window.
        let next_window = DEFAULT_TSC_HZ + 1;
        assert_eq!(sw.route(p, 1000, next_window), SwitchDecision::Forward(p));
    }

    #[test]
    fn lookup_domain_finds_provisioned() {
        let (mut sw, _g) = fresh_switch();
        let p = sw.provision(42, DEFAULT_BW_LIMIT_KBPS).unwrap();
        assert_eq!(sw.lookup_domain(42), Some(p));
        assert_eq!(sw.lookup_domain(43), None);
    }

    #[test]
    fn vnic_accessor_returns_record() {
        let (mut sw, _g) = fresh_switch();
        let p = sw.provision(7, DEFAULT_BW_LIMIT_KBPS).unwrap();
        let v = sw.vnic(p).expect("provisioned port has a vnic");
        assert_eq!(v.domain, 7);
        assert_eq!(v.bw_limit_kbps, DEFAULT_BW_LIMIT_KBPS);
        assert_eq!(v.mac[0] & 0x03, 0x02);
        assert!(sw.vnic(255).is_none());
    }

    #[test]
    fn macs_are_unique_across_provisioned_ports() {
        let (mut sw, _g) = fresh_switch();
        let mut macs: [[u8; 6]; MAX_VSWITCH_PORTS] = [[0; 6]; MAX_VSWITCH_PORTS];
        for i in 0..MAX_VSWITCH_PORTS {
            // Spread the domains apart so the seed is not all zero.
            let p = sw.provision(0xA000 + i as DomainId, DEFAULT_BW_LIMIT_KBPS).unwrap();
            macs[p as usize] = sw.vnic(p).unwrap().mac;
        }
        for i in 0..MAX_VSWITCH_PORTS {
            for j in (i + 1)..MAX_VSWITCH_PORTS {
                assert_ne!(macs[i], macs[j], "ports {} and {} share a MAC", i, j);
            }
        }
    }
}
