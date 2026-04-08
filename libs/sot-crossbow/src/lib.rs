//! Project Crossbow -- kernel-style VNICs and a virtual switch.
//!
//! Crossbow is the Solaris/Illumos heirloom that turns the network
//! stack into a first-class virtualized resource: every guest /
//! domain gets its own VNIC (virtual NIC) plugged into a virtual
//! switch port, with bandwidth limits enforced per port.
//!
//! This crate is the sotOS port: a no_std, no-alloc, fixed-size
//! implementation that complements the existing
//! [`PfInterposer`](../sot_network/pf/struct.PfInterposer.html) by
//! giving each deception-mode domain a dedicated VNIC and a token
//! bucket for rate limiting.
//!
//! # API surface
//!
//! ```ignore
//! use sot_crossbow::{VirtualSwitch, SwitchDecision, DEFAULT_BW_LIMIT_KBPS};
//!
//! let mut sw = VirtualSwitch::new();
//! let port = sw.provision(7, DEFAULT_BW_LIMIT_KBPS).unwrap();
//! match sw.route(port, 1500, rdtsc()) {
//!     SwitchDecision::Forward(p) => { /* hand to ifnet */ }
//!     SwitchDecision::RateLimited => { /* drop, bandwidth exhausted */ }
//!     SwitchDecision::Drop => { /* invalid src */ }
//! }
//! sw.revoke(port);
//! ```
//!
//! # Design notes
//!
//! - **No heap.** The switch is a `[Option<Vnic>; MAX_VSWITCH_PORTS]`
//!   so all operations are O(1) by direct port index. Provision /
//!   revoke / route never allocate.
//! - **MAC generation.** Each VNIC's MAC is locally administered
//!   (the second-least-significant bit of the first octet is set)
//!   and derived from `domain_id ^ tsc`, which is unique enough for
//!   a deception domain that lives for a few seconds.
//! - **Rate limiting.** A token bucket per port refilled once per
//!   one-second TSC window. The TSC frequency is configurable via
//!   [`set_tsc_hz`]; the default (2 GHz) matches the value the
//!   existing vDSO `__vdso_clock_gettime` assumes.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod switch;
mod vnic;

#[cfg(test)]
mod test_sync {
    // Shared mutex used by every unit test that touches the
    // process-wide `TSC_HZ` atomic, so cargo's parallel test runner
    // never observes a torn frequency value.
    use std::sync::Mutex;
    pub(crate) static TSC_HZ_GUARD: Mutex<()> = Mutex::new(());
}

pub use switch::{CrossbowError, SwitchDecision, VirtualSwitch};
pub use vnic::{mac_for_domain, set_tsc_hz, tsc_hz, Vnic};

/// The domain identifier used by the rest of the BSD personality
/// (currently a `u64` to stay compatible with
/// `sot_network::pf::DomainId`). Re-declared locally so this crate
/// has zero deps and builds standalone for `x86_64-unknown-none`.
pub type DomainId = u64;

/// Maximum number of VNICs that can be plugged into a single
/// `VirtualSwitch`. Must be `<= 256` so a port index fits in a `u8`.
pub const MAX_VSWITCH_PORTS: usize = 32;

/// Default per-VNIC bandwidth limit (10 Mbps) used by
/// `PfInterposer::deception_enter`.
pub const DEFAULT_BW_LIMIT_KBPS: u32 = 10_000;
