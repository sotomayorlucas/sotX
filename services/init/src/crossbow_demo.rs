//! Project Crossbow live demo.
//!
//! Walks through the four properties the unit tests already check
//! (provision exhaustion, port reuse on revoke, MAC uniqueness, and
//! token-bucket rate limiting), but does it from inside the running
//! init service so the marker line shows up on the serial console
//! at boot time.
//!
//! Sequence:
//!  1. Provision three VNICs for deception domains 7, 8, 9.
//!  2. Walk a 100-iteration `route()` burst on port 0 with a tiny
//!     bandwidth cap so the bucket trips. Expect a Forward streak
//!     followed by `RateLimited` for the rest of the burst.
//!  3. Revoke port 0 and re-provision -- assert the slot is reused.
//!  4. Sanity-check the MAC of the re-provisioned VNIC is locally
//!     administered (LAA bit set, unicast bit clear).
//!
//! Prints `=== Crossbow: PASS ===` on success or
//! `=== Crossbow: FAIL ===` (with a short reason) on failure.

use crate::framebuffer::{print, print_hex8, print_u64};
use sot_crossbow::{SwitchDecision, VirtualSwitch};

const TINY_BW_KBPS: u32 = 8; // 8 kbps -> 1000 bytes/sec budget.
const BURST_LEN: usize = 100;
const BURST_PKT_BYTES: usize = 100;

fn fail(reason: &[u8]) -> bool {
    print(b"    !! ");
    print(reason);
    print(b"\n=== Crossbow: FAIL ===\n\n");
    false
}

pub fn run() -> bool {
    print(b"\n=== Crossbow VNIC primitive demo ===\n");

    let mut sw = VirtualSwitch::new();

    // -- Step 1: provision three VNICs --------------------------------
    let p7 = match sw.provision(7, TINY_BW_KBPS) {
        Ok(p) => p,
        Err(_) => return fail(b"provision(7) failed"),
    };
    let p8 = match sw.provision(8, TINY_BW_KBPS) {
        Ok(p) => p,
        Err(_) => return fail(b"provision(8) failed"),
    };
    let p9 = match sw.provision(9, TINY_BW_KBPS) {
        Ok(p) => p,
        Err(_) => return fail(b"provision(9) failed"),
    };
    print(b"    provisioned ports 7,8,9 -> ");
    print_u64(p7 as u64);
    print(b",");
    print_u64(p8 as u64);
    print(b",");
    print_u64(p9 as u64);
    print(b"\n");

    if p7 != 0 || p8 != 1 || p9 != 2 {
        return fail(b"port indices not sequential");
    }
    if sw.lookup_domain(7) != Some(p7)
        || sw.lookup_domain(8) != Some(p8)
        || sw.lookup_domain(9) != Some(p9)
    {
        return fail(b"lookup_domain mismatch");
    }

    // -- Step 2: 100-route burst on port 0, expect Forward then RateLimited --
    let mut forwarded = 0u64;
    let mut limited = 0u64;
    for i in 0..BURST_LEN {
        // All inside the same TSC window so the bucket never refills.
        match sw.route(p7, BURST_PKT_BYTES, i as u64) {
            SwitchDecision::Forward(_) => forwarded += 1,
            SwitchDecision::RateLimited => limited += 1,
            SwitchDecision::Drop => return fail(b"route returned Drop"),
        }
    }
    print(b"    burst: forwarded=");
    print_u64(forwarded);
    print(b" rate_limited=");
    print_u64(limited);
    print(b"\n");
    if forwarded == 0 {
        return fail(b"no packets forwarded");
    }
    if limited == 0 {
        return fail(b"rate limiter never tripped");
    }
    if forwarded + limited != BURST_LEN as u64 {
        return fail(b"burst totals don't add up");
    }
    // 8 kbps = 1000 bytes/sec; 100-byte packets -> 10 forwards then trip.
    if forwarded != 10 {
        return fail(b"expected exactly 10 forwards before rate limit");
    }

    // -- Step 3: revoke port 0 and re-provision -- same port returned -----
    sw.revoke(p7);
    if sw.lookup_domain(7).is_some() {
        return fail(b"lookup_domain still finds revoked port");
    }
    if !matches!(sw.route(p7, 64, 0), SwitchDecision::Drop) {
        return fail(b"revoked port still routes");
    }
    let p7b = match sw.provision(7, TINY_BW_KBPS) {
        Ok(p) => p,
        Err(_) => return fail(b"reprovision failed"),
    };
    if p7b != p7 {
        return fail(b"reprovisioned port index changed");
    }
    print(b"    revoke + reprovision -> port ");
    print_u64(p7b as u64);
    print(b" reused\n");

    // -- Step 4: MAC sanity ------------------------------------------------
    let mac_after = match sw.vnic(p7b) {
        Some(v) => v.mac,
        None => return fail(b"reprovisioned port has no vnic"),
    };
    if mac_after[0] & 0x03 != 0x02 {
        return fail(b"reprovisioned MAC not LAA unicast");
    }
    print(b"    MAC[0]=0x");
    print_hex8(mac_after[0]);
    print(b" (LAA unicast)\n");

    print(b"=== Crossbow: PASS ===\n\n");
    true
}
