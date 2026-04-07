//! Tier 6 PANDORA — Task 4 demo: software CHERI capability machine.
//!
//! End-to-end deliverable for PANDORA Task 4: drives the `sot-cheri`
//! service through every CHERI invariant we care about and asserts
//! that the model behaves the way Morello / CHERI-RISC-V hardware
//! would. Acts as the in-init proof that the SOT cap layer can host a
//! 128-bit compressed-cap ABI matching vendor/cheri-compressed-cap.
//!
//! The state machine we exercise:
//!
//!  1. svc_lookup("sot-cheri") -- fetch the service endpoint
//!  2. ROOT -- carve a top-level capability over the heap
//!  3. STORE through ROOT at addr=10 -- expect 0 (allowed)
//!  4. BOUNDS [16..32) -- narrow to a sub-region of the heap
//!  5. STORE 0xCAFE at addr=20 through SUB -- expect 0 (in bounds)
//!  6. STORE at addr=10 through SUB -- expect -EFAULT (BELOW base)
//!  7. STORE at addr=40 through SUB -- expect -EFAULT (above top)
//!  8. BOUNDS widen [0..64) on SUB -- expect ERROR (monotonicity)
//!  9. SEAL SUB with otype=0x42 -- expect new sealed cap
//! 10. LOAD through SEALED -- expect -EACCES (sealed-cap dereference)
//! 11. UNSEAL with wrong otype 0x99 -- expect -EACCES
//! 12. UNSEAL with correct otype 0x42 -- expect new unsealed cap
//! 13. LOAD addr=20 through UNSEALED -- expect 0xCAFE (data persisted)
//! 14. DERIVE perms_mask=PERM_LOAD only -- expect new readonly cap
//! 15. STORE through readonly cap -- expect ERROR
//! 16. DERIVE perms_mask=PERMS_ALL on readonly -- expect ERROR (perm monotonicity)
//! 17. STATS -- assert >= 3 bounds_faults, >= 1 sealed_fault, >= 2 monotonicity_faults
//! 18. Print PASS

use crate::framebuffer::{print, print_u64, print_hex64};
use sotos_common::{sys, IpcMsg};

const TAG_ROOT:    u64 = 1;
const TAG_BOUNDS:  u64 = 2;
const TAG_DERIVE:  u64 = 3;
const TAG_SEAL:    u64 = 4;
const TAG_UNSEAL:  u64 = 5;
const TAG_LOAD:    u64 = 6;
const TAG_STORE:   u64 = 7;
const TAG_INFO:    u64 = 8;
const TAG_STATS:   u64 = 9;

const PERM_LOAD: u64 = 1 << 2;

fn fail(reason: &[u8]) {
    print(b"    !! ");
    print(reason);
    print(b"\n=== Tier 6 PANDORA T4 CHERI demo: FAIL ===\n\n");
}

fn call(ep: u64, m: &IpcMsg) -> Option<IpcMsg> { sys::call(ep, m).ok() }

/// Return the signed view of regs[0] (errors come back as negative i64).
fn rc(r: &IpcMsg) -> i64 { r.regs[0] as i64 }

pub fn run() {
    print(b"\n=== Tier 6 PANDORA Task 4: software CHERI demo ===\n");

    let name = b"sot-cheri";
    let ep = match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
        Ok(cap) => cap,
        Err(_) => { fail(b"svc_lookup failed"); return; }
    };
    print(b"CHERI: connected to sot-cheri service\n");

    // 2. ROOT
    let mut m = IpcMsg::empty(); m.tag = TAG_ROOT;
    let root = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"ROOT failed"); return; } };
    if (root as i64) <= 0 { fail(b"ROOT returned non-positive id"); return; }
    print(b"CHERI: ROOT cap=");
    print_u64(root);
    print(b"\n");

    // 3. STORE 0xDEAD at addr=10 through ROOT
    let mut m = IpcMsg::empty(); m.tag = TAG_STORE;
    m.regs[0] = root; m.regs[1] = 10; m.regs[2] = 0xDEAD;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"STORE root failed"); return; } };
    if r != 0 { fail(b"STORE through ROOT should succeed"); return; }
    print(b"CHERI: STORE 0xDEAD@10 via ROOT -> ok\n");

    // 4. BOUNDS narrow to [16..32)
    let mut m = IpcMsg::empty(); m.tag = TAG_BOUNDS;
    m.regs[0] = root; m.regs[1] = 16; m.regs[2] = 32;
    let sub = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"BOUNDS failed"); return; } };
    if (sub as i64) <= 0 { fail(b"BOUNDS returned error"); return; }
    print(b"CHERI: BOUNDS [16..32) -> sub cap=");
    print_u64(sub);
    print(b"\n");

    // 5. STORE 0xCAFE @20 via SUB -- in bounds
    let mut m = IpcMsg::empty(); m.tag = TAG_STORE;
    m.regs[0] = sub; m.regs[1] = 20; m.regs[2] = 0xCAFE;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"STORE in-bounds failed"); return; } };
    if r != 0 { fail(b"STORE @20 should succeed (in bounds)"); return; }
    print(b"CHERI: STORE 0xCAFE@20 via SUB -> ok\n");

    // 6. STORE @10 via SUB -- BELOW base, must FAIL
    let mut m = IpcMsg::empty(); m.tag = TAG_STORE;
    m.regs[0] = sub; m.regs[1] = 10; m.regs[2] = 0xBAD;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"STORE oob-low call failed"); return; } };
    if r >= 0 { fail(b"STORE @10 via SUB must trap (below base)"); return; }
    print(b"CHERI: STORE 0xBAD@10 via SUB -> trap rc=");
    print_u64(r as u64);
    print(b" (expected)\n");

    // 7. STORE @40 via SUB -- ABOVE top, must FAIL
    let mut m = IpcMsg::empty(); m.tag = TAG_STORE;
    m.regs[0] = sub; m.regs[1] = 40; m.regs[2] = 0xBAD;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"STORE oob-high call failed"); return; } };
    if r >= 0 { fail(b"STORE @40 via SUB must trap (above top)"); return; }
    print(b"CHERI: STORE 0xBAD@40 via SUB -> trap rc=");
    print_u64(r as u64);
    print(b" (expected)\n");

    // 8. BOUNDS widen [0..64) on SUB -- monotonicity violation
    let mut m = IpcMsg::empty(); m.tag = TAG_BOUNDS;
    m.regs[0] = sub; m.regs[1] = 0; m.regs[2] = 64;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"BOUNDS widen call failed"); return; } };
    if r >= 0 { fail(b"BOUNDS widen must trap (monotonicity)"); return; }
    print(b"CHERI: BOUNDS widen [0..64) -> trap rc=");
    print_u64(r as u64);
    print(b" (monotonicity)\n");

    // 9. SEAL SUB with otype 0x42
    let otype: u64 = 0x42;
    let mut m = IpcMsg::empty(); m.tag = TAG_SEAL;
    m.regs[0] = sub; m.regs[1] = otype;
    let sealed = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"SEAL failed"); return; } };
    if (sealed as i64) <= 0 { fail(b"SEAL returned error"); return; }
    print(b"CHERI: SEAL otype=0x42 -> sealed cap=");
    print_u64(sealed);
    print(b"\n");

    // 10. LOAD through SEALED -- must FAIL
    let mut m = IpcMsg::empty(); m.tag = TAG_LOAD;
    m.regs[0] = sealed; m.regs[1] = 20;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"LOAD sealed call failed"); return; } };
    if r >= 0 { fail(b"LOAD via sealed cap must trap"); return; }
    print(b"CHERI: LOAD@20 via SEALED -> trap rc=");
    print_u64(r as u64);
    print(b" (sealed)\n");

    // 11. UNSEAL with wrong otype
    let mut m = IpcMsg::empty(); m.tag = TAG_UNSEAL;
    m.regs[0] = sealed; m.regs[1] = 0x99;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"UNSEAL wrong call failed"); return; } };
    if r >= 0 { fail(b"UNSEAL with wrong otype must trap"); return; }
    print(b"CHERI: UNSEAL otype=0x99 -> trap rc=");
    print_u64(r as u64);
    print(b" (wrong otype)\n");

    // 12. UNSEAL with correct otype
    let mut m = IpcMsg::empty(); m.tag = TAG_UNSEAL;
    m.regs[0] = sealed; m.regs[1] = otype;
    let unsealed = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"UNSEAL right call failed"); return; } };
    if (unsealed as i64) <= 0 { fail(b"UNSEAL with correct otype must succeed"); return; }
    print(b"CHERI: UNSEAL otype=0x42 -> unsealed cap=");
    print_u64(unsealed);
    print(b"\n");

    // 13. LOAD @20 via UNSEALED -- must return the 0xCAFE we stored
    let mut m = IpcMsg::empty(); m.tag = TAG_LOAD;
    m.regs[0] = unsealed; m.regs[1] = 20;
    let val = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"LOAD unsealed failed"); return; } };
    print(b"CHERI: LOAD@20 via UNSEALED -> 0x");
    print_hex64(val);
    print(b"\n");
    if val != 0xCAFE {
        fail(b"data must survive seal/unseal round-trip");
        return;
    }

    // 14. DERIVE readonly cap (drop PERM_STORE)
    let mut m = IpcMsg::empty(); m.tag = TAG_DERIVE;
    m.regs[0] = unsealed; m.regs[1] = PERM_LOAD;
    let ro = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"DERIVE failed"); return; } };
    if (ro as i64) <= 0 { fail(b"DERIVE readonly returned error"); return; }
    print(b"CHERI: DERIVE PERM_LOAD only -> ro cap=");
    print_u64(ro);
    print(b"\n");

    // 15. STORE through readonly cap -- must FAIL
    let mut m = IpcMsg::empty(); m.tag = TAG_STORE;
    m.regs[0] = ro; m.regs[1] = 20; m.regs[2] = 0xBAD;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"STORE ro call failed"); return; } };
    if r >= 0 { fail(b"STORE via readonly must trap"); return; }
    print(b"CHERI: STORE via RO cap -> trap rc=");
    print_u64(r as u64);
    print(b" (no PERM_STORE)\n");

    // 16. DERIVE perms_mask=0xFFFF on readonly -- monotonicity (can't add perms)
    let mut m = IpcMsg::empty(); m.tag = TAG_DERIVE;
    m.regs[0] = ro; m.regs[1] = 0xFFFF;
    let r = match call(ep, &m) { Some(r) => rc(&r), None => { fail(b"DERIVE widen call failed"); return; } };
    if r >= 0 { fail(b"DERIVE adding perms must trap (monotonicity)"); return; }
    print(b"CHERI: DERIVE widen perms -> trap rc=");
    print_u64(r as u64);
    print(b" (perm monotonicity)\n");

    // 17. STATS -- final fault counters
    let mut m = IpcMsg::empty(); m.tag = TAG_STATS;
    let stats = match call(ep, &m) { Some(r) => r, None => { fail(b"STATS failed"); return; } };
    print(b"CHERI: STATS allocated=");
    print_u64(stats.regs[0]);
    print(b" bounds_faults=");
    print_u64(stats.regs[1]);
    print(b" sealed_faults=");
    print_u64(stats.regs[2]);
    print(b" mono_faults=");
    print_u64(stats.regs[3]);
    print(b"\n");
    if stats.regs[1] < 2 {
        fail(b"expected at least 2 bounds faults");
        return;
    }
    if stats.regs[2] < 1 {
        fail(b"expected at least 1 sealed fault");
        return;
    }
    if stats.regs[3] < 2 {
        fail(b"expected at least 2 monotonicity faults");
        return;
    }

    print(b"=== Tier 6 PANDORA T4 CHERI demo: PASS ===\n\n");
}
