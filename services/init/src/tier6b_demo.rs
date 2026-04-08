//! Tier 6 PANDORA — Task 2 demo: pkgsrc bridge.
//!
//! End-to-end deliverable for PANDORA Task 2: runs a sequence of
//! pkgsrc-equivalent operations through the `sot-pkg` service and
//! asserts the state machine behaves correctly. Acts as the in-init
//! client that a real pkgsrc `pkg_add` would spawn.
//!
//! Sequence:
//!
//!  1. svc_lookup("sot-pkg") -- fetch the service endpoint
//!  2. COUNT -- expect 1 (hello-1.0 seeded by the service at boot)
//!  3. LIST from cursor 0 -- walk the database, print every pkg name
//!  4. REGISTER new pkg "nginx" "1.27.5" -- expect id > 0
//!  5. REGISTER again -- expect collision (0)
//!  6. COUNT -- expect 2
//!  7. INFO on the nginx id -- expect install_order > 1 and name matches
//!  8. REMOVE the nginx id -- expect 0
//!  9. COUNT -- expect 1 again
//! 10. Print PASS
//!
//! Any failing assertion aborts with `=== Tier 6 PANDORA T2 pkgsrc
//! demo: FAIL ===`.

use crate::framebuffer::{print, print_u64};
use sotos_common::{sys, IpcMsg};

const TAG_REGISTER: u64 = 1;
const TAG_INFO:     u64 = 2;
const TAG_LIST:     u64 = 3;
const TAG_REMOVE:   u64 = 4;
const TAG_COUNT:    u64 = 5;

fn pack_name_version(msg: &mut IpcMsg, name: &[u8], version: &[u8]) {
    let raw = unsafe {
        core::slice::from_raw_parts_mut(msg.regs.as_mut_ptr() as *mut u8, 56)
    };
    // name -> [0..48)
    let n_take = name.len().min(47);
    raw[..n_take].copy_from_slice(&name[..n_take]);
    raw[n_take] = 0;
    // version -> [48..56)
    let v_off = 48;
    let v_take = version.len().min(7);
    raw[v_off..v_off + v_take].copy_from_slice(&version[..v_take]);
    raw[v_off + v_take] = 0;
}

fn extract_name_from_reply(reply: &IpcMsg, off: usize) -> &'static [u8] {
    let raw = unsafe {
        core::slice::from_raw_parts(reply.regs.as_ptr() as *const u8, 64)
    };
    let start = off.min(raw.len());
    let slice = &raw[start..];
    let mut len = 0;
    while len < slice.len() && slice[len] != 0 { len += 1; }
    unsafe { core::slice::from_raw_parts(slice.as_ptr(), len) }
}

fn fail(reason: &[u8]) {
    print(b"    !! ");
    print(reason);
    print(b"\n=== Tier 6 PANDORA T2 pkgsrc demo: FAIL ===\n\n");
}

pub fn run() {
    print(b"\n=== Tier 6 PANDORA Task 2: pkgsrc bridge demo ===\n");

    // 1. Connect
    let name = b"sot-pkg";
    let ep = match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
        Ok(cap) => cap,
        Err(_) => { fail(b"svc_lookup failed"); return; }
    };
    print(b"PKG: connected to sot-pkg service\n");

    // 2. Initial COUNT
    let mut m = IpcMsg::empty(); m.tag = TAG_COUNT;
    let initial_count = match sys::call(ep, &m) {
        Ok(r) => r.regs[0],
        Err(_) => { fail(b"COUNT call failed"); return; }
    };
    print(b"PKG: initial COUNT=");
    print_u64(initial_count);
    print(b"\n");
    if initial_count != 1 {
        fail(b"expected 1 seeded package (hello-1.0)");
        return;
    }

    // 3. LIST
    print(b"PKG: installed packages:\n");
    let mut cursor = 0u64;
    let mut listed = 0;
    for _ in 0..4 {
        let mut m = IpcMsg::empty(); m.tag = TAG_LIST; m.regs[0] = cursor;
        let r = match sys::call(ep, &m) {
            Ok(r) => r, Err(_) => break,
        };
        if r.regs[0] == 0 { break; }
        cursor = r.regs[0];
        let nm = extract_name_from_reply(&r, 8);
        print(b"    ");
        for &b in nm { sys::debug_print(b); }
        print(b"\n");
        listed += 1;
    }
    if listed != 1 {
        fail(b"LIST should show exactly 1 package");
        return;
    }

    // 4. REGISTER nginx-1.27.5
    let mut m = IpcMsg::empty();
    m.tag = TAG_REGISTER;
    pack_name_version(&mut m, b"nginx", b"1.27.5");
    let nginx_id = match sys::call(ep, &m) {
        Ok(r) => r.regs[0],
        Err(_) => { fail(b"REGISTER nginx failed"); return; }
    };
    print(b"PKG: REGISTER nginx-1.27.5 -> id=");
    print_u64(nginx_id);
    print(b"\n");
    if nginx_id == 0 || (nginx_id as i64) < 0 {
        fail(b"REGISTER nginx returned 0 or negative");
        return;
    }

    // 5. REGISTER again -- expect collision (0)
    let mut m = IpcMsg::empty();
    m.tag = TAG_REGISTER;
    pack_name_version(&mut m, b"nginx", b"1.27.5");
    let collision = match sys::call(ep, &m) {
        Ok(r) => r.regs[0],
        Err(_) => { fail(b"REGISTER collision call failed"); return; }
    };
    print(b"PKG: REGISTER nginx (collision) -> ");
    print_u64(collision);
    print(b"\n");
    if collision != 0 {
        fail(b"collision should return 0");
        return;
    }

    // 6. COUNT should be 2
    let mut m = IpcMsg::empty(); m.tag = TAG_COUNT;
    let c2 = match sys::call(ep, &m) { Ok(r) => r.regs[0], Err(_) => 0 };
    print(b"PKG: COUNT after register=");
    print_u64(c2);
    print(b"\n");
    if c2 != 2 {
        fail(b"COUNT should be 2 after register");
        return;
    }

    // 7. INFO on nginx
    let mut m = IpcMsg::empty();
    m.tag = TAG_INFO;
    m.regs[0] = nginx_id;
    let info = match sys::call(ep, &m) {
        Ok(r) => r, Err(_) => { fail(b"INFO call failed"); return; }
    };
    let install_order = info.regs[0];
    let nm = extract_name_from_reply(&info, 8);
    print(b"PKG: INFO install_order=");
    print_u64(install_order);
    print(b" name='");
    for &b in nm { sys::debug_print(b); }
    print(b"'\n");
    if install_order < 2 {
        fail(b"nginx install_order should be >= 2");
        return;
    }
    if nm != b"nginx" {
        fail(b"INFO name mismatch");
        return;
    }

    // 8. REMOVE nginx
    let mut m = IpcMsg::empty();
    m.tag = TAG_REMOVE;
    m.regs[0] = nginx_id;
    let rm = match sys::call(ep, &m) { Ok(r) => r.regs[0], Err(_) => u64::MAX };
    print(b"PKG: REMOVE nginx -> ");
    print_u64(rm);
    print(b"\n");
    if rm != 0 {
        fail(b"REMOVE should return 0");
        return;
    }

    // 9. COUNT should be 1 again
    let mut m = IpcMsg::empty(); m.tag = TAG_COUNT;
    let c3 = match sys::call(ep, &m) { Ok(r) => r.regs[0], Err(_) => 0 };
    print(b"PKG: final COUNT=");
    print_u64(c3);
    print(b"\n");
    if c3 != 1 {
        fail(b"final COUNT should be 1");
        return;
    }

    print(b"=== Tier 6 PANDORA T2 pkgsrc demo: PASS ===\n\n");
}
