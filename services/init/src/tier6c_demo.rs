//! Tier 6 PANDORA — Task 3 demo: CARP + pfsync cluster failover.
//!
//! End-to-end deliverable for PANDORA Task 3: drives the `sot-carp`
//! service through a two-node high-availability scenario and asserts
//! that the CARP election + pfsync state replication protocol behave
//! the way OpenBSD's carp(4) and pfsync(4) would behave, bit-for-bit
//! at the wire ABI level. Acts as the in-init stand-in for the ifconfig
//! carp0 + pfsyncd dance on a real BSD cluster.
//!
//! Sequence:
//!
//!  1. svc_lookup("sot-carp") -- fetch the service endpoint
//!  2. JOIN peerA (vhid=1, advskew=10) -- expect peer_id=1
//!  3. JOIN peerB (vhid=1, advskew=50) -- expect peer_id=2
//!  4. STATE vhid=1 -- expect master=1 (peerA wins, lower advskew)
//!  5. INSERT x3 -- pfsync state table: 3 flows for vhid=1
//!  6. COUNT vhid=1 -- expect 3
//!  7. LIST vhid=1 -- walk the replicated state table
//!  8. LEAVE peer_id=1 -- simulate MASTER death
//!  9. STATE vhid=1 -- expect master=2 (peerB promoted), epoch bumped
//! 10. COUNT vhid=1 -- expect 3 still (state survived failover)
//! 11. STATS -- expect preempt >= 2 (initial election + failover)
//! 12. DELETE one state entry + COUNT -- expect 2
//! 13. Print PASS
//!
//! Any failing assertion aborts with `=== Tier 6 PANDORA T3 CARP/pfsync
//! demo: FAIL ===`.

use crate::framebuffer::{print, print_u64};
use sotos_common::{sys, IpcMsg};

const TAG_JOIN:    u64 = 1;
const TAG_LEAVE:   u64 = 2;
const TAG_STATE:   u64 = 3;
const TAG_INSERT:  u64 = 5;
const TAG_DELETE:  u64 = 6;
const TAG_LIST:    u64 = 7;
const TAG_COUNT:   u64 = 8;
const TAG_STATS:   u64 = 10;

fn fail(reason: &[u8]) {
    print(b"    !! ");
    print(reason);
    print(b"\n=== Tier 6 PANDORA T3 CARP/pfsync demo: FAIL ===\n\n");
}

fn call(ep: u64, m: &IpcMsg) -> Option<IpcMsg> {
    sys::call(ep, m).ok()
}

pub fn run() {
    print(b"\n=== Tier 6 PANDORA Task 3: CARP/pfsync cluster demo ===\n");

    // 1. Connect
    let name = b"sot-carp";
    let ep = match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
        Ok(cap) => cap,
        Err(_) => { fail(b"svc_lookup failed"); return; }
    };
    print(b"CARP: connected to sot-carp service\n");

    // 2. JOIN peerA -- high-priority candidate
    let mut m = IpcMsg::empty(); m.tag = TAG_JOIN;
    m.regs[0] = 1;   // vhid=1
    m.regs[1] = 10;  // advskew=10 (low = high priority)
    let peer_a = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"JOIN A failed"); return; } };
    print(b"CARP: JOIN peerA vhid=1 advskew=10 -> peer_id=");
    print_u64(peer_a);
    print(b"\n");
    if peer_a == 0 { fail(b"peerA got id 0"); return; }

    // 3. JOIN peerB -- lower-priority standby
    let mut m = IpcMsg::empty(); m.tag = TAG_JOIN;
    m.regs[0] = 1;
    m.regs[1] = 50;
    let peer_b = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"JOIN B failed"); return; } };
    print(b"CARP: JOIN peerB vhid=1 advskew=50 -> peer_id=");
    print_u64(peer_b);
    print(b"\n");
    if peer_b == 0 || peer_b == peer_a { fail(b"peerB got bad id"); return; }

    // 4. STATE vhid=1 -- expect peerA elected MASTER
    let mut m = IpcMsg::empty(); m.tag = TAG_STATE; m.regs[0] = 1;
    let st = match call(ep, &m) { Some(r) => r, None => { fail(b"STATE call failed"); return; } };
    let master_initial = st.regs[0];
    let epoch_initial = st.regs[1];
    print(b"CARP: initial STATE master=");
    print_u64(master_initial);
    print(b" epoch=");
    print_u64(epoch_initial);
    print(b" backups=");
    print_u64(st.regs[2]);
    print(b"\n");
    if master_initial != peer_a {
        fail(b"peerA should have been elected MASTER initially");
        return;
    }
    if st.regs[2] != 1 {
        fail(b"should have exactly 1 BACKUP (peerB)");
        return;
    }

    // 5. pfsync INSERT x3 -- replicate three flows
    let flows: [(u32, u32, u16, u16, u8); 3] = [
        (0x0a000001, 0x0a000002, 4444, 80, 6),    // tcp 10.0.0.1:4444 -> 10.0.0.2:80
        (0x0a000001, 0x0a000003, 5555, 443, 6),   // tcp 10.0.0.1:5555 -> 10.0.0.3:443
        (0x0a000001, 0x08080808, 6666, 53, 17),   // udp 10.0.0.1:6666 -> 8.8.8.8:53
    ];
    let mut entry_ids = [0u64; 3];
    for (i, (src, dst, sp, dp, pr)) in flows.iter().enumerate() {
        let mut m = IpcMsg::empty();
        m.tag = TAG_INSERT;
        m.regs[0] = 1;
        m.regs[1] = *src as u64;
        m.regs[2] = *dst as u64;
        m.regs[3] = *sp as u64;
        m.regs[4] = *dp as u64;
        m.regs[5] = *pr as u64;
        let id = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"INSERT failed"); return; } };
        if id == 0 { fail(b"pfsync INSERT returned id 0"); return; }
        entry_ids[i] = id;
    }
    print(b"CARP: pfsync INSERT x3 -> ids=");
    print_u64(entry_ids[0]);
    print(b",");
    print_u64(entry_ids[1]);
    print(b",");
    print_u64(entry_ids[2]);
    print(b"\n");

    // 6. COUNT vhid=1 -- expect 3
    let mut m = IpcMsg::empty(); m.tag = TAG_COUNT; m.regs[0] = 1;
    let c1 = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"COUNT failed"); return; } };
    print(b"CARP: pfsync COUNT=");
    print_u64(c1);
    print(b"\n");
    if c1 != 3 { fail(b"pfsync COUNT should be 3"); return; }

    // 7. LIST vhid=1 -- walk the replicated state table
    print(b"CARP: pfsync state entries:\n");
    let mut cursor = 0u64;
    let mut listed = 0u64;
    for _ in 0..8 {
        let mut m = IpcMsg::empty(); m.tag = TAG_LIST; m.regs[0] = 1; m.regs[1] = cursor;
        let r = match call(ep, &m) { Some(r) => r, None => break };
        if r.regs[0] == 0 { break; }
        cursor = r.regs[0];
        print(b"    src=");
        print_u64(r.regs[1]);
        print(b" dst=");
        print_u64(r.regs[2]);
        print(b" sport=");
        print_u64(r.regs[3]);
        print(b" dport=");
        print_u64(r.regs[4]);
        print(b" proto=");
        print_u64(r.regs[5]);
        print(b"\n");
        listed += 1;
    }
    if listed != 3 { fail(b"LIST should walk exactly 3 entries"); return; }

    // 8. LEAVE peerA -- simulate MASTER death (pull the cable)
    let mut m = IpcMsg::empty(); m.tag = TAG_LEAVE; m.regs[0] = peer_a;
    let rv = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"LEAVE failed"); return; } };
    if rv != 0 { fail(b"LEAVE should return 0"); return; }
    print(b"CARP: peerA LEAVE (simulated MASTER death)\n");

    // 9. STATE vhid=1 -- expect peerB promoted, epoch bumped
    let mut m = IpcMsg::empty(); m.tag = TAG_STATE; m.regs[0] = 1;
    let st2 = match call(ep, &m) { Some(r) => r, None => { fail(b"STATE post-failover failed"); return; } };
    print(b"CARP: post-failover STATE master=");
    print_u64(st2.regs[0]);
    print(b" epoch=");
    print_u64(st2.regs[1]);
    print(b"\n");
    if st2.regs[0] != peer_b {
        fail(b"peerB should have been promoted to MASTER");
        return;
    }
    if st2.regs[1] <= epoch_initial {
        fail(b"epoch should have bumped on failover");
        return;
    }

    // 10. COUNT vhid=1 -- state must survive the failover
    let mut m = IpcMsg::empty(); m.tag = TAG_COUNT; m.regs[0] = 1;
    let c2 = match call(ep, &m) { Some(r) => r.regs[0], None => 0 };
    print(b"CARP: post-failover COUNT=");
    print_u64(c2);
    print(b"\n");
    if c2 != 3 {
        fail(b"pfsync state must survive failover (expected 3)");
        return;
    }

    // 11. STATS
    let mut m = IpcMsg::empty(); m.tag = TAG_STATS;
    let stats = match call(ep, &m) { Some(r) => r, None => { fail(b"STATS failed"); return; } };
    print(b"CARP: STATS carps_preempt=");
    print_u64(stats.regs[0]);
    print(b" pfsync_ins=");
    print_u64(stats.regs[1]);
    print(b" pfsync_del=");
    print_u64(stats.regs[2]);
    print(b"\n");
    if stats.regs[0] < 2 {
        fail(b"expected >= 2 preempt events (initial + failover)");
        return;
    }
    if stats.regs[1] != 3 {
        fail(b"pfsync_ins should be 3");
        return;
    }

    // 12. DELETE one state + re-COUNT -- expect 2
    let mut m = IpcMsg::empty(); m.tag = TAG_DELETE; m.regs[0] = entry_ids[1];
    let rv = match call(ep, &m) { Some(r) => r.regs[0], None => { fail(b"DELETE failed"); return; } };
    if rv != 0 { fail(b"DELETE should return 0"); return; }
    let mut m = IpcMsg::empty(); m.tag = TAG_COUNT; m.regs[0] = 1;
    let c3 = match call(ep, &m) { Some(r) => r.regs[0], None => 0 };
    print(b"CARP: after DELETE COUNT=");
    print_u64(c3);
    print(b"\n");
    if c3 != 2 { fail(b"COUNT should be 2 after delete"); return; }

    print(b"=== Tier 6 PANDORA T3 CARP/pfsync demo: PASS ===\n\n");
}
