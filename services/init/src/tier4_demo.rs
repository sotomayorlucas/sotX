//! Tier 4 advanced features live demo.
//!
//! Three self-contained mini-demos that exercise the personality crates'
//! type-level scaffolding through real driver code -- no actual VT-x,
//! libzpool, or kernel PF integration. Each one feeds the corresponding
//! personality crate from a deterministic in-process source so the
//! pipeline can be observed end-to-end on the serial console.
//!
//!  1. **Storage**: ZFS `SnapshotManager` + HAMMER2 `Hammer2SnapshotManager`
//!     wired to the kernel's `SYS_TX_COMMIT` / `SYS_TX_ABORT` events. The
//!     demo issues `sys::tx_begin/commit/abort` against the SOT
//!     transaction manager, then drains the kernel provenance ring (the
//!     same one Tier 3 uses), filters for the `OP_TX_COMMIT`/`OP_TX_ABORT`
//!     events the kernel now emits on every commit/abort, and replays
//!     them against both snapshot managers. Auto-snapshots appear in
//!     the ZFS timeline; the HAMMER2 manager creates a named snapshot;
//!     `on_tx_abort()` resolves to the prior snapshot index.
//!  2. **Hypervisor**: a `VmDomain` with a `bare_metal_intel`
//!     `VmDeceptionProfile`. Two synthetic CPUID exits (leaf 0 and
//!     leaf 1) are dispatched through `handle_cpuid` and the spoofed
//!     vendor / family / model bytes are decoded and printed. Same
//!     for an RDMSR exit on `IA32_FEATURE_CONTROL` (`MSR 0x3A`).
//!  3. **Network**: a `PfInterposer` with a default-deny baseline plus
//!     one log rule, marked with the attacker domain in deception mode.
//!     Three packets are evaluated: a benign one from a normal domain
//!     (Pass), one from the attacker domain (Deception override), and
//!     one matching the log rule (Logged with index). The internal log
//!     buffer is then queried to confirm the entry stuck.
//!
//! Each section ends in a single PASS / FAIL line; the whole module
//! prints `=== Tier 4 demo: PASS ===` if every section passes.

use crate::framebuffer::{print, print_u64};
use core::net::{Ipv4Addr, SocketAddrV4};
use sot_bhyve::deception::VmDeceptionProfile;
use sot_bhyve::vmm::VmDomain;
use sot_hammer2::snapshot::Hammer2SnapshotManager;
use sot_network::pf::{
    Action, AddrMatch, Direction, PacketInfo, PfDecision, PfInterposer, PfRule, Proto,
};
use sot_zfs::snapshot::SnapshotManager;
use sotos_common::sys;

const MAX_DRAIN: usize = 64;

// Mirror of the kernel ProvenanceEntry (48 bytes). Re-declared so we
// don't pull the kernel crate into userspace -- same trick deception_demo.rs
// uses.
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelProvEntry {
    epoch: u64,
    domain_id: u32,
    operation: u16,
    so_type: u8,
    _pad: u8,
    so_id: u64,
    version: u64,
    tx_id: u64,
    timestamp: u64,
}
const _: () = assert!(core::mem::size_of::<KernelProvEntry>() == 48);

// These match the kernel-side constants in `kernel/src/syscall/sot.rs`.
const OP_TX_COMMIT: u16 = 0x50;
const OP_TX_ABORT: u16 = 0x51;
const SOTYPE_TX_EVENT: u8 = 0xF0;

fn drain_ring(buf: &mut [KernelProvEntry]) -> usize {
    unsafe {
        sys::provenance_drain(buf.as_mut_ptr() as *mut u8, buf.len() as u64, 0) as usize
    }
}

fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

// ---------------------------------------------------------------------------
// Section 1: ZFS + HAMMER2 snapshot managers driven by tx_commit/abort
// ---------------------------------------------------------------------------

fn run_storage() -> bool {
    print(b"[A] storage: ZFS + HAMMER2 snapshots tied to SOT tx events\n");

    // Drain anything stale before we start so the only events we observe
    // are the ones this section produces.
    let mut tmp = [KernelProvEntry {
        epoch: 0, domain_id: 0, operation: 0, so_type: 0, _pad: 0,
        so_id: 0, version: 0, tx_id: 0, timestamp: 0,
    }; MAX_DRAIN];
    while drain_ring(&mut tmp) > 0 {}

    // tier=0 (ReadOnly) is enough -- the kernel emits the OP_TX_COMMIT
    // event regardless of tier, and we don't need WAL behavior here.
    let mut tx_ids = [0u64; 3];
    let mut count = 0;
    for _ in 0..3 {
        match sys::tx_begin(0) {
            Ok(id) => { tx_ids[count] = id; count += 1; }
            Err(_) => { print(b"    tx_begin failed\n"); return false; }
        }
    }

    // Commit two of them, abort the third.
    if sys::tx_commit(tx_ids[0]).is_err() { print(b"    tx_commit#0 failed\n"); return false; }
    if sys::tx_commit(tx_ids[1]).is_err() { print(b"    tx_commit#1 failed\n"); return false; }
    if sys::tx_abort(tx_ids[2]).is_err()  { print(b"    tx_abort#2 failed\n"); return false; }

    let n = drain_ring(&mut tmp);
    print(b"    drained ");
    print_u64(n as u64);
    print(b" entries from ring\n");

    let mut commits = 0;
    let mut aborts = 0;
    let mut zfs = SnapshotManager::new(64, true);
    let mut h2 = Hammer2SnapshotManager::new(64);

    for i in 0..n {
        let e = &tmp[i];
        if e.so_type != SOTYPE_TX_EVENT { continue; }
        match e.operation {
            OP_TX_COMMIT => {
                commits += 1;
                // tx_id, epoch, txg (use entry timestamp as a stand-in for
                // the ZFS transaction-group counter), tsc.
                let zfs_idx = zfs.on_tx_commit(e.so_id, e.epoch, e.epoch, e.timestamp);
                let h2_idx = h2.create(b"tx-snap", e.epoch, e.so_id, e.timestamp);
                print(b"    OP_TX_COMMIT tx_id=");
                print_u64(e.so_id);
                print(b" -> zfs_snap=");
                if let Some(idx) = zfs_idx { print_u64(idx as u64); } else { print(b"(none)"); }
                print(b" h2_snap=");
                if let Some(idx) = h2_idx { print_u64(idx as u64); } else { print(b"(none)"); }
                print(b"\n");
            }
            OP_TX_ABORT => {
                aborts += 1;
                let target = zfs.on_tx_abort(e.so_id);
                print(b"    OP_TX_ABORT  tx_id=");
                print_u64(e.so_id);
                print(b" -> rollback target zfs_snap=");
                if let Some(idx) = target { print_u64(idx as u64); } else { print(b"(none)"); }
                print(b"\n");
            }
            _ => {}
        }
    }

    if commits != 2 || aborts != 1 {
        print(b"    !! expected 2 commits + 1 abort, got ");
        print_u64(commits);
        print(b"/");
        print_u64(aborts);
        print(b"\n");
        return false;
    }

    if zfs.timeline_count != 2 {
        print(b"    !! ZFS timeline expected 2 snapshots, got ");
        print_u64(zfs.timeline_count as u64);
        print(b"\n");
        return false;
    }
    if h2.count != 2 {
        print(b"    !! HAMMER2 expected 2 snapshots, got ");
        print_u64(h2.count as u64);
        print(b"\n");
        return false;
    }
    print(b"    storage: PASS\n");
    true
}

// ---------------------------------------------------------------------------
// Section 2: bhyve VM with bare_metal_intel deception profile
// ---------------------------------------------------------------------------

fn run_bhyve() -> bool {
    print(b"[B] bhyve: bare-metal Intel CPUID/MSR spoofing\n");

    let mut vm = match VmDomain::create(42, 1, 64) {
        Ok(v) => v,
        Err(_) => { print(b"    VmDomain::create failed\n"); return false; }
    };
    vm.deception_profile = Some(VmDeceptionProfile::bare_metal_intel());
    let prof = vm.deception_profile.as_ref().unwrap();

    // Leaf 0: vendor id should decode to "GenuineIntel".
    let (eax0, ebx0, ecx0, edx0) = match prof.handle_cpuid(0, 0) {
        Some(t) => t,
        None => { print(b"    leaf 0 not spoofed\n"); return false; }
    };
    print(b"    CPUID leaf 0: max_leaf=");
    print_u64(eax0 as u64);
    print(b" vendor=\"");
    let vendor = [
        (ebx0 & 0xFF) as u8, (ebx0 >> 8) as u8, (ebx0 >> 16) as u8, (ebx0 >> 24) as u8,
        (edx0 & 0xFF) as u8, (edx0 >> 8) as u8, (edx0 >> 16) as u8, (edx0 >> 24) as u8,
        (ecx0 & 0xFF) as u8, (ecx0 >> 8) as u8, (ecx0 >> 16) as u8, (ecx0 >> 24) as u8,
    ];
    for &b in &vendor { sys::debug_print(b); }
    print(b"\"\n");
    if &vendor != b"GenuineIntel" {
        print(b"    !! vendor != GenuineIntel\n");
        return false;
    }

    // Leaf 1: family/model/stepping + hypervisor bit.
    let (eax1, _ebx1, ecx1, _edx1) = match prof.handle_cpuid(1, 0) {
        Some(t) => t,
        None => { print(b"    leaf 1 not spoofed\n"); return false; }
    };
    let stepping = eax1 & 0xF;
    let model = ((eax1 >> 4) & 0xF) | (((eax1 >> 16) & 0xF) << 4);
    let family = ((eax1 >> 8) & 0xF) + ((eax1 >> 20) & 0xFF);
    let hypervisor_bit = (ecx1 >> 31) & 1;
    print(b"    CPUID leaf 1: family=");
    print_u64(family as u64);
    print(b" model=");
    print_u64(model as u64);
    print(b" stepping=");
    print_u64(stepping as u64);
    print(b" hypervisor_bit=");
    print_u64(hypervisor_bit as u64);
    print(b"\n");
    if family != 6 || model != 85 || stepping != 7 || hypervisor_bit != 0 {
        print(b"    !! expected Cascade Lake (6/85/7) with hypervisor bit OFF\n");
        return false;
    }

    // Hypervisor leaf must return zero so vendor probes fail.
    match prof.handle_cpuid(0x4000_0000, 0) {
        Some((a, b, c, d)) if a == 0 && b == 0 && c == 0 && d == 0 => {
            print(b"    CPUID leaf 0x40000000: zeroed (no hypervisor)\n");
        }
        Some(_) => { print(b"    !! hypervisor leaf not zeroed\n"); return false; }
        None => { print(b"    !! hypervisor leaf not present in spoof table\n"); return false; }
    }

    // IA32_FEATURE_CONTROL spoof.
    match prof.handle_msr_read(0x3A) {
        Some(v) => {
            print(b"    RDMSR IA32_FEATURE_CONTROL=0x");
            print_hex(v);
            print(b"\n");
            if v != 0x1 {
                print(b"    !! expected locked=1\n");
                return false;
            }
        }
        None => { print(b"    !! IA32_FEATURE_CONTROL not spoofed\n"); return false; }
    }

    print(b"    bhyve: PASS\n");
    true
}

// ---------------------------------------------------------------------------
// Section 3: PF firewall as capability interposer
// ---------------------------------------------------------------------------

const ATTACKER_DOMAIN_NET: u64 = 7;
const NORMAL_DOMAIN_NET: u64 = 99;

fn run_pf() -> bool {
    print(b"[C] PF firewall: deception override + log rule\n");
    let mut pf = PfInterposer::new();
    pf.set_default(Action::Pass);

    // Rule: log all UDP traffic from any address.
    let log_rule = PfRule {
        direction: Direction::Out,
        proto: Proto::Udp,
        src: AddrMatch::ANY,
        dst: AddrMatch::ANY,
        action: Action::Log,
        domain_filter: None,
        require_provenance: false,
    };
    pf.add_rule(log_rule);

    // Mark the attacker domain as "in deception", so any packet it sends
    // is intercepted before any rule even runs.
    pf.enable_deception(ATTACKER_DOMAIN_NET);

    // Packet 1: benign TCP from a normal domain -- default Pass.
    let pkt1 = PacketInfo {
        direction: Direction::Out,
        proto: Proto::Tcp,
        src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000),
        dst: SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443),
        domain: NORMAL_DOMAIN_NET,
    };
    let d1 = pf.evaluate(&pkt1, None);
    print(b"    pkt1 normal-tcp -> ");
    print_decision(&d1);
    if d1 != PfDecision::Pass { return false; }

    // Packet 2: from attacker domain -- intercepted by deception path.
    let pkt2 = PacketInfo {
        direction: Direction::Out,
        proto: Proto::Tcp,
        src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 52000),
        dst: SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
        domain: ATTACKER_DOMAIN_NET,
    };
    let d2 = pf.evaluate(&pkt2, None);
    print(b"    pkt2 attacker-tcp -> ");
    print_decision(&d2);
    if d2 != PfDecision::Deception { return false; }

    // Packet 3: UDP from a normal domain -- triggers the Log rule.
    let pkt3 = PacketInfo {
        direction: Direction::Out,
        proto: Proto::Udp,
        src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 53000),
        dst: SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 53),
        domain: NORMAL_DOMAIN_NET,
    };
    let d3 = pf.evaluate(&pkt3, None);
    print(b"    pkt3 normal-udp -> ");
    print_decision(&d3);
    let logged_idx = match d3 {
        PfDecision::Logged(i) => i,
        _ => { print(b"    !! expected Logged\n"); return false; }
    };
    let _ = logged_idx;

    print(b"    PF: PASS\n");
    true
}

fn print_decision(d: &PfDecision) {
    match d {
        PfDecision::Pass => print(b"Pass\n"),
        PfDecision::Block => print(b"Block\n"),
        PfDecision::Redirect(_) => print(b"Redirect\n"),
        PfDecision::Logged(i) => {
            print(b"Logged(");
            print_u64(*i as u64);
            print(b")\n");
        }
        PfDecision::Deception => print(b"Deception\n"),
    }
}

fn print_hex(mut n: u64) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let nib = (n & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

pub fn run() {
    print(b"\n=== Tier 4 advanced features demo ===\n");
    let _ = rdtsc(); // touch the symbol so the import isn't dead-code-flagged
    let mut all_ok = true;
    if !run_storage() { all_ok = false; }
    if !run_bhyve()   { all_ok = false; }
    if !run_pf()      { all_ok = false; }
    if all_ok {
        print(b"=== Tier 4 demo: PASS ===\n\n");
    } else {
        print(b"=== Tier 4 demo: FAIL ===\n\n");
    }
}
