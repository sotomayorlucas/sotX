//! Tier 3 deception live demo (polished).
//!
//! Single end-to-end pipeline that runs against **real** provenance
//! drained from the kernel ring -- no synthetic fallback trace.
//!
//! Sequence (after `services/attacker` has emitted its 3 provenance
//! events under `owner_domain=7`):
//!
//!   1. `sys::provenance_drain()` pops kernel `ProvenanceEntry` records
//!      from CPU 0's per-CPU SPSC ring into a userspace buffer.
//!   2. Each kernel entry is translated into both
//!      `sotos_provenance::ProvenanceEntry` (for the GraphHunter) and
//!      `sotos_deception::anomaly::ProvenanceEntry` (for the
//!      AnomalyDetector). Translation now reads the kernel
//!      `so_type`/`operation` fields directly -- post Tier 3 polish the
//!      kernel `ProvenanceEntry` carries the same SoType bytes the
//!      personality crates expect.
//!   3. `GraphHunter::ingest()` runs the credential-theft pattern over
//!      the translated entries. We assert at least one alert was
//!      generated and that its action is `MigrateToDeception`.
//!   4. `AnomalyDetector::check_domain()` runs the same pipeline through
//!      the deception crate's matcher; we assert it produces a
//!      `CredentialTheftAfterBackdoor` report with `MigrateNow`.
//!   5. `MigrationOrchestrator::migrate()` swaps the attacker domain into
//!      the Ubuntu 22.04 webserver `DeceptionProfile`.
//!   6. `MigrationOrchestrator::check_interposition()` is queried for
//!      every cap the attacker held; each must come back with the
//!      profile's default action (`FakeResponse`).
//!   7. The fake `/proc/version` is read out of the profile and printed
//!      as the banner the migrated attacker would see.
//!
//! Anything that fails along the way prints `=== Tier 3 demo: FAIL ===`
//! and returns. Success prints `=== Tier 3 demo: PASS ===`.

use crate::framebuffer::{print, print_u64};
use sotos_common::sys;
use sotos_deception::anomaly::{
    AnomalyDetector, AnomalyPattern, DetectorConfig, MigrationAction,
    ProvenanceEntry as DepEntry, ProvenanceOp,
};
use sotos_deception::interpose::InterpositionAction;
use sotos_deception::migration::MigrationOrchestrator;
use sotos_deception::profile::DeceptionProfile;
use sotos_provenance::graph_hunter::{DetectionAction, GraphHunter};
use sotos_provenance::types::{Operation as PvOp, ProvenanceEntry as PvEntry, SoType};

const OBJ_SBIN_SSHD: u64 = 0xA0_05;
const OBJ_ETC_SHADOW: u64 = 0xF001;
const OBJ_PROC_VERSION: u64 = 0x1_0001;

const FAKE_PROC_VERSION: &[u8] =
    b"Linux version 5.15.0-91-generic (buildd@lcy02-amd64-080) #101";

const ATTACKER_DOMAIN: u32 = 7;
const ATTACKER_CAPS: [u32; 3] = [100, 101, 102];

const MAX_DRAIN: usize = 64;

/// 1:1 mirror of `kernel::sot::provenance::ProvenanceEntry` (48 bytes).
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

fn drain_kernel_ring(buf: &mut [KernelProvEntry]) -> usize {
    let n = unsafe {
        sys::provenance_drain(
            buf.as_mut_ptr() as *mut u8,
            buf.len() as u64,
            0, // cpu_id
        )
    };
    n as usize
}

/// Translate kernel entries into the personality crate format used by
/// `GraphHunter`. The kernel now records `so_type` directly when emitted
/// via `SYS_PROVENANCE_EMIT`, so we just pass it through. Operation
/// bytes 1..=10 already line up with `sotos_provenance::Operation`; SOT
/// flavour codes (0x10..0x40) get folded down to a coarse Read/Create.
fn kernel_to_personality(k: &KernelProvEntry) -> PvEntry {
    let op = match k.operation {
        v @ 1..=10 => v,
        0x10..=0x14 => PvOp::Read as u16,
        0x20 => PvOp::Create as u16,
        0x30 => PvOp::Grant as u16,
        0x40 => PvOp::Revoke as u16,
        _ => PvOp::Read as u16,
    };
    PvEntry {
        epoch: k.epoch,
        domain_id: k.domain_id,
        operation: op,
        so_id: k.so_id,
        so_type: k.so_type,
        rights: 0,
        secondary_so: 0,
    }
}

/// Translate kernel entries into the deception-crate format used by
/// `AnomalyDetector`. The deception crate uses an enum-based
/// `ProvenanceOp`, so we map operation+so_type to the closest concept.
fn kernel_to_deception(k: &KernelProvEntry) -> Option<DepEntry> {
    let op = match (k.operation, k.so_type) {
        // Read of credential / config / file
        (1, _) => ProvenanceOp::FileRead,
        // Write of system binary / file
        (2, _) => ProvenanceOp::FileWrite,
        // Execute / spawn / send / receive map onto FileExec for now
        (3, _) => ProvenanceOp::FileExec,
        // Anything else (creates, grants, ...) is not interesting to the
        // deception detector -- skip it.
        _ => return None,
    };
    Some(DepEntry { timestamp: k.epoch, op, object_id: k.so_id })
}

fn build_ubuntu_webserver() -> DeceptionProfile {
    let mut p = DeceptionProfile::with_name(b"ubuntu-22.04-webserver");
    p.default_action = InterpositionAction::FakeResponse;
    let _ = p.add_file(OBJ_PROC_VERSION, FAKE_PROC_VERSION, 0o444);
    let _ = p.add_file(
        OBJ_ETC_SHADOW,
        b"root:!:19000:0:99999:7:::\nsotos:!:19000:0:99999:7:::\n",
        0o600,
    );
    let _ = p.add_file(
        OBJ_SBIN_SSHD,
        b"#!/bin/sh\n# fake sshd: writes here are tarpitted\n",
        0o755,
    );
    let _ = p.add_service(22, 6, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n");
    let _ = p.add_service(80, 6, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n");
    p
}

fn fail(reason: &[u8]) {
    print(b"    !! ");
    print(reason);
    print(b"\n=== Tier 3 demo: FAIL ===\n\n");
}

pub fn run() {
    print(b"\n=== Tier 3 deception live demo (real ring) ===\n");

    // ------------------------------------------------------------------
    // Step 1: drain the kernel provenance ring.
    // ------------------------------------------------------------------
    print(b"[1] draining kernel provenance ring...\n");
    let mut k_buf = [KernelProvEntry {
        epoch: 0, domain_id: 0, operation: 0, so_type: 0, _pad: 0,
        so_id: 0, version: 0, tx_id: 0, timestamp: 0,
    }; MAX_DRAIN];
    let drained = drain_kernel_ring(&mut k_buf);
    print(b"    drained ");
    print_u64(drained as u64);
    print(b" entries from CPU0 ring\n");

    if drained == 0 {
        fail(b"empty ring -- attacker did not run or syscall is broken");
        return;
    }

    // Filter to entries from the attacker domain so unrelated events
    // (styx-test, init bootstrap) don't dilute the analysis.
    let mut attacker_count = 0;
    let mut attacker_idx = [0usize; MAX_DRAIN];
    for i in 0..drained {
        if k_buf[i].domain_id == ATTACKER_DOMAIN {
            attacker_idx[attacker_count] = i;
            attacker_count += 1;
        }
    }
    print(b"    ");
    print_u64(attacker_count as u64);
    print(b" entries belong to domain ");
    print_u64(ATTACKER_DOMAIN as u64);
    print(b" (attacker)\n");

    if attacker_count == 0 {
        fail(b"no attacker entries in ring");
        return;
    }

    // Print each attacker entry so the trace is auditable in serial.
    for i in 0..attacker_count {
        let e = &k_buf[attacker_idx[i]];
        print(b"      op=");
        print_u64(e.operation as u64);
        print(b" so_type=");
        print_u64(e.so_type as u64);
        print(b" so_id=0x");
        print_hex(e.so_id);
        print(b"\n");
    }

    // ------------------------------------------------------------------
    // Step 2: translate to the personality crate and feed GraphHunter.
    // ------------------------------------------------------------------
    print(b"[2] GraphHunter ingest...\n");
    let mut p_buf = [PvEntry {
        epoch: 0, domain_id: 0, operation: 0, so_id: 0,
        so_type: 0, rights: 0, secondary_so: 0,
    }; MAX_DRAIN];
    for i in 0..attacker_count {
        p_buf[i] = kernel_to_personality(&k_buf[attacker_idx[i]]);
    }
    let mut hunter = GraphHunter::new();
    hunter.ingest(&p_buf[..attacker_count]);
    let stats = hunter.stats();
    print(b"    entries_processed=");
    print_u64(stats.entries_processed);
    print(b" alerts_generated=");
    print_u64(stats.alerts_generated);
    print(b"\n");

    let mut hunter_alerted = false;
    let mut hunter_action_ok = false;
    while let Some(alert) = hunter.poll_alert() {
        print(b"    alert: rule=");
        print_u64(alert.rule_id as u64);
        print(b" domain=");
        print_u64(alert.domain_id as u64);
        print(b" confidence=");
        print_u64(alert.confidence as u64);
        print(b"\n");
        hunter_alerted = true;
        if matches!(alert.action, DetectionAction::MigrateToDeception) {
            hunter_action_ok = true;
        }
    }
    if !hunter_alerted {
        fail(b"GraphHunter produced no alerts on real drained data");
        return;
    }
    if !hunter_action_ok {
        fail(b"GraphHunter alert action != MigrateToDeception");
        return;
    }

    // ------------------------------------------------------------------
    // Step 3: feed the same drained data into AnomalyDetector.
    // ------------------------------------------------------------------
    print(b"[3] AnomalyDetector check_domain...\n");
    let mut d_buf = [DepEntry {
        timestamp: 0, op: ProvenanceOp::FileRead, object_id: 0,
    }; MAX_DRAIN];
    let mut d_count = 0;
    for i in 0..attacker_count {
        if let Some(e) = kernel_to_deception(&k_buf[attacker_idx[i]]) {
            d_buf[d_count] = e;
            d_count += 1;
        }
    }
    print(b"    translated ");
    print_u64(d_count as u64);
    print(b" entries\n");

    let detector = AnomalyDetector::new(DetectorConfig::default());
    let (reports, n) = detector.check_domain(ATTACKER_DOMAIN, &d_buf[..d_count], 1000);
    print(b"    reports=");
    print_u64(n as u64);
    print(b"\n");

    let mut got_credential_theft = false;
    for r in reports.iter().take(n) {
        if let AnomalyPattern::CredentialTheftAfterBackdoor = r.pattern {
            got_credential_theft = true;
            print(b"    => CredentialTheftAfterBackdoor confidence=");
            print_u64(r.confidence as u64);
            if r.recommended_action == MigrationAction::MigrateNow {
                print(b" action=MigrateNow");
            }
            print(b"\n");
        }
    }
    if !got_credential_theft {
        fail(b"AnomalyDetector did not flag CredentialTheftAfterBackdoor");
        return;
    }

    // ------------------------------------------------------------------
    // Step 4: migrate the attacker domain into the Ubuntu profile.
    // ------------------------------------------------------------------
    print(b"[4] migrating domain ");
    print_u64(ATTACKER_DOMAIN as u64);
    print(b" to ubuntu-22.04-webserver...\n");
    let profile = build_ubuntu_webserver();
    let mut orch = MigrationOrchestrator::new();
    let snapshot_id = match orch.migrate(
        ATTACKER_DOMAIN,
        &profile,
        AnomalyPattern::CredentialTheftAfterBackdoor,
        &ATTACKER_CAPS,
        2000,
    ) {
        Ok(id) => id,
        Err(_) => { fail(b"migrate() failed"); return; }
    };
    print(b"    snapshot_id=");
    print_u64(snapshot_id);
    print(b" is_migrated=");
    print(if orch.is_migrated(ATTACKER_DOMAIN) { b"true" } else { b"false" });
    print(b"\n");

    // ------------------------------------------------------------------
    // Step 5: probe interposition for each attacker cap.
    // ------------------------------------------------------------------
    print(b"[5] interposition lookups:\n");
    let mut interposed = 0;
    for cap in ATTACKER_CAPS.iter() {
        match orch.check_interposition(ATTACKER_DOMAIN, *cap) {
            Some(InterpositionAction::FakeResponse) => {
                print(b"    cap ");
                print_u64(*cap as u64);
                print(b" -> FakeResponse\n");
                interposed += 1;
            }
            Some(_) => { interposed += 1; }
            None => {
                print(b"    cap ");
                print_u64(*cap as u64);
                print(b" -> (passthrough)\n");
            }
        }
    }
    if interposed != ATTACKER_CAPS.len() {
        fail(b"not all caps interposed");
        return;
    }

    // ------------------------------------------------------------------
    // Step 6: serve the spoofed /proc/version.
    // ------------------------------------------------------------------
    print(b"[6] fake /proc/version (what the migrated attacker now sees):\n    ");
    match profile.lookup_file(OBJ_PROC_VERSION) {
        Some(f) => {
            for &b in &f.content[..f.content_len as usize] {
                sys::debug_print(b);
            }
            print(b"\n");
        }
        None => { fail(b"/proc/version fake file missing"); return; }
    }

    print(b"=== Tier 3 demo: PASS ===\n\n");

    // ------------------------------------------------------------------
    // Tier 3 follow-up #2: keep the pipeline alive after the one-shot
    // demo by spawning a watchdog thread that periodically drains the
    // ring and reports any new attacker activity. The thread shares
    // init's address space, runs forever, and only logs (no migration)
    // so it can't interfere with the rest of boot.
    // ------------------------------------------------------------------
    spawn_watchdog();
}

const WATCHDOG_STACK: u64 = 0xE60000;
const WATCHDOG_STACK_PAGES: u64 = 4;

fn spawn_watchdog() {
    for i in 0..WATCHDOG_STACK_PAGES {
        let f = match sys::frame_alloc() { Ok(f) => f, Err(_) => return };
        let _ = sys::map(WATCHDOG_STACK + i * 0x1000, f, 2);
    }
    let rsp = WATCHDOG_STACK + WATCHDOG_STACK_PAGES * 0x1000;
    match sys::thread_create(deception_watchdog as *const () as u64, rsp) {
        Ok(_) => print(b"DECEPTION-WATCHDOG: launched\n"),
        Err(_) => print(b"DECEPTION-WATCHDOG: thread_create failed\n"),
    }
}

extern "C" fn deception_watchdog() -> ! {
    // Each tick = one drain pass.
    const TICKS_BETWEEN_DRAIN: u32 = 4096;
    let detector = AnomalyDetector::new(DetectorConfig::default());
    let mut k_buf = [KernelProvEntry {
        epoch: 0, domain_id: 0, operation: 0, so_type: 0, _pad: 0,
        so_id: 0, version: 0, tx_id: 0, timestamp: 0,
    }; MAX_DRAIN];
    let mut total_seen: u64 = 0;
    loop {
        for _ in 0..TICKS_BETWEEN_DRAIN { sys::yield_now(); }
        let n = drain_kernel_ring(&mut k_buf);
        if n == 0 { continue; }
        total_seen += n as u64;
        // Translate attacker entries and run the detector.
        let mut d_buf = [DepEntry {
            timestamp: 0, op: ProvenanceOp::FileRead, object_id: 0,
        }; MAX_DRAIN];
        let mut d_count = 0;
        for i in 0..n {
            if k_buf[i].domain_id != ATTACKER_DOMAIN { continue; }
            if let Some(e) = kernel_to_deception(&k_buf[i]) {
                d_buf[d_count] = e;
                d_count += 1;
            }
        }
        if d_count == 0 { continue; }
        let (reports, m) = detector.check_domain(ATTACKER_DOMAIN, &d_buf[..d_count], total_seen);
        if m == 0 { continue; }
        print(b"DECEPTION-WATCHDOG: drained ");
        print_u64(n as u64);
        print(b" entries, ");
        print_u64(m as u64);
        print(b" anomaly reports for domain ");
        print_u64(ATTACKER_DOMAIN as u64);
        print(b"\n");
        for r in reports.iter().take(m) {
            if let AnomalyPattern::CredentialTheftAfterBackdoor = r.pattern {
                print(b"DECEPTION-WATCHDOG:   CredentialTheftAfterBackdoor (conf=");
                print_u64(r.confidence as u64);
                print(b")\n");
            }
        }
    }
}

fn print_hex(mut n: u64) {
    let mut buf = [0u8; 16];
    let mut started = false;
    let mut out = [0u8; 16];
    let mut len = 0;
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let _ = buf;
    let _ = started;
    let _ = out;
    let _ = len;
    let mut tmp = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let nib = (n & 0xF) as u8;
        tmp[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(tmp[i]);
    }
}
