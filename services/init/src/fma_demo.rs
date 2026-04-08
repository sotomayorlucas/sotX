//! Boot-time demo for the Fault Management Architecture (FMA) engine.
//!
//! Drives the [`sot_fma::FaultManagement`] state machine through the
//! same correlation rules covered by the unit tests, but as runtime
//! asserts on the real init binary so the boot log shows the engine
//! working end-to-end. Mirrors the structure of the existing
//! `tier4_demo` / `tier5_demo` modules.
//!
//! Sections:
//!   A. Empty engine -> NoAction.
//!   B. 5 DiskReadRetry events at the same LBA -> MigrateNow
//!      "disk read retries".
//!   C. 1 EccUncorrectable -> immediate MigrateNow "ecc uncorrectable".
//!   D. ThermalWarn alone -> MonitorClosely.
//!   E. ThermalWarn + behavioural anomalies -> MigrateNow
//!      "thermal + behavioral anomaly".
//!
//! Prints `=== FMA: PASS ===` (or `... FAIL ...`) and returns the
//! aggregate boolean.

use crate::framebuffer::print;
use sot_fma::{
    FaultManagement, HwFault, HwFaultClass, MigrationRecommendation, ProvenanceEntry, OP_REVOKE,
};

fn fault(class: HwFaultClass, location: u64, ts: u64) -> HwFault {
    HwFault {
        class,
        location,
        timestamp_tsc: ts,
    }
}

fn revoke_entry() -> ProvenanceEntry {
    ProvenanceEntry {
        epoch: 0,
        domain_id: 7,
        operation: OP_REVOKE,
        so_id: 0,
        so_type: 0,
        rights: 0,
        secondary_so: 0,
    }
}

fn check(label: &[u8], cond: bool) -> bool {
    if cond {
        print(b"FMA: ");
        print(label);
        print(b" PASS\n");
    } else {
        print(b"FMA: ");
        print(label);
        print(b" FAIL\n");
    }
    cond
}

pub fn run() -> bool {
    print(b"--- FMA demo ---\n");

    // A. Empty engine.
    let fma = FaultManagement::new();
    let ok_a = check(b"[A] empty",
        matches!(fma.predict_failure(), MigrationRecommendation::NoAction));

    // B. Five DiskReadRetry events at the same LBA -> MigrateNow.
    let mut fma_b = FaultManagement::new();
    for i in 0..5 {
        fma_b.ingest_hw_fault(fault(HwFaultClass::DiskReadRetry, 0xDEAD_BEEF, 1000 + i));
    }
    let rec_b = fma_b.predict_failure();
    let ok_b = check(
        b"[B] disk read retries cluster",
        matches!(
            rec_b,
            MigrationRecommendation::MigrateNow { reason: "disk read retries" }
        ),
    );

    // C. Single EccUncorrectable event -> immediate MigrateNow.
    let mut fma_c = FaultManagement::new();
    fma_c.ingest_hw_fault(fault(HwFaultClass::EccUncorrectable, 0xCAFE, 2000));
    let rec_c = fma_c.predict_failure();
    let ok_c = check(
        b"[C] ecc uncorrectable single shot",
        matches!(
            rec_c,
            MigrationRecommendation::MigrateNow { reason: "ecc uncorrectable" }
        ),
    );

    // D. ThermalWarn alone -> MonitorClosely (anomaly threshold not met).
    let mut fma_d = FaultManagement::new();
    fma_d.ingest_hw_fault(fault(HwFaultClass::ThermalWarn, 0, 3000));
    let rec_d = fma_d.predict_failure();
    let ok_d = check(
        b"[D] thermal alone monitors",
        matches!(rec_d, MigrationRecommendation::MonitorClosely { .. }),
    );

    // E. ThermalWarn + behavioural anomalies (>10 OP_REVOKE events) ->
    //    MigrateNow "thermal + behavioral anomaly".
    let mut fma_e = FaultManagement::new();
    fma_e.ingest_hw_fault(fault(HwFaultClass::ThermalWarn, 0, 4000));
    let revokes = [revoke_entry(); 11];
    fma_e.ingest_provenance(&revokes);
    let rec_e = fma_e.predict_failure();
    let ok_e = check(
        b"[E] thermal + anomalies migrates",
        matches!(
            rec_e,
            MigrationRecommendation::MigrateNow { reason: "thermal + behavioral anomaly" }
        ),
    );

    let all = ok_a && ok_b && ok_c && ok_d && ok_e;
    if all {
        print(b"=== FMA: PASS ===\n");
    } else {
        print(b"=== FMA: FAIL ===\n");
    }
    all
}
