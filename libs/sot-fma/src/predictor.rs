//! Correlation rules.
//!
//! Each rule is a small pure function over the fault history slice
//! and the behavioural anomaly counter. The top-level [`predict`]
//! function evaluates them in priority order and returns the strongest
//! recommendation. Severity ordering, highest first:
//!
//! 1. ECC uncorrectable -- always migrate now.
//! 2. ECC soft-error clustering at one DIMM -- migrate now.
//! 3. Disk read retries clustering at one LBA -- migrate now.
//! 4. Thermal warning combined with behavioural anomalies -- migrate now.
//! 5. Single hardware fault, no clustering -- monitor closely.
//! 6. Otherwise -- no action.

use crate::correlator::{any_of, count_at_location, newest_timestamp};
use crate::{HwFault, HwFaultClass, MigrationRecommendation};

/// Default correlation window for disk-retry rule (~1 billion TSC ticks,
/// roughly 0.5 s on a 2 GHz host -- short enough to catch a hammering
/// driver retry loop).
pub const DEFAULT_DISK_WINDOW_TSC: u64 = 1_000_000_000;

/// Threshold for the disk-retry rule.
pub const DISK_RETRY_THRESHOLD: usize = 5;

/// Threshold for the soft-ECC clustering rule.
pub const ECC_CORRECTABLE_THRESHOLD: usize = 5;

/// Threshold for the "thermal AND behavioural anomalies" rule.
pub const THERMAL_ANOMALY_THRESHOLD: u32 = 10;

/// Evaluate every rule in priority order and return the strongest
/// recommendation. `history` is the slot array; `prov_anomalies` is
/// the behavioural counter from the provenance ingest pipeline.
pub fn predict(
    history: &[Option<HwFault>],
    prov_anomalies: u32,
) -> MigrationRecommendation {
    // Rule 1: ECC uncorrectable -- single occurrence is enough.
    if any_of(history, HwFaultClass::EccUncorrectable) {
        return MigrationRecommendation::MigrateNow {
            reason: "ecc uncorrectable",
        };
    }

    let now = newest_timestamp(history);

    // Rule 2: ECC correctable clustering at the same DIMM/page.
    if let Some(_loc) = clustered_location(
        history,
        HwFaultClass::EccCorrectable,
        ECC_CORRECTABLE_THRESHOLD,
        DEFAULT_DISK_WINDOW_TSC,
        now,
    ) {
        return MigrationRecommendation::MigrateNow {
            reason: "ecc soft errors clustering",
        };
    }

    // Rule 3: Disk read retries clustering at the same LBA.
    if let Some(_loc) = clustered_location(
        history,
        HwFaultClass::DiskReadRetry,
        DISK_RETRY_THRESHOLD,
        DEFAULT_DISK_WINDOW_TSC,
        now,
    ) {
        return MigrationRecommendation::MigrateNow {
            reason: "disk read retries",
        };
    }

    // Rule 4: Thermal warning + sustained behavioural anomalies.
    if any_of(history, HwFaultClass::ThermalWarn) && prov_anomalies > THERMAL_ANOMALY_THRESHOLD {
        return MigrationRecommendation::MigrateNow {
            reason: "thermal + behavioral anomaly",
        };
    }

    // Rule 5: At least one hardware fault present, but no clustering.
    if history.iter().any(|s| s.is_some()) {
        return MigrationRecommendation::MonitorClosely {
            reason: "single hardware fault",
        };
    }

    MigrationRecommendation::NoAction
}

/// Return the first `location` for which `class` has at least
/// `threshold` faults inside the time window. None if no location
/// reaches the threshold.
fn clustered_location(
    history: &[Option<HwFault>],
    class: HwFaultClass,
    threshold: usize,
    window_tsc: u64,
    now_tsc: u64,
) -> Option<u64> {
    // Two-pass scan: pick a candidate location from the history, then
    // count how many entries match. Fixed-size, no heap, no dedup
    // table -- the same location may be re-checked but the slice is
    // already small (FMA_FAULT_HISTORY entries).
    for (i, slot) in history.iter().enumerate() {
        let Some(f) = slot else { continue };
        if f.class != class {
            continue;
        }
        // Skip duplicates we've already evaluated earlier in the pass.
        let mut seen_earlier = false;
        for prev in &history[..i] {
            if let Some(p) = prev {
                if p.class == class && p.location == f.location {
                    seen_earlier = true;
                    break;
                }
            }
        }
        if seen_earlier {
            continue;
        }
        let n = count_at_location(history, class, f.location, window_tsc, now_tsc);
        if n >= threshold {
            return Some(f.location);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FMA_FAULT_HISTORY;

    fn empty() -> [Option<HwFault>; FMA_FAULT_HISTORY] {
        [None; FMA_FAULT_HISTORY]
    }

    fn fault(class: HwFaultClass, loc: u64, ts: u64) -> HwFault {
        HwFault {
            class,
            location: loc,
            timestamp_tsc: ts,
        }
    }

    #[test]
    fn empty_history_no_action() {
        let h = empty();
        assert_eq!(predict(&h, 0), MigrationRecommendation::NoAction);
    }

    #[test]
    fn ecc_uncorrectable_single_event_migrates_now() {
        let mut h = empty();
        h[0] = Some(fault(HwFaultClass::EccUncorrectable, 0xCAFE, 1));
        assert_eq!(
            predict(&h, 0),
            MigrationRecommendation::MigrateNow { reason: "ecc uncorrectable" }
        );
    }

    #[test]
    fn five_disk_retries_same_lba_migrates_now() {
        let mut h = empty();
        for i in 0..5 {
            h[i] = Some(fault(HwFaultClass::DiskReadRetry, 0x1000, 100 + i as u64));
        }
        assert_eq!(
            predict(&h, 0),
            MigrationRecommendation::MigrateNow { reason: "disk read retries" }
        );
    }

    #[test]
    fn four_disk_retries_only_monitor() {
        let mut h = empty();
        for i in 0..4 {
            h[i] = Some(fault(HwFaultClass::DiskReadRetry, 0x1000, 100 + i as u64));
        }
        assert!(matches!(
            predict(&h, 0),
            MigrationRecommendation::MonitorClosely { .. }
        ));
    }

    #[test]
    fn disk_retries_at_different_lbas_only_monitor() {
        let mut h = empty();
        h[0] = Some(fault(HwFaultClass::DiskReadRetry, 0x1000, 100));
        h[1] = Some(fault(HwFaultClass::DiskReadRetry, 0x2000, 101));
        h[2] = Some(fault(HwFaultClass::DiskReadRetry, 0x3000, 102));
        assert!(matches!(
            predict(&h, 0),
            MigrationRecommendation::MonitorClosely { .. }
        ));
    }

    #[test]
    fn five_correctable_ecc_same_dimm_migrates_now() {
        let mut h = empty();
        for i in 0..5 {
            h[i] = Some(fault(HwFaultClass::EccCorrectable, 0xDEAD, 200 + i as u64));
        }
        assert_eq!(
            predict(&h, 0),
            MigrationRecommendation::MigrateNow { reason: "ecc soft errors clustering" }
        );
    }

    #[test]
    fn four_correctable_ecc_only_monitor() {
        let mut h = empty();
        for i in 0..4 {
            h[i] = Some(fault(HwFaultClass::EccCorrectable, 0xDEAD, 200 + i as u64));
        }
        assert!(matches!(
            predict(&h, 0),
            MigrationRecommendation::MonitorClosely { .. }
        ));
    }

    #[test]
    fn thermal_alone_only_monitors() {
        let mut h = empty();
        h[0] = Some(fault(HwFaultClass::ThermalWarn, 0, 1));
        // prov_anomalies below threshold.
        assert!(matches!(
            predict(&h, 5),
            MigrationRecommendation::MonitorClosely { .. }
        ));
    }

    #[test]
    fn thermal_plus_anomalies_migrates_now() {
        let mut h = empty();
        h[0] = Some(fault(HwFaultClass::ThermalWarn, 0, 1));
        assert_eq!(
            predict(&h, 11),
            MigrationRecommendation::MigrateNow { reason: "thermal + behavioral anomaly" }
        );
    }

    #[test]
    fn thermal_anomalies_at_threshold_does_not_fire() {
        let mut h = empty();
        h[0] = Some(fault(HwFaultClass::ThermalWarn, 0, 1));
        // Strictly greater than 10 is required.
        assert!(matches!(
            predict(&h, 10),
            MigrationRecommendation::MonitorClosely { .. }
        ));
    }

    #[test]
    fn ecc_uncorrectable_takes_priority_over_others() {
        let mut h = empty();
        // Plenty of disk retries first.
        for i in 0..5 {
            h[i] = Some(fault(HwFaultClass::DiskReadRetry, 0x1000, 100 + i as u64));
        }
        // ...then a single uncorrectable ECC.
        h[5] = Some(fault(HwFaultClass::EccUncorrectable, 0, 200));
        assert_eq!(
            predict(&h, 0),
            MigrationRecommendation::MigrateNow { reason: "ecc uncorrectable" }
        );
    }

    #[test]
    fn pci_link_degrade_only_monitors() {
        let mut h = empty();
        h[0] = Some(fault(HwFaultClass::PciLinkDegrade, 0, 1));
        assert!(matches!(
            predict(&h, 0),
            MigrationRecommendation::MonitorClosely { .. }
        ));
    }

    #[test]
    fn clustered_location_detects_match() {
        let mut h = empty();
        h[0] = Some(fault(HwFaultClass::EccCorrectable, 0xAAA, 1));
        h[1] = Some(fault(HwFaultClass::EccCorrectable, 0xBBB, 2));
        h[2] = Some(fault(HwFaultClass::EccCorrectable, 0xAAA, 3));
        h[3] = Some(fault(HwFaultClass::EccCorrectable, 0xAAA, 4));
        h[4] = Some(fault(HwFaultClass::EccCorrectable, 0xAAA, 5));
        h[5] = Some(fault(HwFaultClass::EccCorrectable, 0xAAA, 6));
        // 5 hits at 0xAAA -> threshold met.
        assert_eq!(
            clustered_location(
                &h,
                HwFaultClass::EccCorrectable,
                ECC_CORRECTABLE_THRESHOLD,
                DEFAULT_DISK_WINDOW_TSC,
                10
            ),
            Some(0xAAA)
        );
    }
}
