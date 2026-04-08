//! Fault history helpers.
//!
//! Pure functions over a fixed-size slice of `Option<HwFault>`. Kept
//! free of mutable state so the predictor can reason over the same
//! slice multiple times without side effects.

use crate::{HwFault, HwFaultClass};

/// Count faults of `class` whose timestamp falls within
/// `[now_tsc - window_tsc, now_tsc]`. Saturating subtraction avoids
/// wraparound when `window_tsc > now_tsc`.
pub fn count_in_window(
    history: &[Option<HwFault>],
    class: HwFaultClass,
    window_tsc: u64,
    now_tsc: u64,
) -> usize {
    let lower = now_tsc.saturating_sub(window_tsc);
    let mut n = 0;
    for f in history.iter().flatten() {
        if f.class == class && f.timestamp_tsc >= lower && f.timestamp_tsc <= now_tsc {
            n += 1;
        }
    }
    n
}

/// Count faults of `class` at a specific `location` (e.g. same LBA,
/// same DIMM, same PCI BDF) within the given window.
pub fn count_at_location(
    history: &[Option<HwFault>],
    class: HwFaultClass,
    location: u64,
    window_tsc: u64,
    now_tsc: u64,
) -> usize {
    let lower = now_tsc.saturating_sub(window_tsc);
    let mut n = 0;
    for f in history.iter().flatten() {
        if f.class == class
            && f.location == location
            && f.timestamp_tsc >= lower
            && f.timestamp_tsc <= now_tsc
        {
            n += 1;
        }
    }
    n
}

/// Whether `history` contains at least one fault of `class` (no time
/// constraint). Used by rules that fire on a single occurrence
/// (e.g. uncorrectable ECC).
pub fn any_of(history: &[Option<HwFault>], class: HwFaultClass) -> bool {
    history
        .iter()
        .any(|slot| matches!(slot, Some(f) if f.class == class))
}

/// Newest timestamp present in the history (0 if empty). Cheap helper
/// for the predictor's "now" reference when the caller doesn't have a
/// dedicated TSC source.
pub fn newest_timestamp(history: &[Option<HwFault>]) -> u64 {
    let mut newest = 0;
    for f in history.iter().flatten() {
        if f.timestamp_tsc > newest {
            newest = f.timestamp_tsc;
        }
    }
    newest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(class: HwFaultClass, loc: u64, ts: u64) -> Option<HwFault> {
        Some(HwFault {
            class,
            location: loc,
            timestamp_tsc: ts,
        })
    }

    #[test]
    fn count_in_window_basic() {
        let history = [
            make(HwFaultClass::DiskReadRetry, 100, 10),
            make(HwFaultClass::DiskReadRetry, 100, 20),
            make(HwFaultClass::DiskReadRetry, 100, 1_000_000),
            None,
        ];
        // Window covers ts 10..30 -> two hits.
        assert_eq!(
            count_in_window(&history, HwFaultClass::DiskReadRetry, 25, 30),
            2
        );
        // Window covers ts 999_990..1_000_010 -> one hit.
        assert_eq!(
            count_in_window(&history, HwFaultClass::DiskReadRetry, 20, 1_000_000),
            1
        );
    }

    #[test]
    fn count_in_window_class_filter() {
        let history = [
            make(HwFaultClass::EccCorrectable, 0, 10),
            make(HwFaultClass::DiskReadRetry, 0, 11),
        ];
        assert_eq!(
            count_in_window(&history, HwFaultClass::EccCorrectable, 100, 100),
            1
        );
    }

    #[test]
    fn count_at_location_filters_by_address() {
        let history = [
            make(HwFaultClass::DiskReadRetry, 100, 1),
            make(HwFaultClass::DiskReadRetry, 200, 2),
            make(HwFaultClass::DiskReadRetry, 100, 3),
        ];
        assert_eq!(
            count_at_location(&history, HwFaultClass::DiskReadRetry, 100, 100, 100),
            2
        );
        assert_eq!(
            count_at_location(&history, HwFaultClass::DiskReadRetry, 200, 100, 100),
            1
        );
    }

    #[test]
    fn any_of_finds_single_event() {
        let history = [None, make(HwFaultClass::EccUncorrectable, 1, 1), None];
        assert!(any_of(&history, HwFaultClass::EccUncorrectable));
        assert!(!any_of(&history, HwFaultClass::ThermalWarn));
    }

    #[test]
    fn newest_timestamp_picks_max() {
        let history = [
            make(HwFaultClass::DiskReadRetry, 0, 5),
            make(HwFaultClass::DiskReadRetry, 0, 100),
            make(HwFaultClass::DiskReadRetry, 0, 50),
            None,
        ];
        assert_eq!(newest_timestamp(&history), 100);
    }

    #[test]
    fn saturating_sub_handles_window_larger_than_now() {
        let history = [make(HwFaultClass::DiskReadRetry, 0, 5)];
        // window > now_tsc; lower bound clamps to 0, so the entry counts.
        assert_eq!(
            count_in_window(&history, HwFaultClass::DiskReadRetry, u64::MAX, 5),
            1
        );
    }
}
