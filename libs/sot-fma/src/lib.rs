//! sot-fma — Fault Management Architecture for sotBSD/sotOS.
//!
//! A predictive self-healing engine inspired by Solaris' FMA. The
//! [`FaultManagement`] state machine consumes two streams:
//!
//! 1. Hardware fault events injected by drivers (`HwFault`), classified
//!    via [`HwFaultClass`] (disk read retries, ECC, thermal, PCIe link
//!    quality, ...). These are kept in a fixed-size ring so we can run
//!    correlation rules over a recent window.
//!
//! 2. Provenance entries drained from the per-CPU SOT ring buffers
//!    (`sotos_provenance::ProvenanceEntry`). High-anomaly operations
//!    (e.g. cap revocation storms) bump a behavioural anomaly counter
//!    that the rules can combine with hardware signals.
//!
//! The output is a [`MigrationRecommendation`] -- the same vocabulary
//! used by the deception migration orchestrator -- so a higher-level
//! supervisor can decide to evacuate a domain off a flaky frame, NIC,
//! or NUMA node before it actually fails.
//!
//! The crate is `no_std` and uses only fixed-size arrays so it can run
//! inside the microkernel, a privileged userspace server, or a unit
//! test on the host.

#![no_std]
#![forbid(unsafe_code)]

pub mod correlator;
pub mod predictor;

/// Mirror of `sotos_provenance::types::ProvenanceEntry` (same field set
/// and order). Re-defined here so the FMA crate can build inside the
/// kernel workspace without pulling the personality crate in as a
/// secondary workspace root. Keep these two definitions in sync.
#[derive(Clone, Copy, Debug)]
pub struct ProvenanceEntry {
    /// Monotonic epoch counter (kernel tick).
    pub epoch: u64,
    /// Domain that performed the operation.
    pub domain_id: u32,
    /// Operation code (see `OP_*` constants and the upstream
    /// `sotos_provenance::types::Operation` enum).
    pub operation: u16,
    /// Semantic object ID that was acted upon.
    pub so_id: u64,
    /// Semantic object type tag.
    pub so_type: u8,
    /// Rights mask that was exercised.
    pub rights: u32,
    /// Optional second SO (e.g. delegation target).
    pub secondary_so: u64,
}

/// Operation code for "capability revoked", mirrors the Solaris FMA
/// notion of a "high-severity event" coming from the policy layer.
/// We treat this as a behavioural anomaly indicator. Matches
/// `sotos_provenance::types::Operation::Revoke`.
pub const OP_REVOKE: u16 = 7;

// Compile-time guard: if a future edit grows or shrinks `ProvenanceEntry`
// without updating the consumers that walk drained ring entries, this
// assertion breaks the build instead of silently corrupting the data.
// Reflects rustc's default field-reordered layout (no `#[repr(C)]`).
const _: () = assert!(core::mem::size_of::<ProvenanceEntry>() == 40);
// Pin the Solaris-FMA "Revoke" discriminant — local invariant only;
// upstream divergence still has to be caught at the ingest boundary.
const _: () = assert!(OP_REVOKE == 7);

/// Hardware fault classes the FMA engine knows how to correlate.
///
/// Kept deliberately small. New classes should map onto a real driver
/// signal (SMART log, EDAC counter, ACPI thermal zone, PCIe AER, ...).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwFaultClass {
    /// Block driver retried a read at this offset (likely bad sector).
    DiskReadRetry,
    /// ECC corrected a single-bit error at this DIMM/page address.
    EccCorrectable,
    /// Uncorrectable ECC error -- treat as a hard data integrity event.
    EccUncorrectable,
    /// CPU/SoC thermal zone crossed its warning threshold.
    ThermalWarn,
    /// PCIe link width/speed dropped below the trained maximum.
    PciLinkDegrade,
}

/// One hardware fault sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwFault {
    /// Fault class.
    pub class: HwFaultClass,
    /// Class-specific location: LBA, DIMM index, PCI BDF, ...
    pub location: u64,
    /// TSC value at the moment the driver reported the fault.
    pub timestamp_tsc: u64,
}

/// Engine output. Vocabulary picked to be drop-in-compatible with the
/// deception migration orchestrator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationRecommendation {
    /// Evacuate the affected domain right now -- the failure is
    /// considered imminent. `reason` is a short, stable string.
    MigrateNow { reason: &'static str },
    /// Keep the domain in place but raise the sampling rate /
    /// schedule a re-evaluation. Failure is plausible but not certain.
    MonitorClosely { reason: &'static str },
    /// Nothing to do.
    NoAction,
}

/// Capacity of the hardware fault history ring.
///
/// 64 entries is enough for ~10 s of bursty PCIe AER + ECC events
/// at typical drain rates without forcing the engine to keep state
/// in a heap.
pub const FMA_FAULT_HISTORY: usize = 64;

/// Capacity of the provenance scan window.
///
/// The engine scans up to this many provenance entries per
/// `ingest_provenance` call -- callers stream the per-CPU ring through
/// in fixed-size chunks.
pub const FMA_PROVENANCE_HISTORY: usize = 256;

/// Predictive fault management state machine.
///
/// All storage is fixed-size; safe to instantiate in a `static`.
pub struct FaultManagement {
    /// Circular buffer of recent hardware faults. `None` slots are
    /// unused (the buffer is not pre-populated).
    fault_history: [Option<HwFault>; FMA_FAULT_HISTORY],
    /// Next write position in `fault_history`.
    fault_idx: usize,
    /// Behavioural anomaly counter from provenance ingest. Decays
    /// only when the caller explicitly resets it via
    /// [`FaultManagement::reset_anomaly_window`].
    prov_window_anomalies: u32,
    /// Recommendation from the most recent `predict_failure` call.
    /// Mirrors what the predictor would compute right now -- maintained
    /// here so it can be observed via the immutable accessor without
    /// re-running the rules.
    last_recommendation: MigrationRecommendation,
}

impl FaultManagement {
    /// Construct an empty engine. `const` so it can be used in a
    /// `static FMA: FaultManagement = FaultManagement::new();`.
    pub const fn new() -> Self {
        Self {
            fault_history: [None; FMA_FAULT_HISTORY],
            fault_idx: 0,
            prov_window_anomalies: 0,
            last_recommendation: MigrationRecommendation::NoAction,
        }
    }

    /// Drain a slice of provenance entries into the anomaly window.
    /// High-anomaly operations (currently `OP_REVOKE`) bump the
    /// counter. We saturate at `u32::MAX` so a runaway producer can't
    /// wrap the counter back to zero.
    pub fn ingest_provenance(&mut self, entries: &[ProvenanceEntry]) {
        let mut bumps: u32 = 0;
        let cap = entries.len().min(FMA_PROVENANCE_HISTORY);
        for entry in &entries[..cap] {
            if entry.operation == OP_REVOKE {
                bumps = bumps.saturating_add(1);
            }
        }
        self.prov_window_anomalies = self.prov_window_anomalies.saturating_add(bumps);
        // Refresh the cached recommendation so an immutable
        // `predict_failure()` call always sees the latest state.
        self.last_recommendation =
            predictor::predict(&self.fault_history, self.prov_window_anomalies);
    }

    /// Inject a hardware fault sample into the history ring. Oldest
    /// entries are evicted in FIFO order.
    pub fn ingest_hw_fault(&mut self, fault: HwFault) {
        self.fault_history[self.fault_idx] = Some(fault);
        self.fault_idx = (self.fault_idx + 1) % FMA_FAULT_HISTORY;
        self.last_recommendation =
            predictor::predict(&self.fault_history, self.prov_window_anomalies);
    }

    /// Run the correlation rules and return the resulting
    /// recommendation. The state machine itself is not modified --
    /// callers can poll this from a read-only context.
    pub fn predict_failure(&self) -> MigrationRecommendation {
        self.last_recommendation
    }

    /// Count faults of a given class within `[now_tsc - window_tsc, now_tsc]`.
    /// Used by the rule engine and useful for diagnostics / unit tests.
    pub fn fault_count(&self, class: HwFaultClass, window_tsc: u64, now_tsc: u64) -> usize {
        correlator::count_in_window(&self.fault_history, class, window_tsc, now_tsc)
    }

    /// Reset the behavioural anomaly counter. Call this once the
    /// scheduler has acted on (or aged out) the previous window.
    pub fn reset_anomaly_window(&mut self) {
        self.prov_window_anomalies = 0;
        self.last_recommendation =
            predictor::predict(&self.fault_history, self.prov_window_anomalies);
    }

    /// Read-only accessor for the anomaly counter (tests / diagnostics).
    pub fn anomaly_count(&self) -> u32 {
        self.prov_window_anomalies
    }
}

impl Default for FaultManagement {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(op: u16) -> ProvenanceEntry {
        ProvenanceEntry {
            epoch: 0,
            domain_id: 1,
            operation: op,
            so_id: 42,
            so_type: 1,
            rights: 0,
            secondary_so: 0,
        }
    }

    #[test]
    fn empty_engine_has_no_action() {
        let fma = FaultManagement::new();
        assert_eq!(fma.predict_failure(), MigrationRecommendation::NoAction);
        assert_eq!(fma.anomaly_count(), 0);
    }

    #[test]
    fn predict_updates_after_each_ingest() {
        let mut fma = FaultManagement::new();
        for i in 0..5 {
            fma.ingest_hw_fault(HwFault {
                class: HwFaultClass::DiskReadRetry,
                location: 0xABCD,
                timestamp_tsc: 100 + i,
            });
        }
        assert_eq!(
            fma.predict_failure(),
            MigrationRecommendation::MigrateNow {
                reason: "disk read retries"
            }
        );
    }

    #[test]
    fn ingest_provenance_counts_revokes_only() {
        let mut fma = FaultManagement::new();
        let mixed = [
            entry(1),
            entry(OP_REVOKE),
            entry(2),
            entry(OP_REVOKE),
            entry(OP_REVOKE),
        ];
        fma.ingest_provenance(&mixed);
        assert_eq!(fma.anomaly_count(), 3);
    }

    #[test]
    fn ingest_provenance_caps_at_window() {
        let mut fma = FaultManagement::new();
        // Build a buffer larger than the window of all revokes.
        let buf = [entry(OP_REVOKE); FMA_PROVENANCE_HISTORY + 32];
        fma.ingest_provenance(&buf);
        // Capped at window size, not 32 more.
        assert_eq!(fma.anomaly_count(), FMA_PROVENANCE_HISTORY as u32);
    }

    #[test]
    fn ingest_provenance_saturates() {
        let mut fma = FaultManagement::new();
        // Drive the counter to near-saturation, then push more.
        fma.prov_window_anomalies = u32::MAX - 2;
        let buf = [entry(OP_REVOKE); 16];
        fma.ingest_provenance(&buf);
        assert_eq!(fma.anomaly_count(), u32::MAX);
    }

    #[test]
    fn fault_history_is_circular() {
        let mut fma = FaultManagement::new();
        for i in 0..FMA_FAULT_HISTORY + 5 {
            fma.ingest_hw_fault(HwFault {
                class: HwFaultClass::DiskReadRetry,
                location: i as u64,
                timestamp_tsc: i as u64,
            });
        }
        // Older entries (locations 0..4) should have been evicted.
        let count = fma.fault_history.iter().filter_map(|f| f.as_ref()).count();
        assert_eq!(count, FMA_FAULT_HISTORY);
    }

    #[test]
    fn reset_anomaly_window_clears_counter() {
        let mut fma = FaultManagement::new();
        fma.ingest_provenance(&[entry(OP_REVOKE), entry(OP_REVOKE)]);
        assert_eq!(fma.anomaly_count(), 2);
        fma.reset_anomaly_window();
        assert_eq!(fma.anomaly_count(), 0);
    }
}
