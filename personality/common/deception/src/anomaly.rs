//! Anomaly patterns that trigger automatic deception migration.
//!
//! These encode known attack behaviors detected via provenance analysis.
//! The [`AnomalyDetector`] scans provenance entries for a domain and
//! produces [`AnomalyReport`]s that the migration orchestrator acts on.

/// Known attack patterns detected from provenance graph.
#[derive(Debug, Clone, Copy)]
pub enum AnomalyPattern {
    /// Process reads /etc/shadow after modifying a system binary.
    CredentialTheftAfterBackdoor,
    /// Process scans multiple sensitive files in rapid succession.
    ReconnaissanceSweep,
    /// Process opens network connection after reading crypto keys.
    DataExfiltration,
    /// Process modifies multiple config files then restarts services.
    PersistenceInstall,
    /// Process executes unexpected binary from /tmp or /dev/shm.
    StagedPayload,
    /// Process attempts privilege escalation via known CVE patterns.
    PrivilegeEscalation,
    /// Unusual fan-out: single domain touches >N objects in a short window.
    AnomalousFanOut { threshold: u32 },
    /// Custom pattern defined by policy.
    Custom { pattern_id: u32 },
}

/// Action recommended after anomaly detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationAction {
    /// Immediately migrate to deception environment.
    MigrateNow,
    /// Increase monitoring; migrate if pattern continues.
    EscalateMonitoring,
    /// Alert SOC but do not migrate yet.
    AlertOnly,
    /// False positive, ignore.
    Ignore,
}

/// Result of anomaly analysis for a single detected pattern.
pub struct AnomalyReport {
    /// Domain that triggered the anomaly.
    pub domain_id: u32,
    /// Which pattern was matched.
    pub pattern: AnomalyPattern,
    /// Confidence score (0-100).
    pub confidence: u8,
    /// Number of provenance entries supporting this detection.
    pub evidence_count: u32,
    /// Timestamp (TSC or monotonic tick) when the anomaly was detected.
    pub timestamp: u64,
    /// What the detector recommends doing about it.
    pub recommended_action: MigrationAction,
}

/// A single provenance entry that the detector analyzes.
///
/// This is a simplified view of the provenance graph node --
/// the real provenance subsystem produces these.
#[derive(Clone, Copy)]
pub struct ProvenanceEntry {
    /// Monotonic timestamp.
    pub timestamp: u64,
    /// Type of operation observed.
    pub op: ProvenanceOp,
    /// Object (file/service/cap) that was the target.
    pub object_id: u64,
}

/// Categories of operations recorded in the provenance graph.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceOp {
    FileRead,
    FileWrite,
    FileExec,
    NetConnect,
    NetListen,
    CapGrant,
    CapRevoke,
    ServiceCall,
    ProcessSpawn,
    ConfigModify,
    ServiceRestart,
}

// ---------------------------------------------------------------------------
// Well-known object IDs used by pattern matchers
// ---------------------------------------------------------------------------

const OBJ_ETC_SHADOW: u64 = 0xF001;
const OBJ_CRYPTO_KEYS: u64 = 0xF002;

/// Paths under /tmp or /dev/shm are in this range.
const fn is_tmp_path(oid: u64) -> bool {
    oid >= 0xE000 && oid < 0xF000
}

/// System binaries live in this range.
const fn is_system_binary(oid: u64) -> bool {
    oid >= 0xA000 && oid < 0xB000
}

/// Config files live in this range.
const fn is_config_file(oid: u64) -> bool {
    oid >= 0xC000 && oid < 0xD000
}

/// Sensitive files (credentials, keys, etc.).
const fn is_sensitive_file(oid: u64) -> bool {
    oid >= 0xF000 && oid < 0xF100
}

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/// Configurable thresholds for anomaly detection.
pub struct DetectorConfig {
    /// Minimum confidence to report (0-100).
    pub min_confidence: u8,
    /// How many sensitive files in a window triggers ReconnaissanceSweep.
    pub recon_file_threshold: u32,
    /// Time window (ticks) for reconnaissance detection.
    pub recon_window_ticks: u64,
    /// Default fan-out threshold when AnomalousFanOut has none.
    pub default_fanout_threshold: u32,
    /// How many config modifications trigger PersistenceInstall.
    pub persistence_config_threshold: u32,
}

impl DetectorConfig {
    pub const fn default() -> Self {
        Self {
            min_confidence: 30,
            recon_file_threshold: 5,
            recon_window_ticks: 10_000,
            default_fanout_threshold: 20,
            persistence_config_threshold: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Maximum reports returned from a single `check_domain` call.
const MAX_REPORTS: usize = 16;

/// Anomaly detector that scans provenance entries for attack patterns.
pub struct AnomalyDetector {
    config: DetectorConfig,
}

impl AnomalyDetector {
    pub const fn new(config: DetectorConfig) -> Self {
        Self { config }
    }

    /// Analyze recent provenance entries for a domain and return any
    /// anomaly reports. The caller provides the current timestamp so the
    /// detector can reason about time windows.
    pub fn check_domain(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
    ) -> ([AnomalyReport; MAX_REPORTS], usize) {
        let mut reports = uninit_reports();
        let mut count = 0;

        count += self.check_credential_theft(domain_id, entries, now, &mut reports, count);
        count += self.check_reconnaissance(domain_id, entries, now, &mut reports, count);
        count += self.check_data_exfiltration(domain_id, entries, now, &mut reports, count);
        count += self.check_persistence(domain_id, entries, now, &mut reports, count);
        count += self.check_staged_payload(domain_id, entries, now, &mut reports, count);
        count += self.check_privilege_escalation(domain_id, entries, now, &mut reports, count);
        count += self.check_fanout(domain_id, entries, now, &mut reports, count);

        (reports, count)
    }

    // -- Pattern matchers ---------------------------------------------------

    /// CredentialTheftAfterBackdoor: write to system binary followed by
    /// read of /etc/shadow.
    fn check_credential_theft(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
        out: &mut [AnomalyReport; MAX_REPORTS],
        base: usize,
    ) -> usize {
        if base >= MAX_REPORTS {
            return 0;
        }

        let mut saw_binary_write = false;
        let mut shadow_read_after = false;

        for e in entries {
            if matches!(e.op, ProvenanceOp::FileWrite) && is_system_binary(e.object_id) {
                saw_binary_write = true;
            }
            if saw_binary_write
                && matches!(e.op, ProvenanceOp::FileRead)
                && e.object_id == OBJ_ETC_SHADOW
            {
                shadow_read_after = true;
                break;
            }
        }

        if shadow_read_after {
            let confidence = 90;
            if confidence >= self.config.min_confidence {
                out[base] = AnomalyReport {
                    domain_id,
                    pattern: AnomalyPattern::CredentialTheftAfterBackdoor,
                    confidence,
                    evidence_count: 2,
                    timestamp: now,
                    recommended_action: MigrationAction::MigrateNow,
                };
                return 1;
            }
        }
        0
    }

    /// ReconnaissanceSweep: many sensitive file reads in a short window.
    fn check_reconnaissance(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
        out: &mut [AnomalyReport; MAX_REPORTS],
        base: usize,
    ) -> usize {
        if base >= MAX_REPORTS {
            return 0;
        }

        let window_start = now.saturating_sub(self.config.recon_window_ticks);
        let mut sensitive_reads = 0u32;

        for e in entries {
            if e.timestamp >= window_start
                && matches!(e.op, ProvenanceOp::FileRead)
                && is_sensitive_file(e.object_id)
            {
                sensitive_reads += 1;
            }
        }

        if sensitive_reads >= self.config.recon_file_threshold {
            let confidence = core::cmp::min(
                100,
                50 + (sensitive_reads - self.config.recon_file_threshold) * 10,
            ) as u8;
            if confidence >= self.config.min_confidence {
                out[base] = AnomalyReport {
                    domain_id,
                    pattern: AnomalyPattern::ReconnaissanceSweep,
                    confidence,
                    evidence_count: sensitive_reads,
                    timestamp: now,
                    recommended_action: if confidence >= 70 {
                        MigrationAction::MigrateNow
                    } else {
                        MigrationAction::EscalateMonitoring
                    },
                };
                return 1;
            }
        }
        0
    }

    /// DataExfiltration: read crypto keys then open a network connection.
    fn check_data_exfiltration(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
        out: &mut [AnomalyReport; MAX_REPORTS],
        base: usize,
    ) -> usize {
        if base >= MAX_REPORTS {
            return 0;
        }

        let mut saw_key_read = false;
        let mut net_after_key = false;

        for e in entries {
            if matches!(e.op, ProvenanceOp::FileRead) && e.object_id == OBJ_CRYPTO_KEYS {
                saw_key_read = true;
            }
            if saw_key_read && matches!(e.op, ProvenanceOp::NetConnect) {
                net_after_key = true;
                break;
            }
        }

        if net_after_key {
            let confidence = 85;
            if confidence >= self.config.min_confidence {
                out[base] = AnomalyReport {
                    domain_id,
                    pattern: AnomalyPattern::DataExfiltration,
                    confidence,
                    evidence_count: 2,
                    timestamp: now,
                    recommended_action: MigrationAction::MigrateNow,
                };
                return 1;
            }
        }
        0
    }

    /// PersistenceInstall: modify multiple config files then restart a service.
    fn check_persistence(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
        out: &mut [AnomalyReport; MAX_REPORTS],
        base: usize,
    ) -> usize {
        if base >= MAX_REPORTS {
            return 0;
        }

        let mut config_writes = 0u32;
        let mut restart_after = false;

        for e in entries {
            if matches!(e.op, ProvenanceOp::ConfigModify | ProvenanceOp::FileWrite)
                && is_config_file(e.object_id)
            {
                config_writes += 1;
            }
            if config_writes >= self.config.persistence_config_threshold
                && matches!(e.op, ProvenanceOp::ServiceRestart)
            {
                restart_after = true;
                break;
            }
        }

        if restart_after {
            let confidence = 80;
            if confidence >= self.config.min_confidence {
                out[base] = AnomalyReport {
                    domain_id,
                    pattern: AnomalyPattern::PersistenceInstall,
                    confidence,
                    evidence_count: config_writes + 1,
                    timestamp: now,
                    recommended_action: MigrationAction::MigrateNow,
                };
                return 1;
            }
        }
        0
    }

    /// StagedPayload: exec of a binary from /tmp or /dev/shm.
    fn check_staged_payload(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
        out: &mut [AnomalyReport; MAX_REPORTS],
        base: usize,
    ) -> usize {
        if base >= MAX_REPORTS {
            return 0;
        }

        for e in entries {
            if matches!(e.op, ProvenanceOp::FileExec) && is_tmp_path(e.object_id) {
                let confidence = 75;
                if confidence >= self.config.min_confidence {
                    out[base] = AnomalyReport {
                        domain_id,
                        pattern: AnomalyPattern::StagedPayload,
                        confidence,
                        evidence_count: 1,
                        timestamp: now,
                        recommended_action: MigrationAction::EscalateMonitoring,
                    };
                    return 1;
                }
            }
        }
        0
    }

    /// PrivilegeEscalation: write to a system binary then spawn a process.
    fn check_privilege_escalation(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
        out: &mut [AnomalyReport; MAX_REPORTS],
        base: usize,
    ) -> usize {
        if base >= MAX_REPORTS {
            return 0;
        }

        let mut saw_sysbin_write = false;
        let mut spawn_after = false;

        for e in entries {
            if matches!(e.op, ProvenanceOp::FileWrite) && is_system_binary(e.object_id) {
                saw_sysbin_write = true;
            }
            if saw_sysbin_write && matches!(e.op, ProvenanceOp::ProcessSpawn) {
                spawn_after = true;
                break;
            }
        }

        if spawn_after {
            let confidence = 70;
            if confidence >= self.config.min_confidence {
                out[base] = AnomalyReport {
                    domain_id,
                    pattern: AnomalyPattern::PrivilegeEscalation,
                    confidence,
                    evidence_count: 2,
                    timestamp: now,
                    recommended_action: MigrationAction::MigrateNow,
                };
                return 1;
            }
        }
        0
    }

    /// AnomalousFanOut: domain touches too many distinct objects in a window.
    fn check_fanout(
        &self,
        domain_id: u32,
        entries: &[ProvenanceEntry],
        now: u64,
        out: &mut [AnomalyReport; MAX_REPORTS],
        base: usize,
    ) -> usize {
        if base >= MAX_REPORTS {
            return 0;
        }

        let threshold = self.config.default_fanout_threshold;
        let window_start = now.saturating_sub(self.config.recon_window_ticks);

        // Count distinct object IDs in the window. Use a small fixed set
        // to stay no_std/no-alloc.
        let mut seen = [0u64; 64];
        let mut seen_count = 0usize;

        for e in entries {
            if e.timestamp < window_start {
                continue;
            }
            let mut found = false;
            for i in 0..seen_count {
                if seen[i] == e.object_id {
                    found = true;
                    break;
                }
            }
            if !found && seen_count < seen.len() {
                seen[seen_count] = e.object_id;
                seen_count += 1;
            }
        }

        let distinct = seen_count as u32;
        if distinct >= threshold {
            let overshoot = distinct - threshold;
            let confidence = core::cmp::min(100, 40 + overshoot * 5) as u8;
            if confidence >= self.config.min_confidence {
                out[base] = AnomalyReport {
                    domain_id,
                    pattern: AnomalyPattern::AnomalousFanOut { threshold },
                    confidence,
                    evidence_count: distinct,
                    timestamp: now,
                    recommended_action: if confidence >= 70 {
                        MigrationAction::MigrateNow
                    } else {
                        MigrationAction::EscalateMonitoring
                    },
                };
                return 1;
            }
        }
        0
    }
}

/// Helper: zero-initialize the report array (no Default trait in no_std).
fn uninit_reports() -> [AnomalyReport; MAX_REPORTS] {
    const EMPTY: AnomalyReport = AnomalyReport {
        domain_id: 0,
        pattern: AnomalyPattern::Custom { pattern_id: 0 },
        confidence: 0,
        evidence_count: 0,
        timestamp: 0,
        recommended_action: MigrationAction::Ignore,
    };
    [EMPTY; MAX_REPORTS]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ts: u64, op: ProvenanceOp, oid: u64) -> ProvenanceEntry {
        ProvenanceEntry {
            timestamp: ts,
            op,
            object_id: oid,
        }
    }

    #[test]
    fn credential_theft_detected() {
        let detector = AnomalyDetector::new(DetectorConfig::default());
        let entries = [
            make_entry(1, ProvenanceOp::FileWrite, 0xA001), // system binary write
            make_entry(2, ProvenanceOp::FileRead, OBJ_ETC_SHADOW), // shadow read
        ];
        let (reports, count) = detector.check_domain(1, &entries, 3);
        assert_eq!(count, 1);
        assert!(matches!(
            reports[0].pattern,
            AnomalyPattern::CredentialTheftAfterBackdoor
        ));
        assert_eq!(reports[0].recommended_action, MigrationAction::MigrateNow);
    }

    #[test]
    fn no_false_positive_on_normal_read() {
        let detector = AnomalyDetector::new(DetectorConfig::default());
        let entries = [
            make_entry(1, ProvenanceOp::FileRead, 0x1234), // random file
        ];
        let (_reports, count) = detector.check_domain(1, &entries, 2);
        assert_eq!(count, 0);
    }

    #[test]
    fn reconnaissance_sweep_detected() {
        let detector = AnomalyDetector::new(DetectorConfig::default());
        let entries = [
            make_entry(100, ProvenanceOp::FileRead, 0xF010),
            make_entry(101, ProvenanceOp::FileRead, 0xF011),
            make_entry(102, ProvenanceOp::FileRead, 0xF012),
            make_entry(103, ProvenanceOp::FileRead, 0xF013),
            make_entry(104, ProvenanceOp::FileRead, 0xF014),
        ];
        let (reports, count) = detector.check_domain(2, &entries, 200);
        assert_eq!(count, 1);
        assert!(matches!(
            reports[0].pattern,
            AnomalyPattern::ReconnaissanceSweep
        ));
    }

    #[test]
    fn data_exfiltration_detected() {
        let detector = AnomalyDetector::new(DetectorConfig::default());
        let entries = [
            make_entry(1, ProvenanceOp::FileRead, OBJ_CRYPTO_KEYS),
            make_entry(2, ProvenanceOp::NetConnect, 0x9999),
        ];
        let (reports, count) = detector.check_domain(3, &entries, 3);
        assert!(count >= 1);
        let exfil = reports.iter().take(count).find(|r| {
            matches!(r.pattern, AnomalyPattern::DataExfiltration)
        });
        assert!(exfil.is_some());
    }

    #[test]
    fn staged_payload_detected() {
        let detector = AnomalyDetector::new(DetectorConfig::default());
        let entries = [
            make_entry(1, ProvenanceOp::FileExec, 0xE100), // /tmp exec
        ];
        let (reports, count) = detector.check_domain(4, &entries, 2);
        assert!(count >= 1);
        let staged = reports.iter().take(count).find(|r| {
            matches!(r.pattern, AnomalyPattern::StagedPayload)
        });
        assert!(staged.is_some());
    }

    #[test]
    fn fanout_threshold() {
        let mut cfg = DetectorConfig::default();
        cfg.default_fanout_threshold = 3;
        cfg.recon_window_ticks = 1000;
        let detector = AnomalyDetector::new(cfg);
        let entries = [
            make_entry(10, ProvenanceOp::FileRead, 0x0001),
            make_entry(11, ProvenanceOp::FileRead, 0x0002),
            make_entry(12, ProvenanceOp::FileRead, 0x0003),
        ];
        let (reports, count) = detector.check_domain(5, &entries, 20);
        assert!(count >= 1);
        let fanout = reports.iter().take(count).find(|r| {
            matches!(r.pattern, AnomalyPattern::AnomalousFanOut { .. })
        });
        assert!(fanout.is_some());
    }
}
