//! Graph Hunter -- real-time provenance graph anomaly detection.
//!
//! Reads provenance ring buffers, builds a live graph, detects attack patterns.
//! Feeds alerts into the deception migration trigger pipeline.

use crate::graph::ProvenanceGraph;
use crate::types::ProvenanceEntry;

/// A detection rule matching provenance patterns.
pub struct DetectionRule {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    /// Pattern type to match.
    pub pattern: DetectionPattern,
    /// Minimum confidence to trigger (0-100).
    pub min_confidence: u8,
    /// Action when triggered.
    pub action: DetectionAction,
    /// Whether this rule is active.
    pub enabled: bool,
}

/// Pattern types the hunter can detect.
pub enum DetectionPattern {
    /// Domain reads credential SO after writing to a system binary SO.
    CredentialTheft,
    /// Domain touches more than `max_objects` distinct SOs in `window_epochs`.
    AnomalousFanOut {
        max_objects: u32,
        window_epochs: u64,
    },
    /// Domain A grants a cap to domain B that was not in original policy.
    LateralMovement,
    /// Domain reads sensitive data then accesses the network.
    DataExfiltration {
        sensitive_so_prefix: [u8; 16],
        prefix_len: usize,
    },
    /// Domain modifies startup or config SOs.
    PersistenceInstall,
    /// Match a specific (domain, operation, so_type) triple.
    Custom {
        domain: Option<u32>,
        operation: Option<u16>,
        so_type: Option<u8>,
    },
}

/// What to do when a detection rule fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetectionAction {
    Alert,
    MigrateToDeception,
    KillDomain,
    EscalateMonitoring,
}

/// An alert produced by a detection rule match.
pub struct Alert {
    pub rule_id: u32,
    pub domain_id: u32,
    pub confidence: u8,
    pub timestamp: u64,
    /// SO IDs constituting evidence.
    pub evidence: [u64; 8],
    pub evidence_count: usize,
    pub action: DetectionAction,
}

/// Aggregate statistics from the hunter.
pub struct HunterStats {
    pub entries_processed: u64,
    pub alerts_generated: u64,
    pub active_rules: usize,
    pub graph_nodes: usize,
    pub graph_edges: usize,
    pub tracked_domains: usize,
}

const MAX_RULES: usize = 64;
const ALERT_QUEUE_SIZE: usize = 128;

/// Graph Hunter service state.
pub struct GraphHunter {
    graph: ProvenanceGraph,
    rules: [Option<DetectionRule>; MAX_RULES],
    rule_count: usize,
    alerts: [Option<Alert>; ALERT_QUEUE_SIZE],
    alert_head: usize,
    alert_tail: usize,
    entries_processed: u64,
    alerts_generated: u64,
    last_drain_epoch: u64,
}

/// Helper: write a name byte string into a fixed-size array.
fn write_name(buf: &mut [u8; 32], src: &[u8]) -> usize {
    let len = if src.len() > 32 { 32 } else { src.len() };
    buf[..len].copy_from_slice(&src[..len]);
    len
}

impl GraphHunter {
    /// Create a new hunter pre-loaded with default detection rules.
    pub fn new() -> Self {
        let mut rules: [Option<DetectionRule>; MAX_RULES] = {
            const NONE: Option<DetectionRule> = None;
            [NONE; MAX_RULES]
        };
        let alerts: [Option<Alert>; ALERT_QUEUE_SIZE] = {
            const NONE: Option<Alert> = None;
            [NONE; ALERT_QUEUE_SIZE]
        };

        // Rule 0: Credential Theft
        let mut name0 = [0u8; 32];
        let len0 = write_name(&mut name0, b"CredentialTheft");
        rules[0] = Some(DetectionRule {
            id: 0,
            name: name0,
            name_len: len0,
            pattern: DetectionPattern::CredentialTheft,
            min_confidence: 70,
            action: DetectionAction::MigrateToDeception,
            enabled: true,
        });

        // Rule 1: Anomalous Fan-Out (>32 objects in 1000 epochs)
        let mut name1 = [0u8; 32];
        let len1 = write_name(&mut name1, b"AnomalousFanOut");
        rules[1] = Some(DetectionRule {
            id: 1,
            name: name1,
            name_len: len1,
            pattern: DetectionPattern::AnomalousFanOut {
                max_objects: 32,
                window_epochs: 1000,
            },
            min_confidence: 60,
            action: DetectionAction::EscalateMonitoring,
            enabled: true,
        });

        // Rule 2: Lateral Movement
        let mut name2 = [0u8; 32];
        let len2 = write_name(&mut name2, b"LateralMovement");
        rules[2] = Some(DetectionRule {
            id: 2,
            name: name2,
            name_len: len2,
            pattern: DetectionPattern::LateralMovement,
            min_confidence: 80,
            action: DetectionAction::Alert,
            enabled: true,
        });

        Self {
            graph: ProvenanceGraph::new(),
            rules,
            rule_count: 3,
            alerts,
            alert_head: 0,
            alert_tail: 0,
            entries_processed: 0,
            alerts_generated: 0,
            last_drain_epoch: 0,
        }
    }

    /// Ingest a batch of provenance entries. Each entry is added to the graph
    /// and every enabled rule is evaluated against the updated state.
    pub fn ingest(&mut self, entries: &[ProvenanceEntry]) {
        for entry in entries {
            self.graph.ingest_entry(entry);
            self.entries_processed += 1;
            self.evaluate_rules(entry);
            self.last_drain_epoch = entry.epoch;
        }
    }

    /// Dequeue the next pending alert, if any.
    pub fn poll_alert(&mut self) -> Option<Alert> {
        if self.alert_head == self.alert_tail {
            return None;
        }
        let alert = self.alerts[self.alert_head].take();
        self.alert_head = (self.alert_head + 1) % ALERT_QUEUE_SIZE;
        alert
    }

    /// Register a new detection rule. Returns the assigned rule ID.
    pub fn add_rule(&mut self, rule: DetectionRule) -> Result<u32, ()> {
        if self.rule_count >= MAX_RULES {
            return Err(());
        }
        let id = rule.id;
        for slot in self.rules.iter_mut() {
            if slot.is_none() {
                *slot = Some(rule);
                self.rule_count += 1;
                return Ok(id);
            }
        }
        Err(())
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> HunterStats {
        let active_rules = self.rules.iter().filter(|r| {
            r.as_ref().map_or(false, |r| r.enabled)
        }).count();

        HunterStats {
            entries_processed: self.entries_processed,
            alerts_generated: self.alerts_generated,
            active_rules,
            graph_nodes: self.graph.node_count,
            graph_edges: self.graph.edge_count,
            tracked_domains: self.graph.domain_count,
        }
    }

    /// Read-only access to the underlying graph for external queries.
    pub fn graph(&self) -> &ProvenanceGraph {
        &self.graph
    }

    fn evaluate_rules(&mut self, entry: &ProvenanceEntry) {
        // Snapshot: we cannot borrow self mutably twice, so collect
        // matches into a small local buffer first.
        let mut pending = [PendingAlert::EMPTY; 8];
        let mut pending_count = 0usize;

        for slot in self.rules.iter() {
            let rule = match slot {
                Some(r) if r.enabled => r,
                _ => continue,
            };
            if let Some((confidence, evidence, ev_count)) =
                self.match_pattern(rule, entry)
            {
                if confidence >= rule.min_confidence && pending_count < 8 {
                    pending[pending_count] = PendingAlert {
                        rule_id: rule.id,
                        domain_id: entry.domain_id,
                        confidence,
                        action: rule.action,
                        evidence,
                        ev_count,
                    };
                    pending_count += 1;
                }
            }
        }

        for i in 0..pending_count {
            let p = &pending[i];
            self.push_alert(Alert {
                rule_id: p.rule_id,
                domain_id: p.domain_id,
                confidence: p.confidence,
                timestamp: entry.epoch,
                evidence: p.evidence,
                evidence_count: p.ev_count,
                action: p.action,
            });
        }
    }

    /// Try to match a single rule against the current graph state
    /// given the entry that was just ingested.
    /// Returns `Some((confidence, evidence_ids, evidence_count))` on match.
    fn match_pattern(
        &self,
        rule: &DetectionRule,
        entry: &ProvenanceEntry,
    ) -> Option<(u8, [u64; 8], usize)> {
        match &rule.pattern {
            DetectionPattern::CredentialTheft => {
                self.match_credential_theft(entry)
            }
            DetectionPattern::AnomalousFanOut { max_objects, window_epochs } => {
                self.match_anomalous_fanout(entry, *max_objects, *window_epochs)
            }
            DetectionPattern::LateralMovement => {
                self.match_lateral_movement(entry)
            }
            DetectionPattern::DataExfiltration { sensitive_so_prefix, prefix_len } => {
                self.match_data_exfiltration(entry, &sensitive_so_prefix[..*prefix_len])
            }
            DetectionPattern::PersistenceInstall => {
                self.match_persistence_install(entry)
            }
            DetectionPattern::Custom { domain, operation, so_type } => {
                self.match_custom(entry, *domain, *operation, *so_type)
            }
        }
    }

    /// Credential theft: domain wrote to a system binary AND read a credential.
    fn match_credential_theft(
        &self,
        entry: &ProvenanceEntry,
    ) -> Option<(u8, [u64; 8], usize)> {
        let da = self.graph.domain_activity(entry.domain_id)?;
        if da.wrote_system_binary && da.read_credential {
            let mut evidence = [0u64; 8];
            evidence[0] = entry.so_id;
            Some((85, evidence, 1))
        } else {
            None
        }
    }

    /// Anomalous fan-out: domain touched too many distinct SOs in a window.
    fn match_anomalous_fanout(
        &self,
        entry: &ProvenanceEntry,
        max_objects: u32,
        window_epochs: u64,
    ) -> Option<(u8, [u64; 8], usize)> {
        let window_start = entry.epoch.saturating_sub(window_epochs);
        let fanout = self.graph.domain_fanout(entry.domain_id, window_start);
        if fanout > max_objects {
            let mut evidence = [0u64; 8];
            evidence[0] = entry.so_id;
            evidence[1] = fanout as u64;
            // Confidence scales with how far over the threshold.
            let ratio = (fanout as u64 * 100) / (max_objects as u64);
            let confidence = if ratio > 200 { 95 } else { 60 + ((ratio - 100) * 35 / 100) as u8 };
            Some((confidence, evidence, 2))
        } else {
            None
        }
    }

    /// Lateral movement: domain granted a cap to another domain.
    fn match_lateral_movement(
        &self,
        entry: &ProvenanceEntry,
    ) -> Option<(u8, [u64; 8], usize)> {
        let da = self.graph.domain_activity(entry.domain_id)?;
        if da.granted_cap && da.grant_target != 0 {
            let mut evidence = [0u64; 8];
            evidence[0] = entry.so_id;
            evidence[1] = da.grant_target as u64;
            Some((80, evidence, 2))
        } else {
            None
        }
    }

    /// Data exfiltration: domain read sensitive data then accessed network.
    fn match_data_exfiltration(
        &self,
        entry: &ProvenanceEntry,
        _prefix: &[u8],
    ) -> Option<(u8, [u64; 8], usize)> {
        let da = self.graph.domain_activity(entry.domain_id)?;
        if da.read_credential && da.accessed_network {
            let mut evidence = [0u64; 8];
            evidence[0] = entry.so_id;
            Some((90, evidence, 1))
        } else {
            None
        }
    }

    /// Persistence install: domain modified a config or startup SO.
    fn match_persistence_install(
        &self,
        entry: &ProvenanceEntry,
    ) -> Option<(u8, [u64; 8], usize)> {
        let da = self.graph.domain_activity(entry.domain_id)?;
        if da.modified_config {
            let mut evidence = [0u64; 8];
            evidence[0] = entry.so_id;
            Some((75, evidence, 1))
        } else {
            None
        }
    }

    /// Custom: match a specific (domain, operation, so_type) triple.
    fn match_custom(
        &self,
        entry: &ProvenanceEntry,
        domain: Option<u32>,
        operation: Option<u16>,
        so_type: Option<u8>,
    ) -> Option<(u8, [u64; 8], usize)> {
        if let Some(d) = domain {
            if entry.domain_id != d {
                return None;
            }
        }
        if let Some(op) = operation {
            if entry.operation != op {
                return None;
            }
        }
        if let Some(st) = so_type {
            if entry.so_type != st {
                return None;
            }
        }
        let mut evidence = [0u64; 8];
        evidence[0] = entry.so_id;
        Some((70, evidence, 1))
    }

    fn push_alert(&mut self, alert: Alert) {
        let next_tail = (self.alert_tail + 1) % ALERT_QUEUE_SIZE;
        if next_tail == self.alert_head {
            // Queue full -- drop oldest.
            self.alert_head = (self.alert_head + 1) % ALERT_QUEUE_SIZE;
        }
        self.alerts[self.alert_tail] = Some(alert);
        self.alert_tail = next_tail;
        self.alerts_generated += 1;
    }
}

/// Temporary buffer entry used during rule evaluation to avoid
/// borrowing `self` mutably while iterating rules.
#[derive(Clone, Copy)]
struct PendingAlert {
    rule_id: u32,
    domain_id: u32,
    confidence: u8,
    action: DetectionAction,
    evidence: [u64; 8],
    ev_count: usize,
}

impl PendingAlert {
    const EMPTY: Self = Self {
        rule_id: 0,
        domain_id: 0,
        confidence: 0,
        action: DetectionAction::Alert,
        evidence: [0; 8],
        ev_count: 0,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Operation, SoType};

    fn make_entry(
        epoch: u64,
        domain_id: u32,
        op: Operation,
        so_id: u64,
        so_type: SoType,
    ) -> ProvenanceEntry {
        ProvenanceEntry {
            epoch,
            domain_id,
            operation: op as u16,
            so_id,
            so_type: so_type as u8,
            rights: 0,
            secondary_so: 0,
        }
    }

    #[test]
    fn test_credential_theft_detection() {
        let mut hunter = GraphHunter::new();

        // Domain 1 writes to a system binary.
        let e1 = make_entry(1, 1, Operation::Write, 100, SoType::SystemBinary);
        // Domain 1 reads a credential.
        let e2 = make_entry(2, 1, Operation::Read, 200, SoType::Credential);

        hunter.ingest(&[e1, e2]);

        let alert = hunter.poll_alert();
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.rule_id, 0); // CredentialTheft rule
        assert_eq!(a.domain_id, 1);
        assert!(a.confidence >= 70);
    }

    #[test]
    fn test_anomalous_fanout_detection() {
        let mut hunter = GraphHunter::new();

        // Domain 2 touches 40 distinct SOs in quick succession.
        // Use a fixed array instead of Vec since we are no_std.
        let mut entries = [make_entry(0, 2, Operation::Read, 1000, SoType::File); 40];
        for i in 0..40 {
            entries[i] = make_entry(i as u64, 2, Operation::Read, 1000 + i as u64, SoType::File);
        }

        hunter.ingest(&entries);

        // Should have generated at least one fan-out alert.
        let mut found_fanout = false;
        while let Some(alert) = hunter.poll_alert() {
            if alert.rule_id == 1 {
                found_fanout = true;
                assert_eq!(alert.domain_id, 2);
            }
        }
        assert!(found_fanout);
    }

    #[test]
    fn test_lateral_movement_detection() {
        let mut hunter = GraphHunter::new();

        // Domain 3 grants a cap to domain 5.
        let e = ProvenanceEntry {
            epoch: 10,
            domain_id: 3,
            operation: Operation::Grant as u16,
            so_id: 500,
            so_type: SoType::Capability as u8,
            rights: 0x7,
            secondary_so: 5, // target domain
        };
        hunter.ingest(&[e]);

        let mut found = false;
        while let Some(alert) = hunter.poll_alert() {
            if alert.rule_id == 2 {
                found = true;
                assert_eq!(alert.domain_id, 3);
                assert_eq!(alert.evidence[1], 5); // target domain
            }
        }
        assert!(found);
    }

    #[test]
    fn test_add_custom_rule() {
        let mut hunter = GraphHunter::new();

        let mut name = [0u8; 32];
        let name_len = write_name(&mut name, b"WatchDomain42");
        let rule = DetectionRule {
            id: 100,
            name,
            name_len,
            pattern: DetectionPattern::Custom {
                domain: Some(42),
                operation: None,
                so_type: None,
            },
            min_confidence: 50,
            action: DetectionAction::KillDomain,
            enabled: true,
        };
        assert!(hunter.add_rule(rule).is_ok());

        let e = make_entry(1, 42, Operation::Read, 999, SoType::File);
        hunter.ingest(&[e]);

        let mut found = false;
        while let Some(alert) = hunter.poll_alert() {
            if alert.rule_id == 100 {
                found = true;
                assert_eq!(alert.action, DetectionAction::KillDomain);
            }
        }
        assert!(found);
    }

    #[test]
    fn test_stats() {
        let mut hunter = GraphHunter::new();
        let e = make_entry(1, 1, Operation::Read, 10, SoType::File);
        hunter.ingest(&[e]);

        let s = hunter.stats();
        assert_eq!(s.entries_processed, 1);
        assert_eq!(s.active_rules, 3);
        assert_eq!(s.graph_nodes, 1);
    }

    #[test]
    fn test_no_false_positive() {
        let mut hunter = GraphHunter::new();
        // Single benign read -- should not trigger anything.
        let e = make_entry(1, 10, Operation::Read, 50, SoType::File);
        hunter.ingest(&[e]);
        assert!(hunter.poll_alert().is_none());
    }
}
