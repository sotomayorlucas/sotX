//! BlastRadius -- capability graph attack path analysis.
//!
//! "If domain X is compromised, what can be reached?"
//! BFS through the capability delegation graph to compute
//! direct reach, transitive reach, and risk score.

use crate::types::SoType;

const MAX_DOMAINS: usize = 64;
const MAX_CAPS_PER_DOMAIN: usize = 64;
const MAX_DIRECT: usize = 128;
const MAX_TRANSITIVE: usize = 256;
const MAX_CRITICAL: usize = 16;

/// A single capability entry in the adjacency list.
#[derive(Clone, Copy)]
pub struct CapEntry {
    pub so_id: u64,
    pub so_type: u8,
    pub rights: u32,
    /// Domain IDs this cap was delegated to.
    pub delegated_to: [u32; 4],
    pub delegation_count: usize,
}

impl CapEntry {
    pub const fn empty() -> Self {
        Self {
            so_id: 0,
            so_type: 0,
            rights: 0,
            delegated_to: [0; 4],
            delegation_count: 0,
        }
    }
}

/// All capabilities held by a single domain.
#[derive(Clone)]
pub struct DomainCaps {
    pub domain_id: u32,
    pub caps: [CapEntry; MAX_CAPS_PER_DOMAIN],
    pub cap_count: usize,
}

impl DomainCaps {
    pub const fn empty() -> Self {
        Self {
            domain_id: 0,
            caps: [CapEntry::empty(); MAX_CAPS_PER_DOMAIN],
            cap_count: 0,
        }
    }
}

/// Result of blast radius analysis for a single domain.
pub struct BlastReport {
    /// Domain that was analyzed.
    pub domain_id: u32,
    /// SOs directly reachable (held by this domain).
    pub direct_reach: [u64; MAX_DIRECT],
    pub direct_count: usize,
    /// SOs transitively reachable via delegation chains.
    pub transitive_reach: [u64; MAX_TRANSITIVE],
    pub transitive_count: usize,
    /// Risk score 0-100.
    pub risk_score: u8,
    /// Critical assets within the blast radius.
    pub critical_assets: [u64; MAX_CRITICAL],
    pub critical_count: usize,
}

impl BlastReport {
    fn new(domain_id: u32) -> Self {
        Self {
            domain_id,
            direct_reach: [0; MAX_DIRECT],
            direct_count: 0,
            transitive_reach: [0; MAX_TRANSITIVE],
            transitive_count: 0,
            risk_score: 0,
            critical_assets: [0; MAX_CRITICAL],
            critical_count: 0,
        }
    }

    fn add_direct(&mut self, so_id: u64) {
        insert_unique(&mut self.direct_reach, &mut self.direct_count, so_id);
    }

    fn add_transitive(&mut self, so_id: u64) {
        insert_unique(&mut self.transitive_reach, &mut self.transitive_count, so_id);
    }

    fn add_critical(&mut self, so_id: u64) {
        insert_unique(&mut self.critical_assets, &mut self.critical_count, so_id);
    }
}

/// Diff between two blast reports (e.g., before/after a policy change).
pub struct BlastDelta {
    /// SOs newly reachable (in `after` but not `before`).
    pub added: [u64; MAX_TRANSITIVE],
    pub added_count: usize,
    /// SOs no longer reachable (in `before` but not `after`).
    pub removed: [u64; MAX_TRANSITIVE],
    pub removed_count: usize,
    /// Risk score change (positive = worse).
    pub risk_delta: i16,
}

/// Append `value` to `arr[..count]` if not already present and capacity remains.
fn insert_unique(arr: &mut [u64], count: &mut usize, value: u64) {
    if *count < arr.len() && !arr[..*count].iter().any(|&v| v == value) {
        arr[*count] = value;
        *count += 1;
    }
}

// ---- BlastRadius engine ----

/// Capability graph attack path analyzer.
pub struct BlastRadius {
    cap_graph: [Option<DomainCaps>; MAX_DOMAINS],
    domain_count: usize,
}

impl BlastRadius {
    pub const fn new() -> Self {
        const NONE: Option<DomainCaps> = None;
        Self {
            cap_graph: [NONE; MAX_DOMAINS],
            domain_count: 0,
        }
    }

    /// Update (or insert) the capability snapshot for a domain.
    pub fn update_caps(&mut self, domain_id: u32, caps: &[CapEntry]) {
        // Find existing slot index, or first empty slot index.
        let mut idx = None;
        let mut is_new = false;
        let mut first_empty = None;

        for (i, slot) in self.cap_graph.iter().enumerate() {
            match slot {
                Some(dc) if dc.domain_id == domain_id => { idx = Some(i); break; }
                None if first_empty.is_none() => { first_empty = Some(i); }
                _ => {}
            }
        }
        if idx.is_none() {
            idx = first_empty;
            is_new = true;
        }

        if let Some(i) = idx {
            let mut dc = DomainCaps::empty();
            dc.domain_id = domain_id;
            let n = caps.len().min(MAX_CAPS_PER_DOMAIN);
            dc.caps[..n].copy_from_slice(&caps[..n]);
            dc.cap_count = n;
            self.cap_graph[i] = Some(dc);
            if is_new {
                self.domain_count += 1;
            }
        }
    }

    /// Analyze blast radius for a given domain via BFS through delegation chains.
    pub fn analyze(&self, domain_id: u32) -> BlastReport {
        let mut report = BlastReport::new(domain_id);

        // BFS queue: domain IDs to visit.
        let mut queue = [0u32; MAX_DOMAINS];
        let mut q_head = 0usize;
        let mut q_tail = 0usize;
        let mut visited = [false; MAX_DOMAINS];

        // Seed with the starting domain.
        if let Some(start_idx) = self.domain_index(domain_id) {
            queue[q_tail] = domain_id;
            q_tail += 1;
            visited[start_idx] = true;

            while q_head < q_tail {
                let current = queue[q_head];
                q_head += 1;

                let is_direct = current == domain_id;

                if let Some(dc) = self.domain_caps(current) {
                    for i in 0..dc.cap_count {
                        let cap = &dc.caps[i];

                        // Record SO in appropriate reach set.
                        if is_direct {
                            report.add_direct(cap.so_id);
                        }
                        report.add_transitive(cap.so_id);

                        // Check if critical.
                        if let Some(st) = SoType::from_u8(cap.so_type) {
                            if st.is_critical() {
                                report.add_critical(cap.so_id);
                            }
                        }

                        // Enqueue delegated-to domains for traversal.
                        for d in 0..cap.delegation_count {
                            let target = cap.delegated_to[d];
                            if let Some(tidx) = self.domain_index(target) {
                                if !visited[tidx] && q_tail < MAX_DOMAINS {
                                    visited[tidx] = true;
                                    queue[q_tail] = target;
                                    q_tail += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        report.risk_score = Self::risk_score(&report);
        report
    }

    /// Compute risk score (0-100) based on reachable asset counts and types.
    pub fn risk_score(report: &BlastReport) -> u8 {
        let mut score: u32 = 0;

        // Base score from transitive reach breadth.
        score += (report.transitive_count as u32).min(40);

        // Critical assets weigh heavily.
        score += (report.critical_count as u32) * 15;

        // Direct reach adds a smaller component.
        score += (report.direct_count as u32).min(10);

        if score > 100 {
            100
        } else {
            score as u8
        }
    }

    /// Compare two reports and produce a delta showing what changed.
    pub fn compare(before: &BlastReport, after: &BlastReport) -> BlastDelta {
        let mut delta = BlastDelta {
            added: [0; MAX_TRANSITIVE],
            added_count: 0,
            removed: [0; MAX_TRANSITIVE],
            removed_count: 0,
            risk_delta: after.risk_score as i16 - before.risk_score as i16,
        };

        // Added: in after.transitive but not in before.transitive.
        for i in 0..after.transitive_count {
            let so = after.transitive_reach[i];
            let in_before = before.transitive_reach[..before.transitive_count]
                .iter()
                .any(|&id| id == so);
            if !in_before && delta.added_count < MAX_TRANSITIVE {
                delta.added[delta.added_count] = so;
                delta.added_count += 1;
            }
        }

        // Removed: in before.transitive but not in after.transitive.
        for i in 0..before.transitive_count {
            let so = before.transitive_reach[i];
            let in_after = after.transitive_reach[..after.transitive_count]
                .iter()
                .any(|&id| id == so);
            if !in_after && delta.removed_count < MAX_TRANSITIVE {
                delta.removed[delta.removed_count] = so;
                delta.removed_count += 1;
            }
        }

        delta
    }

    /// Find the slot index for a domain ID.
    fn domain_index(&self, domain_id: u32) -> Option<usize> {
        for (i, slot) in self.cap_graph.iter().enumerate() {
            if let Some(ref dc) = slot {
                if dc.domain_id == domain_id {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Get immutable domain caps by ID.
    fn domain_caps(&self, domain_id: u32) -> Option<&DomainCaps> {
        self.domain_index(domain_id)
            .and_then(|i| self.cap_graph[i].as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SoType;

    #[test]
    fn test_direct_reach() {
        let mut br = BlastRadius::new();
        let caps = [
            CapEntry {
                so_id: 10,
                so_type: SoType::File as u8,
                rights: 0x3,
                delegated_to: [0; 4],
                delegation_count: 0,
            },
            CapEntry {
                so_id: 20,
                so_type: SoType::Socket as u8,
                rights: 0x1,
                delegated_to: [0; 4],
                delegation_count: 0,
            },
        ];
        br.update_caps(1, &caps);

        let report = br.analyze(1);
        assert_eq!(report.direct_count, 2);
        assert_eq!(report.transitive_count, 2);
        assert_eq!(report.critical_count, 0);
    }

    #[test]
    fn test_transitive_reach_via_delegation() {
        let mut br = BlastRadius::new();

        // Domain 1 holds cap to SO 10, delegated to domain 2.
        let caps1 = [CapEntry {
            so_id: 10,
            so_type: SoType::File as u8,
            rights: 0x3,
            delegated_to: [2, 0, 0, 0],
            delegation_count: 1,
        }];
        br.update_caps(1, &caps1);

        // Domain 2 holds cap to SO 20 (a credential), delegated to domain 3.
        let caps2 = [CapEntry {
            so_id: 20,
            so_type: SoType::Credential as u8,
            rights: 0x1,
            delegated_to: [3, 0, 0, 0],
            delegation_count: 1,
        }];
        br.update_caps(2, &caps2);

        // Domain 3 holds cap to SO 30.
        let caps3 = [CapEntry {
            so_id: 30,
            so_type: SoType::File as u8,
            rights: 0x1,
            delegated_to: [0; 4],
            delegation_count: 0,
        }];
        br.update_caps(3, &caps3);

        let report = br.analyze(1);

        // Direct: only SO 10.
        assert_eq!(report.direct_count, 1);
        assert_eq!(report.direct_reach[0], 10);

        // Transitive: SOs 10, 20, 30 (BFS through 1->2->3).
        assert_eq!(report.transitive_count, 3);

        // Critical: SO 20 is a Credential.
        assert_eq!(report.critical_count, 1);
        assert_eq!(report.critical_assets[0], 20);

        // Risk should be >0 due to critical asset.
        assert!(report.risk_score > 0);
    }

    #[test]
    fn test_risk_score_scaling() {
        let mut report = BlastReport::new(1);
        // No reach = zero risk.
        assert_eq!(BlastRadius::risk_score(&report), 0);

        // Add some transitive reach.
        for i in 0..10 {
            report.add_transitive(i as u64);
        }
        let s1 = BlastRadius::risk_score(&report);

        // Add a critical asset -- score should jump.
        report.add_critical(100);
        report.critical_count = 1;
        let s2 = BlastRadius::risk_score(&report);
        assert!(s2 > s1);
    }

    #[test]
    fn test_compare_delta() {
        let mut before = BlastReport::new(1);
        before.add_transitive(10);
        before.add_transitive(20);
        before.risk_score = 20;

        let mut after = BlastReport::new(1);
        after.add_transitive(20);
        after.add_transitive(30);
        after.risk_score = 25;

        let delta = BlastRadius::compare(&before, &after);
        // SO 30 was added.
        assert_eq!(delta.added_count, 1);
        assert_eq!(delta.added[0], 30);
        // SO 10 was removed.
        assert_eq!(delta.removed_count, 1);
        assert_eq!(delta.removed[0], 10);
        // Risk went up by 5.
        assert_eq!(delta.risk_delta, 5);
    }

    #[test]
    fn test_update_caps_replaces() {
        let mut br = BlastRadius::new();
        let caps_v1 = [CapEntry {
            so_id: 10,
            so_type: SoType::File as u8,
            rights: 0x3,
            delegated_to: [0; 4],
            delegation_count: 0,
        }];
        br.update_caps(1, &caps_v1);

        // Replace with different caps.
        let caps_v2 = [
            CapEntry {
                so_id: 50,
                so_type: SoType::Socket as u8,
                rights: 0x1,
                delegated_to: [0; 4],
                delegation_count: 0,
            },
            CapEntry {
                so_id: 60,
                so_type: SoType::Credential as u8,
                rights: 0x7,
                delegated_to: [0; 4],
                delegation_count: 0,
            },
        ];
        br.update_caps(1, &caps_v2);

        let report = br.analyze(1);
        assert_eq!(report.direct_count, 2);
        // SO 10 should be gone, SO 50 and 60 present.
        assert!(report.direct_reach[..2].contains(&50));
        assert!(report.direct_reach[..2].contains(&60));
    }

    #[test]
    fn test_empty_domain() {
        let br = BlastRadius::new();
        let report = br.analyze(999);
        assert_eq!(report.direct_count, 0);
        assert_eq!(report.transitive_count, 0);
        assert_eq!(report.risk_score, 0);
    }
}
