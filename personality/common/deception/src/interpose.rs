//! Capability interposition engine for deception environments.
//!
//! When a domain is migrated into deception, its capabilities are
//! "interposed" — the original capability is replaced by a wrapper
//! that routes operations through the deception profile, returning
//! fake data or silently logging the access.

/// Maximum interposition rules that can be active at once.
pub const MAX_RULES: usize = 128;

/// What to do when an interposed capability is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpositionAction {
    /// Return fake data defined by the deception profile.
    FakeResponse,
    /// Allow the operation but log it for forensics.
    PassthroughAndLog,
    /// Deny the operation with an error code.
    Deny { error_code: u32 },
    /// Delay the operation (simulate slow I/O to waste attacker time).
    Delay { ticks: u64 },
    /// Return success with empty/zeroed data.
    EmptySuccess,
}

/// A single interposition rule mapping a capability to a deception action.
#[derive(Clone, Copy)]
pub struct InterpositionRule {
    /// The original capability ID being interposed.
    pub cap_id: u32,
    /// Domain this rule applies to.
    pub domain_id: u32,
    /// What to do when this cap is used.
    pub action: InterpositionAction,
    /// Whether this rule is currently active.
    pub active: bool,
    /// Snapshot ID for rollback (links to migration).
    pub snapshot_id: u64,
    /// Number of times this rule has been triggered.
    pub hit_count: u64,
}

impl InterpositionRule {
    pub const fn empty() -> Self {
        Self {
            cap_id: 0,
            domain_id: 0,
            action: InterpositionAction::EmptySuccess,
            active: false,
            snapshot_id: 0,
            hit_count: 0,
        }
    }
}

/// Manages the set of active interposition rules.
pub struct InterpositionEngine {
    rules: [InterpositionRule; MAX_RULES],
    count: usize,
}

impl InterpositionEngine {
    pub const fn new() -> Self {
        Self {
            rules: [InterpositionRule::empty(); MAX_RULES],
            count: 0,
        }
    }

    /// Add an interposition rule. Returns the rule index, or `None` if full.
    pub fn add_rule(
        &mut self,
        cap_id: u32,
        domain_id: u32,
        action: InterpositionAction,
        snapshot_id: u64,
    ) -> Option<usize> {
        if self.count >= MAX_RULES {
            return None;
        }
        let idx = self.count;
        self.rules[idx] = InterpositionRule {
            cap_id,
            domain_id,
            action,
            active: true,
            snapshot_id,
            hit_count: 0,
        };
        self.count += 1;
        Some(idx)
    }

    /// Look up the interposition action for a (domain, cap) pair.
    /// Returns `None` if no active rule matches.
    pub fn lookup(&self, domain_id: u32, cap_id: u32) -> Option<&InterpositionRule> {
        for i in 0..self.count {
            let r = &self.rules[i];
            if r.active && r.domain_id == domain_id && r.cap_id == cap_id {
                return Some(r);
            }
        }
        None
    }

    /// Record a hit on a rule (capability was invoked while interposed).
    pub fn record_hit(&mut self, domain_id: u32, cap_id: u32) {
        for i in 0..self.count {
            let r = &mut self.rules[i];
            if r.active && r.domain_id == domain_id && r.cap_id == cap_id {
                r.hit_count += 1;
                return;
            }
        }
    }

    /// Lookup and record a hit in a single pass. Returns the action if found.
    pub fn lookup_and_hit(&mut self, domain_id: u32, cap_id: u32) -> Option<InterpositionAction> {
        for i in 0..self.count {
            let r = &mut self.rules[i];
            if r.active && r.domain_id == domain_id && r.cap_id == cap_id {
                r.hit_count += 1;
                return Some(r.action);
            }
        }
        None
    }

    /// Remove all rules for a domain (used during rollback).
    /// Returns the number of rules removed.
    pub fn remove_domain_rules(&mut self, domain_id: u32) -> u32 {
        let mut removed = 0u32;
        for i in 0..self.count {
            if self.rules[i].domain_id == domain_id && self.rules[i].active {
                self.rules[i].active = false;
                removed += 1;
            }
        }
        removed
    }

    /// Count active rules for a domain.
    pub fn active_rules_for(&self, domain_id: u32) -> u32 {
        let mut n = 0u32;
        for i in 0..self.count {
            if self.rules[i].active && self.rules[i].domain_id == domain_id {
                n += 1;
            }
        }
        n
    }

    /// Total number of hits across all rules for a domain.
    pub fn total_hits_for(&self, domain_id: u32) -> u64 {
        let mut total = 0u64;
        for i in 0..self.count {
            if self.rules[i].domain_id == domain_id {
                total += self.rules[i].hit_count;
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_lookup() {
        let mut engine = InterpositionEngine::new();
        engine
            .add_rule(42, 1, InterpositionAction::FakeResponse, 100)
            .unwrap();
        let rule = engine.lookup(1, 42).unwrap();
        assert_eq!(rule.cap_id, 42);
        assert_eq!(rule.action, InterpositionAction::FakeResponse);
        assert!(engine.lookup(1, 99).is_none());
        assert!(engine.lookup(2, 42).is_none());
    }

    #[test]
    fn remove_domain_rules() {
        let mut engine = InterpositionEngine::new();
        engine
            .add_rule(1, 10, InterpositionAction::FakeResponse, 0)
            .unwrap();
        engine
            .add_rule(2, 10, InterpositionAction::PassthroughAndLog, 0)
            .unwrap();
        engine
            .add_rule(3, 20, InterpositionAction::FakeResponse, 0)
            .unwrap();

        let removed = engine.remove_domain_rules(10);
        assert_eq!(removed, 2);
        assert_eq!(engine.active_rules_for(10), 0);
        assert_eq!(engine.active_rules_for(20), 1);
    }

    #[test]
    fn hit_counting() {
        let mut engine = InterpositionEngine::new();
        engine
            .add_rule(5, 1, InterpositionAction::EmptySuccess, 0)
            .unwrap();
        engine.record_hit(1, 5);
        engine.record_hit(1, 5);
        engine.record_hit(1, 5);
        assert_eq!(engine.total_hits_for(1), 3);
    }
}
