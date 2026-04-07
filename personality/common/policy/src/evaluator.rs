use alloc::vec::Vec;

use crate::zt_policy::{PolicyAction, ZtRule};

/// The result of evaluating a policy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub audit_required: bool,
    pub matched_rule_id: Option<u32>,
}

/// Evaluates a (domain, so_type, operation) triple against an ordered rule set.
///
/// Semantics: first-match wins, default-deny.
pub struct PolicyEvaluator {
    rules: Vec<ZtRule>,
}

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Append a rule. Rules are evaluated in insertion order.
    pub fn add_rule(&mut self, rule: ZtRule) {
        self.rules.push(rule);
    }

    /// Evaluate the triple and return a decision.
    pub fn evaluate(&self, domain_id: u32, so_type: u8, operation: u16) -> PolicyDecision {
        for rule in &self.rules {
            if rule.matches(domain_id, so_type, operation) {
                return PolicyDecision {
                    action: rule.action,
                    audit_required: matches!(
                        rule.action,
                        PolicyAction::Audit | PolicyAction::MigrateToDeception
                    ),
                    matched_rule_id: Some(rule.rule_id),
                };
            }
        }
        // Default deny.
        PolicyDecision {
            action: PolicyAction::Deny,
            audit_required: true,
            matched_rule_id: None,
        }
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_match_wins() {
        let mut eval = PolicyEvaluator::new();
        eval.add_rule(ZtRule {
            source_domain: Some(10),
            target_so_type: None,
            operation: None,
            action: PolicyAction::Allow,
            rule_id: 1,
        });
        eval.add_rule(ZtRule {
            source_domain: None,
            target_so_type: None,
            operation: None,
            action: PolicyAction::Deny,
            rule_id: 2,
        });

        let d = eval.evaluate(10, 0, 0);
        assert_eq!(d.action, PolicyAction::Allow);
        assert_eq!(d.matched_rule_id, Some(1));
    }

    #[test]
    fn default_deny() {
        let eval = PolicyEvaluator::new();
        let d = eval.evaluate(1, 2, 3);
        assert_eq!(d.action, PolicyAction::Deny);
        assert!(d.audit_required);
        assert_eq!(d.matched_rule_id, None);
    }

    #[test]
    fn audit_action_sets_audit_flag() {
        let mut eval = PolicyEvaluator::new();
        eval.add_rule(ZtRule {
            source_domain: None,
            target_so_type: None,
            operation: None,
            action: PolicyAction::Audit,
            rule_id: 5,
        });
        let d = eval.evaluate(1, 2, 3);
        assert_eq!(d.action, PolicyAction::Audit);
        assert!(d.audit_required);
    }

    #[test]
    fn deception_sets_audit_flag() {
        let mut eval = PolicyEvaluator::new();
        eval.add_rule(ZtRule {
            source_domain: None,
            target_so_type: None,
            operation: None,
            action: PolicyAction::MigrateToDeception,
            rule_id: 6,
        });
        let d = eval.evaluate(1, 2, 3);
        assert!(d.audit_required);
    }
}
