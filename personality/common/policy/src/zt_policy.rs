/// Action to take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
    Audit,
    MigrateToDeception,
}

/// A single Zero Trust policy rule.
///
/// Each field is optional (`None` = wildcard / match-any).
/// Rules are evaluated in order; first match wins.
#[derive(Debug, Clone)]
pub struct ZtRule {
    /// Restrict to a specific source domain, or `None` for any.
    pub source_domain: Option<u32>,
    /// Restrict to a specific SO type, or `None` for any.
    pub target_so_type: Option<u8>,
    /// Restrict to a specific operation code, or `None` for any.
    pub operation: Option<u16>,
    /// Action to take when this rule matches.
    pub action: PolicyAction,
    /// Unique id for this rule (used in audit / decision reporting).
    pub rule_id: u32,
}

impl ZtRule {
    /// Check whether this rule matches the given request triple.
    pub fn matches(&self, domain_id: u32, so_type: u8, operation: u16) -> bool {
        if let Some(d) = self.source_domain {
            if d != domain_id {
                return false;
            }
        }
        if let Some(t) = self.target_so_type {
            if t != so_type {
                return false;
            }
        }
        if let Some(o) = self.operation {
            if o != operation {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_rule_matches_everything() {
        let rule = ZtRule {
            source_domain: None,
            target_so_type: None,
            operation: None,
            action: PolicyAction::Deny,
            rule_id: 0,
        };
        assert!(rule.matches(1, 2, 3));
        assert!(rule.matches(99, 0, 0));
    }

    #[test]
    fn specific_rule_filters() {
        let rule = ZtRule {
            source_domain: Some(10),
            target_so_type: Some(0),
            operation: None,
            action: PolicyAction::Allow,
            rule_id: 1,
        };
        assert!(rule.matches(10, 0, 999));
        assert!(!rule.matches(11, 0, 999));
        assert!(!rule.matches(10, 1, 999));
    }
}
