//! Capability interposition engine.
//!
//! Every service-object access in sotOS goes through capabilities. The
//! interposition engine sits between a domain's capability invocations and
//! the real service objects, applying one of four policies per capability.

use crate::{DeceptionError, InterceptResult, MAX_INTERPOSITIONS};

/// Policy applied when an interposed capability is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpositionPolicy {
    /// Forward to real SO, log only (~50 cycle overhead).
    Passthrough,
    /// Full IPC to proxy domain -- proxy decides what to do.
    Inspect,
    /// Always route to an alternative service object.
    Redirect,
    /// Proxy generates a synthetic response; real SO is never contacted.
    Fabricate,
}

/// A single interposition rule binding a capability to a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterpositionRule {
    /// The original capability being interposed.
    pub original_cap: u64,
    /// Domain ID of the proxy that handles Inspect/Redirect/Fabricate.
    pub proxy_domain: u32,
    /// Which policy to apply.
    pub policy: InterpositionPolicy,
    /// If true, the engine caches proxy decisions to avoid repeated IPC.
    pub cache_decisions: bool,
}

/// The interposition engine manages all active rules for a domain.
///
/// Fixed-size, no heap allocation for the rule table itself.
pub struct InterpositionEngine {
    rules: [Option<InterpositionRule>; MAX_INTERPOSITIONS],
    count: usize,
}

impl InterpositionEngine {
    /// Create a new engine with no active rules.
    pub const fn new() -> Self {
        Self {
            rules: [None; MAX_INTERPOSITIONS],
            count: 0,
        }
    }

    /// Number of active interposition rules.
    pub fn active_count(&self) -> usize {
        self.count
    }

    /// Add an interposition rule. Returns the slot index on success.
    pub fn add_rule(&mut self, rule: InterpositionRule) -> Result<usize, DeceptionError> {
        for slot in self.rules.iter().flatten() {
            if slot.original_cap == rule.original_cap {
                return Err(DeceptionError::Duplicate);
            }
        }
        for (i, slot) in self.rules.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(rule);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(DeceptionError::TableFull)
    }

    /// Remove the rule at `index`. Returns the removed rule on success.
    pub fn remove_rule(&mut self, index: usize) -> Result<InterpositionRule, DeceptionError> {
        if index >= MAX_INTERPOSITIONS {
            return Err(DeceptionError::NotFound);
        }
        match self.rules[index].take() {
            Some(rule) => {
                self.count -= 1;
                Ok(rule)
            }
            None => Err(DeceptionError::NotFound),
        }
    }

    /// Remove the rule for `cap`. Returns the removed rule on success.
    pub fn remove_rule_for_cap(&mut self, cap: u64) -> Result<InterpositionRule, DeceptionError> {
        for slot in self.rules.iter_mut() {
            if let Some(rule) = slot {
                if rule.original_cap == cap {
                    let removed = *rule;
                    *slot = None;
                    self.count -= 1;
                    return Ok(removed);
                }
            }
        }
        Err(DeceptionError::NotFound)
    }

    /// Check whether `cap` has an interposition rule.
    pub fn is_interposed(&self, cap: u64) -> bool {
        self.rules
            .iter()
            .flatten()
            .any(|r| r.original_cap == cap)
    }

    /// Look up the rule for `cap` and return the appropriate action.
    ///
    /// `_operation` and `_args` are provided for future use by Inspect
    /// policies that may filter on specific operation types.
    pub fn intercept(
        &self,
        cap: u64,
        _operation: u32,
        _args: &[u64],
    ) -> InterceptResult {
        for (i, slot) in self.rules.iter().enumerate() {
            if let Some(rule) = slot {
                if rule.original_cap == cap {
                    return match rule.policy {
                        InterpositionPolicy::Passthrough => {
                            InterceptResult::Passthrough { rule_index: i }
                        }
                        InterpositionPolicy::Inspect => InterceptResult::Inspect {
                            rule_index: i,
                            proxy_domain: rule.proxy_domain,
                        },
                        InterpositionPolicy::Redirect => InterceptResult::Redirect {
                            rule_index: i,
                            proxy_domain: rule.proxy_domain,
                        },
                        InterpositionPolicy::Fabricate => InterceptResult::Fabricate {
                            rule_index: i,
                            proxy_domain: rule.proxy_domain,
                        },
                    };
                }
            }
        }
        InterceptResult::NotInterposed
    }

    /// Get a reference to the rule at `index`, if occupied.
    pub fn get_rule(&self, index: usize) -> Option<&InterpositionRule> {
        if index < MAX_INTERPOSITIONS {
            self.rules[index].as_ref()
        } else {
            None
        }
    }

    /// Iterate over all active rules with their indices.
    pub fn iter_rules(&self) -> impl Iterator<Item = (usize, &InterpositionRule)> {
        self.rules
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|r| (i, r)))
    }

    /// Set all active rules to a given policy (used during migration).
    pub fn set_all_policy(&mut self, policy: InterpositionPolicy) {
        for slot in self.rules.iter_mut().flatten() {
            slot.policy = policy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_intercept() {
        let mut engine = InterpositionEngine::new();
        let rule = InterpositionRule {
            original_cap: 42,
            proxy_domain: 1,
            policy: InterpositionPolicy::Fabricate,
            cache_decisions: false,
        };
        let idx = engine.add_rule(rule).unwrap();
        assert!(engine.is_interposed(42));
        assert!(!engine.is_interposed(99));

        match engine.intercept(42, 0, &[]) {
            InterceptResult::Fabricate {
                rule_index,
                proxy_domain,
            } => {
                assert_eq!(rule_index, idx);
                assert_eq!(proxy_domain, 1);
            }
            other => panic!("expected Fabricate, got {:?}", other),
        }
        assert_eq!(engine.intercept(99, 0, &[]), InterceptResult::NotInterposed);
    }

    #[test]
    fn remove_rule() {
        let mut engine = InterpositionEngine::new();
        let rule = InterpositionRule {
            original_cap: 10,
            proxy_domain: 2,
            policy: InterpositionPolicy::Passthrough,
            cache_decisions: true,
        };
        let idx = engine.add_rule(rule).unwrap();
        assert_eq!(engine.active_count(), 1);
        engine.remove_rule(idx).unwrap();
        assert_eq!(engine.active_count(), 0);
        assert!(!engine.is_interposed(10));
    }

    #[test]
    fn duplicate_rejected() {
        let mut engine = InterpositionEngine::new();
        let rule = InterpositionRule {
            original_cap: 7,
            proxy_domain: 1,
            policy: InterpositionPolicy::Inspect,
            cache_decisions: false,
        };
        engine.add_rule(rule).unwrap();
        assert_eq!(engine.add_rule(rule), Err(DeceptionError::Duplicate));
    }
}
