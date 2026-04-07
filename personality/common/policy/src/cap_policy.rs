use alloc::vec::Vec;

/// Constraints on capability delegation.
#[derive(Debug, Clone)]
pub struct CapPolicy {
    /// Maximum number of times a capability may be re-delegated.
    pub max_depth: u32,
    /// Domains that are permitted to receive delegated capabilities.
    /// An empty list means *no* domains are allowed (closed by default).
    pub allowed_targets: Vec<u32>,
    /// Optional expiry epoch. `None` means the capability never expires.
    pub expiry_epoch: Option<u64>,
}

/// Result of checking a delegation request against a `CapPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapDecision {
    Allowed,
    DeniedDepthExceeded,
    DeniedTargetNotAllowed,
    DeniedExpired,
}

impl CapPolicy {
    /// Create a fully-open policy (useful for tests).
    pub fn allow_all() -> Self {
        Self {
            max_depth: u32::MAX,
            allowed_targets: Vec::new(),
            expiry_epoch: None,
        }
    }

    /// Evaluate whether a delegation request is permitted.
    ///
    /// - `current_depth`: how many times the cap has already been delegated.
    /// - `target_domain`: the domain that would receive the delegated cap.
    /// - `now_epoch`: current timestamp for expiry checks.
    pub fn check(
        &self,
        current_depth: u32,
        target_domain: u32,
        now_epoch: u64,
    ) -> CapDecision {
        if let Some(expiry) = self.expiry_epoch {
            if now_epoch >= expiry {
                return CapDecision::DeniedExpired;
            }
        }
        if current_depth >= self.max_depth {
            return CapDecision::DeniedDepthExceeded;
        }
        if !self.allowed_targets.is_empty()
            && !self.allowed_targets.contains(&target_domain)
        {
            return CapDecision::DeniedTargetNotAllowed;
        }
        CapDecision::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_exceeded() {
        let policy = CapPolicy {
            max_depth: 2,
            allowed_targets: Vec::new(),
            expiry_epoch: None,
        };
        assert_eq!(policy.check(2, 1, 0), CapDecision::DeniedDepthExceeded);
        assert_eq!(policy.check(1, 1, 0), CapDecision::Allowed);
    }

    #[test]
    fn target_not_allowed() {
        let policy = CapPolicy {
            max_depth: 10,
            allowed_targets: alloc::vec![1, 2, 3],
            expiry_epoch: None,
        };
        assert_eq!(policy.check(0, 2, 0), CapDecision::Allowed);
        assert_eq!(policy.check(0, 99, 0), CapDecision::DeniedTargetNotAllowed);
    }

    #[test]
    fn expired() {
        let policy = CapPolicy {
            max_depth: 10,
            allowed_targets: Vec::new(),
            expiry_epoch: Some(1000),
        };
        assert_eq!(policy.check(0, 1, 999), CapDecision::Allowed);
        assert_eq!(policy.check(0, 1, 1000), CapDecision::DeniedExpired);
    }
}
