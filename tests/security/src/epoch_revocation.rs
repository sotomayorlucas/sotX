//! Epoch-based revocation tests.
//!
//! These tests verify that revoking a capability invalidates it and all
//! its descendants, and that revoked capabilities cannot be used.

#[cfg(test)]
mod tests {
    use crate::{MockCap, MockCapTable};

    /// Verify that a revoked capability is rejected.
    ///
    /// Scenario: Create cap, revoke via epoch bump, attempt to use.
    /// Expected: Validation returns StaleCap.
    #[test]
    fn revoked_cap_is_rejected() {
        let mut table = MockCapTable::new();
        table.insert(MockCap::root(1));
        assert!(table.validate(1, MockCap::READ).is_ok());
        table.revoke();
        assert_eq!(table.validate(1, MockCap::READ), Err("StaleCap"));
    }

    /// Verify that descendants of a revoked cap are also invalid.
    ///
    /// Scenario: Create root cap, derive child, derive grandchild.
    /// Revoke root. All three should be stale.
    #[test]
    fn revocation_invalidates_descendants() {
        let mut table = MockCapTable::new();
        let root = MockCap::root(1);
        let child = root.derive(2, MockCap::READ | MockCap::GRANT);
        let grandchild = child.derive(3, MockCap::READ);

        table.insert(root);
        table.insert(child);
        table.insert(grandchild);

        // All valid before revocation
        assert!(table.validate(1, MockCap::READ).is_ok());
        assert!(table.validate(2, MockCap::READ).is_ok());
        assert!(table.validate(3, MockCap::READ).is_ok());

        // Revoke (epoch bump)
        table.revoke();

        // All stale after revocation
        assert_eq!(table.validate(1, MockCap::READ), Err("StaleCap"));
        assert_eq!(table.validate(2, MockCap::READ), Err("StaleCap"));
        assert_eq!(table.validate(3, MockCap::READ), Err("StaleCap"));
    }

    /// Verify that revocation is O(1) regardless of descendant count.
    ///
    /// Scenario: Create 1000 descendants from a root cap. Revoke root.
    /// Expected: Revocation completes in bounded time (epoch bump is
    /// a single atomic increment).
    #[test]
    fn revocation_is_constant_time() {
        let mut table = MockCapTable::new();
        let root = MockCap::root(0);
        table.insert(root);

        // Create many descendants
        for i in 1..=1000 {
            let child = root.derive(i, MockCap::READ);
            table.insert(child);
        }

        // Revocation is a single epoch bump
        let start = std::time::Instant::now();
        table.revoke();
        let elapsed = start.elapsed();

        // Should be well under 1ms (it is a single integer increment)
        assert!(
            elapsed.as_micros() < 1000,
            "revocation took {:?}, expected < 1ms",
            elapsed
        );

        // Verify all caps are stale
        for i in 0..=1000 {
            assert_eq!(table.validate(i, MockCap::READ), Err("StaleCap"));
        }
    }

    /// Verify that caps created after revocation are valid.
    ///
    /// Scenario: Revoke (epoch bump to 1). Create new cap with epoch 1.
    /// Expected: The new cap is valid; only old caps are stale.
    #[test]
    fn new_caps_after_revocation_are_valid() {
        let mut table = MockCapTable::new();
        table.insert(MockCap::root(1));
        table.revoke(); // epoch = 1

        // Old cap (epoch 0) is stale
        assert_eq!(table.validate(1, MockCap::READ), Err("StaleCap"));

        // New cap with current epoch
        let new_cap = MockCap {
            id: 2,
            rights: MockCap::ALL,
            epoch: 1, // matches current object epoch
            parent_id: None,
        };
        table.insert(new_cap);
        assert!(table.validate(2, MockCap::READ).is_ok());
    }

    /// Verify that the use-after-revoke race is handled.
    ///
    /// Scenario: Thread A validates cap (gets Ok), thread B revokes,
    /// thread A uses the previously-validated cap.
    /// Expected: In the real kernel, the operation checks epoch again
    /// at commit time. In this mock, we verify the epoch check catches it.
    #[test]
    fn use_after_revoke_detected() {
        let mut table = MockCapTable::new();
        table.insert(MockCap::root(1));

        // Thread A validates (succeeds)
        assert!(table.validate(1, MockCap::READ).is_ok());

        // Thread B revokes between validate and use
        table.revoke();

        // Thread A's second validation (at use time) fails
        assert_eq!(table.validate(1, MockCap::READ), Err("StaleCap"));
    }
}
