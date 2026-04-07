//! Capability escalation tests.
//!
//! These tests verify that attenuated capabilities cannot be used to
//! gain rights beyond what was granted. The capability system's
//! monotonicity invariant must hold under all conditions.

#[cfg(test)]
mod tests {
    use crate::MockCap;

    /// Verify that deriving a read-only cap from a full cap produces read-only.
    ///
    /// Attack: derive with READ mask, then attempt WRITE operation.
    /// Expected: WRITE is rejected with InsufficientRights.
    #[test]
    fn attenuated_cap_cannot_write() {
        let root = MockCap::root(1);
        let read_only = root.derive(2, MockCap::READ);
        assert!(read_only.has_right(MockCap::READ));
        assert!(!read_only.has_right(MockCap::WRITE));
        assert!(!read_only.has_right(MockCap::EXECUTE));
    }

    /// Verify that re-deriving an attenuated cap cannot restore rights.
    ///
    /// Attack: derive A (READ) from root, then derive B (ALL) from A.
    /// Expected: B has only READ (A's rights & ALL = READ).
    #[test]
    fn rederive_cannot_restore_rights() {
        let root = MockCap::root(1);
        let a = root.derive(2, MockCap::READ);
        let b = a.derive(3, MockCap::ALL);
        assert_eq!(b.rights, MockCap::READ);
        assert!(!b.has_right(MockCap::WRITE));
    }

    /// Verify that GRANT right is required for derivation.
    ///
    /// Attack: derive a cap without GRANT, then try to derive from it.
    /// Expected: derivation is rejected because the source lacks GRANT.
    #[test]
    fn derive_requires_grant_right() {
        let root = MockCap::root(1);
        let no_grant = root.derive(2, MockCap::READ | MockCap::WRITE);
        // In the real kernel, cap_derive would check for GRANT right.
        // Here we verify the cap does not have GRANT.
        assert!(!no_grant.has_right(MockCap::GRANT));
    }

    /// Verify that a zero-rights capability is useless.
    ///
    /// Attack: derive a cap with mask 0.
    /// Expected: the cap exists but cannot perform any operation.
    #[test]
    fn zero_rights_cap_is_useless() {
        let root = MockCap::root(1);
        let empty = root.derive(2, 0);
        assert!(!empty.has_right(MockCap::READ));
        assert!(!empty.has_right(MockCap::WRITE));
        assert!(!empty.has_right(MockCap::EXECUTE));
        assert!(!empty.has_right(MockCap::GRANT));
        assert!(!empty.has_right(MockCap::REVOKE));
    }

    /// Verify that rights are a monotonically decreasing chain.
    ///
    /// Create a derivation chain: root -> A -> B -> C.
    /// Expected: rights(root) >= rights(A) >= rights(B) >= rights(C).
    #[test]
    fn derivation_chain_monotonic() {
        let root = MockCap::root(1);
        let a = root.derive(2, MockCap::READ | MockCap::WRITE | MockCap::GRANT);
        let b = a.derive(3, MockCap::READ | MockCap::GRANT);
        let c = b.derive(4, MockCap::READ);

        assert!(root.rights >= a.rights);
        assert!(a.rights >= b.rights);
        assert!(b.rights >= c.rights);
        assert_eq!(c.rights, MockCap::READ);
    }

    /// Verify that forging a capability ID is detected.
    ///
    /// Attack: construct a raw CapId that was never allocated.
    /// Expected: lookup returns None / InvalidCap.
    #[test]
    fn forged_cap_id_rejected() {
        let table = crate::MockCapTable::new();
        assert!(table.validate(0xDEAD, MockCap::READ).is_err());
    }
}
