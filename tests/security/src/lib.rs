//! Security tests for sotX.
//!
//! These tests attempt to violate the kernel's security invariants.
//! Every test in this suite SHOULD FAIL to exploit the system. A passing
//! test means the attack was correctly blocked by the kernel.

mod cap_escalation;
mod domain_escape;
mod rollback;
mod epoch_revocation;

// ---------------------------------------------------------------------------
// Security test helpers
// ---------------------------------------------------------------------------

/// Simulated capability for security testing.
#[derive(Debug, Clone, Copy)]
pub struct MockCap {
    pub id: u32,
    pub rights: u32,
    pub epoch: u32,
    pub parent_id: Option<u32>,
}

impl MockCap {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const GRANT: u32 = 1 << 3;
    pub const REVOKE: u32 = 1 << 4;
    pub const ALL: u32 = 0x1F;

    pub fn root(id: u32) -> Self {
        Self {
            id,
            rights: Self::ALL,
            epoch: 0,
            parent_id: None,
        }
    }

    pub fn derive(&self, new_id: u32, mask: u32) -> Self {
        Self {
            id: new_id,
            rights: self.rights & mask,
            epoch: self.epoch,
            parent_id: Some(self.id),
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }
}

/// Simulated capability table for security tests.
pub struct MockCapTable {
    caps: Vec<MockCap>,
    object_epoch: u32,
}

impl MockCapTable {
    pub fn new() -> Self {
        Self {
            caps: Vec::new(),
            object_epoch: 0,
        }
    }

    pub fn insert(&mut self, cap: MockCap) {
        self.caps.push(cap);
    }

    pub fn lookup(&self, id: u32) -> Option<&MockCap> {
        self.caps.iter().find(|c| c.id == id)
    }

    /// Validate a capability: check it exists and epoch is current.
    pub fn validate(&self, id: u32, required_right: u32) -> Result<(), &'static str> {
        let cap = self.lookup(id).ok_or("InvalidCap")?;
        if cap.epoch < self.object_epoch {
            return Err("StaleCap");
        }
        if !cap.has_right(required_right) {
            return Err("InsufficientRights");
        }
        Ok(())
    }

    /// Revoke: bump object epoch, invalidating all caps with older epochs.
    pub fn revoke(&mut self) {
        self.object_epoch += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_cap_derive_reduces_rights() {
        let root = MockCap::root(1);
        let child = root.derive(2, MockCap::READ);
        assert!(child.has_right(MockCap::READ));
        assert!(!child.has_right(MockCap::WRITE));
    }

    #[test]
    fn mock_cap_table_validates() {
        let mut table = MockCapTable::new();
        table.insert(MockCap::root(1));
        assert!(table.validate(1, MockCap::READ).is_ok());
        assert!(table.validate(99, MockCap::READ).is_err());
    }

    #[test]
    fn mock_cap_table_revocation() {
        let mut table = MockCapTable::new();
        table.insert(MockCap::root(1));
        assert!(table.validate(1, MockCap::READ).is_ok());
        table.revoke();
        assert_eq!(table.validate(1, MockCap::READ), Err("StaleCap"));
    }
}
