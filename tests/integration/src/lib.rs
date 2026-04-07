//! Integration tests for sotBSD.
//!
//! These tests verify end-to-end behavior: boot sequence, IPC message
//! delivery, domain lifecycle, and service registration. They are
//! host-side test runners that will eventually drive QEMU instances
//! via serial protocol or GDB stub.

mod boot_tests;
mod ipc_tests;
mod domain_tests;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Simulated capability rights for test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestRights(u32);

impl TestRights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);
    pub const REVOKE: Self = Self(1 << 4);
    pub const ALL: Self = Self(0x1F);

    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn attenuate(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }
}

/// Simulated domain state for integration test scaffolding.
#[derive(Debug, Clone)]
pub struct TestDomain {
    pub id: u32,
    pub caps: Vec<(u32, TestRights)>,
    pub quantum_ms: u32,
    pub period_ms: u32,
}

/// Create a test domain with default scheduling parameters.
///
/// Returns a TestDomain with a single root capability (ALL rights)
/// and a 10ms quantum / 100ms period budget.
pub fn setup_test_domain() -> TestDomain {
    TestDomain {
        id: 1,
        caps: vec![(0, TestRights::ALL)],
        quantum_ms: 10,
        period_ms: 100,
    }
}

/// Verify that a capability has the expected rights.
///
/// Panics with a descriptive message if the capability is missing
/// or has insufficient rights.
pub fn verify_cap_rights(domain: &TestDomain, cap_id: u32, expected: TestRights) {
    let found = domain
        .caps
        .iter()
        .find(|(id, _)| *id == cap_id);

    match found {
        Some((_, rights)) => {
            assert!(
                rights.contains(expected),
                "cap {} has rights {:?}, expected {:?}",
                cap_id, rights, expected
            );
        }
        None => {
            panic!("cap {} not found in domain {}", cap_id, domain.id);
        }
    }
}

/// Simulate an IPC message for test purposes.
#[derive(Debug, Clone)]
pub struct TestMessage {
    pub tag: u64,
    pub regs: [u64; 8],
}

impl TestMessage {
    pub fn new(tag: u64) -> Self {
        Self {
            tag,
            regs: [0; 8],
        }
    }
}

/// Verify that a test message was delivered with the expected tag.
pub fn verify_message_delivery(sent: &TestMessage, received: &TestMessage) {
    assert_eq!(
        sent.tag, received.tag,
        "message tag mismatch: sent {}, received {}",
        sent.tag, received.tag
    );
    assert_eq!(
        sent.regs, received.regs,
        "message payload mismatch"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_domain_has_root_cap() {
        let domain = setup_test_domain();
        assert_eq!(domain.caps.len(), 1);
        verify_cap_rights(&domain, 0, TestRights::ALL);
    }

    #[test]
    fn test_rights_attenuation() {
        let full = TestRights::ALL;
        let read_only = full.attenuate(TestRights::READ);
        assert!(read_only.contains(TestRights::READ));
        assert!(!read_only.contains(TestRights::WRITE));
    }

    #[test]
    fn test_message_roundtrip() {
        let msg = TestMessage::new(42);
        let received = msg.clone();
        verify_message_delivery(&msg, &received);
    }
}
