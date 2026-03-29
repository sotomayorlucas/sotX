//! SecureObject trait — the core abstraction for every kernel-managed resource.
//!
//! Every resource (memory, file, channel, domain, device) is accessed
//! exclusively through this interface in the SOT exokernel.

use crate::cap::{CapObject, Rights};

use super::types::{Policy, SOId, SOType, SOVersion};

/// The core trait implemented by every kernel-managed object in the SOT exokernel.
pub trait SecureObject {
    /// Unique identifier for this object.
    fn id(&self) -> SOId;
    /// The type discriminant.
    fn type_of(&self) -> SOType;
    /// Security policy governing delegation and audit.
    fn policy(&self) -> Policy;
    /// Monotonic version counter (incremented on mutation).
    fn version(&self) -> SOVersion;
}

/// Adapter that wraps an existing `CapObject` and implements `SecureObject`.
///
/// This bridges the current capability system to the new SOT type system,
/// mapping each `CapObject` variant to the appropriate `SOType`.
pub struct CapObjectAdapter {
    inner: CapObject,
    id: SOId,
    version: SOVersion,
    policy: Policy,
}

impl CapObjectAdapter {
    /// Wrap a `CapObject` with a given id and default policy.
    pub fn new(inner: CapObject, id: SOId) -> Self {
        Self {
            inner,
            id,
            version: SOVersion(0),
            policy: Policy {
                max_rights: Rights::ALL.raw(),
                interposable: false,
                audited: false,
                owner_domain: 0, // kernel
            },
        }
    }

    /// Wrap with explicit policy and version.
    pub fn with_policy(inner: CapObject, id: SOId, policy: Policy, version: SOVersion) -> Self {
        Self {
            inner,
            id,
            version,
            policy,
        }
    }

    /// Return the underlying `CapObject`.
    pub fn inner(&self) -> &CapObject {
        &self.inner
    }

    /// Map a `CapObject` variant to its `SOType`.
    fn map_type(obj: &CapObject) -> SOType {
        match obj {
            CapObject::Memory { .. } => SOType::Memory,
            CapObject::Endpoint { .. } => SOType::Endpoint,
            CapObject::Channel { .. } => SOType::Channel,
            CapObject::Thread { .. } => SOType::Thread,
            CapObject::Irq { .. } => SOType::Irq,
            CapObject::IoPort { .. } => SOType::IoPort,
            CapObject::Notification { .. } => SOType::Notification,
            CapObject::Domain { .. } => SOType::Domain,
            CapObject::AddrSpace { .. } => SOType::AddrSpace,
            CapObject::Null => SOType::Capability, // Null slot maps to Capability type
        }
    }
}

impl SecureObject for CapObjectAdapter {
    fn id(&self) -> SOId {
        self.id
    }

    fn type_of(&self) -> SOType {
        Self::map_type(&self.inner)
    }

    fn policy(&self) -> Policy {
        self.policy
    }

    fn version(&self) -> SOVersion {
        self.version
    }
}
