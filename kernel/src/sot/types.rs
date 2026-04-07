//! SOT type system — identifiers, versioning, policy, and operation codes.
//!
//! Every kernel-managed Secure Object carries an SOType, a unique SOId,
//! a monotonic SOVersion, and a Policy controlling delegation and audit.

/// Secure Object type enumeration — every kernel object has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SOType {
    Memory = 0,
    File = 1,
    Channel = 2,
    Domain = 3,
    Device = 4,
    Capability = 5,
    Endpoint = 6,
    Thread = 7,
    Notification = 8,
    Irq = 9,
    IoPort = 10,
    AddrSpace = 11,
}

/// Unique Secure Object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SOId(pub u64);

/// Version counter for tracking mutations (epoch-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SOVersion(pub u64);

/// Security policy attached to every Secure Object.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Maximum rights that can be delegated from this SO.
    pub max_rights: u32,
    /// Whether this SO can be interposed (deception).
    pub interposable: bool,
    /// Whether mutations are logged to provenance.
    pub audited: bool,
    /// Domain ID of the owner (0 = kernel).
    pub owner_domain: u32,
}

/// Operation codes for so_invoke dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SOOperation {
    Read = 0,
    Write = 1,
    Execute = 2,
    Lock = 3,
    Unlock = 4,
    Stat = 5,
    Destroy = 6,
}

impl SOOperation {
    /// Convert from raw u32 (e.g. from syscall argument).
    /// Returns `None` for custom ops (>= 256), which are dispatched by raw value.
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Execute),
            3 => Some(Self::Lock),
            4 => Some(Self::Unlock),
            5 => Some(Self::Stat),
            6 => Some(Self::Destroy),
            _ => None, // custom ops handled separately by dispatch layer
        }
    }

    /// Return the raw u32 discriminant.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}
