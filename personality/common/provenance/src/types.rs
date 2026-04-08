//! Shared types for the provenance subsystem.

/// A single provenance record emitted by the kernel capability layer.
#[derive(Clone, Copy)]
pub struct ProvenanceEntry {
    /// Monotonic epoch counter (kernel tick).
    pub epoch: u64,
    /// Domain that performed the operation.
    pub domain_id: u32,
    /// Operation code (see [`Operation`]).
    pub operation: u16,
    /// Semantic object ID that was acted upon.
    pub so_id: u64,
    /// Semantic object type tag.
    pub so_type: u8,
    /// Rights mask that was exercised.
    pub rights: u32,
    /// Optional second SO (e.g., delegation target, rename dest).
    pub secondary_so: u64,
}

/// Operation codes for provenance entries.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Operation {
    Read = 1,
    Write = 2,
    Execute = 3,
    Create = 4,
    Delete = 5,
    Grant = 6,
    Revoke = 7,
    Send = 8,
    Receive = 9,
    NetworkAccess = 10,
}

impl Operation {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Execute),
            4 => Some(Self::Create),
            5 => Some(Self::Delete),
            6 => Some(Self::Grant),
            7 => Some(Self::Revoke),
            8 => Some(Self::Send),
            9 => Some(Self::Receive),
            10 => Some(Self::NetworkAccess),
            _ => None,
        }
    }
}

/// Semantic object type tags.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SoType {
    File = 1,
    Directory = 2,
    Process = 3,
    Socket = 4,
    Capability = 5,
    SystemBinary = 6,
    Credential = 7,
    ConfigFile = 8,
    NetworkEndpoint = 9,
}

impl SoType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::File),
            2 => Some(Self::Directory),
            3 => Some(Self::Process),
            4 => Some(Self::Socket),
            5 => Some(Self::Capability),
            6 => Some(Self::SystemBinary),
            7 => Some(Self::Credential),
            8 => Some(Self::ConfigFile),
            9 => Some(Self::NetworkEndpoint),
            _ => None,
        }
    }

    /// Whether this type is considered a critical asset for risk scoring.
    pub fn is_critical(self) -> bool {
        matches!(self, Self::Credential | Self::SystemBinary | Self::ConfigFile)
    }
}
