//! Capability table implementation.
//!
//! Pool-backed table mapping CapId → (Object, Rights, Parent).
//! The Capability Derivation Tree (CDT) tracks parent-child
//! relationships for O(n) revocation of all derivatives.

use alloc::vec::Vec;
use sotos_common::SysError;

use crate::pool::Pool;

/// Unique capability identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapId(u32);

impl CapId {
    pub fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Rights bitmask for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);
    pub const REVOKE: Self = Self(1 << 4);
    pub const ALL: Self = Self(0x1F);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Derive new rights that are a subset of the current rights.
    pub const fn restrict(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }
}

/// Kernel objects that capabilities can reference.
#[derive(Debug, Clone, Copy)]
pub enum CapObject {
    /// Physical memory: base address + size in bytes.
    Memory { base: u64, size: u64 },
    /// IPC endpoint.
    Endpoint { id: u32 },
    /// Async IPC channel.
    Channel { id: u32 },
    /// Thread.
    Thread { id: u32 },
    /// Hardware IRQ line.
    Irq { line: u32 },
    /// x86 I/O port range.
    IoPort { base: u16, count: u16 },
    /// Notification object (binary semaphore for shared-memory IPC).
    Notification { id: u32 },
    /// Null / empty slot.
    Null,
}

/// A single entry in the capability table.
#[derive(Debug, Clone, Copy)]
struct CapEntry {
    object: CapObject,
    rights: Rights,
    /// Parent capability (for the CDT). None = root capability.
    parent: Option<CapId>,
}

/// The kernel's capability table.
pub struct CapabilityTable {
    entries: Pool<CapEntry>,
}

impl CapabilityTable {
    pub const fn new() -> Self {
        Self {
            entries: Pool::new(),
        }
    }

    /// Insert a new capability.
    pub fn insert(
        &mut self,
        object: CapObject,
        rights: Rights,
        parent: Option<CapId>,
    ) -> Option<CapId> {
        let id = self.entries.alloc(CapEntry {
            object,
            rights,
            parent,
        });
        Some(CapId(id))
    }

    /// Validate a capability: look up by ID, check rights.
    pub fn validate(&self, id: CapId, required: Rights) -> Result<CapObject, SysError> {
        let entry = self.entries.get(id.0).ok_or(SysError::InvalidCap)?;
        if !entry.rights.contains(required) {
            return Err(SysError::NoRights);
        }
        Ok(entry.object)
    }

    /// Look up a capability by ID. Returns None if not found.
    pub fn lookup(&self, id: CapId) -> Option<(CapObject, Rights)> {
        let entry = self.entries.get(id.0)?;
        Some((entry.object, entry.rights))
    }

    /// Revoke a capability and all capabilities derived from it (CDT walk).
    pub fn revoke(&mut self, id: CapId) {
        if self.entries.free(id.0).is_none() {
            return;
        }

        // Walk the pool and revoke all children whose parent was revoked.
        // This is O(n*depth) in the worst case — acceptable for now.
        let mut to_revoke: Vec<u32> = Vec::new();
        let mut changed = true;
        while changed {
            changed = false;
            for (i, entry) in self.entries.iter() {
                if let Some(parent) = entry.parent {
                    if self.entries.get(parent.0).is_none() {
                        to_revoke.push(i);
                        changed = true;
                    }
                }
            }
            for id in to_revoke.drain(..) {
                self.entries.free(id);
            }
        }
    }
}
