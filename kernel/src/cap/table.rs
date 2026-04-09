//! Capability table implementation.
//!
//! Pool-backed table mapping CapId → (Object, Rights, Parent).
//! The Capability Derivation Tree (CDT) tracks parent-child
//! relationships for O(n) revocation of all derivatives.
//!
//! CapId wraps a PoolHandle, so stale capabilities (pointing at
//! recycled slots) are detected by generation check.

use alloc::vec::Vec;
use sotos_common::SysError;

use crate::pool::{Pool, PoolHandle};
use crate::sot::cap_epoch::InterpositionPolicy;

/// Unique capability identifier (wraps a generation-checked PoolHandle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapId(PoolHandle);

impl CapId {
    /// Construct from raw u32 (e.g. from userspace syscall argument).
    pub fn new(raw: u32) -> Self {
        Self(PoolHandle::from_raw(raw))
    }

    /// Return the raw u32 representation (opaque to userspace).
    pub fn raw(self) -> u32 {
        self.0.raw()
    }

    /// Return the underlying PoolHandle.
    pub fn handle(self) -> PoolHandle {
        self.0
    }
}

/// Rights bitmask for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    #[allow(dead_code)]
    pub const EXECUTE: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);
    pub const REVOKE: Self = Self(1 << 4);
    pub const ALL: Self = Self(0x1F);

    #[allow(dead_code)]
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
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
    /// Scheduling domain (budget-enforced thread group).
    Domain { id: u32 },
    /// User address space (PML4).
    AddrSpace { cr3: u64 },
    /// Interposed capability: routes through a proxy domain before
    /// reaching the original kernel object.
    Interposed {
        /// Handle of the original capability being proxied.
        original: u32,
        /// Domain that intercepts operations on this capability.
        proxy_domain: u32,
        /// Interposition policy (see `InterpositionPolicy`).
        policy: u8,
    },
    /// VT-x guest virtual machine. `id` is the public, KARL-randomised
    /// VM identifier (assigned by `vm::create_vm`); the kernel maps it
    /// to a `Pool<VmObject>` slot internally. RUN/PROFILE/INTROSPECT
    /// gating uses the standard READ/WRITE Rights bits.
    Vm { id: u32 },
    /// Null / empty slot.
    #[allow(dead_code)]
    Null,
}

/// A single entry in the capability table.
#[derive(Debug, Clone, Copy)]
struct CapEntry {
    object: CapObject,
    rights: Rights,
    /// Parent capability (for the CDT). None = root capability.
    parent: Option<PoolHandle>,
    /// Epoch at which this capability was created (for O(1) revocation).
    epoch: u64,
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

    /// Insert a new capability stamped with the given epoch.
    pub fn insert(
        &mut self,
        object: CapObject,
        rights: Rights,
        parent: Option<CapId>,
        epoch: u64,
    ) -> Option<CapId> {
        let handle = self.entries.alloc(CapEntry {
            object,
            rights,
            parent: parent.map(|c| c.handle()),
            epoch,
        });
        Some(CapId(handle))
    }

    /// Validate a capability: look up by ID, check rights.
    pub fn validate(&self, id: CapId, required: Rights) -> Result<CapObject, SysError> {
        let entry = self.entries.get(id.handle()).ok_or(SysError::InvalidCap)?;
        if !entry.rights.contains(required) {
            return Err(SysError::NoRights);
        }
        Ok(entry.object)
    }

    /// Look up a capability by ID. Returns None if not found.
    pub fn lookup(&self, id: CapId) -> Option<(CapObject, Rights)> {
        let entry = self.entries.get(id.handle())?;
        Some((entry.object, entry.rights))
    }

    /// Create a derived capability with narrowed rights (child in CDT).
    ///
    /// The new cap refers to the same object but with `rights & mask`.
    /// It inherits the parent's epoch.
    pub fn attenuate(&mut self, id: CapId, rights_mask: Rights) -> Option<CapId> {
        let entry = *self.entries.get(id.handle())?;
        let new_rights = entry.rights.restrict(rights_mask);
        self.insert(entry.object, new_rights, Some(id), entry.epoch)
    }

    /// Create an interposed capability that routes through a proxy domain.
    ///
    /// The returned cap has an `Interposed` object wrapping the original
    /// handle, the proxy domain id, and the interposition policy byte.
    /// Rights and epoch are copied from the original.
    pub fn interpose(&mut self, id: CapId, proxy_domain: u32, policy: u8) -> Option<CapId> {
        // Validate the policy byte.
        let _policy = InterpositionPolicy::from_u8(policy)?;
        let entry = *self.entries.get(id.handle())?;
        let object = CapObject::Interposed {
            original: id.raw(),
            proxy_domain,
            policy,
        };
        self.insert(object, entry.rights, Some(id), entry.epoch)
    }

    /// Check whether a capability is interposed.
    pub fn is_interposed(&self, id: CapId) -> bool {
        self.entries
            .get(id.handle())
            .map(|e| matches!(e.object, CapObject::Interposed { .. }))
            .unwrap_or(false)
    }

    /// O(1) epoch check: returns true if the capability's epoch >= min_epoch.
    pub fn check_epoch(&self, id: CapId, min_epoch: u64) -> bool {
        self.entries
            .get(id.handle())
            .map(|e| e.epoch >= min_epoch)
            .unwrap_or(false)
    }

    /// Revoke a capability and all capabilities derived from it (CDT walk).
    pub fn revoke(&mut self, id: CapId) {
        if self.entries.free(id.handle()).is_none() {
            return;
        }

        // Iteratively revoke orphaned children until no more are found.
        let mut to_revoke: Vec<PoolHandle> = Vec::new();
        loop {
            for (handle, entry) in self.entries.iter() {
                if let Some(parent_handle) = entry.parent {
                    if self.entries.get(parent_handle).is_none() {
                        to_revoke.push(handle);
                    }
                }
            }
            if to_revoke.is_empty() {
                break;
            }
            for h in to_revoke.drain(..) {
                self.entries.free(h);
            }
        }
    }
}
