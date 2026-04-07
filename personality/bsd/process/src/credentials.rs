//! Capability-based credential model.
//!
//! There is NO setuid/setgid in SOT. Instead, when a binary executes, its
//! capability exec policy determines which caps the new domain receives.
//! The policy is identified by the binary's content hash, so it cannot be
//! forged by renaming or replacing the file.
//!
//! This replaces the entire UNIX permission model:
//! - `setuid root` becomes "this binary's policy grants the NET_BIND cap"
//! - `chmod 4755` becomes "register a policy for this hash"
//! - `/etc/passwd` uid lookup becomes "look up the policy by binary hash"

use alloc::vec::Vec;

/// A 256-bit hash identifying a binary's contents.
pub type BinaryHash = [u8; 32];

/// Resource limits enforced by the kernel on a domain.
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    /// Maximum CPU ticks before preemption escalates to throttling.
    pub max_cpu_ticks: u64,
    /// Maximum physical pages the domain may hold.
    pub max_memory_pages: u32,
    /// Maximum number of capabilities the domain may hold.
    pub max_caps: u32,
    /// Maximum number of child domains.
    pub max_children: u32,
}

impl ResourceLimits {
    /// Permissive defaults for unprivileged processes.
    pub const DEFAULT: Self = Self {
        max_cpu_ticks: 1_000_000,
        max_memory_pages: 4096, // 16 MiB
        max_caps: 256,
        max_children: 64,
    };
}

/// Well-known capability classes that a policy may grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CapClass {
    /// Bind to privileged network ports (< 1024).
    NetBind = 1,
    /// Access raw network devices.
    NetRaw = 2,
    /// Mount/unmount filesystems.
    FsMount = 3,
    /// Send signals to any domain.
    SignalAny = 4,
    /// Create new domains (fork).
    DomainCreate = 5,
    /// Access hardware devices directly.
    DeviceAccess = 6,
    /// Modify system time.
    TimeSet = 7,
    /// Load kernel modules (if supported).
    ModuleLoad = 8,
}

/// An allowed capability in an exec policy.
#[derive(Debug, Clone)]
pub struct AllowedCap {
    /// Which class of capability to grant.
    pub class: CapClass,
    /// Optional restriction (e.g., specific device path, port range).
    pub restriction: Option<CapRestriction>,
}

/// Restrictions that can narrow an allowed capability.
#[derive(Debug, Clone)]
pub enum CapRestriction {
    /// Only for a specific port range.
    PortRange { low: u16, high: u16 },
    /// Only for paths under a given prefix.
    PathPrefix(Vec<u8>),
    /// Only for a specific device.
    DeviceId(u32),
}

/// Capability exec policy -- determines what a binary receives at exec time.
///
/// The policy is looked up by the binary's content hash. If no policy exists,
/// the binary gets only the default (minimal) cap set.
#[derive(Debug, Clone)]
pub struct CapExecPolicy {
    /// Content hash of the binary this policy applies to.
    pub binary_hash: BinaryHash,
    /// Capabilities the binary is allowed to receive.
    pub allowed_caps: Vec<AllowedCap>,
    /// Resource limits enforced on the domain.
    pub resource_limits: ResourceLimits,
    /// Whether the binary may inherit caps from the parent domain.
    /// If false, the domain starts with ONLY the caps listed above.
    pub inherit_parent_caps: bool,
}

impl CapExecPolicy {
    /// Create a minimal policy for an unknown binary.
    pub fn default_for(hash: BinaryHash) -> Self {
        Self {
            binary_hash: hash,
            allowed_caps: Vec::new(),
            resource_limits: ResourceLimits::DEFAULT,
            inherit_parent_caps: true,
        }
    }
}

/// Policy store -- maps binary hashes to their exec policies.
///
/// In a real system this would be backed by a persistent VFS object.
/// For now it is an in-memory table.
#[derive(Debug, Default)]
pub struct PolicyStore {
    policies: Vec<CapExecPolicy>,
}

impl PolicyStore {
    pub const fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Register a policy. Overwrites any existing policy for the same hash.
    pub fn register(&mut self, policy: CapExecPolicy) {
        self.policies.retain(|p| p.binary_hash != policy.binary_hash);
        self.policies.push(policy);
    }

    /// Look up the policy for a binary hash.
    pub fn lookup(&self, hash: &BinaryHash) -> Option<&CapExecPolicy> {
        self.policies.iter().find(|p| &p.binary_hash == hash)
    }

    /// Look up or return a default policy.
    pub fn lookup_or_default(&self, hash: BinaryHash) -> CapExecPolicy {
        match self.lookup(&hash) {
            Some(p) => p.clone(),
            None => CapExecPolicy::default_for(hash),
        }
    }
}

/// Resolve the effective capabilities for a new domain after exec.
///
/// If `inherit_parent_caps` is false, the domain gets only the caps from
/// the policy's allowed list. If true, parent caps that match the allowed
/// list are also included (intersection of parent caps and policy caps).
///
/// Since the policy's allowed_caps already enumerate all grantable classes,
/// the result is the same in both cases for now. The distinction matters
/// when the policy grants a class conditionally (e.g., only if the parent
/// also holds it) -- that refinement is future work.
pub fn resolve_exec_caps(
    policy: &CapExecPolicy,
    _parent_caps: &[CapClass],
) -> Vec<CapClass> {
    policy.allowed_caps.iter().map(|a| a.class).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash() -> BinaryHash {
        [0xAA; 32]
    }

    #[test]
    fn default_policy_inherits_parent_caps() {
        let policy = CapExecPolicy::default_for(test_hash());
        assert!(policy.inherit_parent_caps);
        assert!(policy.allowed_caps.is_empty());
    }

    #[test]
    fn policy_store_register_and_lookup() {
        let mut store = PolicyStore::new();
        let mut policy = CapExecPolicy::default_for(test_hash());
        policy.allowed_caps.push(AllowedCap {
            class: CapClass::NetBind,
            restriction: Some(CapRestriction::PortRange { low: 80, high: 443 }),
        });
        store.register(policy);

        let found = store.lookup(&test_hash()).unwrap();
        assert_eq!(found.allowed_caps.len(), 1);
        assert_eq!(found.allowed_caps[0].class, CapClass::NetBind);
    }

    #[test]
    fn resolve_exec_caps_no_inherit() {
        let policy = CapExecPolicy {
            binary_hash: test_hash(),
            allowed_caps: alloc::vec![AllowedCap {
                class: CapClass::NetBind,
                restriction: None,
            }],
            resource_limits: ResourceLimits::DEFAULT,
            inherit_parent_caps: false,
        };
        let parent = &[CapClass::NetRaw, CapClass::FsMount];
        let caps = resolve_exec_caps(&policy, parent);
        assert_eq!(caps, alloc::vec![CapClass::NetBind]);
    }

    #[test]
    fn resolve_exec_caps_with_inherit() {
        let policy = CapExecPolicy {
            binary_hash: test_hash(),
            allowed_caps: alloc::vec![
                AllowedCap { class: CapClass::NetBind, restriction: None },
                AllowedCap { class: CapClass::NetRaw, restriction: None },
            ],
            resource_limits: ResourceLimits::DEFAULT,
            inherit_parent_caps: true,
        };
        // Parent has NetRaw (in policy) and FsMount (not in policy).
        let parent = &[CapClass::NetRaw, CapClass::FsMount];
        let caps = resolve_exec_caps(&policy, parent);
        // NetBind (from policy) + NetRaw (from policy, also in parent)
        // FsMount NOT included because it is not in the policy's allowed list.
        assert!(caps.contains(&CapClass::NetBind));
        assert!(caps.contains(&CapClass::NetRaw));
        assert!(!caps.contains(&CapClass::FsMount));
    }
}
