//! Exec-time policy resolution.
//!
//! When a domain calls exec(), this module determines which capabilities
//! the new binary receives based on its identity (hash, path, signature).
//! The policy database is a fixed-size, no-heap structure suitable for
//! kernel-adjacent use.

/// Maximum number of registered policies.
const MAX_POLICIES: usize = 64;

/// Binary identity for policy lookup.
pub struct BinaryIdentity {
    pub path: [u8; 256],
    pub path_len: usize,
    pub sha256_hash: [u8; 32],
    pub signature_valid: bool,
    pub signer: [u8; 64],
    pub signer_len: usize,
}

impl BinaryIdentity {
    /// Create an identity from a path and hash.
    pub fn new(path: &[u8], hash: [u8; 32]) -> Self {
        let mut p = [0u8; 256];
        let len = if path.len() > 256 { 256 } else { path.len() };
        p[..len].copy_from_slice(&path[..len]);
        Self {
            path: p,
            path_len: len,
            sha256_hash: hash,
            signature_valid: false,
            signer: [0u8; 64],
            signer_len: 0,
        }
    }

    fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// Action to take when a domain is detected as compromised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompromiseAction {
    /// Immediately terminate the domain.
    Kill,
    /// Move the domain into a deception environment for analysis.
    MigrateToDeception,
    /// Log an alert but allow continued execution.
    Alert,
    /// Do nothing (for testing or trusted binaries).
    Ignore,
}

/// Resolved execution policy -- determines what a binary gets at exec time.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedExecPolicy {
    pub max_capabilities: u32,
    pub max_child_domains: u32,
    pub network_allowed: bool,
    pub fs_write_allowed: bool,
    pub fs_read_paths: [[u8; 128]; 16],
    pub fs_read_count: usize,
    pub fs_write_paths: [[u8; 128]; 8],
    pub fs_write_count: usize,
    pub ipc_targets: [[u8; 32]; 8],
    pub ipc_target_count: usize,
    pub max_memory_pages: u32,
    pub on_compromise: CompromiseAction,
}

impl ResolvedExecPolicy {
    /// Restrictive defaults: no network, no fs writes, read only /usr and /lib.
    pub fn default_restrictive() -> Self {
        let mut policy = Self {
            max_capabilities: 16,
            max_child_domains: 4,
            network_allowed: false,
            fs_write_allowed: false,
            fs_read_paths: [[0u8; 128]; 16],
            fs_read_count: 0,
            fs_write_paths: [[0u8; 128]; 8],
            fs_write_count: 0,
            ipc_targets: [[0u8; 32]; 8],
            ipc_target_count: 0,
            max_memory_pages: 4096, // 16 MiB
            on_compromise: CompromiseAction::Kill,
        };
        policy.add_read_path(b"/usr");
        policy.add_read_path(b"/lib");
        policy
    }

    /// Example policy matching a typical nginx deployment.
    ///
    /// Grants: network access, listening on 80/443, reading web root
    /// and config, writing to log directory, limited memory.
    pub fn nginx_example() -> Self {
        let mut policy = Self {
            max_capabilities: 32,
            max_child_domains: 8,
            network_allowed: true,
            fs_write_allowed: true,
            fs_read_paths: [[0u8; 128]; 16],
            fs_read_count: 0,
            fs_write_paths: [[0u8; 128]; 8],
            fs_write_count: 0,
            ipc_targets: [[0u8; 32]; 8],
            ipc_target_count: 0,
            max_memory_pages: 32768, // 128 MiB
            on_compromise: CompromiseAction::MigrateToDeception,
        };
        policy.add_read_path(b"/etc/nginx");
        policy.add_read_path(b"/usr/share/nginx");
        policy.add_read_path(b"/var/www");
        policy.add_read_path(b"/usr/lib");
        policy.add_write_path(b"/var/log/nginx");
        policy.add_write_path(b"/var/run");
        policy.add_ipc_target(b"net");
        policy.add_ipc_target(b"dns");
        policy
    }

    fn add_read_path(&mut self, path: &[u8]) {
        copy_into_slot(&mut self.fs_read_paths, &mut self.fs_read_count, path);
    }

    fn add_write_path(&mut self, path: &[u8]) {
        copy_into_slot(&mut self.fs_write_paths, &mut self.fs_write_count, path);
    }

    fn add_ipc_target(&mut self, name: &[u8]) {
        copy_into_slot(&mut self.ipc_targets, &mut self.ipc_target_count, name);
    }
}

/// Copy `src` into the next available slot of a fixed-size array of byte buffers.
/// Silently does nothing if the array is full.
fn copy_into_slot<const N: usize>(slots: &mut [[u8; N]], count: &mut usize, src: &[u8]) {
    if *count >= slots.len() {
        return;
    }
    let len = if src.len() > N { N } else { src.len() };
    slots[*count] = [0u8; N];
    slots[*count][..len].copy_from_slice(&src[..len]);
    *count += 1;
}

/// A single entry in the policy database.
struct PolicyEntry {
    /// Match by path prefix (e.g., "/usr/bin/").
    path_prefix: [u8; 128],
    prefix_len: usize,
    /// Match by SHA-256 hash. All zeros means "match any hash".
    hash: [u8; 32],
    /// The resolved policy if matched.
    policy: ResolvedExecPolicy,
}

impl PolicyEntry {
    fn prefix_matches(&self, path: &[u8]) -> bool {
        if self.prefix_len == 0 {
            return false;
        }
        if path.len() < self.prefix_len {
            return false;
        }
        path[..self.prefix_len] == self.path_prefix[..self.prefix_len]
    }
}

/// Policy database -- maps binary identities to execution policies.
///
/// Resolution order: exact hash match first, then path prefix, then default.
/// All storage is inline (no heap allocation).
pub struct PolicyDatabase {
    entries: [Option<PolicyEntry>; MAX_POLICIES],
    count: usize,
    default_policy: ResolvedExecPolicy,
}

impl PolicyDatabase {
    /// Create a new database with restrictive defaults.
    pub fn new() -> Self {
        // Initialize with None entries. We use a const to avoid needing
        // array::from_fn which would require Clone on Option<PolicyEntry>.
        const NONE: Option<PolicyEntry> = None;
        Self {
            entries: [NONE; MAX_POLICIES],
            count: 0,
            default_policy: ResolvedExecPolicy::default_restrictive(),
        }
    }

    /// Register a policy for binaries matching the given prefix and/or hash.
    ///
    /// Returns true if added, false if the database is full.
    pub fn add_policy(
        &mut self,
        path_prefix: &[u8],
        hash: [u8; 32],
        policy: ResolvedExecPolicy,
    ) -> bool {
        if self.count >= MAX_POLICIES {
            return false;
        }

        let mut prefix_buf = [0u8; 128];
        let prefix_len = if path_prefix.len() > 128 { 128 } else { path_prefix.len() };
        prefix_buf[..prefix_len].copy_from_slice(&path_prefix[..prefix_len]);

        self.entries[self.count] = Some(PolicyEntry {
            path_prefix: prefix_buf,
            prefix_len,
            hash,
            policy,
        });
        self.count += 1;
        true
    }

    /// Resolve the execution policy for a binary.
    ///
    /// Resolution order:
    /// 1. Exact hash match (first entry whose hash matches the identity's hash).
    /// 2. Path prefix match (first entry whose prefix matches the identity's path).
    /// 3. Default restrictive policy.
    pub fn resolve(&self, identity: &BinaryIdentity) -> &ResolvedExecPolicy {
        // Pass 1: exact hash match (non-wildcard entries only).
        for entry in &self.entries[..self.count] {
            if let Some(e) = entry {
                if e.hash != [0u8; 32] && e.hash == identity.sha256_hash {
                    return &e.policy;
                }
            }
        }

        // Pass 2: path prefix match.
        for entry in &self.entries[..self.count] {
            if let Some(e) = entry {
                if e.prefix_matches(identity.path_bytes()) {
                    return &e.policy;
                }
            }
        }

        // Pass 3: default.
        &self.default_policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(path: &[u8], hash: [u8; 32]) -> BinaryIdentity {
        BinaryIdentity::new(path, hash)
    }

    #[test]
    fn default_restrictive_has_no_network() {
        let policy = ResolvedExecPolicy::default_restrictive();
        assert!(!policy.network_allowed);
        assert!(!policy.fs_write_allowed);
        assert_eq!(policy.fs_read_count, 2); // /usr and /lib
        assert_eq!(policy.on_compromise, CompromiseAction::Kill);
    }

    #[test]
    fn nginx_example_has_network() {
        let policy = ResolvedExecPolicy::nginx_example();
        assert!(policy.network_allowed);
        assert!(policy.fs_write_allowed);
        assert_eq!(policy.fs_read_count, 4);
        assert_eq!(policy.fs_write_count, 2);
        assert_eq!(policy.ipc_target_count, 2);
        assert_eq!(policy.on_compromise, CompromiseAction::MigrateToDeception);
    }

    #[test]
    fn resolve_by_hash() {
        let mut db = PolicyDatabase::new();
        let hash = [0xAA; 32];
        db.add_policy(b"/usr/sbin/nginx", hash, ResolvedExecPolicy::nginx_example());

        let id = make_identity(b"/some/other/path", hash);
        let resolved = db.resolve(&id);
        // Should match by hash regardless of path.
        assert!(resolved.network_allowed);
    }

    #[test]
    fn resolve_by_prefix() {
        let mut db = PolicyDatabase::new();
        let wildcard_hash = [0u8; 32]; // match any hash
        let mut policy = ResolvedExecPolicy::default_restrictive();
        policy.network_allowed = true;
        db.add_policy(b"/usr/sbin/", wildcard_hash, policy);

        let id = make_identity(b"/usr/sbin/nginx", [0xBB; 32]);
        let resolved = db.resolve(&id);
        assert!(resolved.network_allowed);
    }

    #[test]
    fn resolve_falls_back_to_default() {
        let db = PolicyDatabase::new();
        let id = make_identity(b"/tmp/unknown", [0xCC; 32]);
        let resolved = db.resolve(&id);
        assert!(!resolved.network_allowed);
        assert!(!resolved.fs_write_allowed);
    }

    #[test]
    fn hash_takes_priority_over_prefix() {
        let mut db = PolicyDatabase::new();

        // Register a permissive prefix policy.
        let mut prefix_policy = ResolvedExecPolicy::default_restrictive();
        prefix_policy.network_allowed = true;
        prefix_policy.max_memory_pages = 9999;
        db.add_policy(b"/usr/bin/", [0u8; 32], prefix_policy);

        // Register a restrictive hash policy for a specific binary.
        let hash = [0xDD; 32];
        let mut hash_policy = ResolvedExecPolicy::default_restrictive();
        hash_policy.max_memory_pages = 1111;
        db.add_policy(b"", hash, hash_policy);

        // Binary under /usr/bin/ with the specific hash should match hash policy.
        let id = make_identity(b"/usr/bin/malicious", hash);
        let resolved = db.resolve(&id);
        assert_eq!(resolved.max_memory_pages, 1111);
        assert!(!resolved.network_allowed);
    }

    #[test]
    fn database_full_returns_false() {
        let mut db = PolicyDatabase::new();
        for i in 0..MAX_POLICIES {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            assert!(db.add_policy(b"/test", hash, ResolvedExecPolicy::default_restrictive()));
        }
        // 65th should fail.
        assert!(!db.add_policy(b"/overflow", [0xFF; 32], ResolvedExecPolicy::default_restrictive()));
    }
}
