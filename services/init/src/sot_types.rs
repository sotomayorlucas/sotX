//! SOT type definitions for the LUCAS-to-SOT bridge layer.
//!
//! These types model the SOT exokernel concepts (domains, policies,
//! provenance) that the bridge module uses to wrap raw syscalls.

pub const MAX_DOMAIN_CAPS: usize = 256;
pub const MAX_POLICY_PATHS: usize = 16;
pub const MAX_POLICY_PATH_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Domain info returned by sot_fork
// ---------------------------------------------------------------------------

/// Domain info for a forked child process.
pub struct SotChildDomain {
    pub domain_id: u32,
    pub caps: [u64; MAX_DOMAIN_CAPS],
    pub cap_count: u32,
    pub cr3: u64,
}

// ---------------------------------------------------------------------------
// Execution policy for sot_exec
// ---------------------------------------------------------------------------

/// Execution policy controlling what a domain is allowed to do.
pub struct ExecPolicy {
    pub max_caps: u32,
    pub network_allowed: bool,
    pub fs_write_allowed: bool,
    pub allowed_paths: [[u8; MAX_POLICY_PATH_LEN]; MAX_POLICY_PATHS],
    /// 0 = no path restriction (allow all).
    pub path_count: u32,
}

impl ExecPolicy {
    pub const fn permissive() -> Self {
        Self {
            max_caps: MAX_DOMAIN_CAPS as u32,
            network_allowed: true,
            fs_write_allowed: true,
            allowed_paths: [[0u8; MAX_POLICY_PATH_LEN]; MAX_POLICY_PATHS],
            path_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Provenance operation codes
// ---------------------------------------------------------------------------

pub const OP_FORK: u16 = 1;
pub const OP_EXEC: u16 = 2;
pub const OP_OPEN: u16 = 3;
pub const OP_READ: u16 = 4;
pub const OP_WRITE: u16 = 5;
pub const OP_CLOSE: u16 = 6;
pub const OP_PIPE: u16 = 7;
pub const OP_KILL: u16 = 8;
pub const OP_EXIT: u16 = 9;

// ---------------------------------------------------------------------------
// Channel type tags
// ---------------------------------------------------------------------------

pub const CHANNEL_TYPE_STREAM: u64 = 1;
pub const CHANNEL_TYPE_MSG: u64 = 2;
pub const CHANNEL_TYPE_SIGNAL: u64 = 3;

// ---------------------------------------------------------------------------
// Domain policy flags (bitfield for sot_domain_create)
// ---------------------------------------------------------------------------

pub const DOMAIN_POLICY_NET: u64 = 1 << 0;
pub const DOMAIN_POLICY_FS_WRITE: u64 = 1 << 1;
pub const DOMAIN_POLICY_FORK: u64 = 1 << 2;
pub const DOMAIN_POLICY_EXEC: u64 = 1 << 3;

// ---------------------------------------------------------------------------
// SO type tags for so_create
// ---------------------------------------------------------------------------

pub const SO_TYPE_FILE: u64 = 1;
pub const SO_TYPE_DIR: u64 = 2;
pub const SO_TYPE_PIPE: u64 = 3;
pub const SO_TYPE_SOCKET: u64 = 4;
pub const SO_TYPE_PROCESS: u64 = 5;

// ---------------------------------------------------------------------------
// SO method IDs for so_invoke
// ---------------------------------------------------------------------------

pub const SO_METHOD_READ: u64 = 1;
pub const SO_METHOD_WRITE: u64 = 2;
pub const SO_METHOD_SEEK: u64 = 3;
pub const SO_METHOD_STAT: u64 = 4;
pub const SO_METHOD_TRUNCATE: u64 = 5;
pub const SO_METHOD_READDIR: u64 = 6;
pub const SO_METHOD_SIGNAL: u64 = 10;
