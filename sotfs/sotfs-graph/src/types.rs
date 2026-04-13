//! Node types, edge types, and attribute structures for the sotFS type graph.
//!
//! Maps directly to §5.2-5.3 of the design document.

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Timestamp as seconds since Unix epoch. Works in both std and no_std.
pub type Timestamp = u64;

/// Get current timestamp. In std mode uses SystemTime, in no_std returns 0.
pub fn now() -> Timestamp {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    #[cfg(not(feature = "std"))]
    {
        0 // Caller should provide timestamp via RDTSC or IPC
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Unique inode identifier (maps to OID in the object store).
pub type InodeId = u64;
/// Unique directory identifier.
pub type DirId = u64;
/// Unique capability identifier.
pub type CapId = u64;
/// Unique transaction identifier.
pub type TxnId = u64;
/// Unique version (snapshot) identifier.
pub type VersionId = u64;
/// Unique block identifier.
pub type BlockId = u64;

/// Generic node identifier — wraps the typed ID with its type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeId {
    Inode(InodeId),
    Directory(DirId),
    Capability(CapId),
    Transaction(TxnId),
    Version(VersionId),
    Block(BlockId),
}

// ---------------------------------------------------------------------------
// Node types (§5.2)
// ---------------------------------------------------------------------------

/// Inode vtype — what kind of filesystem object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VnodeType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
}

/// POSIX permission bits (9 bits: rwxrwxrwx).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions(pub u16);

impl Permissions {
    pub const DIR_DEFAULT: Self = Self(0o755);
    pub const FILE_DEFAULT: Self = Self(0o644);

    pub fn mode(&self) -> u16 {
        self.0
    }
}

/// Inode node — represents a filesystem object (§5.2.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    pub id: InodeId,
    pub vtype: VnodeType,
    pub permissions: Permissions,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub link_count: u32,
    pub ctime: Timestamp,
    pub mtime: Timestamp,
    pub atime: Timestamp,
}

impl Inode {
    pub fn new_file(id: InodeId, permissions: Permissions, uid: u32, gid: u32) -> Self {
        let now = now();
        Self {
            id,
            vtype: VnodeType::Regular,
            permissions,
            uid,
            gid,
            size: 0,
            link_count: 0,
            ctime: now,
            mtime: now,
            atime: now,
        }
    }

    pub fn new_dir(id: InodeId, permissions: Permissions, uid: u32, gid: u32) -> Self {
        let now = now();
        Self {
            id,
            vtype: VnodeType::Directory,
            permissions,
            uid,
            gid,
            size: 0,
            link_count: 0,
            ctime: now,
            mtime: now,
            atime: now,
        }
    }
}

/// Directory node — namespace container (§5.2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directory {
    pub id: DirId,
    /// The paired inode id (the inode that "." points to).
    pub inode_id: InodeId,
}

/// Capability rights bitmask (§5.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rights(pub u8);

impl Rights {
    pub const READ: u8 = 1 << 0;
    pub const WRITE: u8 = 1 << 1;
    pub const EXECUTE: u8 = 1 << 2;
    pub const GRANT: u8 = 1 << 3;
    pub const REVOKE: u8 = 1 << 4;
    pub const ALL: Self = Self(0x1F);

    pub fn contains(&self, right: u8) -> bool {
        self.0 & right == right
    }

    pub fn is_subset_of(&self, other: &Rights) -> bool {
        self.0 & other.0 == self.0
    }

    pub fn restrict(&self, mask: Rights) -> Rights {
        Rights(self.0 & mask.0)
    }
}

/// Capability node (§5.2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: CapId,
    pub rights: Rights,
    pub epoch: u64,
}

/// Transaction state machine (§5.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxState {
    Active,
    Preparing,
    Committed,
    Aborted,
}

/// Transaction tier (maps to SOT tiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxTier {
    Tier0,
    Tier1,
    Tier2,
}

/// Transaction node (§5.2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxnId,
    pub tier: TxTier,
    pub state: TxState,
    pub read_set: BTreeSet<InodeId>,
    pub write_set: BTreeSet<InodeId>,
    pub begin_ts: Timestamp,
}

/// Version (snapshot) node (§5.2.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub id: VersionId,
    pub timestamp: Timestamp,
    pub root_inode_id: InodeId,
}

/// Block extent node (§5.2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub id: BlockId,
    pub sector_start: u64,
    pub sector_count: u64,
    pub refcount: u32,
}

/// Extended attribute node (§5.2.7).
///
/// Each xattr is stored as a separate node with a HasXattr edge from its inode.
/// This models xattrs as first-class graph citizens, enabling capability-based
/// access control over individual attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XAttr {
    pub id: XAttrId,
    pub namespace: XAttrNamespace,
    pub name: String,
    pub value: Vec<u8>,
}

/// Extended attribute namespaces (following Linux conventions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XAttrNamespace {
    User,
    System,
    Security,
    Trusted,
}

/// Symlink target stored in the inode's data.
/// For short symlinks (< 60 bytes), stored inline.
/// For long symlinks, stored in file_data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymlinkTarget(pub String);

/// ACL entry for POSIX.1e compatibility (§5.2.8).
///
/// Maps to capability graph edges: each ACL entry becomes a Grants edge
/// from a synthesized capability with rights derived from the permission bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub tag: AclTag,
    pub qualifier: u32, // uid or gid, 0 for USER_OBJ/GROUP_OBJ/OTHER/MASK
    pub permissions: Permissions,
}

/// ACL entry tag types (POSIX.1e).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclTag {
    UserObj,
    User,
    GroupObj,
    Group,
    Mask,
    Other,
}

/// Quota tracking node — attached per-subtree root (§5.2.9).
///
/// Uses summary propagation: each directory maintains cumulative counters
/// for its entire subtree. On DPO operations, only the path from the
/// modified node to the quota root is updated (O(depth) amortized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quota {
    pub inode_limit: u64,
    pub inode_usage: u64,
    pub byte_limit: u64,
    pub byte_usage: u64,
}

impl Quota {
    pub fn new(inode_limit: u64, byte_limit: u64) -> Self {
        Self {
            inode_limit,
            inode_usage: 0,
            byte_limit,
            byte_usage: 0,
        }
    }

    pub fn check_inode(&self) -> bool {
        self.inode_limit == 0 || self.inode_usage < self.inode_limit
    }

    pub fn check_bytes(&self, additional: u64) -> bool {
        self.byte_limit == 0 || self.byte_usage + additional <= self.byte_limit
    }
}

// ---------------------------------------------------------------------------
// Edge types (§5.3)
// ---------------------------------------------------------------------------

/// Unique extended attribute identifier.
pub type XAttrId = u64;

/// A unique edge identifier.
pub type EdgeId = u64;

/// Typed edge in the type graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Edge {
    /// Directory → Inode, labeled with filename (§5.3.1).
    Contains {
        id: EdgeId,
        src: DirId,
        tgt: InodeId,
        name: String,
    },
    /// Capability → Inode (§5.3.2).
    Grants {
        id: EdgeId,
        src: CapId,
        tgt: InodeId,
        rights: Rights,
    },
    /// Capability → Capability, CDT parent→child (§5.3.3).
    Delegates {
        id: EdgeId,
        src: CapId,
        tgt: CapId,
    },
    /// Version → Version, snapshot lineage (§5.3.4).
    DerivedFrom {
        id: EdgeId,
        src: VersionId,
        tgt: VersionId,
    },
    /// Inode → Inode, atomic rename replacement (§5.3.5).
    Supersedes {
        id: EdgeId,
        src: InodeId,
        tgt: InodeId,
    },
    /// Inode → Block, with byte offset (§5.3.6).
    PointsTo {
        id: EdgeId,
        src: InodeId,
        tgt: BlockId,
        offset: u64,
    },
    /// Inode → XAttr (§5.3.7).
    HasXattr {
        id: EdgeId,
        src: InodeId,
        tgt: XAttrId,
    },
}

impl Edge {
    pub fn id(&self) -> EdgeId {
        match self {
            Edge::Contains { id, .. }
            | Edge::Grants { id, .. }
            | Edge::Delegates { id, .. }
            | Edge::DerivedFrom { id, .. }
            | Edge::Supersedes { id, .. }
            | Edge::PointsTo { id, .. }
            | Edge::HasXattr { id, .. } => *id,
        }
    }

    pub fn src_node(&self) -> NodeId {
        match self {
            Edge::Contains { src, .. } => NodeId::Directory(*src),
            Edge::Grants { src, .. } => NodeId::Capability(*src),
            Edge::Delegates { src, .. } => NodeId::Capability(*src),
            Edge::DerivedFrom { src, .. } => NodeId::Version(*src),
            Edge::Supersedes { src, .. } => NodeId::Inode(*src),
            Edge::PointsTo { src, .. } => NodeId::Inode(*src),
            Edge::HasXattr { src, .. } => NodeId::Inode(*src),
        }
    }

    pub fn tgt_node(&self) -> NodeId {
        match self {
            Edge::Contains { tgt, .. } => NodeId::Inode(*tgt),
            Edge::Grants { tgt, .. } => NodeId::Inode(*tgt),
            Edge::Delegates { tgt, .. } => NodeId::Capability(*tgt),
            Edge::DerivedFrom { tgt, .. } => NodeId::Version(*tgt),
            Edge::Supersedes { tgt, .. } => NodeId::Inode(*tgt),
            Edge::PointsTo { tgt, .. } => NodeId::Inode(*tgt),
            Edge::HasXattr { tgt, .. } => NodeId::Inode(*tgt as InodeId),
        }
    }
}
