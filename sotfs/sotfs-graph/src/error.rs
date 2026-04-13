//! Error types for the sotFS type graph.

#[cfg(not(feature = "std"))]
use alloc::string::String;

use crate::types::*;

#[derive(Debug)]
pub enum GraphError {
    InodeNotFound(InodeId),
    DirNotFound(DirId),
    CapNotFound(CapId),
    BlockNotFound(BlockId),
    EdgeNotFound(EdgeId),

    // Gluing condition violations
    NameExists { dir: DirId, name: String },
    DirNotEmpty(DirId),
    LinkToDirectory(InodeId),
    LinkCountExceeded(u32),
    WouldCreateCycle,
    NameNotFound(String),
    NotADirectory(InodeId),
    NotAFile(InodeId),
    OutOfIds,

    // xattr errors
    XAttrNotFound(String),
    XAttrExists(String),
    XAttrTooLarge(usize),

    // symlink errors
    NotASymlink(InodeId),
    SymlinkLoop,

    // quota errors
    QuotaExceeded { dir: DirId, resource: String },

    // Invariant violations
    InvariantViolation(String),
}

impl core::fmt::Display for GraphError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InodeNotFound(id) => write!(f, "inode {} not found", id),
            Self::DirNotFound(id) => write!(f, "directory {} not found", id),
            Self::CapNotFound(id) => write!(f, "capability {} not found", id),
            Self::BlockNotFound(id) => write!(f, "block {} not found", id),
            Self::EdgeNotFound(id) => write!(f, "edge {} not found", id),
            Self::NameExists { dir, name } => {
                write!(f, "name '{}' already exists in directory {}", name, dir)
            }
            Self::DirNotEmpty(id) => write!(f, "directory {} is not empty", id),
            Self::LinkToDirectory(id) => {
                write!(f, "cannot hard-link to directory inode {}", id)
            }
            Self::LinkCountExceeded(max) => {
                write!(f, "link count would exceed maximum ({})", max)
            }
            Self::WouldCreateCycle => write!(f, "rename would create directory cycle"),
            Self::NameNotFound(name) => write!(f, "name '{}' not found", name),
            Self::NotADirectory(id) => write!(f, "inode {} is not a directory", id),
            Self::NotAFile(id) => write!(f, "inode {} is not a regular file", id),
            Self::OutOfIds => write!(f, "no free inode/dir/block IDs available"),
            Self::XAttrNotFound(name) => write!(f, "xattr '{}' not found", name),
            Self::XAttrExists(name) => write!(f, "xattr '{}' already exists", name),
            Self::XAttrTooLarge(size) => write!(f, "xattr value too large ({} bytes)", size),
            Self::NotASymlink(id) => write!(f, "inode {} is not a symlink", id),
            Self::SymlinkLoop => write!(f, "too many levels of symbolic links"),
            Self::QuotaExceeded { dir, resource } => {
                write!(f, "{} quota exceeded for directory {}", resource, dir)
            }
            Self::InvariantViolation(msg) => write!(f, "invariant violation: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GraphError {}
