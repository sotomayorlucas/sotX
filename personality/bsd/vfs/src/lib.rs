//! SOT VFS Server Domain
//!
//! BSD-style virtual filesystem running as a SOT domain. Serves POSIX file
//! operations over IPC channels, gating every access through capabilities.
//!
//! Architecture:
//!   - Vnodes represent every file-like object (regular, directory, device).
//!   - Mount table maps path prefixes to filesystem backends (sub-domains).
//!   - Path lookup walks mount + vnode trees, checking caps at each component.
//!   - File handles (`FileCap`) carry rights derived from open flags.

#![no_std]
extern crate alloc;

pub mod vnode;
pub mod mount;
pub mod lookup;
pub mod ops;

/// Capability-gated file handle returned by OPEN.
#[derive(Debug, Clone, Copy)]
pub struct FileCap {
    pub cap_id: u64,
    pub rights: FileRights,
    pub vnode_id: u64,
    pub offset: u64,
}

/// File access rights (derived from open flags).
#[derive(Debug, Clone, Copy)]
pub struct FileRights {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub append_only: bool,
}

impl FileRights {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
        append_only: false,
    };

    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
        append_only: false,
    };

    pub const APPEND: Self = Self {
        read: true,
        write: true,
        execute: false,
        append_only: true,
    };
}

/// VFS operation IPC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VfsOp {
    Open = 1,
    Close = 2,
    Read = 3,
    Write = 4,
    Stat = 5,
    Readdir = 6,
    Mkdir = 7,
    Rmdir = 8,
    Unlink = 9,
    Rename = 10,
    Lseek = 11,
    Fstat = 12,
    Fsync = 13,
    Ftruncate = 14,
}

impl VfsOp {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Open),
            2 => Some(Self::Close),
            3 => Some(Self::Read),
            4 => Some(Self::Write),
            5 => Some(Self::Stat),
            6 => Some(Self::Readdir),
            7 => Some(Self::Mkdir),
            8 => Some(Self::Rmdir),
            9 => Some(Self::Unlink),
            10 => Some(Self::Rename),
            11 => Some(Self::Lseek),
            12 => Some(Self::Fstat),
            13 => Some(Self::Fsync),
            14 => Some(Self::Ftruncate),
            _ => None,
        }
    }
}

/// Standard POSIX error codes returned by VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum VfsError {
    Perm = -1,
    NoEnt = -2,
    Io = -5,
    BadF = -9,
    Access = -13,
    Exist = -17,
    NotDir = -20,
    IsDir = -21,
    Inval = -22,
    NoSpc = -28,
    NameTooLong = -36,
    NotEmpty = -39,
    NoCap = -62,
}

/// Provenance tier — tracks data origin for integrity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tier {
    /// Read-only data from a verified source.
    Tier0 = 0,
    /// Written data — requires audit trail.
    Tier1 = 1,
}
