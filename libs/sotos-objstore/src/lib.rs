//! sotOS Object Store — a transactional object store with WAL for crash consistency.
//!
//! Provides named blob storage on top of virtio-blk, with a POSIX-like VFS shim.

#![no_std]

extern crate alloc;

pub mod layout;
pub mod bitmap;
pub mod wal;
pub mod store;
pub mod vfs;
pub mod nvme_backend;
pub mod distributed;
pub mod fat;

pub use layout::*;
pub use store::ObjectStore;
pub use vfs::Vfs;
pub use nvme_backend::{BlockDevice, NvmeIpcBackend};
pub use distributed::DistributedVfs;
pub use fat::{VirtioBlkDevice, FixedTimeSource, BOOT_PARTITION_LBA};
