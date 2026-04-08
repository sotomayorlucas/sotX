//! fs_vfs.rs — thin compatibility shim.
//!
//! The 2940-LOC monolith was split into 5 sub-modules by operation family
//! (see vfs_read_write, vfs_metadata, vfs_open, vfs_path, vfs_delete).
//! This module re-exports every public function from the new sub-modules so
//! that existing callers which still use `fs::fs_vfs::*` keep compiling
//! without any signature changes.

pub(crate) use super::vfs_read_write::{
    read_vfs, read_virtual, read_tcp, read_udp,
    write_vfs, write_tcp, write_udp,
    close_vfs, close_tcp,
    sys_pread64, sys_preadv, sys_pwritev, sys_pwrite64,
    sys_copy_file_range, sys_sendfile,
    readv_vfs, readv_tcp, readv_virtual,
    writev_devnull, writev_tcp, writev_vfs,
};

pub(crate) use super::vfs_metadata::{
    sys_fstat, sys_stat, sys_lseek,
    sys_fsync, sys_ftruncate,
    sys_statfs, sys_fadvise64, sys_statx,
    sys_file_metadata_stubs,
};

pub(crate) use super::vfs_open::{
    sys_open, sys_openat, sys_creat,
};

pub(crate) use super::vfs_path::{
    sys_fstatat, sys_readlinkat, sys_readlink,
    sys_access, sys_rename, sys_renameat,
    sys_faccessat2, sys_umask,
};

pub(crate) use super::vfs_delete::{
    sys_unlink, sys_unlinkat,
};
