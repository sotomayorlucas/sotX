//! FUSE filesystem implementation for sotFS.
//!
//! Maps FUSE operations to sotfs-ops DPO rules. Each FUSE callback
//! acquires a lock on the TypeGraph, performs the operation, and
//! replies with the result.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};

use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;
use sotfs_ops;

const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 4096;

/// The FUSE filesystem backed by a sotFS TypeGraph.
pub struct SotFsFilesystem {
    graph: Mutex<TypeGraph>,
    /// Map InodeId → FUSE inode number. FUSE uses u64 inode numbers.
    /// We use InodeId directly since they're already u64.
    /// Track open file handles: fh → InodeId
    open_files: Mutex<BTreeMap<u64, InodeId>>,
    next_fh: Mutex<u64>,
}

impl SotFsFilesystem {
    pub fn new() -> Self {
        Self {
            graph: Mutex::new(TypeGraph::new()),
            open_files: Mutex::new(BTreeMap::new()),
            next_fh: Mutex::new(1),
        }
    }

    fn alloc_fh(&self) -> u64 {
        let mut fh = self.next_fh.lock().unwrap();
        let id = *fh;
        *fh += 1;
        id
    }
}

/// Convert sotFS Inode to FUSE FileAttr.
fn inode_to_attr(inode: &Inode) -> FileAttr {
    let kind = match inode.vtype {
        VnodeType::Regular => FileType::RegularFile,
        VnodeType::Directory => FileType::Directory,
        VnodeType::Symlink => FileType::Symlink,
        VnodeType::CharDevice => FileType::CharDevice,
        VnodeType::BlockDevice => FileType::BlockDevice,
    };

    FileAttr {
        ino: inode.id,
        size: inode.size,
        blocks: (inode.size + 511) / 512,
        atime: inode.atime,
        mtime: inode.mtime,
        ctime: inode.ctime,
        crtime: inode.ctime,
        kind,
        perm: inode.permissions.mode(),
        nlink: inode.link_count,
        uid: inode.uid,
        gid: inode.gid,
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

impl Filesystem for SotFsFilesystem {
    // -------------------------------------------------------------------
    // Lookup: resolve a name in a directory
    // -------------------------------------------------------------------
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let g = self.graph.lock().unwrap();
        let name_str = name.to_str().unwrap_or("");

        // Find the directory for this parent inode
        let parent_dir = match g.dir_for_inode(parent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        match g.resolve_name(parent_dir, name_str) {
            Some(inode_id) => {
                if let Some(inode) = g.get_inode(inode_id) {
                    reply.entry(&TTL, &inode_to_attr(inode), 0);
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            None => reply.error(libc::ENOENT),
        }
    }

    // -------------------------------------------------------------------
    // getattr: return file attributes
    // -------------------------------------------------------------------
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let g = self.graph.lock().unwrap();
        match g.get_inode(ino) {
            Some(inode) => reply.attr(&TTL, &inode_to_attr(inode)),
            None => reply.error(libc::ENOENT),
        }
    }

    // -------------------------------------------------------------------
    // setattr: change file attributes (chmod, truncate, etc.)
    // -------------------------------------------------------------------
    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let mut g = self.graph.lock().unwrap();

        if let Some(m) = mode {
            if sotfs_ops::chmod(&mut g, ino, (m & 0o7777) as u16).is_err() {
                reply.error(libc::ENOENT);
                return;
            }
        }

        if uid.is_some() || gid.is_some() {
            if sotfs_ops::chown(&mut g, ino, uid, gid).is_err() {
                reply.error(libc::ENOENT);
                return;
            }
        }

        if let Some(new_size) = size {
            if sotfs_ops::truncate(&mut g, ino, new_size).is_err() {
                reply.error(libc::ENOENT);
                return;
            }
        }

        match g.get_inode(ino) {
            Some(inode) => reply.attr(&TTL, &inode_to_attr(inode)),
            None => reply.error(libc::ENOENT),
        }
    }

    // -------------------------------------------------------------------
    // readdir: list directory entries
    // -------------------------------------------------------------------
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let g = self.graph.lock().unwrap();

        let dir_id = match g.dir_for_inode(ino) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        let entries = g.list_dir(dir_id);
        for (i, (name, inode_id)) in entries.iter().enumerate().skip(offset as usize) {
            let kind = match g.get_inode(*inode_id) {
                Some(inode) => match inode.vtype {
                    VnodeType::Directory => FileType::Directory,
                    VnodeType::Symlink => FileType::Symlink,
                    _ => FileType::RegularFile,
                },
                None => FileType::RegularFile,
            };

            // reply.add returns true if the buffer is full
            if reply.add(*inode_id, (i + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    // -------------------------------------------------------------------
    // mkdir: create a directory
    // -------------------------------------------------------------------
    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let mut g = self.graph.lock().unwrap();
        let name_str = name.to_str().unwrap_or("");

        let parent_dir = match g.dir_for_inode(parent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        let perms = Permissions((mode & 0o7777) as u16);
        match sotfs_ops::mkdir(&mut g, parent_dir, name_str, req.uid(), req.gid(), perms) {
            Ok(result) => {
                let inode = &g.inodes[&result.inode_id];
                reply.entry(&TTL, &inode_to_attr(inode), 0);
            }
            Err(_) => reply.error(libc::EEXIST),
        }
    }

    // -------------------------------------------------------------------
    // rmdir: remove a directory
    // -------------------------------------------------------------------
    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let mut g = self.graph.lock().unwrap();
        let name_str = name.to_str().unwrap_or("");

        let parent_dir = match g.dir_for_inode(parent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        match sotfs_ops::rmdir(&mut g, parent_dir, name_str) {
            Ok(()) => reply.ok(),
            Err(sotfs_graph::GraphError::DirNotEmpty(_)) => reply.error(libc::ENOTEMPTY),
            Err(sotfs_graph::GraphError::NameNotFound(_)) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    // -------------------------------------------------------------------
    // create: create and open a file
    // -------------------------------------------------------------------
    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let mut g = self.graph.lock().unwrap();
        let name_str = name.to_str().unwrap_or("");

        let parent_dir = match g.dir_for_inode(parent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        let perms = Permissions((mode & 0o7777) as u16);
        match sotfs_ops::create_file(&mut g, parent_dir, name_str, req.uid(), req.gid(), perms) {
            Ok(inode_id) => {
                let fh = self.alloc_fh();
                self.open_files.lock().unwrap().insert(fh, inode_id);
                let inode = &g.inodes[&inode_id];
                reply.created(&TTL, &inode_to_attr(inode), 0, fh, 0);
            }
            Err(_) => reply.error(libc::EEXIST),
        }
    }

    // -------------------------------------------------------------------
    // unlink: remove a file
    // -------------------------------------------------------------------
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let mut g = self.graph.lock().unwrap();
        let name_str = name.to_str().unwrap_or("");

        let parent_dir = match g.dir_for_inode(parent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        match sotfs_ops::unlink(&mut g, parent_dir, name_str) {
            Ok(()) => reply.ok(),
            Err(sotfs_graph::GraphError::NameNotFound(_)) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    // -------------------------------------------------------------------
    // rename: move/rename a file or directory
    // -------------------------------------------------------------------
    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let mut g = self.graph.lock().unwrap();
        let old_name = name.to_str().unwrap_or("");
        let new_name = newname.to_str().unwrap_or("");

        let src_dir = match g.dir_for_inode(parent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let dst_dir = match g.dir_for_inode(newparent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        match sotfs_ops::rename(&mut g, src_dir, old_name, dst_dir, new_name) {
            Ok(()) => reply.ok(),
            Err(sotfs_graph::GraphError::WouldCreateCycle) => reply.error(libc::EINVAL),
            Err(sotfs_graph::GraphError::NameNotFound(_)) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    // -------------------------------------------------------------------
    // link: create a hard link
    // -------------------------------------------------------------------
    fn link(
        &mut self,
        _req: &Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let mut g = self.graph.lock().unwrap();
        let name_str = newname.to_str().unwrap_or("");

        let parent_dir = match g.dir_for_inode(newparent) {
            Some(d) => d,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        match sotfs_ops::link(&mut g, parent_dir, name_str, ino) {
            Ok(()) => {
                let inode = &g.inodes[&ino];
                reply.entry(&TTL, &inode_to_attr(inode), 0);
            }
            Err(sotfs_graph::GraphError::LinkToDirectory(_)) => reply.error(libc::EPERM),
            Err(sotfs_graph::GraphError::NameExists { .. }) => reply.error(libc::EEXIST),
            Err(_) => reply.error(libc::EIO),
        }
    }

    // -------------------------------------------------------------------
    // open: open a file
    // -------------------------------------------------------------------
    fn open(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        let g = self.graph.lock().unwrap();
        if g.contains_inode(ino) {
            let fh = self.alloc_fh();
            self.open_files.lock().unwrap().insert(fh, ino);
            reply.opened(fh, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    // -------------------------------------------------------------------
    // read: read file data
    // -------------------------------------------------------------------
    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let g = self.graph.lock().unwrap();
        match sotfs_ops::read_data(&g, ino, offset as u64, size as usize) {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(libc::EIO),
        }
    }

    // -------------------------------------------------------------------
    // write: write file data
    // -------------------------------------------------------------------
    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let mut g = self.graph.lock().unwrap();
        match sotfs_ops::write_data(&mut g, ino, offset as u64, data) {
            Ok(written) => reply.written(written as u32),
            Err(_) => reply.error(libc::EIO),
        }
    }

    // -------------------------------------------------------------------
    // release: close a file handle
    // -------------------------------------------------------------------
    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.open_files.lock().unwrap().remove(&fh);
        reply.ok();
    }

    // -------------------------------------------------------------------
    // opendir / releasedir
    // -------------------------------------------------------------------
    fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        let g = self.graph.lock().unwrap();
        if g.dir_for_inode(ino).is_some() {
            reply.opened(0, 0);
        } else {
            reply.error(libc::ENOTDIR);
        }
    }

    fn releasedir(&mut self, _req: &Request, _ino: u64, _fh: u64, _flags: i32, reply: ReplyEmpty) {
        reply.ok();
    }
}

/// Parse CLI args and mount the filesystem.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: sotfs-fuse <mountpoint>");
        std::process::exit(1);
    }

    let mountpoint = &args[1];
    let fs = SotFsFilesystem::new();

    let options = vec![
        MountOption::RW,
        MountOption::FSName("sotfs".to_string()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
    ];

    println!("sotFS: mounting at {}", mountpoint);
    println!("sotFS: type graph initialized (root inode=1, root dir=1)");
    println!("sotFS: Ctrl+C to unmount");

    fuser::mount2(fs, mountpoint, &options).expect("failed to mount sotFS");
}
