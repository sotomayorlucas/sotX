//! VFS-IPC server — a dedicated init thread that serves non-LUCAS
//! native sotOS clients (sotsh, future tools) over the protocol
//! documented in `docs/sotsh-ipc-protocols.md` (Part A). The matching
//! client lives in `libs/sotos-common/src/vfs.rs`.
//!
//! Design decisions locked in by the spec:
//!   - Separate endpoint (service name `"vfs"`), NOT multiplexed with
//!     anything else and NOT branched off `lucas_handler`.
//!   - cwd lives server-side (this module's `CWD`).
//!   - Paths travel inline (<= 48 B); larger paths get `-ENAMETOOLONG`.
//!   - Per-op replies fit in a single IpcMsg (≤ 56 B data). READ and
//!     GETDENTS64 are chunked: clients loop until EOF.
//!
//! MVP simplification over the design doc: the server keeps a **single
//! global FD table** rather than per-client tables. That is sufficient
//! for B2a (sotsh is the only client today). Swapping in per-pid state
//! is a drop-in change once a cap-transfer or sender-tid path lands.

use core::sync::atomic::{AtomicU64, Ordering};

use sotos_common::sys;
use sotos_common::IpcMsg;
use sotos_common::vfs::{
    VFS_OPEN, VFS_CLOSE, VFS_READ, VFS_STAT, VFS_GETDENTS64, VFS_CHDIR, VFS_FSTAT,
    VFS_MAX_INLINE_PATH, VFS_READ_CHUNK, VFS_DIRENT_NAME_MAX,
};
use sotos_objstore::{DirEntry, ROOT_OID};

use crate::fd::{resolve_with_cwd, GRP_CWD_MAX};
use crate::framebuffer::{print, print_u64};
use crate::{shared_store, vfs_lock, vfs_unlock};

// Linux errno negatives we hand back in the `tag` field on failure.
const ENOENT: i64 = -2;
const EIO: i64 = -5;
const EBADF: i64 = -9;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENAMETOOLONG: i64 = -36;

// ---------------------------------------------------------------
// Stack + endpoint globals
// ---------------------------------------------------------------

/// VFS service handler stack (8 pages = 32 KiB).
const VFS_SVC_STACK: u64 = 0xEC0000;
const VFS_SVC_STACK_PAGES: u64 = 8;

/// IPC endpoint cap — shared between `start_vfs_service` and
/// `vfs_service_thread` via atomic.
static VFS_EP_CAP: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------
// Per-client (currently single-client) FD + cwd state
// ---------------------------------------------------------------

const MAX_FDS: usize = 64;

#[derive(Clone, Copy)]
struct FdSlot {
    in_use: bool,
    oid: u64,
    is_dir: bool,
    size: u64,
    off: u64,
    /// Monotonic directory cursor — index into `store.list_dir` output.
    dir_pos: u32,
}

impl FdSlot {
    const fn empty() -> Self {
        Self { in_use: false, oid: 0, is_dir: false, size: 0, off: 0, dir_pos: 0 }
    }
}

static mut FDS: [FdSlot; MAX_FDS] = [FdSlot::empty(); MAX_FDS];
static mut CWD: [u8; GRP_CWD_MAX] = {
    let mut b = [0u8; GRP_CWD_MAX];
    b[0] = b'/';
    b
};

fn fd_alloc() -> Option<usize> {
    unsafe {
        for i in 0..MAX_FDS {
            if !FDS[i].in_use {
                return Some(i);
            }
        }
    }
    None
}

fn fd_get(fd: u64) -> Option<FdSlot> {
    let i = fd as usize;
    if i >= MAX_FDS { return None; }
    unsafe { if FDS[i].in_use { Some(FDS[i]) } else { None } }
}

fn fd_set(fd: u64, slot: FdSlot) {
    let i = fd as usize;
    if i < MAX_FDS {
        unsafe { FDS[i] = slot; }
    }
}

fn fd_free(fd: u64) -> bool {
    let i = fd as usize;
    if i >= MAX_FDS { return false; }
    unsafe {
        if !FDS[i].in_use { return false; }
        FDS[i] = FdSlot::empty();
    }
    true
}

// ---------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------

fn cwd_set(path: &[u8]) {
    unsafe {
        let n = path.len().min(GRP_CWD_MAX - 1);
        CWD[..n].copy_from_slice(&path[..n]);
        for b in &mut CWD[n..] { *b = 0; }
    }
}

/// Resolve `path` against the server-side cwd. Thin wrapper over
/// `fd::resolve_with_cwd` so our cwd semantics stay byte-compatible
/// with LUCAS's `GRP_CWD`.
fn resolve_cwd(path: &[u8], out: &mut [u8; 256]) -> usize {
    unsafe { resolve_with_cwd(&CWD, path, out) }
}

/// Unpack an inline path from `regs[0..6]` / `regs[7]` low 32.
/// Returns `Err(-ENAMETOOLONG)` if len > 48.
fn unpack_path(msg: &IpcMsg, buf: &mut [u8; VFS_MAX_INLINE_PATH]) -> Result<usize, i64> {
    let len = msg.regs[7] as usize;
    if len > VFS_MAX_INLINE_PATH {
        return Err(ENAMETOOLONG);
    }
    for i in 0..6 {
        buf[i * 8..i * 8 + 8].copy_from_slice(&msg.regs[i].to_le_bytes());
    }
    Ok(len)
}

/// Pack `bytes` into `regs[start_reg..]` as little-endian u64 chunks.
/// Caller guarantees `(8 - start_reg) * 8 >= bytes.len()`.
fn pack_bytes_into_regs(regs: &mut [u64; 8], start_reg: usize, bytes: &[u8]) {
    let mut buf = [0u8; 56];
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    let slots = 8 - start_reg;
    for i in 0..slots {
        let o = i * 8;
        if o >= buf.len() { break; }
        regs[start_reg + i] = u64::from_le_bytes([
            buf[o], buf[o + 1], buf[o + 2], buf[o + 3],
            buf[o + 4], buf[o + 5], buf[o + 6], buf[o + 7],
        ]);
    }
}

// ---------------------------------------------------------------
// Reply helpers
// ---------------------------------------------------------------

fn reply_err(ep: u64, errno: i64) {
    let msg = IpcMsg { tag: errno as u64, regs: [0; 8] };
    let _ = sys::send(ep, &msg);
}

fn reply_ok(ep: u64, regs: [u64; 8]) {
    let msg = IpcMsg { tag: 0, regs };
    let _ = sys::send(ep, &msg);
}

/// Reply with a raw tag value (non-zero success payload such as byte
/// count for READ or name_len for GETDENTS64).
fn reply_tag(ep: u64, tag: u64, regs: [u64; 8]) {
    let msg = IpcMsg { tag, regs };
    let _ = sys::send(ep, &msg);
}

// ---------------------------------------------------------------
// Public: spawn the service
// ---------------------------------------------------------------

/// Create the `vfs` endpoint, register it in the kernel service
/// registry, and fork off the handler thread.
pub fn start_vfs_service() {
    let ep = match sys::endpoint_create() {
        Ok(c) => c,
        Err(_) => {
            print(b"vfs: endpoint_create failed\n");
            return;
        }
    };
    VFS_EP_CAP.store(ep, Ordering::Release);

    let name = b"vfs";
    if sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep).is_err() {
        print(b"vfs: svc_register failed\n");
        return;
    }

    // Map handler stack.
    for i in 0..VFS_SVC_STACK_PAGES {
        let f = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => { print(b"vfs: frame_alloc failed\n"); return; }
        };
        if sys::map(VFS_SVC_STACK + i * 0x1000, f, 2 /* MAP_WRITABLE */).is_err() {
            print(b"vfs: map failed\n");
            return;
        }
    }

    match sys::thread_create(
        vfs_service_thread as *const () as u64,
        VFS_SVC_STACK + VFS_SVC_STACK_PAGES * 0x1000,
    ) {
        Ok(_) => {
            print(b"vfs: registered (cap=");
            print_u64(ep);
            print(b")\n");
        }
        Err(_) => print(b"vfs: thread_create failed\n"),
    }
}

// ---------------------------------------------------------------
// Handler thread — single recv loop
// ---------------------------------------------------------------

extern "C" fn vfs_service_thread() -> ! {
    let ep = VFS_EP_CAP.load(Ordering::Acquire);
    loop {
        let msg = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => { sys::yield_now(); continue; }
        };
        match msg.tag {
            VFS_OPEN        => handle_open(ep, &msg),
            VFS_CLOSE       => handle_close(ep, &msg),
            VFS_READ        => handle_read(ep, &msg),
            VFS_STAT        => handle_stat(ep, &msg),
            VFS_GETDENTS64  => handle_getdents64(ep, &msg),
            VFS_CHDIR       => handle_chdir(ep, &msg),
            VFS_FSTAT       => handle_fstat(ep, &msg),
            _               => reply_err(ep, EINVAL),
        }
    }
}

// ---------------------------------------------------------------
// Op handlers
// ---------------------------------------------------------------

fn handle_open(ep: u64, msg: &IpcMsg) {
    let mut path_buf = [0u8; VFS_MAX_INLINE_PATH];
    let path_len = match unpack_path(msg, &mut path_buf) {
        Ok(n) => n,
        Err(e) => return reply_err(ep, e),
    };
    let mut resolved = [0u8; 256];
    let rlen = resolve_cwd(&path_buf[..path_len], &mut resolved);
    let name = &resolved[..rlen];

    vfs_lock();
    let lookup = unsafe { shared_store() }.and_then(|store| {
        store.resolve_path(name, ROOT_OID).ok()
            .and_then(|oid| store.stat(oid).map(|entry| (oid, entry)))
    });
    vfs_unlock();

    let (oid, entry) = match lookup {
        Some(x) => x,
        None => return reply_err(ep, ENOENT),
    };

    let fd_idx = match fd_alloc() {
        Some(i) => i,
        None => return reply_err(ep, EMFILE),
    };
    let is_dir = entry.is_dir();
    fd_set(fd_idx as u64, FdSlot {
        in_use: true,
        oid,
        is_dir,
        size: entry.size,
        off: 0,
        dir_pos: 0,
    });
    let kind: u8 = if is_dir { 14 } else { 13 };
    let size = if is_dir { 0 } else { entry.size };
    reply_ok(ep, [fd_idx as u64, kind as u64, size, 0, 0, 0, 0, 0]);
}

fn handle_close(ep: u64, msg: &IpcMsg) {
    let fd = msg.regs[0];
    if fd_free(fd) {
        reply_ok(ep, [0; 8]);
    } else {
        reply_err(ep, EBADF);
    }
}

fn handle_read(ep: u64, msg: &IpcMsg) {
    let fd = msg.regs[0];
    let want = (msg.regs[1] as usize).min(VFS_READ_CHUNK);

    let mut slot = match fd_get(fd) {
        Some(s) => s,
        None => return reply_err(ep, EBADF),
    };
    if slot.is_dir { return reply_err(ep, EISDIR); }

    let remaining = slot.size.saturating_sub(slot.off) as usize;
    let count = want.min(remaining);
    if count == 0 {
        // EOF: tag=0
        return reply_tag(ep, 0, [0; 8]);
    }

    let mut data = [0u8; VFS_READ_CHUNK];
    vfs_lock();
    let read_res = unsafe { shared_store() }
        .ok_or(EIO)
        .and_then(|store| store.read_obj_range(slot.oid, slot.off as usize, &mut data[..count])
            .map_err(|_| EIO));
    vfs_unlock();

    let n = match read_res {
        Ok(n) => n,
        Err(e) => return reply_err(ep, e),
    };
    slot.off += n as u64;
    fd_set(fd, slot);

    let mut regs = [0u64; 8];
    pack_bytes_into_regs(&mut regs, 0, &data[..n]);
    reply_tag(ep, n as u64, regs);
}

fn pack_stat(size: u64, is_dir: bool, entry: &DirEntry) -> [u64; 8] {
    // Minimal 7-field stat: (size, mode, nlink, uid, gid, mtime, kind).
    // mode: tack S_IFDIR/S_IFREG on top of the stored perm bits.
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    let mode = if is_dir {
        S_IFDIR | (entry.permissions & 0o777)
    } else {
        S_IFREG | (entry.permissions & 0o777)
    };
    let kind: u8 = if is_dir { 14 } else { 13 };
    [
        size,
        mode as u64,
        1, // nlink
        entry.owner_uid as u64,
        entry.owner_gid as u64,
        entry.modified_time,
        kind as u64,
        0,
    ]
}

fn handle_stat(ep: u64, msg: &IpcMsg) {
    let mut path_buf = [0u8; VFS_MAX_INLINE_PATH];
    let path_len = match unpack_path(msg, &mut path_buf) {
        Ok(n) => n,
        Err(e) => return reply_err(ep, e),
    };
    let mut resolved = [0u8; 256];
    let rlen = resolve_cwd(&path_buf[..path_len], &mut resolved);
    let name = &resolved[..rlen];

    vfs_lock();
    let entry = unsafe { shared_store() }.and_then(|store| {
        store.resolve_path(name, ROOT_OID).ok().and_then(|oid| store.stat(oid))
    });
    vfs_unlock();

    match entry {
        Some(e) => {
            let size = if e.is_dir() { 0 } else { e.size };
            reply_ok(ep, pack_stat(size, e.is_dir(), &e));
        }
        None => reply_err(ep, ENOENT),
    }
}

fn handle_fstat(ep: u64, msg: &IpcMsg) {
    let fd = msg.regs[0];
    let slot = match fd_get(fd) {
        Some(s) => s,
        None => return reply_err(ep, EBADF),
    };

    vfs_lock();
    let entry = unsafe { shared_store() }.and_then(|store| store.stat(slot.oid));
    vfs_unlock();

    match entry {
        Some(e) => {
            let size = if e.is_dir() { 0 } else { e.size };
            reply_ok(ep, pack_stat(size, e.is_dir(), &e));
        }
        None => reply_err(ep, ENOENT),
    }
}

fn handle_getdents64(ep: u64, msg: &IpcMsg) {
    let fd = msg.regs[0];
    let mut slot = match fd_get(fd) {
        Some(s) => s,
        None => return reply_err(ep, EBADF),
    };
    if !slot.is_dir { return reply_err(ep, ENOTDIR); }

    // Re-list the parent directory each call — list_dir is cheap (at
    // most DIR_ENTRIES walks) and avoids stashing a huge buffer per
    // fd.
    const MAX_ENTS: usize = 128;
    let mut ents: [DirEntry; MAX_ENTS] = [DirEntry::zeroed(); MAX_ENTS];

    vfs_lock();
    let count = unsafe { shared_store() }
        .map(|store| store.list_dir(slot.oid, &mut ents))
        .unwrap_or(0);
    vfs_unlock();

    let pos = slot.dir_pos as usize;
    if pos >= count {
        // EOF
        return reply_tag(ep, 0, [0; 8]);
    }
    let entry = &ents[pos];
    slot.dir_pos += 1;
    fd_set(fd, slot);

    let name = entry.name_as_str();
    let name_len = name.len().min(VFS_DIRENT_NAME_MAX);

    let kind: u8 = if entry.is_dir() { 14 } else { 13 };
    let mut regs = [0u64; 8];
    regs[0] = entry.oid;
    regs[1] = kind as u64;
    pack_bytes_into_regs(&mut regs, 2, &name[..name_len]);
    reply_tag(ep, name_len as u64, regs);
}

fn handle_chdir(ep: u64, msg: &IpcMsg) {
    let mut path_buf = [0u8; VFS_MAX_INLINE_PATH];
    let path_len = match unpack_path(msg, &mut path_buf) {
        Ok(n) => n,
        Err(e) => return reply_err(ep, e),
    };
    let mut resolved = [0u8; 256];
    let rlen = resolve_cwd(&path_buf[..path_len], &mut resolved);
    let name = &resolved[..rlen];

    // Validate the target exists and is a directory.
    vfs_lock();
    let ok = unsafe { shared_store() }.and_then(|store| {
        store.resolve_path(name, ROOT_OID).ok().and_then(|oid| store.stat(oid))
    });
    vfs_unlock();

    match ok {
        Some(e) if e.is_dir() => {
            cwd_set(name);
            reply_ok(ep, [0; 8]);
        }
        Some(_) => reply_err(ep, ENOTDIR),
        None => reply_err(ep, ENOENT),
    }
}
