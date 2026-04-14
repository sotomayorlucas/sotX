//! VFS-IPC client — lets non-LUCAS native sotOS binaries (sotsh, future
//! tools) read directories, read files, and change cwd through init's
//! VFS-IPC server without having to speak the Linux ABI.
//!
//! Protocol documented in `docs/sotsh-ipc-protocols.md` (Part A).
//! Reference implementation of the server side lives in
//! `services/init/src/vfs_service.rs`.
//!
//! Wire format (one `IpcMsg` per round-trip, 64 B payload max):
//!
//! | tag | op              | request                                    | reply                                                                     |
//! |-----|-----------------|--------------------------------------------|---------------------------------------------------------------------------|
//! | 1   | `VFS_OPEN`      | path inline regs[0..6], flags regs[6], len regs[7] | tag=0, regs[0]=fd, regs[1]=kind (13=file, 14=dir), regs[2]=size   |
//! | 2   | `VFS_CLOSE`     | regs[0]=fd                                  | tag=0 / -errno                                                            |
//! | 3   | `VFS_READ`      | regs[0]=fd, regs[1]=max_bytes (<=56)        | tag=bytes (0=EOF, neg=errno), regs[0..7]=up to 56 B LE-packed             |
//! | 5   | `VFS_STAT`      | path inline regs[0..6], len regs[7]         | tag=0, regs[0]=size, regs[1]=mode, regs[2]=nlink, regs[3]=uid, regs[4]=gid, regs[5]=mtime, regs[6]=kind |
//! | 6   | `VFS_GETDENTS64`| regs[0]=fd                                  | tag=name_len (0=EOF, neg=errno), regs[0]=oid, regs[1]=kind, regs[2..7]=name bytes (≤ 40 B) |
//! | 11  | `VFS_CHDIR`     | path inline regs[0..6], len regs[7]         | tag=0 / -errno                                                            |
//! | 12  | `VFS_FSTAT`     | regs[0]=fd                                  | same layout as VFS_STAT                                                   |
//!
//! Paths travel inline only; anything >48 B gets `-ENAMETOOLONG`.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::sys;
use crate::IpcMsg;

// ---------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------

pub const VFS_OPEN: u64 = 1;
pub const VFS_CLOSE: u64 = 2;
pub const VFS_READ: u64 = 3;
pub const VFS_STAT: u64 = 5;
pub const VFS_GETDENTS64: u64 = 6;
pub const VFS_CHDIR: u64 = 11;
pub const VFS_FSTAT: u64 = 12;

/// Max path bytes that fit inline in a single IpcMsg (regs[0..6] = 48 B).
pub const VFS_MAX_INLINE_PATH: usize = 48;
/// Max data bytes per VFS_READ round-trip.
pub const VFS_READ_CHUNK: usize = 56;
/// Max name bytes per VFS_GETDENTS64 entry.
pub const VFS_DIRENT_NAME_MAX: usize = 40;

// Errno negatives used by the client (mirror subset of linux_abi).
const ENAMETOOLONG: i64 = -36;
const EIO: i64 = -5;

// ---------------------------------------------------------------
// Cached "vfs" endpoint cap
// ---------------------------------------------------------------

/// Cached endpoint cap for the "vfs" service (0 = not yet resolved).
static VFS_EP_CAP: AtomicU64 = AtomicU64::new(0);

/// Resolve + cache the VFS endpoint. Returns the cap on success, or a
/// negative errno on failure (EIO if `svc_lookup` fails).
fn vfs_ep() -> Result<u64, i64> {
    let cached = VFS_EP_CAP.load(Ordering::Acquire);
    if cached != 0 {
        return Ok(cached);
    }
    let name = b"vfs";
    match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
        Ok(cap) => {
            VFS_EP_CAP.store(cap, Ordering::Release);
            Ok(cap)
        }
        Err(_) => Err(EIO),
    }
}

/// Override the cached "vfs" endpoint cap — useful if the client was
/// handed a cap via BootInfo slots instead of via `svc_lookup`.
pub fn set_vfs_ep(cap: u64) {
    VFS_EP_CAP.store(cap, Ordering::Release);
}

// ---------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------

/// Decode a tag that might be either a byte count (non-negative) or a
/// negative errno. Returns Ok(count) or Err(errno<0).
fn tag_to_result(tag: u64) -> Result<u64, i64> {
    let signed = tag as i64;
    if signed < 0 { Err(signed) } else { Ok(tag) }
}

/// Pack up to 48 B of path bytes into regs[0..6] (NUL-padded) and stash
/// the length in regs[7] low 32. Returns `Err(-ENAMETOOLONG)` if the
/// path doesn't fit.
fn pack_path(path: &[u8], msg: &mut IpcMsg) -> Result<(), i64> {
    if path.len() > VFS_MAX_INLINE_PATH {
        return Err(ENAMETOOLONG);
    }
    let mut buf = [0u8; VFS_MAX_INLINE_PATH];
    buf[..path.len()].copy_from_slice(path);
    for i in 0..6 {
        msg.regs[i] = u64::from_le_bytes([
            buf[i * 8], buf[i * 8 + 1], buf[i * 8 + 2], buf[i * 8 + 3],
            buf[i * 8 + 4], buf[i * 8 + 5], buf[i * 8 + 6], buf[i * 8 + 7],
        ]);
    }
    msg.regs[7] = path.len() as u64;
    Ok(())
}

/// Unpack `count` bytes from regs[0..7] into `out` (LE 8-byte chunks).
/// Caller has to ensure `out.len() >= count` and `count <= 56`.
fn unpack_bytes(regs: &[u64; 8], count: usize, out: &mut [u8]) {
    let mut buf = [0u8; 56];
    for i in 0..7 {
        buf[i * 8..i * 8 + 8].copy_from_slice(&regs[i].to_le_bytes());
    }
    let n = count.min(56).min(out.len());
    out[..n].copy_from_slice(&buf[..n]);
}

// ---------------------------------------------------------------
// Public API
// ---------------------------------------------------------------

/// Result of a successful `vfs_open`.
#[derive(Clone, Copy, Debug)]
pub struct OpenResult {
    pub fd: u64,
    /// 13 = regular file, 14 = directory (matches init's FD kind scheme).
    pub kind: u8,
    pub size: u64,
}

/// Result of `vfs_stat` / `vfs_fstat`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StatResult {
    pub size: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub kind: u8,
}

/// One directory entry returned by `vfs_getdents64_next`.
#[derive(Clone, Copy, Debug)]
pub struct DirentResult {
    pub oid: u64,
    pub kind: u8,
    pub name_len: usize,
    pub name: [u8; VFS_DIRENT_NAME_MAX],
}

/// Open a path via the VFS server. `flags` are the usual `O_*` bits.
pub fn vfs_open(path: &[u8], flags: u64) -> Result<OpenResult, i64> {
    let ep = vfs_ep()?;
    let mut msg = IpcMsg::empty();
    msg.tag = VFS_OPEN;
    pack_path(path, &mut msg)?;
    msg.regs[6] = flags;
    let reply = sys::call(ep, &msg).map_err(|_| EIO)?;
    tag_to_result(reply.tag)?;
    Ok(OpenResult {
        fd: reply.regs[0],
        kind: reply.regs[1] as u8,
        size: reply.regs[2],
    })
}

/// Close a fd previously returned by `vfs_open`.
pub fn vfs_close(fd: u64) -> Result<(), i64> {
    let ep = vfs_ep()?;
    let mut msg = IpcMsg::empty();
    msg.tag = VFS_CLOSE;
    msg.regs[0] = fd;
    let reply = sys::call(ep, &msg).map_err(|_| EIO)?;
    tag_to_result(reply.tag)?;
    Ok(())
}

/// Read up to `out.len()` bytes from `fd`. Loops across multiple
/// IPC round-trips (VFS_READ caps each reply at 56 B). Returns the
/// number of bytes read (0 = EOF).
pub fn vfs_read(fd: u64, out: &mut [u8]) -> Result<usize, i64> {
    let ep = vfs_ep()?;
    let mut total = 0usize;
    while total < out.len() {
        let want = (out.len() - total).min(VFS_READ_CHUNK);
        let mut msg = IpcMsg::empty();
        msg.tag = VFS_READ;
        msg.regs[0] = fd;
        msg.regs[1] = want as u64;
        let reply = sys::call(ep, &msg).map_err(|_| EIO)?;
        let n = tag_to_result(reply.tag)? as usize;
        if n == 0 {
            break; // EOF
        }
        let copy = n.min(out.len() - total);
        unpack_bytes(&reply.regs, copy, &mut out[total..total + copy]);
        total += copy;
        if n < VFS_READ_CHUNK {
            break;
        }
    }
    Ok(total)
}

/// Fetch the next directory entry from a directory `fd`. Returns
/// `Ok(None)` on EOF, `Ok(Some(entry))` otherwise.
pub fn vfs_getdents64(fd: u64) -> Result<Option<DirentResult>, i64> {
    let ep = vfs_ep()?;
    let mut msg = IpcMsg::empty();
    msg.tag = VFS_GETDENTS64;
    msg.regs[0] = fd;
    let reply = sys::call(ep, &msg).map_err(|_| EIO)?;
    let name_len = tag_to_result(reply.tag)? as usize;
    if name_len == 0 {
        return Ok(None);
    }
    let mut name = [0u8; VFS_DIRENT_NAME_MAX];
    // regs[2..7] = up to 40 B of name bytes.
    let mut buf = [0u8; VFS_DIRENT_NAME_MAX];
    for i in 0..5 {
        buf[i * 8..i * 8 + 8].copy_from_slice(&reply.regs[i + 2].to_le_bytes());
    }
    let n = name_len.min(VFS_DIRENT_NAME_MAX);
    name[..n].copy_from_slice(&buf[..n]);
    Ok(Some(DirentResult {
        oid: reply.regs[0],
        kind: reply.regs[1] as u8,
        name_len: n,
        name,
    }))
}

/// Stat a path.
pub fn vfs_stat(path: &[u8]) -> Result<StatResult, i64> {
    let ep = vfs_ep()?;
    let mut msg = IpcMsg::empty();
    msg.tag = VFS_STAT;
    pack_path(path, &mut msg)?;
    let reply = sys::call(ep, &msg).map_err(|_| EIO)?;
    tag_to_result(reply.tag)?;
    Ok(StatResult {
        size: reply.regs[0],
        mode: reply.regs[1] as u32,
        nlink: reply.regs[2] as u32,
        uid: reply.regs[3] as u32,
        gid: reply.regs[4] as u32,
        mtime: reply.regs[5],
        kind: reply.regs[6] as u8,
    })
}

/// Stat an open fd.
pub fn vfs_fstat(fd: u64) -> Result<StatResult, i64> {
    let ep = vfs_ep()?;
    let mut msg = IpcMsg::empty();
    msg.tag = VFS_FSTAT;
    msg.regs[0] = fd;
    let reply = sys::call(ep, &msg).map_err(|_| EIO)?;
    tag_to_result(reply.tag)?;
    Ok(StatResult {
        size: reply.regs[0],
        mode: reply.regs[1] as u32,
        nlink: reply.regs[2] as u32,
        uid: reply.regs[3] as u32,
        gid: reply.regs[4] as u32,
        mtime: reply.regs[5],
        kind: reply.regs[6] as u8,
    })
}

/// Change the server-side cwd for this client.
pub fn vfs_chdir(path: &[u8]) -> Result<(), i64> {
    let ep = vfs_ep()?;
    let mut msg = IpcMsg::empty();
    msg.tag = VFS_CHDIR;
    pack_path(path, &mut msg)?;
    let reply = sys::call(ep, &msg).map_err(|_| EIO)?;
    tag_to_result(reply.tag)?;
    Ok(())
}
