// ---------------------------------------------------------------------------
// sotFS delegation layer: routes VfsOps to the sotfs service via IPC.
//
// When a path falls under the sotFS mount prefix ("/sotfs/"), open/read/write
// etc. are forwarded to the sotfs service endpoint instead of the ObjectStore.
//
// FD kind codes: 36 = sotFS file, 37 = sotFS directory
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::IpcMsg;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::exec::reply_val;
use crate::fd::*;
use crate::syscalls::context::SyscallContext;

/// sotFS mount point prefix.
pub const SOTFS_MOUNT: &[u8] = b"/sotfs/";
pub const SOTFS_MOUNT_EXACT: &[u8] = b"/sotfs";

/// Cached endpoint cap for the sotfs service (0 = not looked up yet).
static SOTFS_EP: AtomicU64 = AtomicU64::new(0);

/// FD kind for sotFS-backed regular files.
pub const FD_KIND_SOTFS_FILE: u8 = 36;
/// FD kind for sotFS-backed directories.
pub const FD_KIND_SOTFS_DIR: u8 = 37;

/// Per-slot sotFS inode tracking: [inode_id, size, offset, fd]
/// Shared with child processes via the group FD mechanism.
pub static mut SOTFS_FILES: [[u64; 4]; 64] = [[0u64; 4]; 64];
pub static mut SOTFS_FILES_LOCK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn sotfs_lock() {
    while unsafe {
        SOTFS_FILES_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
    }
    .is_err()
    {
        core::hint::spin_loop();
    }
}

fn sotfs_unlock() {
    unsafe {
        SOTFS_FILES_LOCK.store(false, Ordering::Release);
    }
}

/// Look up the sotfs service endpoint (cached after first call).
pub fn sotfs_endpoint() -> Option<u64> {
    let cached = SOTFS_EP.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached);
    }
    // svc_lookup("sotfs")
    let name = b"sotfs";
    match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
        Ok(ep) => {
            SOTFS_EP.store(ep, Ordering::Release);
            Some(ep)
        }
        Err(_) => None,
    }
}

/// Check if a path should be handled by sotFS.
pub fn is_sotfs_path(path: &[u8]) -> bool {
    path.starts_with(SOTFS_MOUNT) || path == SOTFS_MOUNT_EXACT
}

/// Strip the /sotfs prefix from a path, returning the relative part.
/// "/sotfs/foo/bar" → "foo/bar", "/sotfs" → ""
pub fn strip_prefix(path: &[u8]) -> &[u8] {
    if path.starts_with(SOTFS_MOUNT) {
        &path[SOTFS_MOUNT.len()..]
    } else if path == SOTFS_MOUNT_EXACT {
        b""
    } else {
        path
    }
}

/// Open a file/dir on sotFS. Returns (inode_id, is_dir, size) on success.
pub fn sotfs_open(path: &[u8], flags: u64) -> Result<(u64, bool, u64), i64> {
    let ep = sotfs_endpoint().ok_or(-2i64)?; // ENOENT if service not up

    let rel = strip_prefix(path);

    // Pack path into IPC regs: tag=1 (Open), regs[0]=flags, regs[1..7]=path bytes
    let mut regs = [0u64; 8];
    regs[0] = flags;

    // Pack relative path bytes into regs[1..7] (up to 56 bytes)
    let mut buf = [0u8; 56];
    let copy_len = rel.len().min(56);
    buf[..copy_len].copy_from_slice(&rel[..copy_len]);
    for i in 0..7 {
        regs[i + 1] = u64::from_le_bytes([
            buf[i * 8],
            buf.get(i * 8 + 1).copied().unwrap_or(0),
            buf.get(i * 8 + 2).copied().unwrap_or(0),
            buf.get(i * 8 + 3).copied().unwrap_or(0),
            buf.get(i * 8 + 4).copied().unwrap_or(0),
            buf.get(i * 8 + 5).copied().unwrap_or(0),
            buf.get(i * 8 + 6).copied().unwrap_or(0),
            buf.get(i * 8 + 7).copied().unwrap_or(0),
        ]);
    }

    let call_msg = IpcMsg { tag: 5, regs }; // tag=5 = Stat (check existence + get metadata)
    let reply = sys::call(ep, &call_msg).map_err(|_| -5i64)?; // EIO

    if reply.tag as i64 >= 0 {
        let size = reply.regs[0];
        let mode = reply.regs[1] as u32;
        let is_dir = (mode & 0o040000) != 0;
        let inode_id = if rel.is_empty() { 1 } else { reply.regs[2] };
        Ok((inode_id, is_dir, size))
    } else {
        Err(reply.tag as i64)
    }
}

/// Allocate a sotFS file slot and assign an FD.
pub fn sotfs_assign_fd(
    ctx: &mut SyscallContext,
    inode_id: u64,
    is_dir: bool,
    size: u64,
) -> Option<usize> {
    // Find a free FD
    let fd = (3..GRP_MAX_FDS).find(|&f| ctx.child_fds[f] == 0)?;

    // Find a free sotFS slot
    sotfs_lock();
    let slot = (0..64).find(|&s| unsafe { SOTFS_FILES[s][0] } == 0);
    if let Some(s) = slot {
        unsafe {
            SOTFS_FILES[s] = [inode_id, size, 0, fd as u64];
        }
    }
    sotfs_unlock();

    slot?; // return None if no free slot

    ctx.child_fds[fd] = if is_dir {
        FD_KIND_SOTFS_DIR
    } else {
        FD_KIND_SOTFS_FILE
    };

    Some(fd)
}

/// Read from a sotFS file via IPC.
pub fn read_sotfs(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let ep = match sotfs_endpoint() {
        Some(e) => e,
        None => {
            reply_val(ctx.ep_cap, -5); // EIO
            return;
        }
    };

    // Find the sotFS slot for this FD
    sotfs_lock();
    let slot = (0..64).find(|&s| unsafe { SOTFS_FILES[s][3] } == fd as u64 && unsafe { SOTFS_FILES[s][0] } != 0);
    let (inode_id, offset) = match slot {
        Some(s) => unsafe { (SOTFS_FILES[s][0], SOTFS_FILES[s][2]) },
        None => {
            sotfs_unlock();
            reply_val(ctx.ep_cap, -9); // EBADF
            return;
        }
    };
    sotfs_unlock();

    // IPC: tag=3 (Read), regs[0]=inode_id, regs[1]=offset, regs[2]=len
    let call_msg = IpcMsg {
        tag: 3,
        regs: [inode_id, offset, len as u64, 0, 0, 0, 0, 0],
    };

    let reply = match sys::call(ep, &call_msg) {
        Ok(r) => r,
        Err(_) => {
            reply_val(ctx.ep_cap, -5);
            return;
        }
    };

    let byte_count = reply.tag as usize;
    if byte_count == 0 {
        reply_val(ctx.ep_cap, 0); // EOF
        return;
    }

    // Unpack data from reply.regs[1..7] and write to child's buffer
    let mut data = [0u8; 56];
    for i in 0..7 {
        let bytes = reply.regs[i + 1].to_le_bytes();
        data[i * 8..i * 8 + 8].copy_from_slice(&bytes);
    }

    let actual = byte_count.min(len).min(56);
    ctx.guest_write(buf_ptr, &data[..actual]);

    // Update offset
    sotfs_lock();
    if let Some(s) = (0..64).find(|&s| unsafe { SOTFS_FILES[s][3] } == fd as u64) {
        unsafe {
            SOTFS_FILES[s][2] += actual as u64;
        }
    }
    sotfs_unlock();

    reply_val(ctx.ep_cap, actual as i64);
}

/// Write to a sotFS file via IPC.
pub fn write_sotfs(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let ep = match sotfs_endpoint() {
        Some(e) => e,
        None => {
            reply_val(ctx.ep_cap, -5);
            return;
        }
    };

    sotfs_lock();
    let slot = (0..64).find(|&s| unsafe { SOTFS_FILES[s][3] } == fd as u64 && unsafe { SOTFS_FILES[s][0] } != 0);
    let (inode_id, offset) = match slot {
        Some(s) => unsafe { (SOTFS_FILES[s][0], SOTFS_FILES[s][2]) },
        None => {
            sotfs_unlock();
            reply_val(ctx.ep_cap, -9);
            return;
        }
    };
    sotfs_unlock();

    // Read data from child's buffer (max 40 bytes per IPC)
    let actual = len.min(40);
    let mut buf = [0u8; 40];
    ctx.guest_read(buf_ptr, &mut buf[..actual]);

    // IPC: tag=4 (Write), regs[0]=inode_id, regs[1]=offset, regs[2]=data_len, regs[3..]=data
    let mut regs = [0u64; 8];
    regs[0] = inode_id;
    regs[1] = offset;
    regs[2] = actual as u64;
    for i in 0..5 {
        if i * 8 < actual {
            let end = ((i + 1) * 8).min(actual);
            let mut bytes = [0u8; 8];
            bytes[..end - i * 8].copy_from_slice(&buf[i * 8..end]);
            regs[i + 3] = u64::from_le_bytes(bytes);
        }
    }

    let call_msg = IpcMsg { tag: 4, regs };
    let reply = match sys::call(ep, &call_msg) {
        Ok(r) => r,
        Err(_) => {
            reply_val(ctx.ep_cap, -5);
            return;
        }
    };

    let written = reply.tag as i64;
    if written >= 0 {
        sotfs_lock();
        if let Some(s) = (0..64).find(|&s| unsafe { SOTFS_FILES[s][3] } == fd as u64) {
            unsafe {
                SOTFS_FILES[s][2] += written as u64;
            }
        }
        sotfs_unlock();
    }

    reply_val(ctx.ep_cap, if written >= 0 { actual as i64 } else { written });
}

/// Clear the SOTFS_FILES slot for a given fd (called from close_fd_internal).
pub fn close_sotfs_slot(fd: usize) {
    sotfs_lock();
    if let Some(s) = (0..64).find(|&s| unsafe { SOTFS_FILES[s][3] } == fd as u64) {
        unsafe {
            SOTFS_FILES[s] = [0; 4];
        }
    }
    sotfs_unlock();
}

/// Mkdir on sotFS via IPC.
pub fn sotfs_mkdir(path: &[u8]) -> Result<u64, i64> {
    let ep = sotfs_endpoint().ok_or(-2i64)?;
    let rel = strip_prefix(path);

    // Find parent dir inode and basename
    // For simplicity, send the full relative path and let the service handle it
    let mut regs = [0u64; 8];
    regs[0] = 1; // parent = root inode (simplified; real impl needs path walk)

    // Pack name into regs[1..7]
    let mut buf = [0u8; 56];
    let copy_len = rel.len().min(56);
    buf[..copy_len].copy_from_slice(&rel[..copy_len]);
    for i in 0..7 {
        regs[i + 1] = u64::from_le_bytes([
            buf[i * 8],
            buf.get(i * 8 + 1).copied().unwrap_or(0),
            buf.get(i * 8 + 2).copied().unwrap_or(0),
            buf.get(i * 8 + 3).copied().unwrap_or(0),
            buf.get(i * 8 + 4).copied().unwrap_or(0),
            buf.get(i * 8 + 5).copied().unwrap_or(0),
            buf.get(i * 8 + 6).copied().unwrap_or(0),
            buf.get(i * 8 + 7).copied().unwrap_or(0),
        ]);
    }

    let call_msg = IpcMsg { tag: 7, regs }; // tag=7 = Mkdir
    let reply = sys::call(ep, &call_msg).map_err(|_| -5i64)?;

    if reply.tag as i64 >= 0 {
        Ok(reply.regs[0]) // new inode id
    } else {
        Err(reply.tag as i64)
    }
}
