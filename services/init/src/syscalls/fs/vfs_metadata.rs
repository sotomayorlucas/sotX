//! VFS metadata operations: fstat, stat, lseek, fsync, ftruncate, statfs,
//! fadvise64, statx, file metadata stubs.

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use crate::exec::{reply_val, starts_with};
use crate::fd::*;
use crate::{vfs_lock, vfs_unlock, shared_store};
use crate::framebuffer::{print, print_u64};
use crate::syscalls::context::SyscallContext;

/// SYS_FSTAT (5): fstat on an open fd.
pub(crate) fn sys_fstat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let stat_ptr = msg.regs[1];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        let mut size = 0u64;
        let mut ino = 0u64;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                size = ctx.initrd_files[s][1];
                // Use file SIZE as stable inode — same file opened twice gets
                // same ino so glibc ld.so detects "already loaded".
                ino = ctx.initrd_files[s][1];
                break;
            }
        }
        let buf = build_linux_stat_dev(1, ino, size, false);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
        let is_vfs_dir = ctx.child_fds[fd] == 14;
        let mut size = 0u64;
        let mut oid = 0u64;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                oid = ctx.vfs_files[s][0];
                vfs_lock();
                if let Some(store) = unsafe { shared_store() } {
                    if let Some(entry) = store.stat(oid) {
                        size = entry.size;
                    }
                }
                vfs_unlock();
                break;
            }
        }
        let buf = build_linux_stat_dev(2, oid, size, is_vfs_dir);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 15 {
        let buf = build_linux_stat(fd as u64, *ctx.dir_len as u64, false);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 30 {
        // DRM device: report as S_IFCHR with major 226
        crate::drm::drm_fstat(ctx, stat_ptr);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 31 || ctx.child_fds[fd] == 32 {
        // evdev input device: S_IFCHR, major=13 (INPUT_MAJOR), minor=64/65
        let minor: u64 = if ctx.child_fds[fd] == 31 { 64 } else { 65 };
        let mut st = [0u8; 144];
        st[8..16].copy_from_slice(&(minor + 1).to_le_bytes()); // st_ino
        st[16..20].copy_from_slice(&1u32.to_le_bytes()); // st_nlink
        let mode: u32 = 0o020000 | 0o660; // S_IFCHR | 0660
        st[24..28].copy_from_slice(&mode.to_le_bytes()); // st_mode
        let rdev: u64 = (13u64 << 8) | minor; // makedev(13, minor)
        st[40..48].copy_from_slice(&rdev.to_le_bytes()); // st_rdev
        st[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
        ctx.guest_write(stat_ptr, &st);
        reply_val(ctx.ep_cap, 0);
    } else {
        let buf = build_linux_stat(fd as u64, 0, false);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    }
}

/// SYS_STAT (4) / SYS_LSTAT (6): stat a path.
pub(crate) fn sys_stat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let stat_ptr = msg.regs[1];
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    trace!(Debug, FS, {
        print(b"STAT P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in &path[..path_len] { sys::debug_print(b); } print(b"]");
    });
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    // Resolve symlinks
    let (path, path_len) = {
        let mut resolved = [0u8; 256];
        let rlen = crate::fd::symlink_resolve(&path[..path_len], &mut resolved);
        let mut out = [0u8; 128];
        let n = rlen.min(127);
        out[..n].copy_from_slice(&resolved[..n]);
        (out, n)
    };
    let name = &path[..path_len];

    let mut basename_start = 0usize;
    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
    let basename = &name[basename_start..];
    if !basename.is_empty() {
        if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
            // dev=1 + ino=size — must match fstat/fstatat for same initrd file
            // so glibc ld.so recognizes already-loaded libraries
            let buf = build_linux_stat_dev(1, sz, sz, false);
            ctx.guest_write(stat_ptr, &buf);
            reply_val(ctx.ep_cap, 0);
            return;
        }
    }

    vfs_lock();
    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        Some((oid, entry.size, entry.is_dir()))
    });
    vfs_unlock();

    if let Some((oid, size, is_dir)) = vfs_stat {
        let buf = build_linux_stat_dev(2, oid, size, is_dir);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else {
        let is_known_dir = name == b"." || path_len == 0
            || name == b"/" || name == b"/usr" || name == b"/etc"
            || name == b"/lib" || name == b"/lib64"
            || name == b"/bin" || name == b"/sbin"
            || name == b"/tmp" || name == b"/home" || name == b"/var"
            || name == b"/usr/bin" || name == b"/usr/lib"
            || name == b"/usr/sbin" || name == b"/usr/lib64"
            || name == b"/usr/share" || name == b"/usr/share/terminfo"
            || name == b"/usr/share/terminfo/x"
            || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
            || starts_with(name, b"/usr/share/X11/xkb/")
            || name == b"/usr/libexec"
            || name == b"/usr/libexec/git-core"
            || name == b"/usr/local" || name == b"/usr/local/bin"
            || starts_with(name, b"/dev/")
            || crate::udev::is_sys_drm_dir(name);
        // DRM and evdev device files should be reported as character devices, not dirs.
        let is_dev_char = name == b"/dev/dri/card0"
            || name == b"/dev/input/event0"
            || name == b"/dev/input/event1";
        if is_dev_char {
            crate::drm::drm_fstat(ctx, stat_ptr);
            reply_val(ctx.ep_cap, 0);
        } else if is_known_dir {
            trace!(Debug, FS, {
                print(b"STAT-DIR-OK ["); for &b in name { sys::debug_print(b); } print(b"]");
            });
            let buf = build_linux_stat(0, 4096, true);
            ctx.guest_write(stat_ptr, &buf);
            reply_val(ctx.ep_cap, 0);
        } else {
            trace!(Debug, FS, {
                print(b"STAT-ENOENT ["); for &b in name { sys::debug_print(b); } print(b"]");
            });
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_LSEEK (8): seek on an open fd.
pub(crate) fn sys_lseek(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let offset_val = msg.regs[1] as i64;
    let whence = msg.regs[2] as u32;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        let mut found = false;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                let file_size = ctx.initrd_files[s][1] as i64;
                let cur_pos = ctx.initrd_files[s][2] as i64;
                let new_pos = match whence {
                    0 => offset_val,
                    1 => cur_pos + offset_val,
                    2 => file_size + offset_val,
                    _ => { reply_val(ctx.ep_cap, -EINVAL); found = true; break; }
                };
                if new_pos < 0 {
                    reply_val(ctx.ep_cap, -EINVAL);
                } else {
                    ctx.initrd_files[s][2] = new_pos as u64;
                    reply_val(ctx.ep_cap, new_pos);
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
        let mut found = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let file_size = ctx.vfs_files[s][1] as i64;
                let cur_pos = ctx.vfs_files[s][2] as i64;
                let new_pos = match whence {
                    0 => offset_val,
                    1 => cur_pos + offset_val,
                    2 => file_size + offset_val,
                    _ => { reply_val(ctx.ep_cap, -EINVAL); found = true; break; }
                };
                if new_pos < 0 {
                    reply_val(ctx.ep_cap, -EINVAL);
                } else {
                    ctx.vfs_files[s][2] = new_pos as u64;
                    reply_val(ctx.ep_cap, new_pos);
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else if ctx.child_fds[fd] == 15 {
        let file_size = *ctx.dir_len as i64;
        let cur_pos = *ctx.dir_pos as i64;
        let new_pos = match whence {
            0 => offset_val,
            1 => cur_pos + offset_val,
            2 => file_size + offset_val,
            _ => { reply_val(ctx.ep_cap, -EINVAL); return; }
        };
        if new_pos < 0 {
            reply_val(ctx.ep_cap, -EINVAL);
        } else {
            *ctx.dir_pos = new_pos as usize;
            reply_val(ctx.ep_cap, new_pos);
        }
    } else {
        reply_val(ctx.ep_cap, -ESPIPE);
    }
}

/// SYS_FSYNC (74) / SYS_FDATASYNC (75).
pub(crate) fn sys_fsync(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_FTRUNCATE (77).
pub(crate) fn sys_ftruncate(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let length = msg.regs[1] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        let mut done = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                ctx.vfs_files[s][1] = length as u64;
                done = true;
                break;
            }
        }
        reply_val(ctx.ep_cap, if done { 0 } else { -9 });
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// SYS_STATFS (137) / SYS_FSTATFS (138).
pub(crate) fn sys_statfs(ctx: &mut SyscallContext, msg: &IpcMsg, _syscall_nr: u64) {
    let buf = msg.regs[1];
    if buf != 0 {
        let mut sfs = [0u8; 120];
        sfs[0..8].copy_from_slice(&0xEF53u64.to_le_bytes());
        sfs[8..16].copy_from_slice(&4096u64.to_le_bytes());
        sfs[16..24].copy_from_slice(&(1024u64 * 1024).to_le_bytes());
        sfs[24..32].copy_from_slice(&(512u64 * 1024).to_le_bytes());
        sfs[32..40].copy_from_slice(&(512u64 * 1024).to_le_bytes());
        sfs[40..48].copy_from_slice(&65536u64.to_le_bytes());
        sfs[48..56].copy_from_slice(&32768u64.to_le_bytes());
        sfs[72..80].copy_from_slice(&255u64.to_le_bytes());
        ctx.guest_write(buf, &sfs);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_FADVISE64 (221): stub.
pub(crate) fn sys_fadvise64(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_STATX (332): modern stat call used by musl 1.2.5+.
///
/// struct statx is 256 bytes. Key fields:
///   stx_mask(u32@0), stx_blksize(u32@4), stx_attributes(u64@8),
///   stx_nlink(u32@16), stx_uid(u32@20), stx_gid(u32@24),
///   stx_mode(u16@28), stx_ino(u64@32), stx_size(u64@40),
///   stx_blocks(u64@48), stx_attributes_mask(u64@56)
pub(crate) fn sys_statx(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let dirfd = msg.regs[0] as i64;
    let path_ptr = msg.regs[1];
    let _flags = msg.regs[2] as u32;
    let _mask = msg.regs[3] as u32;
    let buf_ptr = msg.regs[4];

    // AT_EMPTY_PATH: stat the fd itself
    if path_ptr == 0 || (_flags & 0x1000 != 0) { // AT_EMPTY_PATH = 0x1000
        let fd = dirfd as usize;
        if fd < GRP_MAX_FDS && ctx.child_fds[fd] != 0 {
            let kind = ctx.child_fds[fd];
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes()); // stx_mask = STATX_BASIC_STATS
            sx[4..8].copy_from_slice(&4096u32.to_le_bytes()); // stx_blksize
            sx[16..20].copy_from_slice(&1u32.to_le_bytes()); // stx_nlink
            let mode: u16 = if kind == 14 { 0o040755 } else if kind == 30 { 0o020666 } else { 0o100644 };
            sx[28..30].copy_from_slice(&mode.to_le_bytes()); // stx_mode
            sx[32..40].copy_from_slice(&(fd as u64).to_le_bytes()); // stx_ino
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
            return;
        }
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }

    // Path-based stat
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    if starts_with(name, b"/usr/share/X11") {
        trace!(Debug, FS, {
            print(b"STATX P"); print_u64(ctx.pid as u64);
            print(b" ["); for &b in name { sys::debug_print(b); } print(b"]");
        });
    }

    // Check initrd by basename
    let mut basename_start = 0usize;
    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
    let basename = &name[basename_start..];
    if !basename.is_empty() {
        if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[4..8].copy_from_slice(&4096u32.to_le_bytes());
            sx[16..20].copy_from_slice(&1u32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o100644u16.to_le_bytes()); // S_IFREG
            sx[40..48].copy_from_slice(&sz.to_le_bytes()); // stx_size
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
            return;
        }
    }

    // VFS
    vfs_lock();
    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        Some((oid, entry.size, entry.is_dir()))
    });
    vfs_unlock();

    if let Some((_oid, size, is_dir)) = vfs_stat {
        let mut sx = [0u8; 256];
        sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
        sx[4..8].copy_from_slice(&4096u32.to_le_bytes());
        sx[16..20].copy_from_slice(&1u32.to_le_bytes());
        let mode: u16 = if is_dir { 0o040755 } else { 0o100644 };
        sx[28..30].copy_from_slice(&mode.to_le_bytes());
        sx[40..48].copy_from_slice(&size.to_le_bytes());
        ctx.guest_write(buf_ptr, &sx);
        reply_val(ctx.ep_cap, 0);
    } else {
        // Known directories
        let is_known_dir = name == b"." || path_len == 0
            || name == b"/" || name == b"/usr" || name == b"/etc"
            || name == b"/lib" || name == b"/lib64"
            || name == b"/bin" || name == b"/sbin"
            || name == b"/tmp" || name == b"/home" || name == b"/var"
            || name == b"/usr/bin" || name == b"/usr/lib"
            || name == b"/usr/sbin" || name == b"/usr/lib64"
            || name == b"/usr/share" || name == b"/usr/share/terminfo"
            || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
            || starts_with(name, b"/usr/share/X11/xkb/")
            || name == b"/usr/libexec"
            || name == b"/proc" || name == b"/sys" || name == b"/dev"
            || name == b"/dev/dri" || name == b"/dev/input"
            || name == b"/run" || name == b"/run/user" || name == b"/run/user/0";
        let is_dev_char = name == b"/dev/dri/card0"
            || name == b"/dev/input/event0" || name == b"/dev/input/event1";
        let is_virtual = name == b"/dev/null" || name == b"/dev/zero"
            || name == b"/dev/urandom" || name == b"/dev/random"
            || starts_with(name, b"/etc/") || starts_with(name, b"/proc/");

        if is_dev_char {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o020666u16.to_le_bytes()); // S_IFCHR
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
        } else if is_known_dir {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[4..8].copy_from_slice(&4096u32.to_le_bytes());
            sx[16..20].copy_from_slice(&1u32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o040755u16.to_le_bytes()); // S_IFDIR
            sx[40..48].copy_from_slice(&4096u64.to_le_bytes());
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
        } else if is_virtual {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o100644u16.to_le_bytes());
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// File metadata stubs.
pub(crate) fn sys_file_metadata_stubs(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

