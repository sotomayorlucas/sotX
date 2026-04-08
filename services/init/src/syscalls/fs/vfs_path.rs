//! VFS path operations: fstatat, readlinkat, readlink, access, rename,
//! renameat, faccessat2, umask, proc_self_exe helper.

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::{reply_val, starts_with};
use crate::process::*;
use crate::fd::*;
use crate::{vfs_lock, vfs_unlock, shared_store};
use crate::framebuffer::{print, print_u64};
use crate::syscalls::context::SyscallContext;

/// Helper: get /proc/self/exe path.
pub(crate) fn proc_self_exe(pid: usize) -> [u8; 32] {
    let mut buf = [0u8; 32];
    if pid > 0 && pid <= MAX_PROCS {
        let w0 = PROCESSES[pid - 1].exe_path[0].load(Ordering::Acquire);
        let w1 = PROCESSES[pid - 1].exe_path[1].load(Ordering::Acquire);
        let w2 = PROCESSES[pid - 1].exe_path[2].load(Ordering::Acquire);
        let w3 = PROCESSES[pid - 1].exe_path[3].load(Ordering::Acquire);
        if w0 != 0 {
            buf[0..8].copy_from_slice(&w0.to_le_bytes());
            buf[8..16].copy_from_slice(&w1.to_le_bytes());
            buf[16..24].copy_from_slice(&w2.to_le_bytes());
            buf[24..32].copy_from_slice(&w3.to_le_bytes());
            return buf;
        }
    }
    buf[..12].copy_from_slice(b"/bin/program");
    buf
}

/// SYS_FSTATAT (262): stat relative to dirfd.
pub(crate) fn sys_fstatat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let dirfd = msg.regs[0] as i64;
    let path_ptr = msg.regs[1];
    let stat_ptr = msg.regs[2];
    let flags = msg.regs[3] as u32;
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    if starts_with(&path[..path_len], b"/usr/share/X11") {
        trace!(Debug, FS, {
            print(b"FSTATAT-XKB P"); print_u64(ctx.pid as u64);
            print(b" ["); for &b in &path[..path_len] { sys::debug_print(b); } print(b"]");
        });
    }
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

    if (flags & AT_EMPTY_PATH) != 0 && path_len == 0 {
        let fd = dirfd as usize;
        if fd < GRP_MAX_FDS && ctx.child_fds[fd] != 0 {
            if ctx.child_fds[fd] == 12 {
                let mut size = 0u64;
                let mut ino = 0u64;
                for s in 0..GRP_MAX_INITRD {
                    if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                        size = ctx.initrd_files[s][1];
                        // Use file SIZE as stable inode — same file opened twice gets
                        // same ino so glibc ld.so detects "already loaded" (not dup load)
                        ino = ctx.initrd_files[s][1];
                        break;
                    }
                }
                let buf = build_linux_stat_dev(1, ino, size, false);
                ctx.guest_write(stat_ptr, &buf);
            } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
                let is_vfs_dir = ctx.child_fds[fd] == 14;
                let mut size = 0u64;
                let mut oid = 0u64;
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                        oid = ctx.vfs_files[s][0];
                        size = ctx.vfs_files[s][1];
                        break;
                    }
                }
                let buf = build_linux_stat_dev(2, oid, size, is_vfs_dir);
                ctx.guest_write(stat_ptr, &buf);
            } else if ctx.child_fds[fd] == 30 {
                // DRM device: S_IFCHR with major 226
                crate::drm::drm_fstat(ctx, stat_ptr);
            } else {
                let buf = build_linux_stat(fd as u64, 0, false);
                ctx.guest_write(stat_ptr, &buf);
            }
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -EBADF);
        }
        return;
    }

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
        Some((entry.oid, entry.size, entry.is_dir()))
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
            let buf = build_linux_stat(0, 4096, true);
            ctx.guest_write(stat_ptr, &buf);
            reply_val(ctx.ep_cap, 0);
        } else {
            let mut found_sock = false;
            for i in 0..crate::fd::MAX_UNIX_LISTENERS {
                if crate::fd::UNIX_LISTEN_ACTIVE[i].load(Ordering::Acquire) != 0 {
                    let lpath = unsafe { &crate::fd::UNIX_LISTEN_PATH[i] };
                    let llen = lpath.iter().position(|&b| b == 0).unwrap_or(128);
                    if llen == path_len && &lpath[..llen] == name {
                        let mut st = sotos_common::linux_abi::Stat::zeroed();
                        st.st_ino = 0xA000 + i as u64;
                        st.st_nlink = 1;
                        st.st_mode = 0o140755;
                        let buf: [u8; 144] = unsafe { core::mem::transmute(st) };
                        ctx.guest_write(stat_ptr, &buf);
                        reply_val(ctx.ep_cap, 0);
                        found_sock = true;
                        break;
                    }
                }
            }
            if !found_sock {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    }
}

/// SYS_READLINKAT (267): read symbolic link.
pub(crate) fn sys_readlinkat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let out_buf = msg.regs[2];
    let bufsiz = msg.regs[3] as usize;
    let mut rpath = [0u8; 64];
    let rpath_len = ctx.guest_copy_path(path_ptr, &mut rpath);
    let rname = &rpath[..rpath_len];
    if rpath_len >= 14 && &rpath[..14] == b"/proc/self/exe" {
        let exe = proc_self_exe(ctx.pid);
        let elen = exe.iter().position(|&b| b == 0).unwrap_or(exe.len());
        let n = elen.min(bufsiz);
        ctx.guest_write(out_buf, &exe[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else if let Some(target) = crate::udev::sys_drm_readlink(rname) {
        let n = target.len().min(bufsiz);
        ctx.guest_write(out_buf, &target[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else {
        // Check symlink table (Wine dosdevices compat)
        let mut abs = [0u8; 256];
        let alen = if rpath_len > 0 && rpath[0] != b'/' {
            crate::fd::resolve_with_cwd(ctx.cwd, rname, &mut abs)
        } else {
            let n = rpath_len.min(255);
            abs[..n].copy_from_slice(&rpath[..n]);
            n
        };
        let mut found = false;
        unsafe {
            for i in 0..crate::fd::SYMLINK_COUNT.min(16) {
                let sp = &crate::fd::SYMLINK_PATH[i];
                let slen = sp.iter().position(|&b| b == 0).unwrap_or(128);
                if slen > 0 && alen == slen && abs[..alen] == sp[..slen] {
                    let tgt = &crate::fd::SYMLINK_TARGET[i];
                    let tlen = tgt.iter().position(|&b| b == 0).unwrap_or(128);
                    let n = tlen.min(bufsiz);
                    ctx.guest_write(out_buf, &tgt[..n]);
                    reply_val(ctx.ep_cap, n as i64);
                    found = true;
                    break;
                }
            }
        }
        if !found { reply_val(ctx.ep_cap, -EINVAL); }
    }
}

/// SYS_READLINK (89).
pub(crate) fn sys_readlink(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let buf = msg.regs[1];
    let bufsiz = msg.regs[2] as usize;
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let name = &path[..plen];
    if name == b"/proc/self/exe" {
        let target = proc_self_exe(ctx.pid);
        let tlen = target.iter().position(|&b| b == 0).unwrap_or(target.len());
        let n = tlen.min(bufsiz);
        ctx.guest_write(buf, &target[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else if let Some(target) = crate::udev::sys_drm_readlink(name) {
        let n = target.len().min(bufsiz);
        ctx.guest_write(buf, &target[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else { reply_val(ctx.ep_cap, -EINVAL); }
}

/// SYS_ACCESS (21) / SYS_FACCESSAT (269).
pub(crate) fn sys_access(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let path_ptr = if syscall_nr == SYS_FACCESSAT { msg.regs[1] } else { msg.regs[0] };
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
    let is_dir = name == b"." || name == b".."
        || name == b"/" || name == b"/usr" || name == b"/etc"
        || name == b"/lib" || name == b"/lib64"
        || name == b"/bin" || name == b"/sbin"
        || name == b"/tmp" || name == b"/home" || name == b"/var"
        || name == b"/proc" || name == b"/sys" || name == b"/dev"
        || name == b"/usr/bin" || name == b"/usr/lib"
        || name == b"/usr/sbin" || name == b"/usr/lib64"
        || name == b"/usr/share" || name == b"/usr/share/terminfo"
        || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
        || starts_with(name, b"/usr/share/X11/xkb/");
    let is_virtual = name == b"/etc/passwd" || name == b"/etc/group"
        || name == b"/etc/resolv.conf" || name == b"/etc/hostname"
        || name == b"/etc/nsswitch.conf"
        || name == b"/dev/null" || name == b"/dev/zero"
        || name == b"/dev/urandom" || name == b"/dev/random"
        || name == b"/dev/dri/card0"
        || name == b"/dev/input/event0" || name == b"/dev/input/event1";
    let is_dir = is_dir
        || name == b"/dev/dri" || name == b"/dev/input";
    if is_dir || is_virtual {
        reply_val(ctx.ep_cap, 0);
    } else {
        let mut basename_start = 0usize;
        for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
        let basename = &name[basename_start..];
        if !basename.is_empty() {
            match sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                Ok(_) => reply_val(ctx.ep_cap, 0),
                Err(_) => {
                    vfs_lock();
                    let found = unsafe { shared_store() }.and_then(|store| {
                        store.resolve_path(name, sotos_objstore::ROOT_OID).ok()
                    }).is_some();
                    vfs_unlock();
                    if name.windows(6).any(|w| w == b"config") {
                        trace!(Debug, FS, {
                            print(if found { b"ACCESS-OK: " } else { b"ACCESS-MISS: " });
                            print(name);
                        });
                    }
                    reply_val(ctx.ep_cap, if found { 0 } else { -ENOENT });
                }
            }
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_RENAME (82).
pub(crate) fn sys_rename(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let old_ptr = msg.regs[0];
    let new_ptr = msg.regs[1];
    let mut old_path = [0u8; 128];
    let mut new_path = [0u8; 128];
    let old_len = ctx.guest_copy_path(old_ptr, &mut old_path);
    let new_len = ctx.guest_copy_path(new_ptr, &mut new_path);
    let (old_path, old_len) = if old_len > 0 && old_path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &old_path[..old_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (old_path, old_len) };
    let (new_path, new_len) = if new_len > 0 && new_path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &new_path[..new_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (new_path, new_len) };
    let old_name = &old_path[..old_len];
    let new_name = &new_path[..new_len];

    trace!(Debug, FS, {
        print(b"RENAME P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in old_name { sys::debug_print(b); }
        print(b"] -> ["); for &b in new_name { sys::debug_print(b); }
        print(b"]");
    });

    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let old_oid = match store.resolve_path(old_name, ROOT_OID) {
            Ok(oid) => oid,
            Err(_) => {
                trace!(Error, FS, { print(b"RENAME-FAIL: old path not found"); });
                return None;
            }
        };
        let mut last_slash = None;
        for (i, &b) in new_name.iter().enumerate() {
            if b == b'/' { last_slash = Some(i); }
        }
        let (new_parent, new_basename) = match last_slash {
            Some(pos) => {
                let pp = &new_name[..pos];
                let p = if pp.is_empty() { ROOT_OID }
                    else {
                        match store.resolve_path(pp, ROOT_OID) {
                            Ok(p) => p,
                            Err(_) => {
                                trace!(Error, FS, {
                                    print(b"RENAME-FAIL: new parent not found [");
                                    for &b in pp { sys::debug_print(b); }
                                    print(b"]");
                                });
                                return None;
                            }
                        }
                    };
                (p, &new_name[pos + 1..])
            }
            None => (ROOT_OID, new_name),
        };
        if let Err(e) = store.rename(old_oid, new_basename, new_parent) {
            trace!(Error, FS, {
                print(b"RENAME-FAIL: store.rename err=[");
                print(e.as_bytes());
                print(b"]");
            });
            return None;
        }
        if let Some(entry) = store.stat(old_oid) {
            if entry.is_dir() {
                trace!(Debug, FS, {
                    print(b"REN-POSTCHECK-DIR: oid=");
                    print_u64(old_oid);
                    print(b" flags=");
                    print_u64(entry.flags as u64);
                    print(b" name=[");
                    print(entry.name_as_str());
                    print(b"]");
                });
            }
        }
        if store.resolve_path(old_name, ROOT_OID).is_ok() {
            trace!(Error, FS, {
                print(b"REN-OLDNAME-STILL-EXISTS: ");
                print(old_name);
            });
        }
        Some(())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -2 });
}

/// SYS_RENAMEAT (264) / SYS_RENAMEAT2 (316).
pub(crate) fn sys_renameat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let oldpath_ptr = msg.regs[1];
    let newpath_ptr = msg.regs[3];
    let mut oldpath = [0u8; 128];
    let mut newpath = [0u8; 128];
    let olen = ctx.guest_copy_path(oldpath_ptr, &mut oldpath);
    let nlen = ctx.guest_copy_path(newpath_ptr, &mut newpath);
    let (oldpath, olen) = if olen > 0 && oldpath[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &oldpath[..olen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (oldpath, olen) };
    let (newpath, nlen) = if nlen > 0 && newpath[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &newpath[..nlen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (newpath, nlen) };
    trace!(Debug, FS, {
        print(b"RENAMEAT P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in &oldpath[..olen] { sys::debug_print(b); }
        print(b"] -> ["); for &b in &newpath[..nlen] { sys::debug_print(b); }
        print(b"]");
    });
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let oid = match store.resolve_path(&oldpath[..olen], ROOT_OID) {
            Ok(o) => o,
            Err(_) => {
                trace!(Error, FS, { print(b"RENAMEAT-FAIL: old not found"); });
                return None;
            }
        };
        let mut last_slash = None;
        for (i, &b) in newpath[..nlen].iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, fname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else {
                    match store.resolve_path(&newpath[..pos], ROOT_OID) {
                        Ok(p) => p,
                        Err(_) => {
                            trace!(Error, FS, { print(b"RENAMEAT-FAIL: new parent not found"); });
                            return None;
                        }
                    }
                };
                (p, &newpath[pos+1..nlen])
            }
            None => (ROOT_OID, &newpath[..nlen]),
        };
        if let Err(e) = store.rename(oid, fname, parent) {
            trace!(Error, FS, {
                print(b"RENAMEAT-FAIL: store err=[");
                print(e.as_bytes());
                print(b"]");
            });
            return None;
        }
        Some(())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
}
/// SYS_FACCESSAT2 (439).
pub(crate) fn sys_faccessat2(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let (path, plen) = if plen > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, plen)
    };
    let name = &path[..plen];
    let is_dir = name.is_empty() || name == b"." || name == b"/"
        || name == b"/bin" || name == b"/lib" || name == b"/lib64"
        || name == b"/usr" || name == b"/etc" || name == b"/proc"
        || name == b"/tmp" || name == b"/sbin" || name == b"/var"
        || name == b"/home" || name == b"/sys" || name == b"/dev"
        || name == b"/run" || name == b"/run/user" || name == b"/run/user/0"
        || name == b"/usr/bin" || name == b"/usr/lib" || name == b"/usr/lib64"
        || name == b"/usr/sbin" || name == b"/usr/share"
        || name == b"/usr/share/terminfo"
        || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
        || starts_with(name, b"/usr/share/X11/xkb/")
        || name == b"/usr/libexec"
        || name == b"/dev/dri" || name == b"/dev/input"
        || crate::udev::is_sys_drm_dir(name);
    let is_virtual = name == b"/etc/passwd" || name == b"/etc/group"
        || name == b"/etc/resolv.conf" || name == b"/etc/hostname"
        || name == b"/etc/nsswitch.conf"
        || name == b"/dev/null" || name == b"/dev/zero"
        || name == b"/dev/urandom" || name == b"/dev/random"
        || name == b"/dev/dri/card0"
        || name == b"/dev/input/event0" || name == b"/dev/input/event1"
        || starts_with(name, b"/etc/")
        || crate::udev::sys_class_drm_content(name).is_some();
    if is_dir || is_virtual {
        reply_val(ctx.ep_cap, 0);
    } else {
        let mut bstart = 0usize;
        for idx in 0..plen { if name[idx] == b'/' { bstart = idx + 1; } }
        let bname = &name[bstart..];
        let mut found = false;
        if !bname.is_empty() {
            if sys::initrd_read(bname.as_ptr() as u64, bname.len() as u64, 0, 0).is_ok() {
                found = true;
            }
        }
        if !found {
            vfs_lock();
            found = unsafe { shared_store() }
                .and_then(|store| store.resolve_path(name, sotos_objstore::ROOT_OID).ok())
                .is_some();
            vfs_unlock();
        }
        reply_val(ctx.ep_cap, if found { 0 } else { -ENOENT });
    }
}

/// SYS_UMASK (95).
pub(crate) fn sys_umask(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0o022);
}

