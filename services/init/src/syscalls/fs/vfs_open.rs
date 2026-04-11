//! VFS open operations: open, openat, creat.

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::{reply_val, rdtsc, starts_with,
                  format_uptime_into, format_proc_self_stat};
use crate::process::*;
use crate::fd::*;
use crate::child_handler::open_virtual_file;
use crate::{NET_EP_CAP, vfs_lock, vfs_unlock, shared_store};
use crate::framebuffer::{print, print_u64};
use crate::syscall_log::format_syslog_into;
use crate::syscalls::context::SyscallContext;
use super::dir_store_path;

const MAP_WRITABLE: u64 = 2;

/// SYS_OPEN (2): open file by path.
pub(crate) fn sys_open(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let flags = msg.regs[1] as u32;
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    trace!(Debug, FS, {
        print(b"OPEN P"); print_u64(ctx.pid as u64);
        print(b" fl="); print_u64(flags as u64);
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
    let name = &path[..path_len];

    // --- sotFS mount point intercept (SYS_OPEN) ---
    if super::fs_sotfs::is_sotfs_path(name) {
        match super::fs_sotfs::sotfs_open(name, flags as u64) {
            Ok((inode_id, is_dir, size)) => {
                if let Some(fd) = super::fs_sotfs::sotfs_assign_fd(ctx, inode_id, is_dir, size) {
                    reply_val(ctx.ep_cap, fd as i64);
                } else {
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            }
            Err(e) => reply_val(ctx.ep_cap, e),
        }
        return;
    }

    // Synthetic directory open: /dev/dri/, /dev/input/
    if name == b"/dev/dri" || name == b"/dev/dri/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD01;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    if name == b"/dev/input" || name == b"/dev/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD02;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    let kind = if name == b"/dev/null" { 8u8 }
        else if name == b"/dev/zero" { 9u8 }
        else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
        else if name == b"/dev/dri/card0" { 30u8 }
        else if name == b"/dev/input/event0" { 31u8 }
        else if name == b"/dev/input/event1" { 32u8 }
        else { 0u8 };

    if kind != 0 {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = kind;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if false && crate::xkb::xkb_initrd_name(name).is_some() {
        // XKB files: DISABLED — served via VFS (kind=13) instead of dir_buf (kind=15)
        // VFS supports arbitrary file sizes and per-fd tracking
        unreachable!();
    } else if name == b"/sys/class" || name == b"/sys/class/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD05;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/drm" || name == b"/sys/class/drm/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD03;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/input" || name == b"/sys/class/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD04;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if starts_with(name, b"/etc/") || starts_with(name, b"/proc/")
           || starts_with(name, b"/sys/")
           || starts_with(name, b"/usr/share/")
           || starts_with(name, b"/run/udev/") {
        let virt_len = open_virtual_file(name, ctx.dir_buf);
        if let Some(gen_len) = virt_len {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        } else {
            vfs_lock();
            let vfs_found = unsafe { shared_store() }.and_then(|store| {
                use sotos_objstore::ROOT_OID;
                if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                    let entry = store.stat(oid)?;
                    Some((oid, entry.size, entry.is_dir()))
                } else { None }
            });
            vfs_unlock();
            if let Some((oid, size, is_dir)) = vfs_found {
                let mut vslot = None;
                for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                let mut fd = None;
                for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                if let (Some(vs), Some(f)) = (vslot, fd) {
                    ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                    ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                    ctx.fd_flags[f] = flags;
                    reply_val(ctx.ep_cap, f as i64);
                } else {
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            } else {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    } else if name == b"/proc" {
        use sotos_common::linux_abi::{DT_REG, DT_DIR};
        let mut fd_slot = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd_slot = Some(i); break; } }
        let mut vs = None;
        for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vs = Some(s); break; } }
        if let (Some(f), Some(s)) = (fd_slot, vs) {
            ctx.child_fds[f] = 14;
            ctx.vfs_files[s] = [1, 0, 0xDEAD, f as u64];
            *ctx.dir_len = 0;
            *ctx.dir_pos = 0;
            let entries: &[(&[u8], u8)] = &[
                (b".", DT_DIR), (b"..", DT_DIR),
                (b"stat", DT_REG), (b"meminfo", DT_REG), (b"cpuinfo", DT_REG),
                (b"uptime", DT_REG), (b"loadavg", DT_REG), (b"version", DT_REG),
                (b"self", DT_DIR),
            ];
            for (ename, dtype) in entries {
                let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8;
                if *ctx.dir_len + reclen > ctx.dir_buf.len() { break; }
                let d = &mut ctx.dir_buf[*ctx.dir_len..*ctx.dir_len + reclen];
                for b in d.iter_mut() { *b = 0; }
                d[0..8].copy_from_slice(&1u64.to_le_bytes());
                d[8..16].copy_from_slice(&((*ctx.dir_len + reclen) as u64).to_le_bytes());
                d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                d[18] = *dtype;
                let n = ename.len().min(reclen - 19);
                d[19..19+n].copy_from_slice(&ename[..n]);
                *ctx.dir_len += reclen;
            }
            for i in 0..crate::process::MAX_PROCS {
                if crate::process::PROCESSES[i].state.load(core::sync::atomic::Ordering::Acquire) == 1 {
                    let pid = i + 1;
                    let mut nbuf = [0u8; 8];
                    let nlen = crate::child_handler::fmt_u64(pid as u64, &mut nbuf);
                    let ename = &nbuf[..nlen];
                    let reclen = ((19 + nlen + 1 + 7) / 8) * 8;
                    if *ctx.dir_len + reclen > ctx.dir_buf.len() { break; }
                    let d = &mut ctx.dir_buf[*ctx.dir_len..*ctx.dir_len + reclen];
                    for b in d.iter_mut() { *b = 0; }
                    d[0..8].copy_from_slice(&(pid as u64 + 100).to_le_bytes());
                    d[8..16].copy_from_slice(&((*ctx.dir_len + reclen) as u64).to_le_bytes());
                    d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                    d[18] = DT_DIR;
                    d[19..19+nlen].copy_from_slice(ename);
                    *ctx.dir_len += reclen;
                }
            }
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if name == b"/" || name == b"/bin" || name == b"/lib"
           || name == b"/lib64" || name == b"/sbin" || name == b"/tmp"
           || name == b"/usr" || name == b"/etc"
           || name == b"." {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        let mut vslot = None;
        for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
        if let (Some(f), Some(vs)) = (fd, vslot) {
            let mut dir_oid = 0u64;
            vfs_lock();
            if let Some(store) = unsafe { shared_store() } {
                use sotos_objstore::ROOT_OID;
                if name == b"/" || name == b"." {
                    dir_oid = ROOT_OID;
                } else {
                    if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                        dir_oid = oid;
                    }
                }
            }
            vfs_unlock();
            if dir_oid == 0 { dir_oid = sotos_objstore::ROOT_OID; }
            ctx.child_fds[f] = 14;
            ctx.vfs_files[vs] = [dir_oid, 0, 0, f as u64];
            dir_store_path(ctx, f, name);
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else {
        // Priority: VFS first, then initrd, then VFS O_CREAT.
        vfs_lock();
        let vfs_existing = unsafe { shared_store() }.and_then(|store| {
            use sotos_objstore::ROOT_OID;
            if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                let entry = store.stat(oid)?;
                if flags & O_TRUNC != 0 && !entry.is_dir() {
                    store.write_obj(oid, &[]).ok();
                    return Some((oid, 0u64, entry.is_dir()));
                }
                return Some((oid, entry.size, entry.is_dir()));
            }
            None
        });
        vfs_unlock();

        if let Some((oid, size, is_dir)) = vfs_existing {
            let mut vslot = None;
            for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let (Some(vs), Some(f)) = (vslot, fd) {
                ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                ctx.fd_flags[f] = flags;
                if is_dir { dir_store_path(ctx, f, name); }
                if !is_dir {
                    trace!(Debug, FS, {
                        print(b"VFS-HIT P"); print_u64(ctx.pid as u64);
                        print(b" fd="); print_u64(f as u64);
                        print(b" d=2 oid="); crate::framebuffer::print_hex64(oid);
                        print(b" ["); for &b in &name[..path_len.min(40)] { sys::debug_print(b); } print(b"]");
                    });
                }
                if path_len >= 8 && &name[path_len-8..path_len] == b"ntdll.so" && ctx.pid < 16 {
                    unsafe { (*crate::syscalls::mm::NTDLL_SO_FD.get())[ctx.pid] = f as u8; }
                    trace!(Info, FS, {
                        print(b"NTDLL-FD P"); crate::framebuffer::print_u64(ctx.pid as u64);
                        print(b" fd="); crate::framebuffer::print_u64(f as u64);
                    });
                }
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
            return;
        }

        // Step 2: Try initrd
        let mut basename_start = 0usize;
        for idx in 0..path_len {
            if name[idx] == b'/' { basename_start = idx + 1; }
        }
        let basename = &name[basename_start..];
        let mut opened_initrd = false;
        let skip_initrd = false;







        if !skip_initrd && !basename.is_empty() {
            let mut slot = None;
            for s in 0..GRP_MAX_INITRD {
                if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
            }
            if let Some(slot) = slot {
                let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0xC000000;
                // Query file size first (pass buf=0, len=0)
                let file_sz = sys::initrd_read(
                    basename.as_ptr() as u64, basename.len() as u64, 0, 0
                ).unwrap_or(0);
                let buf_pages = if file_sz > 0 {
                    ((file_sz + 0xFFF) / 0x1000).min(0xC000000 / 0x1000) // cap at 192 MiB
                } else { 576 }; // default 2.25 MiB
                let mut buf_ok = true;
                for p in 0..buf_pages {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            buf_ok = false; break;
                        }
                    } else { buf_ok = false; break; }
                }
                if buf_ok {
                    match sys::initrd_read(
                        basename.as_ptr() as u64,
                        basename.len() as u64,
                        file_buf,
                        buf_pages * 0x1000,
                    ) {
                        Ok(sz) => {
                            let mut fd = None;
                            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                            if let Some(f) = fd {
                                ctx.child_fds[f] = 12;
                                ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                reply_val(ctx.ep_cap, f as i64);
                                opened_initrd = true;
                            } else {
                                for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                reply_val(ctx.ep_cap, -EMFILE);
                                opened_initrd = true;
                            }
                        }
                        Err(_) => {
                            for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                        }
                    }
                }
            }
        }

        // Step 3: VFS O_CREAT
        if !opened_initrd {
            if flags & O_CREAT != 0 {
                vfs_lock();
                let vfs_result = unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    let mut last_slash = None;
                    for (i, &b) in name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
                    let (parent, fname) = match last_slash {
                        Some(pos) => {
                            let p = if pos == 0 { ROOT_OID } else {
                                store.resolve_path(&name[..pos], ROOT_OID).ok()?
                            };
                            (p, &name[pos+1..path_len])
                        }
                        None => (ROOT_OID, name),
                    };
                    let oid = store.create_in(fname, &[], parent).ok()?;
                    Some((oid, 0u64, false))
                });
                vfs_unlock();
                if let Some((oid, size, is_dir)) = vfs_result {
                    let mut vslot = None;
                    for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                    let mut fd = None;
                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                    if let (Some(vs), Some(f)) = (vslot, fd) {
                        ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                        ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                        ctx.fd_flags[f] = flags;
                        reply_val(ctx.ep_cap, f as i64);
                    } else {
                        reply_val(ctx.ep_cap, -EMFILE);
                    }
                } else {
                    reply_val(ctx.ep_cap, -ENOENT);
                }
            } else {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    }
}

/// SYS_OPENAT (257): open file relative to directory fd.
pub(crate) fn sys_openat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let flags = msg.regs[2] as u32;
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    trace!(Debug, FS, {
        print(b"OPENAT P"); print_u64(ctx.pid as u64);
        print(b" fl=0x"); crate::framebuffer::print_hex64(flags as u64);
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
    // Resolve symlinks (Wine dosdevices compat)
    let (path, path_len) = {
        let mut resolved = [0u8; 256];
        let rlen = crate::fd::symlink_resolve(&path[..path_len], &mut resolved);
        let mut out = [0u8; 128];
        let n = rlen.min(127);
        out[..n].copy_from_slice(&resolved[..n]);
        (out, n)
    };

    // ── Step A: Canonicalize path (resolve . and ..) ────────────────
    // Wine uses relative paths like /sysroot/debian/bin/../../share/wine/nls/X
    // which must be resolved to /sysroot/share/wine/nls/X before rewriting.
    let (path, path_len) = {
        let src = &path[..path_len];
        let has_dotdot = {
            let mut found = false;
            let mut i = 0;
            while i + 1 < src.len() {
                if src[i] == b'.' && src[i + 1] == b'.' { found = true; break; }
                i += 1;
            }
            found
        };
        if has_dotdot && src.len() > 1 && src[0] == b'/' {
            let mut canon = [0u8; 128];
            let mut depth: [usize; 16] = [0; 16]; // stack of component start offsets
            let mut dp = 0usize; // depth pointer
            let mut out = 1usize; // output position (start after leading /)
            canon[0] = b'/';

            let mut i = 1usize;
            while i <= src.len() {
                let is_sep = i == src.len() || src[i] == b'/';
                if is_sep {
                    let comp_start = {
                        let mut s = i;
                        while s > 0 && src[s - 1] != b'/' { s -= 1; }
                        s
                    };
                    let comp = &src[comp_start..i];
                    if comp == b".." {
                        // pop one level
                        if dp > 0 {
                            dp -= 1;
                            out = depth[dp];
                        }
                    } else if comp != b"." && !comp.is_empty() {
                        // push component
                        if dp < 16 { depth[dp] = out; dp += 1; }
                        let n = comp.len().min(canon.len().saturating_sub(out + 1));
                        canon[out..out + n].copy_from_slice(&comp[..n]);
                        out += n;
                        if out < canon.len() { canon[out] = b'/'; out += 1; }
                    }
                    i += 1;
                } else {
                    i += 1;
                }
            }
            // Remove trailing /
            if out > 1 && canon[out - 1] == b'/' { out -= 1; }
            let mut result = [0u8; 128];
            let len = out.min(127);
            result[..len].copy_from_slice(&canon[..len]);
            (result, len)
        } else {
            (path, path_len)
        }
    };

    // ── Step B: Personality-aware path rewriting ("Fake Chroot") ──────
    // PERS_GLIBC processes see /sysroot/debian/ as their root for libs.
    // /lib/X  →  /sysroot/debian/lib/X   (glibc, not musl)
    // /usr/lib/X  →  /sysroot/debian/usr/lib/X
    // /sysroot/X (escaped via ..) → /sysroot/debian/X (re-jail)
    // This ensures glibc ld.so never finds musl libs and vice versa.
    let (path, path_len) = {
        let pers = crate::process::get_personality(ctx.pid);
        if pers == crate::process::PERS_GLIBC {
            const SYSROOT_PFX: &[u8] = b"/sysroot/debian";
            let name = &path[..path_len];

            // Rule 1: lib/share paths → prepend /sysroot/debian
            let rewrite_prefixes: &[&[u8]] = &[
                b"/lib/", b"/lib64/", b"/usr/lib/", b"/usr/lib64/",
                b"/share/", b"/usr/share/",
            ];
            let mut should_prepend = false;
            for pfx in rewrite_prefixes {
                if starts_with(name, pfx) { should_prepend = true; break; }
            }
            if !should_prepend && (name == b"/lib64" || name == b"/lib") {
                should_prepend = true;
            }

            // Rule 2: /sysroot/X (not /sysroot/debian/ or /sysroot/alpine/)
            //          → replace /sysroot/ with /sysroot/debian/ (re-jail)
            //          Catches paths like /sysroot/share/wine/nls/ that escaped
            //          the debian sysroot via .. resolution.
            let mut should_rejail = false;
            let sysroot_slash = b"/sysroot/";
            let sysroot_debian = b"/sysroot/debian/";
            let sysroot_alpine = b"/sysroot/alpine/";
            if !should_prepend
                && starts_with(name, sysroot_slash)
                && !starts_with(name, sysroot_debian)
                && !starts_with(name, sysroot_alpine)
            {
                should_rejail = true;
            }

            if should_prepend {
                let total = SYSROOT_PFX.len() + path_len;
                if total <= 127 {
                    let mut rewritten = [0u8; 128];
                    rewritten[..SYSROOT_PFX.len()].copy_from_slice(SYSROOT_PFX);
                    rewritten[SYSROOT_PFX.len()..total].copy_from_slice(&path[..path_len]);
                    trace!(Debug, FS, {
                        print(b"PERS-REWRITE P"); print_u64(ctx.pid as u64);
                        print(b" -> /sysroot/debian/...");
                    });
                    (rewritten, total)
                } else {
                    (path, path_len)
                }
            } else if should_rejail {
                // /sysroot/X → /sysroot/debian/X
                let rest = &path[sysroot_slash.len()..path_len];
                let rest_len = rest.len();
                let total = sysroot_debian.len() + rest_len;
                if total <= 127 {
                    let mut rewritten = [0u8; 128];
                    rewritten[..sysroot_debian.len()].copy_from_slice(sysroot_debian);
                    rewritten[sysroot_debian.len()..total].copy_from_slice(rest);
                    trace!(Debug, FS, {
                        print(b"PERS-REJAIL P"); print_u64(ctx.pid as u64);
                        print(b" -> /sysroot/debian/...");
                    });
                    (rewritten, total)
                } else {
                    (path, path_len)
                }
            } else {
                (path, path_len)
            }
        } else {
            (path, path_len)
        }
    };
    let name = &path[..path_len];

    // --- sotFS mount point intercept (SYS_OPENAT) ---
    if super::fs_sotfs::is_sotfs_path(name) {
        match super::fs_sotfs::sotfs_open(name, flags as u64) {
            Ok((inode_id, is_dir, size)) => {
                if let Some(fd) = super::fs_sotfs::sotfs_assign_fd(ctx, inode_id, is_dir, size) {
                    reply_val(ctx.ep_cap, fd as i64);
                } else {
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            }
            Err(e) => reply_val(ctx.ep_cap, e),
        }
        return;
    }

    // Synthetic directory open: /dev/dri/, /dev/input/
    if name == b"/dev/dri" || name == b"/dev/dri/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD01;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    if name == b"/dev/input" || name == b"/dev/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD02;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    let kind = if name == b"/dev/null" { 8u8 }
        else if name == b"/dev/zero" { 9u8 }
        else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
        else if name == b"/dev/dri/card0" { 30u8 }
        else if name == b"/dev/input/event0" { 31u8 }
        else if name == b"/dev/input/event1" { 32u8 }
        else { 0u8 };

    if kind != 0 {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = kind;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if false && crate::xkb::xkb_initrd_name(name).is_some() {
        // XKB files: DISABLED — served via VFS (kind=13) instead of dir_buf (kind=15)
        // VFS supports arbitrary file sizes and per-fd tracking
        unreachable!();
    } else if name == b"/sys/class" || name == b"/sys/class/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD05;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/drm" || name == b"/sys/class/drm/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD03;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/input" || name == b"/sys/class/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD04;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if starts_with(name, b"/etc/") || starts_with(name, b"/proc/")
           || starts_with(name, b"/sys/")
           || starts_with(name, b"/usr/share/")
           || starts_with(name, b"/run/udev/") {
        let virt_len = open_virtual_file(name, ctx.dir_buf);
        if let Some(gen_len) = virt_len {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        } else {
            vfs_lock();
            let vfs_found = unsafe { shared_store() }.and_then(|store| {
                use sotos_objstore::ROOT_OID;
                if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                    let entry = store.stat(oid)?;
                    Some((oid, entry.size, entry.is_dir()))
                } else { None }
            });
            vfs_unlock();
            if let Some((oid, size, is_dir)) = vfs_found {
                let mut vslot = None;
                for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                let mut fslot = None;
                for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fslot = Some(i); break; } }
                if let (Some(vs), Some(f)) = (vslot, fslot) {
                    ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                    ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                    ctx.fd_flags[f] = flags;
                    reply_val(ctx.ep_cap, f as i64);
                } else {
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            } else {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
        let mut gen_len: usize = 0;
        let mut handled = true;
        if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
            gen_len = crate::syscalls::mm::format_proc_maps(ctx.memg, ctx.dir_buf);
        } else if name == b"/proc/self/status" {
            gen_len = format_proc_status(ctx.dir_buf, ctx.pid);
        } else if name == b"/proc/self/stat" {
            gen_len = format_proc_self_stat(ctx.dir_buf, ctx.pid);
        } else if name == b"/proc/cpuinfo" {
            let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/meminfo" {
            let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/uptime" {
            let tsc = rdtsc();
            let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
            let secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 } + UPTIME_OFFSET_SECS;
            gen_len = format_uptime_into(ctx.dir_buf, secs);
        } else if name == b"/proc/version" {
            let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/loadavg" {
            let info = b"0.01 0.05 0.10 1/32 42\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/self/auxv" || name == b"/proc/self/environ" {
            // Empty content
        } else if starts_with(name, b"/proc/syslog/") {
            let rest = &path[13..path_len];
            let (max_n, _) = parse_u64_from(rest);
            let max_entries = if max_n == 0 { 10 } else { max_n as usize };
            gen_len = format_syslog_into(ctx.dir_buf, max_entries);
        } else if starts_with(name, b"/proc/netmirror/") {
            let rest = &path[16..path_len];
            let enable = rest == b"on" || rest == b"1";
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            if net_cap != 0 {
                let cmd_msg = sotos_common::IpcMsg {
                    tag: 12,
                    regs: [if enable { 1 } else { 0 }, 0, 0, 0, 0, 0, 0, 0],
                };
                let _ = sys::call(net_cap, &cmd_msg);
            }
            let msg_text = if enable { b"packet mirroring: ON\n" as &[u8] } else { b"packet mirroring: OFF\n" };
            let n = msg_text.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&msg_text[..n]);
            gen_len = n;
        } else if starts_with(name, b"/proc/") {
            let rest = &path[6..path_len];
            let (n, consumed) = parse_u64_from(rest);
            if consumed > 0 && n >= 1 && n <= MAX_PROCS as u64
                && PROCESSES[n as usize - 1].state.load(Ordering::Acquire) != 0
            {
                let after = &rest[consumed..];
                if after == b"/status" || after.is_empty() {
                    gen_len = format_proc_status(ctx.dir_buf, n as usize);
                } else {
                    handled = false;
                }
            } else {
                handled = false;
            }
        } else if starts_with(name, b"/sys/") {
            if name == b"/sys/devices/system/cpu/online" {
                let info = b"0-0\n";
                ctx.dir_buf[..info.len()].copy_from_slice(info);
                gen_len = info.len();
            } else if name == b"/sys/devices/system/cpu/possible" {
                let info = b"0-0\n";
                ctx.dir_buf[..info.len()].copy_from_slice(info);
                gen_len = info.len();
            } else if starts_with(name, b"/sys/devices/system/cpu/cpu0/") {
                gen_len = 0;
            } else {
                handled = false;
            }
        }

        if !handled {
            reply_val(ctx.ep_cap, -ENOENT);
        } else {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        }
    } else {
        trace!(Debug, FS, {
            print(b"OA P"); crate::framebuffer::print_u64(ctx.pid as u64);
            print(b" ["); for &b in name { sys::debug_print(b); } print(b"]");
        });
        // Wine debug: log all openat results for P3 with kind + dev info
        let _wine_trace_pid = ctx.pid;
        let oflags = OFlags::from_bits_truncate(flags as u32);
        let has_creat = oflags.contains(OFlags::CREAT);
        let has_trunc = oflags.contains(OFlags::TRUNC);
        let has_dir = oflags.contains(OFlags::DIRECTORY);

        // For library paths, check initrd FIRST to avoid VFS/disk shadow.
        // If the same .so exists in both VFS (disk, dev=2) and initrd (dev=1),
        // glibc ld.so loads both with different identities → fatal assertion.
        // By preferring initrd for /lib/ paths, we ensure consistent (dev, ino).
        //
        // EXCEPTION: PERS_GLIBC processes skip initrd-first entirely — their
        // /lib/ paths are already rewritten to /sysroot/debian/lib/ which lives
        // exclusively in VFS. This prevents glibc from accidentally finding musl.
        let pers = crate::process::get_personality(ctx.pid);
        let initrd_first = pers != crate::process::PERS_GLIBC
            && (starts_with(name, b"/lib/") || starts_with(name, b"/usr/lib/"));
        if initrd_first && !has_creat {
            let mut bn_start = 0usize;
            for idx in 0..path_len { if name[idx] == b'/' { bn_start = idx + 1; } }
            let bn = &name[bn_start..];
            if !bn.is_empty() {
                if let Ok(sz) = sys::initrd_read(bn.as_ptr() as u64, bn.len() as u64, 0, 0) {
                    if sz > 0 {
                        // File exists in initrd — use initrd path (skip VFS)
                        let mut slot = None;
                        for s in 0..GRP_MAX_INITRD {
                            if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
                        }
                        if let Some(slot) = slot {
                            let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0xC000000;
                            let buf_pages = ((sz as u64 + 0xFFF) / 0x1000).min(0x3000000 / 0x1000);
                            let mut buf_ok = true;
                            for p in 0..buf_pages {
                                if let Ok(f) = sys::frame_alloc() {
                                    if sys::map(file_buf + p * 0x1000, f, 2).is_err() {
                                        buf_ok = false; break;
                                    }
                                } else { buf_ok = false; break; }
                            }
                            if buf_ok {
                                if let Ok(actual_sz) = sys::initrd_read(
                                    bn.as_ptr() as u64, bn.len() as u64,
                                    file_buf, buf_pages * 0x1000,
                                ) {
                                    let mut fd = None;
                                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                                    if let Some(f) = fd {
                                        ctx.child_fds[f] = 12;
                                        ctx.initrd_files[slot] = [file_buf, actual_sz, 0, f as u64];
                                        reply_val(ctx.ep_cap, f as i64);
                                        return;
                                    } else {
                                        for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                        reply_val(ctx.ep_cap, -EMFILE);
                                        return;
                                    }
                                } else {
                                    for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Step 1: Try VFS resolve
        vfs_lock();
        let vfs_existing = unsafe { shared_store() }.and_then(|store| {
            use sotos_objstore::ROOT_OID;
            match store.resolve_path(name, ROOT_OID) {
                Ok(oid) => {
                    let entry = store.stat(oid)?;
                    if has_dir && !entry.is_dir() {
                        return None;
                    }
                    if has_trunc && !entry.is_dir() {
                        store.write_obj(oid, &[]).ok();
                        Some((oid, 0u64, entry.is_dir()))
                    } else {
                        Some((oid, entry.size, entry.is_dir()))
                    }
                }
                Err(_) => None,
            }
        });
        vfs_unlock();

        if let Some((oid, size, is_dir)) = vfs_existing {
            let mut vslot = None;
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; }
            }
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let (Some(vs), Some(f)) = (vslot, fd) {
                ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                ctx.fd_flags[f] = flags;
                if is_dir { dir_store_path(ctx, f, name); }
                if !is_dir {
                    trace!(Debug, FS, {
                        print(b"VFS-HIT P"); print_u64(ctx.pid as u64);
                        print(b" fd="); print_u64(f as u64);
                        print(b" d=2 oid="); crate::framebuffer::print_hex64(oid);
                        print(b" ["); for &b in &name[..path_len.min(40)] { sys::debug_print(b); } print(b"]");
                    });
                }
                if path_len >= 8 && &name[path_len-8..path_len] == b"ntdll.so" && ctx.pid < 16 {
                    unsafe { (*crate::syscalls::mm::NTDLL_SO_FD.get())[ctx.pid] = f as u8; }
                    trace!(Info, FS, {
                        print(b"NTDLL-FD P"); crate::framebuffer::print_u64(ctx.pid as u64);
                        print(b" fd="); crate::framebuffer::print_u64(f as u64);
                    });
                }
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
            return;
        }

        // Step 2: Try initrd
        let mut basename_start = 0usize;
        for idx in 0..path_len {
            if name[idx] == b'/' { basename_start = idx + 1; }
        }
        let basename = &name[basename_start..];
        let mut opened_initrd = false;
        // PERS_GLIBC: skip initrd entirely for lib paths — glibc processes
        // must only find their libs in /sysroot/debian/ (VFS, dev=2).
        // Without this, basename "libc.so.6" in initrd shadows the debian copy.
        let skip_initrd = pers == crate::process::PERS_GLIBC
            && (starts_with(name, b"/sysroot/debian/lib")
                || starts_with(name, b"/sysroot/debian/usr/lib"));

        if !skip_initrd && !basename.is_empty() {
            let mut slot = None;
            for s in 0..GRP_MAX_INITRD {
                if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
            }
            if let Some(slot) = slot {
                let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0xC000000;
                // Query file size first, allocate exact pages needed
                let file_sz = sys::initrd_read(
                    basename.as_ptr() as u64, basename.len() as u64, 0, 0
                ).unwrap_or(0);
                let buf_pages = if file_sz > 0 {
                    ((file_sz + 0xFFF) / 0x1000).min(0x3000000 / 0x1000)
                } else { 576 };
                let mut buf_ok = true;
                for p in 0..buf_pages {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            buf_ok = false; break;
                        }
                    } else { buf_ok = false; break; }
                }
                if buf_ok {
                    if let Ok(sz) = sys::initrd_read(
                        basename.as_ptr() as u64,
                        basename.len() as u64,
                        file_buf,
                        buf_pages * 0x1000,
                    ) {
                        let mut fd = None;
                        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            ctx.child_fds[f] = 12;
                            ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                            trace!(Debug, FS, {
                                print(b"IRD-HIT P"); print_u64(ctx.pid as u64);
                                print(b" fd="); print_u64(f as u64);
                                print(b" d=1 sz="); print_u64(sz);
                                print(b" ["); for &b in basename { sys::debug_print(b); } print(b"]");
                            });
                            if path_len >= 8 && &name[path_len-8..path_len] == b"ntdll.so" && ctx.pid < 16 {
                                unsafe { (*crate::syscalls::mm::NTDLL_SO_FD.get())[ctx.pid] = f as u8; }
                                trace!(Info, FS, {
                                    print(b"NTDLL-FD P"); crate::framebuffer::print_u64(ctx.pid as u64);
                                    print(b" fd="); crate::framebuffer::print_u64(f as u64);
                                });
                            }
                            reply_val(ctx.ep_cap, f as i64);
                            opened_initrd = true;
                        } else {
                            for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                            reply_val(ctx.ep_cap, -EMFILE);
                            opened_initrd = true;
                        }
                    } else {
                        for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                    }
                }
            }
        }

        // Step 3: VFS with O_CREAT
        if !opened_initrd {
            vfs_lock();
            let vfs_result = if has_creat {
                unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    match store.resolve_path(name, ROOT_OID) {
                        Ok(oid) => {
                            let entry = store.stat(oid)?;
                            if has_trunc && !entry.is_dir() {
                                store.write_obj(oid, &[]).ok();
                                Some((oid, 0u64, false))
                            } else {
                                Some((oid, entry.size, entry.is_dir()))
                            }
                        }
                        Err(_) => {
                            let mut last_slash = None;
                            for (i, &b) in name.iter().enumerate() {
                                if b == b'/' { last_slash = Some(i); }
                            }
                            let (parent_oid, filename) = match last_slash {
                                Some(pos) => {
                                    let parent_path = &name[..pos];
                                    let fname = &name[pos + 1..];
                                    let p = if parent_path.is_empty() {
                                        ROOT_OID
                                    } else {
                                        store.resolve_path(parent_path, ROOT_OID).ok()?
                                    };
                                    (p, fname)
                                }
                                None => (ROOT_OID, name),
                            };
                            match store.create_in(filename, &[], parent_oid) {
                                Ok(oid) => Some((oid, 0u64, false)),
                                Err(_) => None,
                            }
                        }
                    }
                })
            } else {
                None
            };
            vfs_unlock();

            if has_creat && vfs_result.is_none() {
                trace!(Error, FS, {
                    print(b"CREAT-FAIL: ");
                    print(name);
                });
            }

            match vfs_result {
                Some((oid, size, is_dir)) => {
                    let mut vslot = None;
                    for s in 0..GRP_MAX_VFS {
                        if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; }
                    }
                    let mut fd = None;
                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                    if let (Some(vs), Some(f)) = (vslot, fd) {
                        ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                        ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                        ctx.fd_flags[f] = flags;
                        trace!(Debug, FS, {
                            print(b"OPENAT-OK P"); print_u64(ctx.pid as u64);
                            print(b" fd="); print_u64(f as u64);
                            print(b" oid=0x"); crate::framebuffer::print_hex64(oid);
                            print(b" vs="); print_u64(vs as u64);
                            print(b" fl=0x"); crate::framebuffer::print_hex64(flags as u64);
                        });
                        reply_val(ctx.ep_cap, f as i64);
                    } else {
                        trace!(Error, FS, {
                            print(b"OPENAT-EMFILE P"); print_u64(ctx.pid as u64);
                            let mut used = 0u64;
                            for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] != 0 { used += 1; } }
                            print(b" vfs_used="); print_u64(used);
                            let mut fd_used = 0u64;
                            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] != 0 { fd_used += 1; } }
                            print(b" fd_used="); print_u64(fd_used);
                        });
                        reply_val(ctx.ep_cap, -EMFILE);
                    }
                }
                None => {
                    let mut found_initrd = false;
                    if !basename.is_empty() {
                        let mut slot = None;
                        for s in 0..GRP_MAX_INITRD {
                            if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
                        }
                        if let Some(slot) = slot {
                            let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0xC000000;
                            let file_sz = sys::initrd_read(
                                basename.as_ptr() as u64, basename.len() as u64, 0, 0
                            ).unwrap_or(0);
                            let buf_pages = if file_sz > 0 {
                                ((file_sz + 0xFFF) / 0x1000).min(0x3000000 / 0x1000)
                            } else { 576 };
                            let mut buf_ok = true;
                            for p in 0..buf_pages {
                                if let Ok(f) = sys::frame_alloc() {
                                    if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                        buf_ok = false; break;
                                    }
                                } else { buf_ok = false; break; }
                            }
                            if buf_ok {
                                if let Ok(sz) = sys::initrd_read(
                                    basename.as_ptr() as u64,
                                    basename.len() as u64,
                                    file_buf,
                                    buf_pages * 0x1000,
                                ) {
                                    let mut fd = None;
                                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                                    if let Some(f) = fd {
                                        ctx.child_fds[f] = 12;
                                        ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                        reply_val(ctx.ep_cap, f as i64);
                                        found_initrd = true;
                                    } else {
                                        for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                        reply_val(ctx.ep_cap, -EMFILE);
                                        found_initrd = true;
                                    }
                                } else {
                                    for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                }
                            }
                        }
                    }
                    if !found_initrd {
                        reply_val(ctx.ep_cap, -ENOENT);
                    }
                }
            }
        }
    }
}

/// SYS_CREAT (85).
pub(crate) fn sys_creat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    trace!(Debug, FS, {
        print(b"CREAT P"); print_u64(ctx.pid as u64);
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
    let name = &path[..path_len];

    vfs_lock();
    let vfs_result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
            let entry = store.stat(oid)?;
            if !entry.is_dir() { store.write_obj(oid, &[]).ok(); }
            return Some((oid, 0u64, false));
        }
        let mut last_slash = None;
        for (i, &b) in name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, fname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else {
                    store.resolve_path(&name[..pos], ROOT_OID).ok()?
                };
                (p, &name[pos+1..path_len])
            }
            None => (ROOT_OID, name),
        };
        let oid = store.create_in(fname, &[], parent).ok()?;
        Some((oid, 0, false))
    });
    vfs_unlock();

    if let Some((oid, size, is_dir)) = vfs_result {
        let mut vslot = None;
        for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let (Some(vs), Some(f)) = (vslot, fd) {
            ctx.child_fds[f] = if is_dir { 14 } else { 13 };
            ctx.vfs_files[vs] = [oid, size, 0, f as u64];
            ctx.fd_flags[f] = O_WRONLY;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else {
        reply_val(ctx.ep_cap, -ENOENT);
    }
}

