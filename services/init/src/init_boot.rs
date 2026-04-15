// ---------------------------------------------------------------------------
// init_boot: PID-1-exclusive boot-time setup.
// Runs once during init startup, NOT from an IPC loop. Hosts filesystem
// sysroot scaffolding (/bin, /lib, /usr/share/X11/xkb, sysroots for
// personality routing) and Wine DLL pre-population.
//
// Extracted from lucas_handler.rs so the shell main loop stays focused
// on dispatch and the boot-time scaffolding lives in a clear home.
// ---------------------------------------------------------------------------

use sotos_objstore::{ObjectStore, ROOT_OID};
use crate::framebuffer::{print, print_u64};

/// Ensure sysroot directories exist for dynamic binary support.
pub(crate) fn sysroot_init(store: &mut ObjectStore) {
    let dirs: &[&[u8]] = &[b"lib", b"lib64", b"bin", b"sbin", b"usr", b"tmp", b"root"];
    for name in dirs {
        if store.resolve_path(name, ROOT_OID).is_err() {
            let _ = store.mkdir(name, ROOT_OID);
        }
    }
    if let Ok(usr_oid) = store.resolve_path(b"usr", ROOT_OID) {
        let sub: &[&[u8]] = &[b"lib", b"lib64", b"bin", b"sbin", b"share"];
        for name in sub {
            if store.find_in(name, usr_oid).is_none() {
                let _ = store.mkdir(name, usr_oid);
            }
        }
        // Create /usr/share/terminfo/x/ for ncurses (nano, htop)
        if let Some(share_oid) = store.find_in(b"share", usr_oid) {
            if store.find_in(b"terminfo", share_oid).is_none() {
                let _ = store.mkdir(b"terminfo", share_oid);
            }
            if let Some(ti_oid) = store.find_in(b"terminfo", share_oid) {
                if store.find_in(b"x", ti_oid).is_none() {
                    let _ = store.mkdir(b"x", ti_oid);
                }
                // Copy xterm terminfo from initrd to /usr/share/terminfo/x/xterm
                if let Some(x_oid) = store.find_in(b"x", ti_oid) {
                    if store.find_in(b"xterm", x_oid).is_none() {
                        let mut buf = [0u8; 4096];
                        if let Ok(sz) = sotos_common::sys::initrd_read(
                            b"xterm\0".as_ptr() as u64, 5, buf.as_mut_ptr() as u64, 4096
                        ) {
                            let sz = sz as usize;
                            if sz > 0 && sz <= 4096 {
                                let _ = store.create_in(b"xterm", &buf[..sz], x_oid);
                            }
                        }
                    }
                }
            }
        }
    }
    // Create /var hierarchy (needed by apk package manager)
    if store.resolve_path(b"var", ROOT_OID).is_err() {
        let _ = store.mkdir(b"var", ROOT_OID);
    }
    if let Ok(var_oid) = store.resolve_path(b"var", ROOT_OID) {
        if store.find_in(b"cache", var_oid).is_none() { let _ = store.mkdir(b"cache", var_oid); }
        if let Some(cache_oid) = store.find_in(b"cache", var_oid) {
            if store.find_in(b"apk", cache_oid).is_none() { let _ = store.mkdir(b"apk", cache_oid); }
        }
        if store.find_in(b"lib", var_oid).is_none() { let _ = store.mkdir(b"lib", var_oid); }
        if let Some(lib_oid) = store.find_in(b"lib", var_oid) {
            if store.find_in(b"apk", lib_oid).is_none() { let _ = store.mkdir(b"apk", lib_oid); }
        }
    }
    // Create /lib/apk/db/ for apk package database
    if let Ok(lib_oid) = store.resolve_path(b"lib", ROOT_OID) {
        if store.find_in(b"apk", lib_oid).is_none() { let _ = store.mkdir(b"apk", lib_oid); }
        if let Some(apk_oid) = store.find_in(b"apk", lib_oid) {
            if store.find_in(b"db", apk_oid).is_none() { let _ = store.mkdir(b"db", apk_oid); }
        }
    }
    // Create /etc/apk directory
    if store.resolve_path(b"etc", ROOT_OID).is_err() {
        let _ = store.mkdir(b"etc", ROOT_OID);
    }
    if let Ok(etc_oid) = store.resolve_path(b"etc", ROOT_OID) {
        if store.find_in(b"apk", etc_oid).is_none() { let _ = store.mkdir(b"apk", etc_oid); }
    }
    // Create /run/user/0 for XDG_RUNTIME_DIR (needed by Wine server directory)
    if store.resolve_path(b"run", ROOT_OID).is_err() {
        let _ = store.mkdir(b"run", ROOT_OID);
    }
    if let Ok(run_oid) = store.resolve_path(b"run", ROOT_OID) {
        if store.find_in(b"user", run_oid).is_none() {
            let _ = store.mkdir(b"user", run_oid);
        }
        if let Some(user_oid) = store.find_in(b"user", run_oid) {
            if store.find_in(b"0", user_oid).is_none() {
                let _ = store.mkdir(b"0", user_oid);
            }
        }
    }
    // Create /usr/share/X11/xkb/ hierarchy and copy XKB files from initrd
    // (needed by xkbcommon for keyboard layouts — weston requires this)
    if let Ok(usr_oid) = store.resolve_path(b"usr", ROOT_OID) {
        if let Some(share_oid) = store.find_in(b"share", usr_oid) {
            trace!(Debug, FS, { print(b"XKB: creating /usr/share/X11..."); });
            if store.find_in(b"X11", share_oid).is_none() {
                match store.mkdir(b"X11", share_oid) {
                    Ok(_) => { trace!(Debug, FS, { print(b"XKB: X11 dir created"); }); },
                    Err(_) => { trace!(Error, FS, { print(b"XKB: X11 mkdir FAILED"); }); },
                }
            }
            if let Some(x11_oid) = store.find_in(b"X11", share_oid) {
                if store.find_in(b"xkb", x11_oid).is_none() { let _ = store.mkdir(b"xkb", x11_oid); }
                if let Some(xkb_oid) = store.find_in(b"xkb", x11_oid) {
                    // Create subdirs
                    let subdirs: &[&[u8]] = &[b"rules", b"keycodes", b"types", b"compat", b"symbols", b"geometry"];
                    for d in subdirs {
                        if store.find_in(d, xkb_oid).is_none() { let _ = store.mkdir(d, xkb_oid); }
                    }
                    // Copy XKB files from initrd into VFS
                    let xkb_files: &[(&[u8], &[u8], &[u8])] = &[
                        (b"rules", b"evdev", b"xkb_rules_evdev\0"),
                        (b"keycodes", b"evdev", b"xkb_keycodes_evdev\0"),
                        (b"types", b"complete", b"xkb_types_complete\0"),
                        (b"types", b"basic", b"xkb_types_basic\0"),
                        (b"compat", b"complete", b"xkb_compat_complete\0"),
                        (b"compat", b"basic", b"xkb_compat_basic\0"),
                        (b"symbols", b"us", b"xkb_symbols_us\0"),
                        (b"symbols", b"pc", b"xkb_symbols_pc\0"),
                        (b"symbols", b"latin", b"xkb_symbols_latin\0"),
                        (b"symbols", b"inet", b"xkb_symbols_inet\0"),
                    ];
                    // Use a 128KB buffer for large xkb files
                    let buf_ptr = 0x5300000u64; // temp page (below EXEC_BUF_BASE)
                    let buf_pages = 32u64; // 128 KiB
                    let mut mapped = false;
                    for p in 0..buf_pages {
                        if let Ok(f) = sotos_common::sys::frame_alloc() {
                            let _ = sotos_common::sys::map(buf_ptr + p * 0x1000, f, 2);
                            mapped = true;
                        }
                    }
                    trace!(Debug, FS, { print(b"XKB: mapped="); print_u64(mapped as u64); });
                    if mapped {
                        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, (buf_pages * 0x1000) as usize) };
                        for &(subdir, fname, initrd_name) in xkb_files {
                            if let Some(dir_oid) = store.find_in(subdir, xkb_oid) {
                                if store.find_in(fname, dir_oid).is_none() {
                                    let name_len = initrd_name.len() - 1; // exclude NUL
                                    trace!(Debug, FS, { print(b"XKB: reading "); print(initrd_name); });
                                    if let Ok(sz) = sotos_common::sys::initrd_read(
                                        initrd_name.as_ptr() as u64, name_len as u64,
                                        buf.as_mut_ptr() as u64, buf.len() as u64
                                    ) {
                                        let sz = sz as usize;
                                        if sz > 0 && sz <= buf.len() {
                                            let _ = store.create_in(fname, &buf[..sz], dir_oid);
                                        }
                                    }
                                }
                            }
                        }
                        // Unmap temp buffer
                        for p in 0..buf_pages {
                            let _ = sotos_common::sys::unmap_free(buf_ptr + p * 0x1000);
                        }
                    }
                }
            }
        }
    }
    // NOTE: Do NOT create /lib/x86_64-linux-gnu/ — it interferes with ld-linux's
    // library resolution by making VFS resolve partially succeed for a path that
    // should fall through to the initrd. The directory will be created on-demand
    // when disk content is accessed via ls.
    // NOTE: Do NOT provide libc.musl-x86_64.so.1 in VFS or initrd.
    // Wine handles the missing musl gracefully: dlopen(ntdll.so) fails,
    // Wine re-execs itself, and the second pass works without musl.
    // If musl IS found, glibc's ld.so crashes with a dual-libc assertion.

    // Personality-isolated sysroot directories: /sysroot/alpine/ and /sysroot/debian/
    // Each personality sees only its own libs via openat path rewriting.
    if store.resolve_path(b"sysroot", ROOT_OID).is_err() {
        let _ = store.mkdir(b"sysroot", ROOT_OID);
    }
    if let Ok(sr_oid) = store.resolve_path(b"sysroot", ROOT_OID) {
        for name in [b"alpine" as &[u8], b"debian"] {
            if store.find_in(name, sr_oid).is_none() {
                let _ = store.mkdir(name, sr_oid);
            }
        }
        // Create subdirs under /sysroot/debian/ for disk-based glibc libs
        if let Some(deb_oid) = store.find_in(b"debian", sr_oid) {
            for sub in [b"lib" as &[u8], b"lib64", b"bin", b"usr", b"etc"] {
                if store.find_in(sub, deb_oid).is_none() {
                    let _ = store.mkdir(sub, deb_oid);
                }
            }
            if let Some(usr_oid) = store.find_in(b"usr", deb_oid) {
                for sub in [b"lib" as &[u8], b"lib64", b"bin"] {
                    if store.find_in(sub, usr_oid).is_none() {
                        let _ = store.mkdir(sub, usr_oid);
                    }
                }
            }
        }
    }
    // ── Wine DLL pre-population ──
    // Wine's wineboot needs DLLs from x86_64-windows/ to run, but wineboot
    // creates c:\windows\system32\ which holds symlinks to those DLLs.
    // Chicken-and-egg: create system32 with hardlinks BEFORE wineboot runs.
    wine_prepopulate_system32(store);

    trace!(Info, FS, { print(b"sysroot dirs initialized (alpine+debian)"); });
}

/// Pre-create Wine prefix with DLL hardlinks so wineboot can find them.
fn wine_prepopulate_system32(store: &mut ObjectStore) {
    use sotos_objstore::layout::{DirEntry, ROOT_OID};

    // Find the Wine DLL source directory on disk:
    // /sysroot/debian/x86_64-linux-gnu/wine/x86_64-windows/
    let src_oid = {
        let sr = match store.resolve_path(b"sysroot", ROOT_OID) { Ok(o) => o, Err(_) => return };
        let deb = match store.find_in(b"debian", sr) { Some(o) => o, None => return };
        let x86 = match store.find_in(b"x86_64-linux-gnu", deb) { Some(o) => o, None => return };
        let wine = match store.find_in(b"wine", x86) { Some(o) => o, None => return };
        match store.find_in(b"x86_64-windows", wine) { Some(o) => o, None => return }
    };

    // Create Wine prefix: /root/.wine/dosdevices/c:/windows/system32/
    let root_oid = match store.resolve_path(b"root", ROOT_OID) { Ok(o) => o, Err(_) => return };
    let wine_oid = match store.find_in(b".wine", root_oid) {
        Some(o) => o,
        None => match store.mkdir(b".wine", root_oid) { Ok(o) => o, Err(_) => return },
    };
    let dd_oid = match store.find_in(b"dosdevices", wine_oid) {
        Some(o) => o,
        None => match store.mkdir(b"dosdevices", wine_oid) { Ok(o) => o, Err(_) => return },
    };
    let c_oid = match store.find_in(b"c:", dd_oid) {
        Some(o) => o,
        None => match store.mkdir(b"c:", dd_oid) { Ok(o) => o, Err(_) => return },
    };
    let win_oid = match store.find_in(b"windows", c_oid) {
        Some(o) => o,
        None => match store.mkdir(b"windows", c_oid) { Ok(o) => o, Err(_) => return },
    };
    let sys32_oid = match store.find_in(b"system32", win_oid) {
        Some(o) => o,
        None => match store.mkdir(b"system32", win_oid) { Ok(o) => o, Err(_) => return },
    };

    // List all DLLs in x86_64-windows/ and hardlink them into system32/
    let mut dll_entries = [DirEntry::zeroed(); 64];
    let count = store.list_dir(src_oid, &mut dll_entries);
    let mut linked = 0u32;
    for i in 0..count.min(64) {
        let e = &dll_entries[i];
        if e.is_dir() || e.size == 0 { continue; }
        let name = e.name_as_str();
        if name.is_empty() { continue; }
        match store.link_into(name, e.oid, sys32_oid) {
            Ok(_) => { linked += 1; }
            Err(_) => {} // might already exist
        }
    }

    if linked > 0 {
        // Flush all changes at once
        let _ = store.flush_dir();
        let _ = store.flush_superblock();
        let _ = store.flush_refcount();
        print(b"WINE: pre-populated system32 with ");
        print_u64(linked as u64);
        print(b" DLLs\n");
    }
}
