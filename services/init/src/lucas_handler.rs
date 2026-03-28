// ---------------------------------------------------------------------------
// lucas_handler: LUCAS shell syscall handler (PID 1).
// Delegates to syscalls/ submodules via SyscallContext (DRY).
// Only PID-1-exclusive logic remains inline (VFS mount, vDSO, child spawn,
// LUCAS-specific /snap/ and /proc/ virtual paths).
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_objstore::{ObjectStore, Vfs, DirEntry, ROOT_OID};
use sotos_virtio::blk::VirtioBlk;
use core::sync::atomic::Ordering;
use crate::child_handler::child_handler;
use crate::framebuffer::{print, print_u64};
use crate::exec::{reply_val, rdtsc, format_u64_into, copy_guest_path, starts_with,
                  format_uptime_into, format_pid_row};
use crate::process::*;
use crate::fd::*;
use crate::syscall_log::{syscall_log_record, format_syslog_into};
use crate::vdso;
use crate::{LUCAS_EP_CAP, LUCAS_VFS_READY, LUCAS_BLK_STORE, NET_EP_CAP, SHARED_STORE_PTR};
use crate::{vfs_lock, vfs_unlock, shared_store};
use crate::syscalls::context::SyscallContext;
use crate::syscalls::mm as syscalls_mm;
use crate::syscalls::fs as syscalls_fs;
use crate::syscalls::net as syscalls_net;
use crate::syscalls::signal as syscalls_signal;
use crate::syscalls::info as syscalls_info;
use crate::syscalls::task as syscalls_task;

const MAP_WRITABLE: u64 = 2;

/// Ensure sysroot directories exist for dynamic binary support.
fn sysroot_init(store: &mut ObjectStore) {
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

/// LUCAS handler — PID 1 syscall loop.
/// Owns the VFS (ObjectStore) and delegates syscalls to shared submodules.
pub(crate) extern "C" fn lucas_handler() -> ! {
    let ep_cap = LUCAS_EP_CAP.load(Ordering::Acquire);
    let boot_tsc_val = rdtsc();
    BOOT_TSC.store(boot_tsc_val, Ordering::Release);

    // Map and forge vDSO page
    let vdso_mapped = if let Ok(vf) = sys::frame_alloc() {
        sys::map(vdso::VDSO_BASE, vf, MAP_WRITABLE).is_ok()
    } else { false };
    {
        let vdso_page = unsafe {
            core::slice::from_raw_parts_mut(vdso::VDSO_BASE as *mut u8, 4096)
        };
        if vdso_mapped {
            for b in vdso_page.iter_mut() { *b = 0; }
        }
        vdso::forge(vdso_page, boot_tsc_val);
        let _ = sys::protect(vdso::VDSO_BASE, 0);
        trace!(Info, PROCESS, { print(b"vDSO forged at 0xB80000"); });
    }

    // Register as PID 1
    let pid: u64 = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    PROCESSES[pid as usize - 1].state.store(1, Ordering::Release);
    proc_group_init(pid as usize);

    // --- VFS init: mount ObjectStore from VirtioBlk ---
    let has_vfs = LUCAS_VFS_READY.load(Ordering::Acquire) != 0;
    let _vfs_opt: Option<Vfs> = if has_vfs {
        let blk = unsafe { core::ptr::read(LUCAS_BLK_STORE as *const VirtioBlk) };
        match ObjectStore::mount(blk) {
            Ok(mut store) => {
                trace!(Info, FS, { print(b"VFS bridge active"); });
                sysroot_init(&mut store);
                let vfs = Vfs::new(store);
                let store_ptr = vfs.store() as *const _ as u64;
                SHARED_STORE_PTR.store(store_ptr, Ordering::Release);
                Some(vfs)
            }
            Err(e) => {
                trace!(Error, FS, { print(b"VFS mount failed: "); print(e.as_bytes()); });
                None
            }
        }
    } else {
        None
    };

    // Initialize THREAD_GROUPS[0] for PID 1 (fd_grp_init already called by proc_group_init)
    let fdg: usize = 0; // PID 1 uses group 0
    unsafe {
        THREAD_GROUPS[fdg].brk = BRK_BASE;
        THREAD_GROUPS[fdg].mmap_next = MMAP_BASE;
        THREAD_GROUPS[fdg].initrd_buf_base = 0x5800000;
    }

    /// Create a SyscallContext from THREAD_GROUPS[0] for PID 1.
    macro_rules! make_ctx {
        () => {
            unsafe {
                let tg = &mut THREAD_GROUPS[fdg];
                SyscallContext {
                    pid: pid as usize,
                    ep_cap,
                    child_as_cap: 0, // PID 1 shares init's address space
                    guard_fdg: usize::MAX,
                    current_brk: &mut tg.brk,
                    mmap_next: &mut tg.mmap_next,
                    my_brk_base: BRK_BASE,
                    my_mmap_base: MMAP_BASE,
                    memg: fdg,
                    child_fds: &mut tg.fds,
                    fd_cloexec: &mut tg.fd_cloexec,
                    initrd_files: &mut tg.initrd,
                    initrd_file_buf_base: tg.initrd_buf_base,
                    vfs_files: &mut tg.vfs,
                    dir_buf: &mut tg.dir_buf,
                    dir_len: &mut tg.dir_len,
                    dir_pos: &mut tg.dir_pos,
                    cwd: &mut tg.cwd,
                    fd_flags: &mut tg.fd_flags,
                    sock_conn_id: &mut tg.sock_conn_id,
                    sock_udp_local_port: &mut tg.sock_udp_local_port,
                    sock_udp_remote_ip: &mut tg.sock_udp_remote_ip,
                    sock_udp_remote_port: &mut tg.sock_udp_remote_port,
                    eventfd_counter: &mut tg.eventfd_counter,
                    eventfd_flags: &mut tg.eventfd_flags,
                    eventfd_slot_fd: &mut tg.eventfd_slot_fd,
                    timerfd_interval_ns: &mut tg.timerfd_interval_ns,
                    timerfd_expiry_tsc: &mut tg.timerfd_expiry_tsc,
                    timerfd_slot_fd: &mut tg.timerfd_slot_fd,
                    memfd_base: &mut tg.memfd_base,
                    memfd_size: &mut tg.memfd_size,
                    memfd_cap: &mut tg.memfd_cap,
                    memfd_slot_fd: &mut tg.memfd_slot_fd,
                    epoll_reg_fd: &mut tg.epoll_reg_fd,
                    epoll_reg_events: &mut tg.epoll_reg_events,
                    epoll_reg_data: &mut tg.epoll_reg_data,
                }
            }
        };
    }

    // seatd: handled inline in child_handler (kind=33 seatd socket)

    // ── Main syscall loop ──
    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let kernel_tid = msg.regs[6];
        if kernel_tid != 0 {
            PROCESSES[pid as usize - 1].kernel_tid.store(kernel_tid, Ordering::Release);
        }

        // Check pending signals (same mechanism as child_handler)
        if let Some(action) = syscalls_signal::check_pending_signals(ep_cap, pid as usize, kernel_tid, 0) {
            if action.is_break() { break; }
            continue;
        }

        let syscall_nr = msg.tag;
        syscall_log_record(pid as u16, syscall_nr as u16, msg.regs[0], 0);

        match syscall_nr {

            // ═══════════════════════════════════════════════════════════
            // PID-1 exclusive: child process spawning
            // ═══════════════════════════════════════════════════════════
            SYS_CLONE => {
                let child_fn = msg.regs[0];
                let stack_base = NEXT_CHILD_STACK.fetch_add(0x21000, Ordering::SeqCst);
                let guest_stack = stack_base;
                let handler_stack = stack_base + 0x1000;

                let gf = match sys::frame_alloc() {
                    Ok(f) => f,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };
                if sys::map(guest_stack, gf, MAP_WRITABLE).is_err() {
                    reply_val(ep_cap, -ENOMEM); continue;
                }
                let mut hok = true;
                for hp in 0..32u64 {
                    let hf = match sys::frame_alloc() {
                        Ok(f) => f,
                        Err(_) => { hok = false; break; }
                    };
                    if sys::map(handler_stack + hp * 0x1000, hf, MAP_WRITABLE).is_err() {
                        hok = false; break;
                    }
                }
                if !hok { reply_val(ep_cap, -ENOMEM); continue; }

                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };
                let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);
                PROCESSES[child_pid as usize - 1].parent.store(pid, Ordering::Release);
                proc_group_init(child_pid as usize);

                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(child_pid, Ordering::Release);
                CHILD_SETUP_FLAGS.store(0, Ordering::Release);
                CHILD_SETUP_AS_CAP.store(0, Ordering::Release);
                CHILD_SETUP_READY.store(1, Ordering::Release);

                if sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack + 0x20000,
                ).is_err() {
                    CHILD_SETUP_READY.store(0, Ordering::Release);
                    reply_val(ep_cap, -ENOMEM); continue;
                }
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 {
                    sys::yield_now();
                }

                let child_thread = match sys::thread_create_redirected(child_fn, guest_stack + 0x1000, child_ep) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };
                let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);
                PROCESSES[child_pid as usize - 1].state.store(1, Ordering::Release);
                reply_val(ep_cap, child_pid as i64);
            }

            // ═══════════════════════════════════════════════════════════
            // PID-1 exclusive: exit just breaks the loop
            // ═══════════════════════════════════════════════════════════
            SYS_EXIT => {
                trace!(Info, PROCESS, { print(b"LUCAS exit("); print_u64(msg.regs[0]); print(b")"); });
                break;
            }
            SYS_EXIT_GROUP => {
                PROCESSES[pid as usize - 1].exit_code.store(msg.regs[0], Ordering::Release);
                PROCESSES[pid as usize - 1].state.store(2, Ordering::Release);
                let ppid = PROCESSES[pid as usize - 1].parent.load(Ordering::Acquire) as usize;
                if ppid > 0 && ppid <= MAX_PROCS {
                    sig_send(ppid, SIGCHLD as u64);
                }
                break;
            }

            // ═══════════════════════════════════════════════════════════
            // SYS_OPEN: pre-check LUCAS-specific paths, then delegate
            // ═══════════════════════════════════════════════════════════
            SYS_OPEN => {
                let mut path = [0u8; 256];
                let path_len = copy_guest_path(msg.regs[0], &mut path);
                let name = &path[..path_len];

                // "." → LUCAS formatted directory listing (for built-in ls)
                if path_len == 1 && path[0] == b'.' {
                    let tg = unsafe { &mut THREAD_GROUPS[fdg] };
                    if lucas_open_cwd_listing(&tg.cwd, &mut tg.dir_buf, &mut tg.dir_len, &mut tg.dir_pos, &mut tg.fds) {
                        reply_val(ep_cap, find_last_alloc_fd(&tg.fds) as i64);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                    continue;
                }

                // /snap/ → snapshot operations (LUCAS-exclusive)
                if starts_with(name, b"/snap/") {
                    let tg = unsafe { &mut THREAD_GROUPS[fdg] };
                    lucas_open_snap(name, &mut tg.dir_buf, &mut tg.dir_len, &mut tg.dir_pos, &mut tg.fds, ep_cap);
                    continue;
                }

                // /proc/ LUCAS-specific paths (syslog, netmirror, uptime, etc.)
                if starts_with(name, b"/proc") {
                    let tg = unsafe { &mut THREAD_GROUPS[fdg] };
                    if lucas_open_proc(name, path_len, pid as usize,
                                       &mut tg.dir_buf, &mut tg.dir_len, &mut tg.dir_pos,
                                       &mut tg.fds, ep_cap) {
                        continue; // Handled by LUCAS-specific /proc/ handler
                    }
                    // Fall through to submodule for standard /proc/ paths
                }

                // Standard paths → delegate to submodule
                let mut ctx = make_ctx!();
                syscalls_fs::sys_open(&mut ctx, &msg);
            }

            // ═══════════════════════════════════════════════════════════
            // Delegated: File/IO (syscalls::fs)
            // ═══════════════════════════════════════════════════════════
            SYS_READ     => { let mut ctx = make_ctx!(); syscalls_fs::sys_read(&mut ctx, &msg); }
            SYS_WRITE    => { let mut ctx = make_ctx!(); syscalls_fs::sys_write(&mut ctx, &msg); }
            SYS_CLOSE    => { let mut ctx = make_ctx!(); syscalls_fs::sys_close(&mut ctx, &msg); }
            SYS_STAT | SYS_LSTAT
                         => { let mut ctx = make_ctx!(); syscalls_fs::sys_stat(&mut ctx, &msg); }
            SYS_FSTAT    => { let mut ctx = make_ctx!(); syscalls_fs::sys_fstat(&mut ctx, &msg); }
            SYS_LSEEK    => { let mut ctx = make_ctx!(); syscalls_fs::sys_lseek(&mut ctx, &msg); }
            SYS_IOCTL    => { let mut ctx = make_ctx!(); syscalls_fs::sys_ioctl(&mut ctx, &msg); }
            SYS_READV    => { let mut ctx = make_ctx!(); syscalls_fs::sys_readv(&mut ctx, &msg); }
            SYS_WRITEV   => { let mut ctx = make_ctx!(); syscalls_fs::sys_writev(&mut ctx, &msg); }
            SYS_ACCESS   => { let mut ctx = make_ctx!(); syscalls_fs::sys_access(&mut ctx, &msg, syscall_nr); }
            SYS_PIPE     => { let mut ctx = make_ctx!(); syscalls_fs::sys_pipe(&mut ctx, &msg); }
            SYS_DUP      => { let mut ctx = make_ctx!(); syscalls_fs::sys_dup(&mut ctx, &msg); }
            SYS_DUP2     => { let mut ctx = make_ctx!(); syscalls_fs::sys_dup2(&mut ctx, &msg); }
            SYS_DUP3     => { let mut ctx = make_ctx!(); syscalls_fs::sys_dup3(&mut ctx, &msg); }
            SYS_FCNTL    => { let mut ctx = make_ctx!(); syscalls_fs::sys_fcntl(&mut ctx, &msg); }
            SYS_FTRUNCATE=> { let mut ctx = make_ctx!(); syscalls_fs::sys_ftruncate(&mut ctx, &msg); }
            SYS_FSYNC    => { let mut ctx = make_ctx!(); syscalls_fs::sys_fsync(&mut ctx, &msg); }
            SYS_GETCWD   => { let mut ctx = make_ctx!(); syscalls_fs::sys_getcwd(&mut ctx, &msg); }
            SYS_CHDIR    => { let mut ctx = make_ctx!(); syscalls_fs::sys_chdir(&mut ctx, &msg); }
            SYS_RENAME   => { let mut ctx = make_ctx!(); syscalls_fs::sys_rename(&mut ctx, &msg); }
            SYS_MKDIR    => { let mut ctx = make_ctx!(); syscalls_fs::sys_mkdir(&mut ctx, &msg); }
            SYS_RMDIR    => { let mut ctx = make_ctx!(); syscalls_fs::sys_rmdir(&mut ctx, &msg); }
            SYS_UNLINK   => { let mut ctx = make_ctx!(); syscalls_fs::sys_unlink(&mut ctx, &msg); }
            SYS_READLINK => { let mut ctx = make_ctx!(); syscalls_fs::sys_readlink(&mut ctx, &msg); }
            SYS_GETDENTS64=>{ let mut ctx = make_ctx!(); syscalls_fs::sys_getdents64(&mut ctx, &msg); }
            SYS_OPENAT   => { let mut ctx = make_ctx!(); syscalls_fs::sys_openat(&mut ctx, &msg); }
            SYS_FSTATAT  => { let mut ctx = make_ctx!(); syscalls_fs::sys_fstatat(&mut ctx, &msg); }
            SYS_READLINKAT=>{ let mut ctx = make_ctx!(); syscalls_fs::sys_readlinkat(&mut ctx, &msg); }
            SYS_FACCESSAT=> { let mut ctx = make_ctx!(); syscalls_fs::sys_access(&mut ctx, &msg, syscall_nr); }
            SYS_UNLINKAT => { let mut ctx = make_ctx!(); syscalls_fs::sys_unlinkat(&mut ctx, &msg); }
            SYS_RENAMEAT | SYS_RENAMEAT2
                         => { let mut ctx = make_ctx!(); syscalls_fs::sys_renameat(&mut ctx, &msg); }
            SYS_MKDIRAT  => { let mut ctx = make_ctx!(); syscalls_fs::sys_mkdirat(&mut ctx, &msg); }
            SYS_PREAD64  => { let mut ctx = make_ctx!(); syscalls_fs::sys_pread64(&mut ctx, &msg); }
            SYS_PWRITE64 => { let mut ctx = make_ctx!(); syscalls_fs::sys_pwrite64(&mut ctx, &msg); }
            SYS_PREADV   => { let mut ctx = make_ctx!(); syscalls_fs::sys_preadv(&mut ctx, &msg); }
            SYS_PWRITEV  => { let mut ctx = make_ctx!(); syscalls_fs::sys_pwritev(&mut ctx, &msg); }
            SYS_PIPE2    => { let mut ctx = make_ctx!(); syscalls_fs::sys_pipe2(&mut ctx, &msg); }
            SYS_STATFS | SYS_FSTATFS
                         => { let mut ctx = make_ctx!(); syscalls_fs::sys_statfs(&mut ctx, &msg, syscall_nr); }
            SYS_FACCESSAT2
                         => { let mut ctx = make_ctx!(); syscalls_fs::sys_faccessat2(&mut ctx, &msg); }
            SYS_SENDFILE => { let mut ctx = make_ctx!(); syscalls_fs::sys_sendfile(&mut ctx, &msg); }
            SYS_UMASK    => { let mut ctx = make_ctx!(); syscalls_fs::sys_umask(&mut ctx, &msg); }

            // ═══════════════════════════════════════════════════════════
            // Delegated: Memory management (syscalls::mm)
            // ═══════════════════════════════════════════════════════════
            SYS_BRK      => { let mut ctx = make_ctx!(); syscalls_mm::sys_brk(&mut ctx, &msg); }
            SYS_MMAP     => { let mut ctx = make_ctx!(); syscalls_mm::sys_mmap(&mut ctx, &msg); }
            SYS_MUNMAP   => { let mut ctx = make_ctx!(); syscalls_mm::sys_munmap(&mut ctx, &msg); }
            SYS_MPROTECT => { let mut ctx = make_ctx!(); syscalls_mm::sys_mprotect(&mut ctx, &msg); }
            SYS_MREMAP   => { let mut ctx = make_ctx!(); syscalls_mm::sys_mremap(&mut ctx, &msg); }

            // ═══════════════════════════════════════════════════════════
            // Delegated: Networking + poll/epoll (syscalls::net)
            // ═══════════════════════════════════════════════════════════
            SYS_POLL     => { let mut ctx = make_ctx!(); syscalls_net::sys_poll(&mut ctx, &msg); }
            SYS_PPOLL    => { let mut ctx = make_ctx!(); syscalls_net::sys_ppoll(&mut ctx, &msg); }
            SYS_SOCKET   => { let mut ctx = make_ctx!(); syscalls_net::sys_socket(&mut ctx, &msg); }
            SYS_CONNECT  => { let mut ctx = make_ctx!(); syscalls_net::sys_connect(&mut ctx, &msg); }
            SYS_SENDTO   => { let mut ctx = make_ctx!(); syscalls_net::sys_sendto(&mut ctx, &msg); }
            SYS_SENDMSG  => { let mut ctx = make_ctx!(); syscalls_net::sys_sendmsg(&mut ctx, &msg); }
            SYS_RECVFROM => { let mut ctx = make_ctx!(); syscalls_net::sys_recvfrom(&mut ctx, &msg); }
            SYS_RECVMSG  => { let mut ctx = make_ctx!(); syscalls_net::sys_recvmsg(&mut ctx, &msg); }
            SYS_BIND     => { let mut ctx = make_ctx!(); syscalls_net::sys_bind(&mut ctx, &msg); }
            SYS_LISTEN   => { let mut ctx = make_ctx!(); syscalls_net::sys_listen(&mut ctx, &msg); }
            SYS_SETSOCKOPT
                         => { let mut ctx = make_ctx!(); syscalls_net::sys_setsockopt(&mut ctx, &msg); }
            SYS_GETSOCKNAME | SYS_GETPEERNAME
                         => { let mut ctx = make_ctx!(); syscalls_net::sys_getsockname(&mut ctx, &msg, syscall_nr); }
            SYS_GETSOCKOPT=>{ let mut ctx = make_ctx!(); syscalls_net::sys_getsockopt(&mut ctx, &msg); }
            SYS_SHUTDOWN => { let mut ctx = make_ctx!(); syscalls_net::sys_shutdown(&mut ctx, &msg); }
            SYS_SELECT | SYS_PSELECT6
                         => { let mut ctx = make_ctx!(); syscalls_net::sys_select(&mut ctx, &msg, syscall_nr); }
            SYS_EPOLL_CREATE1 | SYS_EPOLL_CREATE
                         => { let mut ctx = make_ctx!(); syscalls_net::sys_epoll_create(&mut ctx, &msg); }
            SYS_EPOLL_CTL=> { let mut ctx = make_ctx!(); syscalls_net::sys_epoll_ctl(&mut ctx, &msg); }
            SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT
                         => { let mut ctx = make_ctx!(); syscalls_net::sys_epoll_wait(&mut ctx, &msg); }
            SYS_SOCKETPAIR=>{ let mut ctx = make_ctx!(); syscalls_net::sys_socketpair(&mut ctx, &msg); }
            SYS_ACCEPT | SYS_ACCEPT4
                         => { let mut ctx = make_ctx!(); syscalls_net::sys_accept(&mut ctx, &msg); }

            // ═══════════════════════════════════════════════════════════
            // Delegated: Process lifecycle + identity (syscalls::task)
            // ═══════════════════════════════════════════════════════════
            SYS_GETPID   => { let mut ctx = make_ctx!(); syscalls_task::sys_getpid(&mut ctx, &msg); }
            SYS_GETTID   => { let mut ctx = make_ctx!(); syscalls_task::sys_gettid(&mut ctx, &msg); }
            SYS_GETPPID  => { let mut ctx = make_ctx!(); syscalls_task::sys_getppid(&mut ctx, &msg); }
            SYS_GETUID | SYS_GETGID | SYS_GETEUID | SYS_GETEGID
                         => { let mut ctx = make_ctx!(); syscalls_task::sys_getuid_family(&mut ctx, &msg); }
            SYS_SET_TID_ADDRESS
                         => { let mut ctx = make_ctx!(); syscalls_task::sys_set_tid_address(&mut ctx, &msg); }
            SYS_SET_ROBUST_LIST
                         => { let mut ctx = make_ctx!(); syscalls_task::sys_set_robust_list(&mut ctx, &msg); }
            SYS_KILL     => { let mut ctx = make_ctx!(); syscalls_task::sys_kill(&mut ctx, &msg); }
            SYS_WAIT4    => { let mut ctx = make_ctx!(); syscalls_task::sys_wait4(&mut ctx, &msg); }
            SYS_TKILL | SYS_TGKILL
                         => { let mut ctx = make_ctx!(); syscalls_task::sys_tgkill(&mut ctx, &msg); }
            SYS_SETPGID  => { let mut ctx = make_ctx!(); syscalls_task::sys_setpgid(&mut ctx, &msg); }
            SYS_GETPGRP  => { let mut ctx = make_ctx!(); syscalls_task::sys_getpgrp(&mut ctx, &msg); }
            SYS_SETSID   => { let mut ctx = make_ctx!(); syscalls_task::sys_setsid(&mut ctx, &msg); }
            SYS_GETPGID | SYS_GETSID
                         => { let mut ctx = make_ctx!(); syscalls_task::sys_getpgid(&mut ctx, &msg); }

            // ═══════════════════════════════════════════════════════════
            // Delegated: Signals (syscalls::signal)
            // ═══════════════════════════════════════════════════════════
            SYS_RT_SIGACTION
                         => { let mut ctx = make_ctx!(); syscalls_signal::sys_rt_sigaction(&mut ctx, &msg); }
            SYS_RT_SIGPROCMASK
                         => { let mut ctx = make_ctx!(); syscalls_signal::sys_rt_sigprocmask(&mut ctx, &msg); }
            SYS_SIGALTSTACK
                         => { let mut ctx = make_ctx!(); syscalls_signal::sys_sigaltstack(&mut ctx, &msg); }
            SYS_RT_SIGPENDING
                         => { let mut ctx = make_ctx!(); syscalls_signal::sys_rt_sigpending(&mut ctx, &msg); }
            SYS_RT_SIGTIMEDWAIT
                         => { let mut ctx = make_ctx!(); syscalls_signal::sys_rt_sigtimedwait(&mut ctx, &msg); }
            SYS_RT_SIGSUSPEND
                         => { let mut ctx = make_ctx!(); syscalls_signal::sys_rt_sigsuspend(&mut ctx, &msg); }
            0x7F00       => {
                let mut ctx = make_ctx!();
                let action = syscalls_signal::sys_signal_trampoline(&mut ctx, &msg);
                if action.is_break() { break; }
            }

            // ═══════════════════════════════════════════════════════════
            // Delegated: Info/time/scheduling/events (syscalls::info)
            // ═══════════════════════════════════════════════════════════
            SYS_UNAME => {
                let buf_ptr = msg.regs[0];
                if buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 390) };
                    for b in buf.iter_mut() { *b = 0; }
                    let fields: [&[u8]; 5] = [b"Linux", b"sotos", b"6.1.0-sotOS", b"#1 SMP sotOS 0.1.0", b"x86_64"];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                }
                reply_val(ep_cap, 0);
            }
            SYS_CLOCK_GETTIME
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_clock_gettime(&mut ctx, &msg); }
            SYS_GETTIMEOFDAY
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_gettimeofday(&mut ctx, &msg); }
            SYS_TIME => {
                // time(2): returns seconds since epoch
                let tsc = rdtsc();
                let boot = BOOT_TSC.load(Ordering::Acquire);
                let secs = tsc.saturating_sub(boot) / 2_000_000_000 + UPTIME_OFFSET_SECS + 1_700_000_000;
                let tloc = msg.regs[0];
                if tloc != 0 && tloc < 0x0000_8000_0000_0000 {
                    unsafe { *(tloc as *mut u64) = secs; }
                }
                reply_val(ep_cap, secs as i64);
            }
            SYS_NANOSLEEP=> { let mut ctx = make_ctx!(); syscalls_info::sys_nanosleep(&mut ctx, &msg); }
            SYS_CLOCK_GETRES
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_clock_getres(&mut ctx, &msg); }
            SYS_CLOCK_NANOSLEEP
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_clock_nanosleep(&mut ctx, &msg); }
            SYS_SYSINFO  => { let mut ctx = make_ctx!(); syscalls_info::sys_sysinfo(&mut ctx, &msg); }
            SYS_PRLIMIT64=> { let mut ctx = make_ctx!(); syscalls_info::sys_prlimit64(&mut ctx, &msg); }
            SYS_GETRANDOM=> { let mut ctx = make_ctx!(); syscalls_info::sys_getrandom(&mut ctx, &msg); }
            SYS_FUTEX    => { let mut ctx = make_ctx!(); syscalls_info::sys_futex(&mut ctx, &msg); }
            SYS_GETRUSAGE=> { let mut ctx = make_ctx!(); syscalls_info::sys_getrusage(&mut ctx, &msg); }
            SYS_GETRLIMIT=> { let mut ctx = make_ctx!(); syscalls_info::sys_getrlimit(&mut ctx, &msg); }
            SYS_TIMES    => { let mut ctx = make_ctx!(); syscalls_info::sys_times(&mut ctx, &msg); }
            SYS_PRCTL    => { let mut ctx = make_ctx!(); syscalls_info::sys_prctl(&mut ctx, &msg); }
            SYS_SCHED_YIELD
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_sched_yield(&mut ctx, &msg); }
            SYS_SCHED_GETAFFINITY
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_sched_getaffinity(&mut ctx, &msg); }
            SYS_EVENTFD | SYS_EVENTFD2
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_eventfd(&mut ctx, &msg, syscall_nr); }
            SYS_TIMERFD_CREATE
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_timerfd_create(&mut ctx, &msg); }
            SYS_TIMERFD_SETTIME
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_timerfd_settime(&mut ctx, &msg); }
            SYS_TIMERFD_GETTIME
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_timerfd_gettime(&mut ctx, &msg); }
            SYS_MEMFD_CREATE
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_memfd_create(&mut ctx, &msg); }
            SYS_INOTIFY_INIT1
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_inotify_init1(&mut ctx, &msg); }
            SYS_SIGNALFD | SYS_SIGNALFD4
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_signalfd(&mut ctx, &msg); }
            SYS_CAPGET   => { let mut ctx = make_ctx!(); syscalls_info::sys_capget(&mut ctx, &msg); }
            SYS_GETRESUID | SYS_GETRESGID
                         => { let mut ctx = make_ctx!(); syscalls_info::sys_getresuid(&mut ctx, &msg); }

            // Stubs
            SYS_RSEQ     => reply_val(ep_cap, -ENOSYS),
            SYS_CLONE3   => reply_val(ep_cap, -ENOSYS),
            SYS_STATX    => reply_val(ep_cap, -ENOSYS),
            SYS_FDATASYNC=> { let mut ctx = make_ctx!(); syscalls_fs::sys_fsync(&mut ctx, &msg); }

            // ═══════════════════════════════════════════════════════════
            // Unknown syscall
            // ═══════════════════════════════════════════════════════════
            _ => {
                trace!(Warn, SYSCALL, {
                    print(b"LUCAS unhandled ");
                    print(sotos_common::trace::syscall_name(syscall_nr));
                    print(b"("); print_u64(syscall_nr); print(b")");
                });
                reply_val(ep_cap, -ENOSYS);
            }
        }
    }

    trace!(Info, PROCESS, { print(b"LUCAS done"); });
    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// LUCAS-specific SYS_OPEN helpers (not in shared submodules)
// ---------------------------------------------------------------------------

/// Open CWD as a formatted directory listing (for LUCAS `ls` command).
/// Allocates an FD with kind=15, populates dir_buf with formatted listing.
/// Returns true if successful.
fn lucas_open_cwd_listing(
    cwd: &[u8; GRP_CWD_MAX],
    dir_buf: &mut [u8; 4096],
    dir_len: &mut usize,
    dir_pos: &mut usize,
    child_fds: &mut [u8; GRP_MAX_FDS],
) -> bool {
    // Find free FD
    let fd = match (3..GRP_MAX_FDS).find(|&f| child_fds[f] == 0) {
        Some(f) => f,
        None => return false,
    };

    *dir_len = 0;
    *dir_pos = 0;

    // Resolve CWD path to OID, then list directory
    vfs_lock();
    if let Some(store) = unsafe { shared_store() } {
        let cwd_str = cwd_as_str(cwd);
        let cwd_oid = store.resolve_path(cwd_str, ROOT_OID).unwrap_or(ROOT_OID);
        let mut entries = [DirEntry::zeroed(); 64];
        let count = store.list_dir(cwd_oid, &mut entries);
        for i in 0..count {
            let ename = entries[i].name_as_str();
            let elen = ename.len();
            if *dir_len + elen + 20 > dir_buf.len() { break; }
            dir_buf[*dir_len..*dir_len + elen].copy_from_slice(ename);
            *dir_len += elen;
            if entries[i].is_dir() {
                dir_buf[*dir_len] = b'/';
                *dir_len += 1;
            }
            dir_buf[*dir_len] = b' ';
            dir_buf[*dir_len + 1] = b' ';
            *dir_len += 2;
            let n = format_u64_into(&mut dir_buf[*dir_len..], entries[i].size);
            *dir_len += n;
            dir_buf[*dir_len] = b'\n';
            *dir_len += 1;
        }
    }
    vfs_unlock();

    child_fds[fd] = 15; // virtual file
    true
}

/// Find the highest-numbered allocated FD (used after lucas_open_cwd_listing).
fn find_last_alloc_fd(child_fds: &[u8; GRP_MAX_FDS]) -> usize {
    for f in (3..GRP_MAX_FDS).rev() {
        if child_fds[f] != 0 { return f; }
    }
    3
}

/// Handle /snap/ paths — snapshot create/list/restore/delete.
fn lucas_open_snap(
    name: &[u8],
    dir_buf: &mut [u8; 4096],
    dir_len: &mut usize,
    dir_pos: &mut usize,
    child_fds: &mut [u8; GRP_MAX_FDS],
    ep_cap: u64,
) {
    let snap_cmd = &name[6..]; // skip "/snap/"
    let fd = match (3..GRP_MAX_FDS).find(|&f| child_fds[f] == 0) {
        Some(f) => f,
        None => { reply_val(ep_cap, -EMFILE); return; }
    };

    *dir_len = 0;
    *dir_pos = 0;

    vfs_lock();
    let result = unsafe { shared_store() }.map(|store| {
        if starts_with(snap_cmd, b"create/") && snap_cmd.len() > 7 {
            let snap_name = &snap_cmd[7..];
            match store.snap_create(snap_name) {
                Ok(_) => {
                    let t = b"snapshot created\n";
                    dir_buf[..t.len()].copy_from_slice(t);
                    *dir_len = t.len();
                    true
                }
                Err(_) => { false }
            }
        } else if snap_cmd == b"list" {
            let mut snaps = [sotos_objstore::SnapMeta::zeroed(); sotos_objstore::MAX_SNAPSHOTS];
            let count = store.snap_list(&mut snaps);
            if count == 0 {
                let t = b"no snapshots\n";
                dir_buf[..t.len()].copy_from_slice(t);
                *dir_len = t.len();
            } else {
                for i in 0..count {
                    let sname = snaps[i].name_as_str();
                    if *dir_len + sname.len() + 2 > dir_buf.len() { break; }
                    dir_buf[*dir_len..*dir_len + sname.len()].copy_from_slice(sname);
                    *dir_len += sname.len();
                    dir_buf[*dir_len] = b'\n';
                    *dir_len += 1;
                }
            }
            true
        } else if starts_with(snap_cmd, b"restore/") && snap_cmd.len() > 8 {
            let snap_name = &snap_cmd[8..];
            if let Some(slot) = store.snap_find(snap_name) {
                if store.snap_restore(slot).is_ok() {
                    let t = b"snapshot restored\n";
                    dir_buf[..t.len()].copy_from_slice(t);
                    *dir_len = t.len();
                    return true;
                }
            }
            false
        } else if starts_with(snap_cmd, b"delete/") && snap_cmd.len() > 7 {
            let snap_name = &snap_cmd[7..];
            if let Some(slot) = store.snap_find(snap_name) {
                if store.snap_delete(slot).is_ok() {
                    let t = b"snapshot deleted\n";
                    dir_buf[..t.len()].copy_from_slice(t);
                    *dir_len = t.len();
                    return true;
                }
            }
            false
        } else {
            false
        }
    });
    vfs_unlock();

    match result {
        Some(true) => {
            child_fds[fd] = 15;
            reply_val(ep_cap, fd as i64);
        }
        _ => reply_val(ep_cap, -ENOENT),
    }
}

/// Handle LUCAS-specific /proc/ paths. Returns true if handled.
fn lucas_open_proc(
    name: &[u8], path_len: usize, pid: usize,
    dir_buf: &mut [u8; 4096],
    dir_len: &mut usize,
    dir_pos: &mut usize,
    child_fds: &mut [u8; GRP_MAX_FDS],
    ep_cap: u64,
) -> bool {
    // Check for LUCAS-specific /proc/ paths only
    let is_lucas_proc =
        (path_len == 5 || (path_len == 6 && name[5] == b'/')) // "/proc" or "/proc/"
        || (path_len == 12 && &name[..12] == b"/proc/uptime")
        || name == b"/proc/version"
        || name == b"/proc/loadavg"
        || starts_with(name, b"/proc/syslog/")
        || starts_with(name, b"/proc/netmirror/");

    // Also handle /proc/N/status for PID listing
    let is_pid_path = if !is_lucas_proc && starts_with(name, b"/proc/") && path_len > 6 {
        let rest = &name[6..path_len];
        let (n, consumed) = parse_u64_from(rest);
        consumed > 0 && n >= 1 && n <= MAX_PROCS as u64
            && PROCESSES[n as usize - 1].state.load(Ordering::Acquire) != 0
    } else { false };

    if !is_lucas_proc && !is_pid_path { return false; }

    let fd = match (3..GRP_MAX_FDS).find(|&f| child_fds[f] == 0) {
        Some(f) => f,
        None => { reply_val(ep_cap, -EMFILE); return true; }
    };

    *dir_len = 0;
    *dir_pos = 0;

    if path_len == 5 || (path_len == 6 && name[5] == b'/') {
        // "/proc" or "/proc/" → PID listing
        let hdr = b"PID  STATE  PPID\n";
        dir_buf[..hdr.len()].copy_from_slice(hdr);
        *dir_len = hdr.len();
        for i in 0..MAX_PROCS {
            let st = PROCESSES[i].state.load(Ordering::Acquire);
            if st == 0 { continue; }
            let ppid = PROCESSES[i].parent.load(Ordering::Acquire);
            *dir_len += format_pid_row(&mut dir_buf[*dir_len..], i + 1, st, ppid);
        }
    } else if path_len == 12 && &name[..12] == b"/proc/uptime" {
        let boot = BOOT_TSC.load(Ordering::Acquire);
        let now = rdtsc();
        let secs = now.saturating_sub(boot) / 2_000_000_000 + UPTIME_OFFSET_SECS;
        *dir_len += format_uptime_into(&mut dir_buf[*dir_len..], secs);
    } else if name == b"/proc/version" {
        let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
        let n = info.len().min(dir_buf.len());
        dir_buf[..n].copy_from_slice(&info[..n]);
        *dir_len = n;
    } else if name == b"/proc/loadavg" {
        let info = b"0.01 0.05 0.10 1/32 42\n";
        let n = info.len().min(dir_buf.len());
        dir_buf[..n].copy_from_slice(&info[..n]);
        *dir_len = n;
    } else if starts_with(name, b"/proc/syslog/") {
        let rest = &name[13..path_len];
        let (max_n, _) = parse_u64_from(rest);
        let max_entries = if max_n == 0 { 10 } else { max_n as usize };
        *dir_len = format_syslog_into(dir_buf, max_entries);
    } else if starts_with(name, b"/proc/netmirror/") {
        let rest = &name[16..path_len];
        let enable = rest == b"on" || rest == b"1";
        let net_ep = NET_EP_CAP.load(Ordering::Acquire);
        if net_ep != 0 {
            let cmd_msg = sotos_common::IpcMsg {
                tag: 12, // CMD_NET_MIRROR
                regs: [if enable { 1 } else { 0 }, 0, 0, 0, 0, 0, 0, 0],
            };
            let _ = sys::call(net_ep, &cmd_msg);
        }
        let msg = if enable { b"packet mirroring: ON\n" as &[u8] } else { b"packet mirroring: OFF\n" };
        let n = msg.len().min(dir_buf.len());
        dir_buf[..n].copy_from_slice(&msg[..n]);
        *dir_len = n;
    } else if is_pid_path {
        let rest = &name[6..path_len];
        let (n, consumed) = parse_u64_from(rest);
        let after = &rest[consumed..];
        if after == b"/status" || after.is_empty() {
            *dir_len = format_proc_status(dir_buf, n as usize);
        } else {
            reply_val(ep_cap, -ENOENT);
            return true;
        }
    }

    child_fds[fd] = 15;
    reply_val(ep_cap, fd as i64);
    true
}

/// Extract the path portion from a CWD buffer (up to first NUL).
fn cwd_as_str(cwd: &[u8; GRP_CWD_MAX]) -> &[u8] {
    let end = cwd.iter().position(|&b| b == 0).unwrap_or(cwd.len());
    &cwd[..end]
}
