// ---------------------------------------------------------------------------
// lucas_shell: LUCAS-shell-specific helpers.
// Hosts the SYS_OPEN preprocessing paths that are exclusive to the LUCAS
// shell (not Linux-ABI): `/snap/*`, `/proc/*` LUCAS extensions, and the
// `.` CWD directory listing used by the shell's builtin `ls`.
//
// Callers: lucas_handler::SYS_OPEN arm. Nothing in child_handler/dispatch
// routes through these helpers.
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
use crate::process::{PROCESSES, MAX_PROCS, BOOT_TSC,
                     parse_u64_from, format_proc_status,
                     NEXT_PID, NEXT_CHILD_STACK, proc_group_init,
                     CHILD_SETUP_EP, CHILD_SETUP_PID, CHILD_SETUP_FLAGS,
                     CHILD_SETUP_AS_CAP, CHILD_SETUP_READY, sig_send};
use crate::fd::{THREAD_GROUPS, GRP_MAX_FDS, GRP_CWD_MAX, UPTIME_OFFSET_SECS,
                BRK_BASE, MMAP_BASE};
use crate::syscall_log::{format_syslog_into, syscall_log_record};
use crate::vdso;
use crate::{NET_EP_CAP, LUCAS_EP_CAP, LUCAS_VFS_READY, LUCAS_BLK_STORE,
            SHARED_STORE_PTR, vfs_lock, vfs_unlock, shared_store};
use crate::syscalls::context::SyscallContext;
use crate::syscalls::fs as syscalls_fs;
use crate::syscalls::signal as syscalls_signal;
use crate::init_boot::sysroot_init;

const MAP_WRITABLE: u64 = 2;

/// Open CWD as a formatted directory listing (for LUCAS `ls` builtin).
/// Allocates an FD with kind=15, populates dir_buf with formatted listing.
/// Returns true on success.
pub(crate) fn lucas_open_cwd_listing(
    cwd: &[u8; GRP_CWD_MAX],
    dir_buf: &mut [u8; 4096],
    dir_len: &mut usize,
    dir_pos: &mut usize,
    child_fds: &mut [u8; GRP_MAX_FDS],
) -> bool {
    let fd = match (3..GRP_MAX_FDS).find(|&f| child_fds[f] == 0) {
        Some(f) => f,
        None => return false,
    };

    *dir_len = 0;
    *dir_pos = 0;

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

    child_fds[fd] = 15;
    true
}

/// Find the highest-numbered allocated FD (used after lucas_open_cwd_listing).
pub(crate) fn find_last_alloc_fd(child_fds: &[u8; GRP_MAX_FDS]) -> usize {
    for f in (3..GRP_MAX_FDS).rev() {
        if child_fds[f] != 0 { return f; }
    }
    3
}

/// Handle `/snap/*` paths — snapshot create/list/restore/delete.
pub(crate) fn lucas_open_snap(
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

/// Handle LUCAS-specific `/proc/*` paths. Returns true if handled (reply
/// already sent). Falls through to the shared submodule for standard paths.
pub(crate) fn lucas_open_proc(
    name: &[u8], path_len: usize, _pid: usize,
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
        let info = b"Linux version 5.15.0-sotX (root@sotX) (gcc 12.0) #1 SMP PREEMPT\n";
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
pub(crate) fn cwd_as_str(cwd: &[u8; GRP_CWD_MAX]) -> &[u8] {
    let end = cwd.iter().position(|&b| b == 0).unwrap_or(cwd.len());
    &cwd[..end]
}

// ---------------------------------------------------------------------------
// LUCAS shell main loop — PID 1 entry point.
// Moved from lucas_handler.rs (fase 1.6). Shared Linux-ABI arms fall
// through to `crate::dispatch::dispatch_linux_arm`.
// ---------------------------------------------------------------------------

/// LUCAS shell — PID 1 syscall loop.
/// Owns the VFS (ObjectStore) and delegates syscalls to shared submodules.
pub(crate) extern "C" fn shell_main() -> ! {
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
                    child_as_cap: 0,
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

        if let Some(action) = syscalls_signal::check_pending_signals(ep_cap, pid as usize, kernel_tid, 0) {
            if action.is_break() { break; }
            continue;
        }

        let syscall_nr = msg.tag;
        syscall_log_record(pid as u16, syscall_nr as u16, msg.regs[0], 0);

        match syscall_nr {
            // PID-1 exclusive: child process spawning.
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

            // SYS_OPEN: LUCAS pre-check, then delegate.
            SYS_OPEN => {
                let mut path = [0u8; 256];
                let path_len = copy_guest_path(msg.regs[0], &mut path);
                let name = &path[..path_len];

                if path_len == 1 && path[0] == b'.' {
                    let tg = unsafe { &mut THREAD_GROUPS[fdg] };
                    if lucas_open_cwd_listing(&tg.cwd, &mut tg.dir_buf, &mut tg.dir_len, &mut tg.dir_pos, &mut tg.fds) {
                        reply_val(ep_cap, find_last_alloc_fd(&tg.fds) as i64);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                    continue;
                }

                if starts_with(name, b"/snap/") {
                    let tg = unsafe { &mut THREAD_GROUPS[fdg] };
                    lucas_open_snap(name, &mut tg.dir_buf, &mut tg.dir_len, &mut tg.dir_pos, &mut tg.fds, ep_cap);
                    continue;
                }

                if starts_with(name, b"/proc") {
                    let tg = unsafe { &mut THREAD_GROUPS[fdg] };
                    if lucas_open_proc(name, path_len, pid as usize,
                                       &mut tg.dir_buf, &mut tg.dir_len, &mut tg.dir_pos,
                                       &mut tg.fds, ep_cap) {
                        continue;
                    }
                }

                let mut ctx = make_ctx!();
                syscalls_fs::sys_open(&mut ctx, &msg);
            }

            SYS_OPENAT => { let mut ctx = make_ctx!(); syscalls_fs::sys_openat(&mut ctx, &msg); }

            // LUCAS-only sotX-native syscalls.
            252 => { reply_val(ep_cap, sys::debug_free_frames() as i64); }
            142 => { reply_val(ep_cap, sys::thread_count() as i64); }
            131 => {
                let name_ptr = msg.regs[0];
                let name_len = msg.regs[1] as usize;
                if name_ptr == 0 || name_len == 0 || name_len > 64 {
                    reply_val(ep_cap, -22);
                } else {
                    let mut buf = [0u8; 64];
                    let n = name_len.min(64);
                    for i in 0..n {
                        buf[i] = unsafe { *((name_ptr + i as u64) as *const u8) };
                    }
                    match sys::svc_lookup(buf.as_ptr() as u64, n as u64) {
                        Ok(cap) => reply_val(ep_cap, cap as i64),
                        Err(e) => reply_val(ep_cap, e),
                    }
                }
            }

            // Everything else → shared Linux-ABI dispatcher.
            _ => {
                let mut ctx = make_ctx!();
                match crate::dispatch::dispatch_linux_arm(&mut ctx, &msg, syscall_nr) {
                    crate::dispatch::DispatchOutcome::Handled => {}
                    crate::dispatch::DispatchOutcome::Break => break,
                    crate::dispatch::DispatchOutcome::NotHandled => {
                        drop(ctx);
                        trace!(Warn, SYSCALL, {
                            print(b"LUCAS unhandled ");
                            print(sotos_common::trace::syscall_name(syscall_nr));
                            print(b"("); print_u64(syscall_nr); print(b")");
                        });
                        reply_val(ep_cap, -ENOSYS);
                    }
                }
            }
        }
    }

    trace!(Info, PROCESS, { print(b"LUCAS done"); });
    sys::thread_exit();
}
