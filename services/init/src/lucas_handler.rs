// ---------------------------------------------------------------------------
// lucas_handler: LUCAS shell syscall handler.
// Extracted from main.rs.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_objstore::{ObjectStore, Vfs, DirEntry, ROOT_OID};
use sotos_virtio::blk::VirtioBlk;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::child_handler::child_handler;
use crate::framebuffer::{print, print_u64, fb_putchar, kb_has_char, kb_read_char};
use crate::exec::{reply_val, rdtsc, format_u64_into, copy_guest_path, starts_with,
                  format_uptime_into, format_pid_row};
use crate::process::*;
use crate::fd::*;
use crate::net::{NET_CMD_DNS_QUERY, NET_CMD_TCP_CONNECT, NET_CMD_TCP_SEND, NET_CMD_TCP_RECV,
                 NET_CMD_TCP_CLOSE, NET_CMD_TCP_STATUS, NET_CMD_UDP_BIND, NET_CMD_UDP_SENDTO,
                 NET_CMD_UDP_RECV};
use crate::syscall_log::{syscall_log_record, format_syslog_into};
use crate::vdso;
use crate::{LUCAS_EP_CAP, LUCAS_VFS_READY, LUCAS_BLK_STORE, NET_EP_CAP, SHARED_STORE_PTR};

const MAP_WRITABLE: u64 = 2;

/// Ensure sysroot directories exist for dynamic binary support.
/// Creates /lib, /lib64, /usr, /usr/lib, /usr/lib64, /bin, /sbin if missing.
fn sysroot_init(store: &mut ObjectStore) {
    let dirs: &[&[u8]] = &[b"lib", b"lib64", b"bin", b"sbin", b"usr", b"tmp"];
    for name in dirs {
        if store.resolve_path(name, ROOT_OID).is_err() {
            let _ = store.mkdir(name, ROOT_OID);
        }
    }
    // Create subdirs under /usr
    if let Ok(usr_oid) = store.resolve_path(b"usr", ROOT_OID) {
        let sub: &[&[u8]] = &[b"lib", b"lib64", b"bin", b"sbin"];
        for name in sub {
            // Check by looking up child directly under usr_oid
            if store.find_in(name, usr_oid).is_none() {
                let _ = store.mkdir(name, usr_oid);
            }
        }
    }
    print(b"LUCAS: sysroot dirs initialized\n");
}

/// LUCAS handler — receives forwarded Linux syscalls and translates them.
/// Supports VFS-backed file I/O, FD table, brk, mmap, stat, lseek, dup.

pub(crate) extern "C" fn lucas_handler() -> ! {
    let ep_cap = LUCAS_EP_CAP.load(Ordering::Acquire);
    // Capture boot TSC for /proc/uptime and vDSO
    let boot_tsc_val = rdtsc();
    BOOT_TSC.store(boot_tsc_val, Ordering::Release);

    // Map vDSO page (single page shared by all child processes).
    // Page may already exist (busybox test maps it early for trampoline stubs).
    // If already mapped+writable, just overwrite with full vDSO.
    let vdso_mapped = if let Ok(vf) = sys::frame_alloc() {
        sys::map(vdso::VDSO_BASE, vf, MAP_WRITABLE).is_ok()
    } else { false };
    // Forge vDSO regardless — if already mapped writable, this overwrites the stubs
    {
        let vdso_page = unsafe {
            core::slice::from_raw_parts_mut(vdso::VDSO_BASE as *mut u8, 4096)
        };
        if vdso_mapped {
            for b in vdso_page.iter_mut() { *b = 0; }
        }
        vdso::forge(vdso_page, boot_tsc_val);
        let _ = sys::protect(vdso::VDSO_BASE, 0); // R+X
        print(b"LUCAS: vDSO forged at 0xB80000\n");
    }

    // Register as PID 1 in process table
    let pid: u64 = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    PROC_STATE[pid as usize - 1].store(1, Ordering::Release); // Running
    proc_group_init(pid as usize); // Initialize thread group state

    // --- VFS init: read VirtioBlk from storage page, mount ObjectStore ---
    let has_vfs = LUCAS_VFS_READY.load(Ordering::Acquire) != 0;
    let mut vfs_opt: Option<Vfs> = if has_vfs {
        let blk = unsafe { core::ptr::read(LUCAS_BLK_STORE as *const VirtioBlk) };
        match ObjectStore::mount(blk) {
            Ok(mut store) => {
                print(b"LUCAS: VFS bridge active\n");
                // Create sysroot directories for dynamic binary support
                sysroot_init(&mut store);
                let vfs = Vfs::new(store);
                // Publish the ObjectStore pointer so child_handlers can access VFS
                let store_ptr = vfs.store() as *const _ as u64;
                SHARED_STORE_PTR.store(store_ptr, Ordering::Release);
                Some(vfs)
            }
            Err(e) => {
                print(b"LUCAS: VFS mount failed: ");
                print(e.as_bytes());
                print(b"\n");
                None
            }
        }
    } else {
        None
    };

    // FD table: 0=stdin, 1=stdout, 2=stderr(→stdout)
    let mut fds = [FdEntry::free(); MAX_FDS];
    fds[0] = FdEntry::new(FdKind::Stdin, 0, 0);
    fds[1] = FdEntry::new(FdKind::Stdout, 0, 0);
    fds[2] = FdEntry::new(FdKind::Stdout, 0, 0);

    // Directory listing buffer and state
    let mut dir_buf = [0u8; 1024];
    let mut dir_len: usize = 0;
    let mut dir_pos: usize = 0;

    // Current working directory OID
    let mut cwd_oid: u64 = sotos_objstore::ROOT_OID;

    // brk heap tracking
    let mut current_brk: u64 = BRK_BASE;

    // mmap tracking
    let mut mmaps = [MmapEntry::empty(); MAX_MMAPS];
    let mut mmap_next: u64 = MMAP_BASE;

    // Epoll instances (Phase 4: real non-blocking epoll)
    let mut epoll_instances: [EpollInstance; MAX_EPOLL_INSTANCES] = [
        EpollInstance::new(), EpollInstance::new(),
        EpollInstance::new(), EpollInstance::new(),
    ];
    let mut next_epoll_idx: u16 = 0;

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        // Cache the kernel thread ID for async signal injection
        let kernel_tid = msg.regs[6];
        if kernel_tid != 0 {
            PROC_KERNEL_TID[pid as usize - 1].store(kernel_tid, Ordering::Release);
        }

        // Check for pending unblocked signals
        let sig = sig_dequeue(pid as usize);
        if sig != 0 {
            let child_tid = kernel_tid;
            match sig_dispatch(pid as usize, sig) {
                1 => break, // terminated
                2 => { reply_val(ep_cap, -EINTR); continue; } // -EINTR
                3 => {
                    if signal_deliver(ep_cap, pid as usize, sig, child_tid, 0, false) {
                        continue;
                    }
                }
                _ => {} // ignored, continue
            }
        }

        let syscall_nr = msg.tag;
        // Phase 5: Syscall shadow logging (LUCAS main handler)
        syscall_log_record(pid as u16, syscall_nr as u16, msg.regs[0], 0);
        match syscall_nr {
            // SYS_read(fd, buf, len)
            SYS_READ => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;

                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF); // -EBADF
                    continue;
                }

                match fds[fd].kind {
                    FdKind::Stdin => {
                        if len == 0 {
                            reply_val(ep_cap, 0);
                            continue;
                        }
                        loop {
                            // Check for pending signal while polling stdin
                            let s = sig_dequeue(pid as usize);
                            if s != 0 && sig_dispatch(pid as usize, s) >= 1 {
                                reply_val(ep_cap, -EINTR); // -EINTR
                                break;
                            }
                            match unsafe { kb_read_char() } {
                                Some(0x03) => {
                                    // Ctrl+C
                                    reply_val(ep_cap, -EINTR);
                                    break;
                                }
                                Some(ch) => {
                                    unsafe { *(buf_ptr as *mut u8) = ch; }
                                    // Also return byte in reply regs[1] so kernel
                                    // can write it (workaround for cross-thread visibility).
                                    let reply = sotos_common::IpcMsg {
                                        tag: 0,
                                        regs: [1, ch as u64, 0, 0, 0, 0, 0, 0],
                                    };
                                    let _ = sys::send(ep_cap, &reply);
                                    break;
                                }
                                None => {
                                    sys::yield_now();
                                }
                            }
                        }
                    }
                    FdKind::DirList => {
                        if dir_pos >= dir_len {
                            reply_val(ep_cap, 0);
                            continue;
                        }
                        let avail = dir_len - dir_pos;
                        let to_copy = len.min(avail);
                        let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, to_copy) };
                        dst.copy_from_slice(&dir_buf[dir_pos..dir_pos + to_copy]);
                        dir_pos += to_copy;
                        reply_val(ep_cap, to_copy as i64);
                    }
                    FdKind::VfsFile => {
                        let vfs_fd = fds[fd].vfs_fd;
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
                                match vfs.read(vfs_fd, dst) {
                                    Ok(n) => reply_val(ep_cap, n as i64),
                                    Err(_) => reply_val(ep_cap, -EBADF),
                                }
                            }
                            None => reply_val(ep_cap, -EBADF),
                        }
                    }
                    FdKind::Stdout => {
                        reply_val(ep_cap, -EBADF); // can't read stdout
                    }
                    FdKind::PipeRead => {
                        // Simple pipe: return 0 (EOF) — real data flow needs shared memory
                        reply_val(ep_cap, 0);
                    }
                    FdKind::PipeWrite => {
                        reply_val(ep_cap, -EBADF); // can't read from write end
                    }
                    FdKind::Socket => {
                        // Read from socket → TCP recv via net service.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = fds[fd].net_conn_id as u64;
                        let recv_len = len.min(56); // 7 regs * 8 bytes
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_RECV,
                            regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 500) {
                            Ok(resp) => {
                                let n = resp.regs[0] as usize;
                                if n > 0 && n <= recv_len {
                                    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                    unsafe {
                                        let src = &resp.regs[1] as *const u64 as *const u8;
                                        core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                    }
                                }
                                reply_val(ep_cap, n as i64);
                            }
                            Err(_) => reply_val(ep_cap, 0), // EOF
                        }
                    }
                    FdKind::SocketUdp => {
                        // Read from UDP socket → UDP recv via net service.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let port = fds[fd].udp_local_port;
                        let recv_len = len.min(56);
                        if net_cap == 0 || port == 0 {
                            reply_val(ep_cap, -EBADF);
                        } else {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_RECV,
                                regs: [port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let n = resp.regs[0] as usize;
                                    if n > 0 && n <= recv_len {
                                        let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                        unsafe {
                                            let src = &resp.regs[1] as *const u64 as *const u8;
                                            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                        }
                                    }
                                    reply_val(ep_cap, n as i64);
                                }
                                Err(_) => reply_val(ep_cap, 0),
                            }
                        }
                    }
                    FdKind::DevUrandom => {
                        // /dev/urandom — fill buffer with pseudo-random bytes
                        let n = len.min(4096);
                        if n > 0 {
                            let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                            let mut rng = rdtsc();
                            for b in dst.iter_mut() {
                                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                                *b = rng as u8;
                            }
                        }
                        reply_val(ep_cap, n as i64);
                    }
                    FdKind::DevZero => {
                        // /dev/zero — fill buffer with zeros
                        let n = len.min(4096);
                        if n > 0 {
                            unsafe { core::ptr::write_bytes(buf_ptr as *mut u8, 0, n); }
                        }
                        reply_val(ep_cap, n as i64);
                    }
                    _ => reply_val(ep_cap, -EBADF),
                }
            }

            // SYS_write(fd, buf, len)
            SYS_WRITE => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;

                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }

                match fds[fd].kind {
                    FdKind::Stdout => {
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                        for &b in data {
                            sys::debug_print(b);
                            unsafe { fb_putchar(b); }
                        }
                        reply_val(ep_cap, len as i64);
                    }
                    FdKind::VfsFile => {
                        let vfs_fd = fds[fd].vfs_fd;
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                                match vfs.write(vfs_fd, data) {
                                    Ok(n) => reply_val(ep_cap, n as i64),
                                    Err(_) => reply_val(ep_cap, -EBADF),
                                }
                            }
                            None => reply_val(ep_cap, -EBADF),
                        }
                    }
                    FdKind::Socket => {
                        // Write to socket → TCP send via net service.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = fds[fd].net_conn_id as u64;
                        let send_len = len.min(40);
                        let mut req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_SEND,
                            regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                        };
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                        unsafe {
                            let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                        }
                        match sys::call_timeout(net_cap, &req, 500) {
                            Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                            Err(_) => reply_val(ep_cap, -EIO),
                        }
                    }
                    FdKind::SocketUdp => {
                        // Write to UDP socket → sendto with stored remote address.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let remote_ip = fds[fd].udp_remote_ip;
                        let remote_port = fds[fd].udp_remote_port;
                        let src_port = fds[fd].udp_local_port;
                        if net_cap == 0 || remote_ip == 0 {
                            reply_val(ep_cap, -EDESTADDRREQ); // -EDESTADDRREQ
                        } else {
                            let send_len = len.min(32);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_SENDTO,
                                regs: [remote_ip as u64, remote_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                            unsafe {
                                let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                            }
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                                Err(_) => reply_val(ep_cap, -EIO),
                            }
                        }
                    }
                    FdKind::PipeWrite => {
                        // Simple pipe write: pretend it succeeded (data is discarded)
                        reply_val(ep_cap, len as i64);
                    }
                    _ => {
                        reply_val(ep_cap, -EBADF); // can't write to stdin/dirlist
                    }
                }
            }

            // SYS_open(path, flags, mode)
            SYS_OPEN => {
                let path_ptr = msg.regs[0];
                let flags = msg.regs[1] as u32;

                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                let new_fd = match alloc_fd(&fds, 3) {
                    Some(f) => f,
                    None => {
                        reply_val(ep_cap, -EMFILE); // -EMFILE
                        continue;
                    }
                };

                // "." → directory listing of cwd; other paths may also be dirs
                if path_len == 1 && path[0] == b'.' {
                    dir_len = 0;
                    dir_pos = 0;
                    if let Some(vfs) = vfs_opt.as_ref() {
                        let mut entries = [DirEntry::zeroed(); 64];
                        let count = vfs.store().list_dir(cwd_oid, &mut entries);
                        for i in 0..count {
                            let ename = entries[i].name_as_str();
                            let elen = ename.len();
                            if dir_len + elen + 20 > dir_buf.len() {
                                break;
                            }
                            // Show d/ prefix for directories
                            if entries[i].is_dir() {
                                dir_buf[dir_len..dir_len + elen].copy_from_slice(ename);
                                dir_len += elen;
                                dir_buf[dir_len] = b'/';
                                dir_len += 1;
                            } else {
                                dir_buf[dir_len..dir_len + elen].copy_from_slice(ename);
                                dir_len += elen;
                            }
                            dir_buf[dir_len] = b' ';
                            dir_buf[dir_len + 1] = b' ';
                            dir_len += 2;
                            let n = format_u64_into(&mut dir_buf[dir_len..], entries[i].size);
                            dir_len += n;
                            dir_buf[dir_len] = b'\n';
                            dir_len += 1;
                        }
                    }
                    fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                    reply_val(ep_cap, new_fd as i64);
                    continue;
                }

                // /etc/ virtual files (resolv.conf, hosts, nsswitch.conf, etc.)
                if starts_with(name, b"/etc/") {
                    dir_len = 0;
                    dir_pos = 0;
                    if name == b"/etc/resolv.conf" {
                        let content = b"nameserver 10.0.2.3\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/hosts" {
                        let content = b"127.0.0.1 localhost\n::1 localhost\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/nsswitch.conf" {
                        let content = b"hosts: files dns\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/gai.conf" || name == b"/etc/host.conf" {
                        dir_len = 0; // empty file
                    } else if name == b"/etc/services" {
                        let content = b"http 80/tcp\nhttps 443/tcp\ndns 53/udp\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/protocols" {
                        let content = b"tcp 6 TCP\nudp 17 UDP\nicmp 1 ICMP\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else {
                        reply_val(ep_cap, -ENOENT); // -ENOENT
                        continue;
                    }
                    fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                    reply_val(ep_cap, new_fd as i64);
                    continue;
                }

                // /proc virtual filesystem
                if starts_with(name, b"/proc") {
                    dir_len = 0;
                    dir_pos = 0;

                    if path_len == 5 || (path_len == 6 && path[5] == b'/') {
                        // "/proc" or "/proc/" → PID listing
                        let hdr = b"PID  STATE  PPID\n";
                        dir_buf[..hdr.len()].copy_from_slice(hdr);
                        dir_len = hdr.len();
                        for i in 0..MAX_PROCS {
                            let st = PROC_STATE[i].load(Ordering::Acquire);
                            if st == 0 { continue; }
                            let ppid = PROC_PARENT[i].load(Ordering::Acquire);
                            dir_len += format_pid_row(&mut dir_buf[dir_len..], i + 1, st, ppid);
                        }
                    } else if path_len == 12 && &path[..12] == b"/proc/uptime" {
                        let boot = BOOT_TSC.load(Ordering::Acquire);
                        let now = rdtsc();
                        let secs = now.saturating_sub(boot) / 2_000_000_000 + UPTIME_OFFSET_SECS;
                        dir_len += format_uptime_into(&mut dir_buf[dir_len..], secs);
                    } else if name == b"/proc/version" {
                        let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        dir_len = n;
                    } else if name == b"/proc/loadavg" {
                        let info = b"0.01 0.05 0.10 1/32 42\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        dir_len = n;
                    } else if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
                        let map_text = b"\
00400000-00500000 r-xp 00000000 00:00 0          [text]\n\
00e30000-00e34000 rw-p 00000000 00:00 0          [stack]\n\
02000000-02100000 rw-p 00000000 00:00 0          [heap]\n\
00b80000-00b81000 r-xp 00000000 00:00 0          [vdso]\n";
                        let n = map_text.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&map_text[..n]);
                        dir_len = n;
                    } else if name == b"/proc/cpuinfo" {
                        let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        dir_len = n;
                    } else if name == b"/proc/meminfo" {
                        let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        dir_len = n;
                    } else if path_len == 17 && &path[..17] == b"/proc/self/status" {
                        // "/proc/self/status"
                        dir_len = format_proc_status(&mut dir_buf, pid as usize);
                    } else if starts_with(name, b"/proc/syslog/") {
                        // "/proc/syslog/N" → dump last N syscall log entries
                        let rest = &path[13..path_len];
                        let (max_n, _) = parse_u64_from(rest);
                        let max_entries = if max_n == 0 { 10 } else { max_n as usize };
                        dir_len = format_syslog_into(&mut dir_buf, max_entries);
                    } else if starts_with(name, b"/proc/netmirror/") {
                        // "/proc/netmirror/on" or "/proc/netmirror/off" → toggle net mirror
                        let rest = &path[16..path_len];
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
                        dir_len = n;
                    } else if starts_with(name, b"/proc/") && path_len > 6 {
                        // "/proc/N/status" or "/proc/N"
                        let rest = &path[6..path_len];
                        let (n, consumed) = parse_u64_from(rest);
                        if consumed > 0 && n >= 1 && n <= MAX_PROCS as u64 &&
                           PROC_STATE[n as usize - 1].load(Ordering::Acquire) != 0 {
                            // Check for "/status" suffix
                            let after = &rest[consumed..];
                            if after == b"/status" || after.is_empty() {
                                dir_len = format_proc_status(&mut dir_buf, n as usize);
                            } else {
                                reply_val(ep_cap, -ENOENT); // -ENOENT
                                continue;
                            }
                        } else {
                            reply_val(ep_cap, -ENOENT);
                            continue;
                        }
                    } else {
                        reply_val(ep_cap, -ENOENT);
                        continue;
                    }

                    fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                    reply_val(ep_cap, new_fd as i64);
                    continue;
                }

                // /snap virtual path for snapshot operations
                if starts_with(name, b"/snap/") {
                    let snap_cmd = &path[6..path_len];

                    if starts_with(snap_cmd, b"create/") && snap_cmd.len() > 7 {
                        let snap_name = &snap_cmd[7..];
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                match vfs.store_mut().snap_create(snap_name) {
                                    Ok(_) => {
                                        dir_pos = 0;
                                        let msg_text = b"snapshot created\n";
                                        dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                        dir_len = msg_text.len();
                                        fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                                        reply_val(ep_cap, new_fd as i64);
                                    }
                                    Err(_) => reply_val(ep_cap, -ENOSPC), // -ENOSPC
                                }
                            }
                            None => reply_val(ep_cap, -ENOENT),
                        }
                        continue;
                    } else if snap_cmd == b"list" {
                        dir_len = 0;
                        dir_pos = 0;
                        match vfs_opt.as_ref() {
                            Some(vfs) => {
                                let mut snaps = [sotos_objstore::SnapMeta::zeroed(); sotos_objstore::MAX_SNAPSHOTS];
                                let count = vfs.store().snap_list(&mut snaps);
                                if count == 0 {
                                    let msg_text = b"no snapshots\n";
                                    dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                    dir_len = msg_text.len();
                                } else {
                                    for i in 0..count {
                                        let sname = snaps[i].name_as_str();
                                        if dir_len + sname.len() + 10 > dir_buf.len() { break; }
                                        dir_buf[dir_len..dir_len + sname.len()].copy_from_slice(sname);
                                        dir_len += sname.len();
                                        dir_buf[dir_len] = b'\n';
                                        dir_len += 1;
                                    }
                                }
                            }
                            None => {
                                let msg_text = b"no VFS\n";
                                dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                dir_len = msg_text.len();
                            }
                        }
                        fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                        reply_val(ep_cap, new_fd as i64);
                        continue;
                    } else if starts_with(snap_cmd, b"restore/") && snap_cmd.len() > 8 {
                        let snap_name = &snap_cmd[8..];
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                match vfs.store_mut().snap_find(snap_name) {
                                    Some(slot) => {
                                        match vfs.store_mut().snap_restore(slot) {
                                            Ok(()) => {
                                                dir_pos = 0;
                                                let msg_text = b"snapshot restored\n";
                                                dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                                dir_len = msg_text.len();
                                                fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                                                reply_val(ep_cap, new_fd as i64);
                                            }
                                            Err(_) => reply_val(ep_cap, -EIO), // -EIO
                                        }
                                    }
                                    None => reply_val(ep_cap, -ENOENT), // -ENOENT
                                }
                            }
                            None => reply_val(ep_cap, -ENOENT),
                        }
                        continue;
                    } else if starts_with(snap_cmd, b"delete/") && snap_cmd.len() > 7 {
                        let snap_name = &snap_cmd[7..];
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                match vfs.store_mut().snap_find(snap_name) {
                                    Some(slot) => {
                                        match vfs.store_mut().snap_delete(slot) {
                                            Ok(()) => {
                                                dir_pos = 0;
                                                let msg_text = b"snapshot deleted\n";
                                                dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                                dir_len = msg_text.len();
                                                fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                                                reply_val(ep_cap, new_fd as i64);
                                            }
                                            Err(_) => reply_val(ep_cap, -EIO),
                                        }
                                    }
                                    None => reply_val(ep_cap, -ENOENT),
                                }
                            }
                            None => reply_val(ep_cap, -ENOENT),
                        }
                        continue;
                    } else {
                        reply_val(ep_cap, -ENOENT);
                        continue;
                    }
                }

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        // Sync cwd before path resolution
                        vfs.cwd = cwd_oid;

                        let oflags = OFlags::from_bits_truncate(flags as u32);
                        let linux_access = flags & 0x3; // O_ACCMODE
                        let has_creat = oflags.contains(OFlags::CREAT);
                        let vfs_flags = match linux_access {
                            0 => 1u32,
                            1 => 2u32,
                            2 => 3u32,
                            _ => 1u32,
                        };

                        let result = if has_creat {
                            match vfs.open(name, vfs_flags) {
                                Ok(fd) => Ok(fd),
                                Err(_) => vfs.create(name),
                            }
                        } else {
                            vfs.open(name, vfs_flags)
                        };

                        match result {
                            Ok(vfs_fd) => {
                                fds[new_fd] = FdEntry::new(FdKind::VfsFile, vfs_fd, 0);
                                reply_val(ep_cap, new_fd as i64);
                            }
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_close(fd)
            SYS_CLOSE => {
                let fd = msg.regs[0] as usize;
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }

                match fds[fd].kind {
                    FdKind::VfsFile => {
                        if let Some(vfs) = vfs_opt.as_mut() {
                            let _ = vfs.close(fds[fd].vfs_fd);
                        }
                    }
                    FdKind::DirList => {
                        dir_len = 0;
                        dir_pos = 0;
                    }
                    FdKind::Socket => {
                        // Close TCP connection via net service (only if connected).
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let cid = fds[fd].net_conn_id;
                        if net_cap != 0 && cid != 0xFFFF {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_CLOSE,
                                regs: [cid as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 500);
                        }
                    }
                    _ => {}
                }
                fds[fd] = FdEntry::free();
                reply_val(ep_cap, 0);
            }

            // SYS_stat(path, statbuf)
            SYS_STAT => {
                let path_ptr = msg.regs[0];
                let stat_ptr = msg.regs[1];

                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // "." → current directory
                if path_len == 1 && path[0] == b'.' {
                    write_linux_stat(stat_ptr, cwd_oid, 0, true);
                    reply_val(ep_cap, 0);
                    continue;
                }

                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) => {
                                        let is_dir = entry.is_dir();
                                        write_linux_stat(stat_ptr, oid, entry.size, is_dir);
                                        reply_val(ep_cap, 0);
                                    }
                                    None => reply_val(ep_cap, -ENOENT),
                                }
                            }
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_fstat(fd, statbuf)
            SYS_FSTAT => {
                let fd = msg.regs[0] as usize;
                let stat_ptr = msg.regs[1];

                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }

                match fds[fd].kind {
                    FdKind::Stdin | FdKind::Stdout => {
                        // Char device (terminal)
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o20600; // S_IFCHR | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::DirList => {
                        write_linux_stat(stat_ptr, 1, 0, true);
                        reply_val(ep_cap, 0);
                    }
                    FdKind::VfsFile => {
                        let vfs_fd = fds[fd].vfs_fd;
                        match vfs_opt.as_ref() {
                            Some(vfs) => {
                                let oid = vfs.file_oid(vfs_fd).unwrap_or(0);
                                let size = vfs.file_size(vfs_fd).unwrap_or(0);
                                write_linux_stat(stat_ptr, oid, size, false);
                                reply_val(ep_cap, 0);
                            }
                            None => reply_val(ep_cap, -EBADF),
                        }
                    }
                    FdKind::Socket => {
                        // Socket stat: report as socket type.
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o140600; // S_IFSOCK | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::PipeRead | FdKind::PipeWrite => {
                        // Pipe stat: report as FIFO
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o10600; // S_IFIFO | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::SocketUdp => {
                        // UDP socket stat: report as socket type.
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o140600; // S_IFSOCK | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::DevUrandom | FdKind::DevZero => {
                        // Device stat: report as char device
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o20444; // S_IFCHR | r
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::EpollFd | FdKind::Free => reply_val(ep_cap, -EBADF),
                }
            }

            // SYS_lseek(fd, offset, whence)
            SYS_LSEEK => {
                let fd = msg.regs[0] as usize;
                let offset = msg.regs[1] as i64;
                let whence = msg.regs[2] as u32;

                if fd >= MAX_FDS || fds[fd].kind != FdKind::VfsFile {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }

                let vfs_fd = fds[fd].vfs_fd;
                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        let new_pos = match whence {
                            0 => {
                                // SEEK_SET
                                offset as u64
                            }
                            1 => {
                                // SEEK_CUR
                                let cur = vfs.tell(vfs_fd).unwrap_or(0);
                                (cur as i64 + offset) as u64
                            }
                            2 => {
                                // SEEK_END
                                let size = vfs.file_size(vfs_fd).unwrap_or(0);
                                (size as i64 + offset) as u64
                            }
                            _ => {
                                reply_val(ep_cap, -EINVAL); // -EINVAL
                                continue;
                            }
                        };
                        let _ = vfs.seek(vfs_fd, new_pos);
                        reply_val(ep_cap, new_pos as i64);
                    }
                    None => reply_val(ep_cap, -EBADF),
                }
            }

            // SYS_mmap(addr, len, prot, flags, fd, offset)
            SYS_MMAP => {
                let _addr = msg.regs[0];
                let len = msg.regs[1];
                let _prot = msg.regs[2];
                let flags = msg.regs[3]; // r10 in kernel
                let mmap_fd = msg.regs[4] as usize; // r8
                let mmap_offset = msg.regs[5]; // r9
                let mflags = MFlags::from_bits_truncate(flags as u32);
                let is_anon = mflags.contains(MFlags::ANONYMOUS);

                // Validate: file-backed mmap needs a valid VfsFile fd
                if !is_anon {
                    if mmap_fd >= MAX_FDS || fds[mmap_fd].kind != FdKind::VfsFile {
                        reply_val(ep_cap, -EBADF); // -EBADF
                        continue;
                    }
                    if vfs_opt.is_none() {
                        reply_val(ep_cap, -ENODEV); // -ENODEV
                        continue;
                    }
                }

                let pages = ((len + 0xFFF) / 0x1000) as u32;
                // Find a free mmap slot
                let slot = {
                    let mut found = None;
                    for i in 0..MAX_MMAPS {
                        if mmaps[i].addr == 0 {
                            found = Some(i);
                            break;
                        }
                    }
                    match found {
                        Some(s) => s,
                        None => {
                            reply_val(ep_cap, -ENOMEM); // -ENOMEM
                            continue;
                        }
                    }
                };

                let base = mmap_next;
                let mut ok = true;
                for p in 0..pages {
                    match sys::frame_alloc() {
                        Ok(frame) => {
                            if sys::map(base + (p as u64) * 0x1000, frame, MAP_WRITABLE).is_err() {
                                ok = false;
                                break;
                            }
                        }
                        Err(_) => { ok = false; break; }
                    }
                }
                if !ok {
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Zero the mapped region first
                let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (pages as usize) * 0x1000) };
                for b in region.iter_mut() { *b = 0; }

                // For file-backed mmap: read file content into the mapped region
                if !is_anon {
                    if let Some(vfs) = vfs_opt.as_mut() {
                        let vfs_fd = fds[mmap_fd].vfs_fd;
                        // Save current position, seek to offset, read, restore
                        let saved_pos = vfs.tell(vfs_fd).unwrap_or(0);
                        let _ = vfs.seek(vfs_fd, mmap_offset);
                        let read_len = len as usize;
                        let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, read_len) };
                        let _ = vfs.read(vfs_fd, dst);
                        let _ = vfs.seek(vfs_fd, saved_pos);
                    }
                }

                mmaps[slot] = MmapEntry { addr: base, len, pages };
                mmap_next += (pages as u64) * 0x1000;
                reply_val(ep_cap, base as i64);
            }

            // SYS_munmap(addr, len)
            SYS_MUNMAP => {
                let addr = msg.regs[0];
                let mut found = false;
                for i in 0..MAX_MMAPS {
                    if mmaps[i].addr == addr {
                        for p in 0..mmaps[i].pages {
                            let _ = sys::unmap_free(addr + (p as u64) * 0x1000);
                        }
                        mmaps[i] = MmapEntry::empty();
                        found = true;
                        break;
                    }
                }
                reply_val(ep_cap, if found { 0 } else { -22 });
            }

            // SYS_brk(addr)
            SYS_BRK => {
                let addr = msg.regs[0];
                if addr == 0 {
                    // Query current brk
                    reply_val(ep_cap, current_brk as i64);
                } else if addr > current_brk && addr <= BRK_BASE + BRK_LIMIT {
                    // Grow: allocate and map pages from current_brk to addr
                    let start_page = (current_brk + 0xFFF) & !0xFFF;
                    let end_page = (addr + 0xFFF) & !0xFFF;
                    let mut page = start_page;
                    let mut ok = true;
                    while page < end_page {
                        // Only map if this page hasn't been mapped yet
                        if page >= (current_brk & !0xFFF) + 0x1000 || current_brk == BRK_BASE {
                            match sys::frame_alloc() {
                                Ok(frame) => {
                                    if sys::map(page, frame, MAP_WRITABLE).is_err() {
                                        ok = false;
                                        break;
                                    }
                                }
                                Err(_) => { ok = false; break; }
                            }
                        }
                        page += 0x1000;
                    }
                    if ok {
                        current_brk = addr;
                    }
                    reply_val(ep_cap, current_brk as i64);
                } else if addr <= current_brk {
                    // Shrink or no-op
                    current_brk = addr.max(BRK_BASE);
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    // Beyond limit
                    reply_val(ep_cap, current_brk as i64);
                }
            }

            // SYS_dup(oldfd)
            SYS_DUP => {
                let oldfd = msg.regs[0] as usize;
                if oldfd >= MAX_FDS || fds[oldfd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }
                match alloc_fd(&fds, 0) {
                    Some(newfd) => {
                        fds[newfd] = fds[oldfd];
                        reply_val(ep_cap, newfd as i64);
                    }
                    None => reply_val(ep_cap, -EMFILE),
                }
            }

            // SYS_dup2(oldfd, newfd)
            SYS_DUP2 => {
                let oldfd = msg.regs[0] as usize;
                let newfd = msg.regs[1] as usize;
                if oldfd >= MAX_FDS || fds[oldfd].kind == FdKind::Free || newfd >= MAX_FDS {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }
                // Close newfd if open
                if fds[newfd].kind == FdKind::VfsFile {
                    if let Some(vfs) = vfs_opt.as_mut() {
                        let _ = vfs.close(fds[newfd].vfs_fd);
                    }
                }
                fds[newfd] = fds[oldfd];
                reply_val(ep_cap, newfd as i64);
            }

            // SYS_getpid
            SYS_GETPID => {
                reply_val(ep_cap, pid as i64);
            }

            // SYS_clone(child_fn) — fork a child process
            SYS_CLONE => {
                let child_fn = msg.regs[0];

                // Allocate child stacks: 1 page guest + 4 pages handler
                let stack_base = NEXT_CHILD_STACK.fetch_add(0x5000, Ordering::SeqCst);
                let guest_stack = stack_base;
                let handler_stack = stack_base + 0x1000;

                // Map guest stack (1 page)
                let gf = match sys::frame_alloc() {
                    Ok(f) => f,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };
                if sys::map(guest_stack, gf, MAP_WRITABLE).is_err() {
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Map handler stack (4 pages)
                let mut hok = true;
                for hp in 0..4u64 {
                    let hf = match sys::frame_alloc() {
                        Ok(f) => f,
                        Err(_) => { hok = false; break; }
                    };
                    if sys::map(handler_stack + hp * 0x1000, hf, MAP_WRITABLE).is_err() {
                        hok = false; break;
                    }
                }
                if !hok {
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Create child endpoint
                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };

                // Assign PID
                let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);

                // Set parent in process table (before handshake so child can read it)
                PROC_PARENT[child_pid as usize - 1].store(pid, Ordering::Release);
                // Initialize process group state (fork child = new process leader)
                proc_group_init(child_pid as usize);

                // Pass setup info to child handler
                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(child_pid, Ordering::Release);
                CHILD_SETUP_FLAGS.store(0, Ordering::Release); // normal fork, no CLONE_ flags
                CHILD_SETUP_READY.store(1, Ordering::Release);

                // Spawn child handler thread (stack top = handler_stack + 4 pages)
                if sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack + 0x4000,
                ).is_err() {
                    CHILD_SETUP_READY.store(0, Ordering::Release);
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Wait for child handler to consume setup
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 {
                    sys::yield_now();
                }

                // Spawn child guest thread with redirect pre-set (no race)
                let child_thread = match sys::thread_create_redirected(child_fn, guest_stack + 0x1000, child_ep) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };
                let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

                // Mark child as running
                PROC_STATE[child_pid as usize - 1].store(1, Ordering::Release);

                // Reply to parent with child PID
                reply_val(ep_cap, child_pid as i64);
            }

            // SYS_exit(status)
            SYS_EXIT => {
                let status = msg.regs[0];
                print(b"LUCAS: guest exit(");
                print_u64(status);
                print(b")\n");
                break;
            }

            // SYS_wait4(pid, ...) — waitpid
            SYS_WAIT4 => {
                let target_pid = msg.regs[0] as i64;
                if target_pid <= 0 || target_pid as usize > MAX_PROCS {
                    reply_val(ep_cap, -ECHILD); // -ECHILD
                    continue;
                }
                let idx = target_pid as usize - 1;
                // Spin until child becomes Zombie
                while PROC_STATE[idx].load(Ordering::Acquire) != 2 {
                    sys::yield_now();
                }
                let status = PROC_EXIT[idx].load(Ordering::Acquire);
                PROC_STATE[idx].store(0, Ordering::Release); // Free
                reply_val(ep_cap, status as i64);
            }

            // SYS_kill(pid, sig)
            SYS_KILL => {
                let target = msg.regs[0] as usize;
                let sig = msg.regs[1];
                if target == 0 || target > MAX_PROCS || PROC_STATE[target - 1].load(Ordering::Acquire) == 0 {
                    reply_val(ep_cap, -ESRCH); // -ESRCH
                    continue;
                }
                sig_send(target, sig);
                reply_val(ep_cap, 0);
            }

            // SYS_getcwd(buf, size)
            SYS_GETCWD => {
                let buf_ptr = msg.regs[0];
                let buf_size = msg.regs[1] as usize;

                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        let mut cwd_buf = [0u8; 128];
                        let len = {
                            // Temporarily create a Vfs-like view for getcwd
                            // We need to walk the store's dir entries
                            let store = vfs.store();
                            let mut oids = [0u64; 16];
                            let mut depth = 0;
                            let mut cur = cwd_oid;
                            while cur != sotos_objstore::ROOT_OID && depth < 16 {
                                oids[depth] = cur;
                                depth += 1;
                                if let Some(entry) = store.stat(cur) {
                                    let parent = entry.parent_oid;
                                    cur = if parent == 0 { sotos_objstore::ROOT_OID } else { parent };
                                } else {
                                    break;
                                }
                            }
                            let mut pos = 0;
                            if depth == 0 {
                                cwd_buf[0] = b'/';
                                pos = 1;
                            } else {
                                let mut i = depth;
                                while i > 0 {
                                    i -= 1;
                                    if pos < cwd_buf.len() { cwd_buf[pos] = b'/'; pos += 1; }
                                    if let Some(entry) = store.stat(oids[i]) {
                                        let name = entry.name_as_str();
                                        let copy_len = name.len().min(cwd_buf.len() - pos);
                                        cwd_buf[pos..pos + copy_len].copy_from_slice(&name[..copy_len]);
                                        pos += copy_len;
                                    }
                                }
                            }
                            pos
                        };
                        let copy_len = len.min(buf_size);
                        let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, copy_len) };
                        dst.copy_from_slice(&cwd_buf[..copy_len]);
                        if copy_len < buf_size {
                            unsafe { *((buf_ptr + copy_len as u64) as *mut u8) = 0; }
                        }
                        reply_val(ep_cap, buf_ptr as i64);
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_chdir(path)
            SYS_CHDIR => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) if entry.is_dir() => {
                                        cwd_oid = oid;
                                        reply_val(ep_cap, 0);
                                    }
                                    _ => reply_val(ep_cap, -ENOTDIR), // -ENOTDIR
                                }
                            }
                            Err(_) => reply_val(ep_cap, -ENOENT), // -ENOENT
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_mkdir(path, mode)
            SYS_MKDIR => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        match vfs.mkdir(name) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_rmdir(path)
            SYS_RMDIR => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        match vfs.rmdir(name) {
                            Ok(()) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_unlink(path)
            SYS_UNLINK => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        match vfs.delete(name) {
                            Ok(()) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_getppid
            SYS_GETPPID => {
                reply_val(ep_cap, 0); // PID 1 has no parent
            }

            // SYS_mprotect(addr, len, prot) — change page protections
            SYS_MPROTECT => {
                let addr = msg.regs[0];
                let len = msg.regs[1] as usize;
                let prot = msg.regs[2]; // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
                if addr & 0xFFF != 0 {
                    reply_val(ep_cap, -EINVAL); // -EINVAL
                } else {
                    let pages = (len + 0xFFF) / 0x1000;
                    let mut flags: u64 = 0;
                    if prot & 2 != 0 { flags |= 2; }       // WRITABLE
                    if prot & 4 == 0 { flags |= 1u64 << 63; } // NO_EXECUTE if !PROT_EXEC
                    for i in 0..pages {
                        let _ = sys::protect(addr + (i as u64) * 0x1000, flags);
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_ioctl(fd, request, arg)
            SYS_IOCTL => {
                let _fd = msg.regs[0];
                let request = msg.regs[1];
                match request {
                    // TIOCGWINSZ — terminal window size
                    0x5413 => {
                        let arg = msg.regs[2];
                        if arg != 0 && arg < 0x0000_8000_0000_0000 {
                            // struct winsize { rows(u16), cols(u16), xpixel(u16), ypixel(u16) }
                            let ws = unsafe { core::slice::from_raw_parts_mut(arg as *mut u8, 8) };
                            ws[0..2].copy_from_slice(&25u16.to_le_bytes()); // rows
                            ws[2..4].copy_from_slice(&80u16.to_le_bytes()); // cols
                            ws[4..8].copy_from_slice(&[0; 4]); // xpixel, ypixel
                            reply_val(ep_cap, 0);
                        } else {
                            reply_val(ep_cap, -EINVAL);
                        }
                    }
                    // FIONREAD — bytes available for reading
                    0x541B => {
                        reply_val(ep_cap, 0);
                    }
                    _ => reply_val(ep_cap, -ENOTTY), // -ENOTTY
                }
            }

            // SYS_writev(fd, iov_ptr, iovcnt)
            SYS_WRITEV => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else {
                    // struct iovec { iov_base: *mut u8, iov_len: usize } = 16 bytes each
                    let mut total: usize = 0;
                    let cnt = iovcnt.min(16); // limit scatter count
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let base = unsafe { *(entry as *const u64) };
                        let len = unsafe { *((entry + 8) as *const u64) } as usize;
                        if base == 0 || len == 0 { continue; }
                        if fds[fd].kind == FdKind::Stdout {
                            let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                            for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                            total += len;
                        } else if fds[fd].kind == FdKind::VfsFile {
                            if let Some(vfs) = vfs_opt.as_mut() {
                                let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                                let vfd = fds[fd].vfs_fd;
                                let _ = vfs.store_mut().write_obj(vfd as u64, data);
                                total += len;
                            }
                        } else if fds[fd].kind == FdKind::Socket {
                            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                            let conn_id = fds[fd].net_conn_id as u64;
                            let send_len = len.min(40);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_SEND,
                                regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts(base as *const u8, send_len) };
                            unsafe {
                                let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                            }
                            if let Ok(resp) = sys::call_timeout(net_cap, &req, 500) {
                                total += resp.regs[0] as usize;
                            }
                        } else if fds[fd].kind == FdKind::SocketUdp {
                            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                            let remote_ip = fds[fd].udp_remote_ip;
                            let remote_port = fds[fd].udp_remote_port;
                            let src_port = fds[fd].udp_local_port;
                            if net_cap != 0 && remote_ip != 0 {
                                let send_len = len.min(32);
                                let mut req = sotos_common::IpcMsg {
                                    tag: NET_CMD_UDP_SENDTO,
                                    regs: [remote_ip as u64, remote_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                                };
                                let data = unsafe { core::slice::from_raw_parts(base as *const u8, send_len) };
                                unsafe {
                                    let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                                    core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                                }
                                if let Ok(resp) = sys::call_timeout(net_cap, &req, 500) {
                                    total += resp.regs[0] as usize;
                                }
                            }
                        }
                    }
                    reply_val(ep_cap, total as i64);
                }
            }

            // SYS_access(path, mode) — check file accessibility
            SYS_ACCESS => {
                let path_ptr = msg.regs[0];
                let _mode = msg.regs[1]; // F_OK=0, R_OK=4, W_OK=2, X_OK=1
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -ENOENT), // -ENOENT
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_pipe(pipefd[2])
            SYS_PIPE => {
                let pfd_ptr = msg.regs[0];
                if pfd_ptr == 0 || pfd_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -EFAULT); // -EFAULT
                } else {
                    // Allocate two FDs pointing to a simple pipe
                    match (alloc_fd(&fds, 3), alloc_fd(&fds, 4)) {
                        (Some(rfd), Some(wfd)) if rfd != wfd => {
                            fds[rfd] = FdEntry::new(FdKind::PipeRead, wfd as u32, 0);
                            fds[wfd] = FdEntry::new(FdKind::PipeWrite, rfd as u32, 0);
                            let pfd = unsafe { core::slice::from_raw_parts_mut(pfd_ptr as *mut i32, 2) };
                            pfd[0] = rfd as i32;
                            pfd[1] = wfd as i32;
                            reply_val(ep_cap, 0);
                        }
                        _ => reply_val(ep_cap, -EMFILE), // -EMFILE
                    }
                }
            }

            // SYS_uname(buf) — system info
            SYS_UNAME => {
                let buf_ptr = msg.regs[0];
                if buf_ptr == 0 || buf_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -EFAULT);
                } else {
                    // struct utsname: 5 fields of 65 bytes each = 325 bytes
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 325) };
                    for b in buf.iter_mut() { *b = 0; }
                    let fields: [&[u8]; 5] = [
                        b"sotOS",             // sysname
                        b"sotos",             // nodename
                        b"0.1.0",             // release
                        b"sotOS 0.1.0 LUCAS", // version
                        b"x86_64",            // machine
                    ];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_fcntl(fd, cmd, arg)
            SYS_FCNTL => {
                let fd = msg.regs[0] as usize;
                let cmd = msg.regs[1] as u32;
                let _arg = msg.regs[2];
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else {
                    match cmd {
                        0 => { // F_DUPFD
                            match alloc_fd(&fds, _arg as usize) {
                                Some(newfd) => {
                                    fds[newfd] = fds[fd];
                                    reply_val(ep_cap, newfd as i64);
                                }
                                None => reply_val(ep_cap, -EMFILE),
                            }
                        }
                        1 => reply_val(ep_cap, 0), // F_GETFD → no FD_CLOEXEC
                        2 => reply_val(ep_cap, 0), // F_SETFD → ignore
                        3 => reply_val(ep_cap, 0), // F_GETFL → O_RDONLY
                        4 => reply_val(ep_cap, 0), // F_SETFL → ignore
                        _ => reply_val(ep_cap, -EINVAL), // -EINVAL
                    }
                }
            }

            // SYS_getuid / SYS_geteuid / SYS_getgid / SYS_getegid
            SYS_GETUID | SYS_GETGID | SYS_GETEUID | SYS_GETEGID => {
                reply_val(ep_cap, 0); // root
            }

            // SYS_set_tid_address(tidptr) — store clear_child_tid, return TID
            SYS_SET_TID_ADDRESS => {
                // Just return the PID as TID (single-threaded LUCAS processes)
                reply_val(ep_cap, pid as i64);
            }

            // SYS_clock_gettime(clock_id, timespec) — with 3-day uptime offset
            SYS_CLOCK_GETTIME => {
                let _clock_id = msg.regs[0]; // CLOCK_REALTIME=0, CLOCK_MONOTONIC=1
                let tp_ptr = msg.regs[1];
                if tp_ptr == 0 || tp_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -EFAULT);
                } else {
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_ns = if tsc > boot_tsc { (tsc - boot_tsc) / 2 } else { 0 };
                    let total_ns = elapsed_ns + UPTIME_OFFSET_NS;
                    let secs = total_ns / 1_000_000_000;
                    let nsecs = total_ns % 1_000_000_000;
                    let tp = unsafe { core::slice::from_raw_parts_mut(tp_ptr as *mut u8, 16) };
                    tp[0..8].copy_from_slice(&(secs as i64).to_le_bytes());
                    tp[8..16].copy_from_slice(&(nsecs as i64).to_le_bytes());
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_gettimeofday(tv, tz) — with 3-day uptime offset
            SYS_GETTIMEOFDAY => {
                let tv_ptr = msg.regs[0];
                if tv_ptr != 0 && tv_ptr < 0x0000_8000_0000_0000 {
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_us = if tsc > boot_tsc { (tsc - boot_tsc) / 2000 } else { 0 };
                    let total_secs = elapsed_us / 1_000_000 + UPTIME_OFFSET_SECS;
                    let usecs = elapsed_us % 1_000_000;
                    let tv = unsafe { core::slice::from_raw_parts_mut(tv_ptr as *mut u8, 16) };
                    tv[0..8].copy_from_slice(&(total_secs as i64).to_le_bytes());
                    tv[8..16].copy_from_slice(&(usecs as i64).to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getdents64(fd, dirp, count) — read directory entries
            SYS_GETDENTS64 => {
                let fd = msg.regs[0] as usize;
                let dirp = msg.regs[1];
                let count = msg.regs[2] as usize;
                if fd >= MAX_FDS || fds[fd].kind != FdKind::DirList {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else if dirp == 0 || dirp >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -EFAULT); // -EFAULT
                } else {
                    // If dir_buf is empty, populate it from the VFS
                    if dir_pos >= dir_len {
                        dir_len = 0;
                        dir_pos = 0;
                        let dir_oid = fds[fd].vfs_fd as u64;
                        if let Some(vfs) = vfs_opt.as_ref() {
                            let mut entries = [sotos_objstore::layout::DirEntry::zeroed(); 32];
                            let n = vfs.store().list_dir(dir_oid, &mut entries);
                            for i in 0..n {
                                let entry = &entries[i];
                                let ename = entry.name_as_str();
                                // linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(var+NUL)
                                let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8; // align to 8
                                if dir_len + reclen > dir_buf.len() { break; }
                                let d = &mut dir_buf[dir_len..dir_len + reclen];
                                for b in d.iter_mut() { *b = 0; }
                                d[0..8].copy_from_slice(&entry.oid.to_le_bytes()); // d_ino
                                d[8..16].copy_from_slice(&((dir_len + reclen) as u64).to_le_bytes()); // d_off
                                d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes()); // d_reclen
                                d[18] = if entry.is_dir() { 4 } else { 8 }; // d_type
                                let nlen = ename.len().min(reclen - 19);
                                d[19..19 + nlen].copy_from_slice(&ename[..nlen]);
                                dir_len += reclen;
                            }
                        }
                    }
                    let remaining = if dir_pos < dir_len { dir_len - dir_pos } else { 0 };
                    if remaining == 0 {
                        reply_val(ep_cap, 0); // EOF
                    } else {
                        let copy_len = remaining.min(count);
                        let src = &dir_buf[dir_pos..dir_pos + copy_len];
                        unsafe {
                            core::ptr::copy_nonoverlapping(src.as_ptr(), dirp as *mut u8, copy_len);
                        }
                        dir_pos += copy_len;
                        reply_val(ep_cap, copy_len as i64);
                    }
                }
            }

            // SYS_openat(dirfd, path, flags, mode) — open relative to dirfd
            SYS_OPENAT => {
                // Treat AT_FDCWD (-100) or any dirfd as CWD-relative
                let path_ptr = msg.regs[1];
                let flags = msg.regs[2] as u32;
                let _mode = msg.regs[3];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // Device files: /dev/null, /dev/zero, /dev/urandom
                let dev_kind = if name == b"/dev/null" { Some(FdKind::PipeWrite) }
                    else if name == b"/dev/zero" { Some(FdKind::DevZero) }
                    else if name == b"/dev/urandom" || name == b"/dev/random" { Some(FdKind::DevUrandom) }
                    else { None };
                if let Some(dk) = dev_kind {
                    match alloc_fd(&fds, 3) {
                        Some(newfd) => {
                            fds[newfd] = FdEntry::new(dk, 0, 0);
                            reply_val(ep_cap, newfd as i64);
                        }
                        None => reply_val(ep_cap, -EMFILE),
                    }
                    continue;
                }

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) => {
                                        if entry.is_dir() {
                                            match alloc_fd(&fds, 3) {
                                                Some(newfd) => {
                                                    fds[newfd] = FdEntry::new(FdKind::DirList, oid as u32, 0);
                                                    dir_len = 0; dir_pos = 0; // reset for getdents64
                                                    reply_val(ep_cap, newfd as i64);
                                                }
                                                None => reply_val(ep_cap, -EMFILE),
                                            }
                                        } else {
                                            match alloc_fd(&fds, 3) {
                                                Some(newfd) => {
                                                    fds[newfd] = FdEntry::new(FdKind::VfsFile, oid as u32, 0);
                                                    reply_val(ep_cap, newfd as i64);
                                                }
                                                None => reply_val(ep_cap, -EMFILE),
                                            }
                                        }
                                    }
                                    None => reply_val(ep_cap, -ENOENT),
                                }
                            }
                            Err(_) => {
                                if OFlags::from_bits_truncate(flags as u32).contains(OFlags::CREAT) {
                                    match vfs.create(name) {
                                        Ok(fd) => {
                                            let oid = vfs.file_oid(fd).unwrap_or(0);
                                            let _ = vfs.close(fd);
                                            match alloc_fd(&fds, 3) {
                                                Some(newfd) => {
                                                    fds[newfd] = FdEntry::new(FdKind::VfsFile, oid as u32, 0);
                                                    reply_val(ep_cap, newfd as i64);
                                                }
                                                None => reply_val(ep_cap, -EMFILE),
                                            }
                                        }
                                        Err(_) => reply_val(ep_cap, -ENOENT),
                                    }
                                } else {
                                    reply_val(ep_cap, -ENOENT);
                                }
                            }
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_fstatat(dirfd, path, statbuf, flag) — stat relative to dirfd
            SYS_FSTATAT => {
                let path_ptr = msg.regs[1];
                let stat_ptr = msg.regs[2];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) => {
                                        write_linux_stat(stat_ptr, oid, entry.size, entry.is_dir());
                                        reply_val(ep_cap, 0);
                                    }
                                    None => reply_val(ep_cap, -ENOENT),
                                }
                            }
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_readlinkat(dirfd, path, buf, bufsiz) — always -EINVAL (no symlinks)
            SYS_READLINKAT => {
                reply_val(ep_cap, -EINVAL); // -EINVAL: no symlinks
            }

            // SYS_faccessat(dirfd, path, mode, flags) — check file accessibility
            SYS_FACCESSAT => {
                let path_ptr = msg.regs[1];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_prlimit64(pid, resource, new_rlim, old_rlim) — get/set resource limits
            SYS_PRLIMIT64 => {
                let old_rlim = msg.regs[3];
                if old_rlim != 0 && old_rlim < 0x0000_8000_0000_0000 {
                    // Return generous defaults: cur=RLIM_INFINITY, max=RLIM_INFINITY
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_rlim as *mut u8, 16) };
                    let infinity: u64 = u64::MAX;
                    buf[0..8].copy_from_slice(&infinity.to_le_bytes());
                    buf[8..16].copy_from_slice(&infinity.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getrandom(buf, buflen, flags) — fill buffer with pseudo-random bytes
            SYS_GETRANDOM => {
                let buf_ptr = msg.regs[0];
                let buflen = msg.regs[1] as usize;
                if buf_ptr == 0 || buf_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -EFAULT);
                } else {
                    let len = buflen.min(256); // cap to prevent huge writes
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
                    let mut rng = rdtsc();
                    for b in buf.iter_mut() {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        *b = rng as u8;
                    }
                    reply_val(ep_cap, len as i64);
                }
            }

            // SYS_socket(domain, type, protocol)
            SYS_SOCKET => {
                let domain = msg.regs[0] as u32;
                let sock_type = msg.regs[1] as u32;
                let base_type = sock_type & 0xFF;
                let flags = sock_type & !0xFF; // SOCK_NONBLOCK=0x800, SOCK_CLOEXEC=0x80000
                // AF_INET=2, SOCK_STREAM=1, SOCK_DGRAM=2
                if domain == 2 && (base_type == 1 || base_type == 2) {
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 {
                        reply_val(ep_cap, -EADDRNOTAVAIL); // -EADDRNOTAVAIL
                    } else {
                        match alloc_fd(&fds, 3) {
                            Some(fd) => {
                                if base_type == 1 {
                                    // TCP
                                    fds[fd] = FdEntry::new(FdKind::Socket, 0, 0xFFFF);
                                } else {
                                    // UDP
                                    let mut entry = FdEntry::new(FdKind::SocketUdp, 0, 0xFFFF);
                                    entry.sock_flags = (flags >> 8) as u16;
                                    fds[fd] = entry;
                                }
                                reply_val(ep_cap, fd as i64);
                            }
                            None => reply_val(ep_cap, -EMFILE), // -EMFILE
                        }
                    }
                } else if domain == 2 && base_type == 3 {
                    // SOCK_RAW — stub: return an FD but operations will fail
                    match alloc_fd(&fds, 3) {
                        Some(fd) => {
                            fds[fd] = FdEntry::new(FdKind::SocketUdp, 0, 0xFFFF);
                            reply_val(ep_cap, fd as i64);
                        }
                        None => reply_val(ep_cap, -EMFILE),
                    }
                } else {
                    reply_val(ep_cap, -EAFNOSUPPORT); // -EAFNOSUPPORT
                }
            }

            // SYS_connect(fd, sockaddr_ptr, addrlen)
            SYS_CONNECT => {
                let fd = msg.regs[0] as usize;
                let sockaddr_ptr = msg.regs[1];
                let _addrlen = msg.regs[2];

                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else {
                    // Parse sockaddr_in: family(2) + port(2) + ip(4)
                    let sa = unsafe { core::slice::from_raw_parts(sockaddr_ptr as *const u8, 8) };
                    let port = u16::from_be_bytes([sa[2], sa[3]]);
                    let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

                    if fds[fd].kind == FdKind::SocketUdp {
                        // UDP connect: just store the remote address
                        fds[fd].udp_remote_ip = ip;
                        fds[fd].udp_remote_port = port;
                        reply_val(ep_cap, 0);
                    } else {
                        // TCP connect
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap == 0 {
                            reply_val(ep_cap, -EADDRNOTAVAIL);
                        } else {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_CONNECT,
                                regs: [ip as u64, port as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let conn_id = resp.regs[0];
                                    if conn_id as i64 >= 0 {
                                        fds[fd].net_conn_id = conn_id as u32;
                                        reply_val(ep_cap, 0);
                                    } else {
                                        reply_val(ep_cap, -ECONNREFUSED); // -ECONNREFUSED
                                    }
                                }
                                Err(_) => reply_val(ep_cap, -ECONNREFUSED),
                            }
                        }
                    }
                }
            }

            // SYS_sendto(fd, buf, len, flags, dest_addr, addrlen) = 44
            // SYS_sendmsg = 46 (treated as sendto for simple cases)
            SYS_SENDTO | SYS_SENDMSG => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let _flags = msg.regs[3];
                let dest_ptr = msg.regs[4]; // sockaddr_in* (for UDP)

                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -EBADF);
                } else if fds[fd].kind == FdKind::SocketUdp {
                    // UDP sendto
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); continue; }

                    // Determine destination: from dest_addr or from connect()
                    let (dst_ip, dst_port) = if dest_ptr != 0 {
                        let sa = unsafe { core::slice::from_raw_parts(dest_ptr as *const u8, 8) };
                        (u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]),
                         u16::from_be_bytes([sa[2], sa[3]]))
                    } else {
                        (fds[fd].udp_remote_ip, fds[fd].udp_remote_port)
                    };
                    let src_port = fds[fd].udp_local_port;

                    let send_len = len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_SENDTO,
                        regs: [dst_ip as u64, dst_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -EIO),
                    }
                } else {
                    // TCP sendto (same as before)
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = fds[fd].net_conn_id as u64;
                    let send_len = len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_SEND,
                        regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -EIO),
                    }
                }
            }

            // SYS_recvfrom(fd, buf, len, flags, src_addr, addrlen) = 45
            // SYS_recvmsg = 47
            SYS_RECVFROM | SYS_RECVMSG => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;

                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -EBADF);
                } else if fds[fd].kind == FdKind::SocketUdp {
                    // UDP recvfrom
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); continue; }
                    let src_port = fds[fd].udp_local_port;
                    let recv_len = len.min(48); // Max inline in 6 regs
                    let req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_RECV,
                        regs: [src_port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => {
                            let n = resp.regs[0] as usize;
                            if n > 0 && n <= recv_len {
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                unsafe {
                                    let src = &resp.regs[2] as *const u64 as *const u8;
                                    core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                }
                            }
                            reply_val(ep_cap, n as i64);
                        }
                        Err(_) => reply_val(ep_cap, 0), // timeout = no data
                    }
                } else {
                    // TCP recvfrom (same as before)
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = fds[fd].net_conn_id as u64;
                    let recv_len = len.min(56);
                    let req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_RECV,
                        regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => {
                            let n = resp.regs[0] as usize;
                            if n > 0 && n <= recv_len {
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                unsafe {
                                    let src = &resp.regs[1] as *const u64 as *const u8;
                                    core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                }
                            }
                            reply_val(ep_cap, n as i64);
                        }
                        Err(_) => reply_val(ep_cap, 0), // EOF/timeout
                    }
                }
            }

            // Custom syscall 200: DNS resolve (hostname_ptr, hostname_len) → IP (big-endian u32)
            SYS_TKILL => {
                let name_ptr = msg.regs[0];
                let name_len = msg.regs[1] as usize;
                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                if net_cap == 0 || name_len == 0 || name_len > 48 {
                    reply_val(ep_cap, 0); // 0 = resolution failed
                } else {
                    // Pack hostname into IPC regs[2..] (up to 48 bytes).
                    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len) };
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_DNS_QUERY,
                        regs: [0, name_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    unsafe {
                        let dst = &mut req.regs[2] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(name.as_ptr(), dst, name_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, 0),
                    }
                }
            }

            // Custom syscall 202: ICMP ping (dst_ip, seq) → 0=timeout, 1=reply | (ttl << 32)
            SYS_FUTEX => {
                let dst_ip = msg.regs[0];
                let seq = msg.regs[1];
                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                if net_cap == 0 {
                    reply_val(ep_cap, 0);
                } else {
                    let req = sotos_common::IpcMsg {
                        tag: 1, // CMD_PING
                        regs: [dst_ip, seq, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, 0),
                    }
                }
            }

            // Custom syscall 201: traceroute hop (dst_ip, ttl) → responder_ip | (reached << 32)
            SYS_TIME => {
                let dst_ip = msg.regs[0];
                let ttl = msg.regs[1];
                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                if net_cap == 0 {
                    reply_val(ep_cap, 0);
                } else {
                    let req = sotos_common::IpcMsg {
                        tag: 7, // CMD_TRACEROUTE_HOP
                        regs: [dst_ip, ttl, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, 0),
                    }
                }
            }

            // SYS_rt_sigaction(sig, act, oldact, sigsetsize)
            SYS_RT_SIGACTION => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize;
                let ksa_size = (24 + sigsetsize).min(64);
                let idx = pid as usize - 1;
                // SIGKILL(9) and SIGSTOP(19) cannot be caught
                if signo == 9 || signo == 19 {
                    reply_val(ep_cap, -EINVAL); continue; // -EINVAL
                }
                // Write old handler to oldact
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size) };
                    for b in buf.iter_mut() { *b = 0; }
                    if signo > 0 && signo < 32 {
                        let old_h = SIG_HANDLER[idx][signo].load(Ordering::Acquire);
                        let old_f = SIG_FLAGS[idx][signo].load(Ordering::Acquire);
                        let old_r = SIG_RESTORER[idx][signo].load(Ordering::Acquire);
                        buf[0..8].copy_from_slice(&old_h.to_le_bytes());
                        buf[8..16].copy_from_slice(&old_f.to_le_bytes());
                        buf[16..24].copy_from_slice(&old_r.to_le_bytes());
                    }
                }
                // Install new handler from act
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    let restorer = unsafe { *((act_ptr + 16) as *const u64) };
                    SIG_HANDLER[idx][signo].store(handler, Ordering::Release);
                    SIG_FLAGS[idx][signo].store(flags, Ordering::Release);
                    SIG_RESTORER[idx][signo].store(restorer, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_rt_sigprocmask(how, set, oldset, sigsetsize)
            SYS_RT_SIGPROCMASK => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = pid as usize - 1;
                let cur_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
                // Write old mask
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur_mask; }
                }
                // Apply new mask
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    let safe_set = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => SIG_BLOCKED[idx].store(cur_mask | safe_set, Ordering::Release),  // SIG_BLOCK
                        1 => SIG_BLOCKED[idx].store(cur_mask & !safe_set, Ordering::Release), // SIG_UNBLOCK
                        2 => SIG_BLOCKED[idx].store(safe_set, Ordering::Release),             // SIG_SETMASK
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_nanosleep(req, rem) — sleep for specified time
            SYS_NANOSLEEP => {
                let req_ptr = msg.regs[0];
                if req_ptr != 0 && req_ptr < 0x0000_8000_0000_0000 {
                    let secs = unsafe { *(req_ptr as *const i64) };
                    let _nsecs = unsafe { *((req_ptr + 8) as *const i64) };
                    // Approximate: yield for a number of iterations
                    let iters = (secs as u64).saturating_mul(100).max(1).min(10000);
                    for _ in 0..iters { sys::yield_now(); }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_sigaltstack(ss, old_ss) — set alternate signal stack
            SYS_SIGALTSTACK => {
                let old_ss = msg.regs[1];
                if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
                    // Return empty stack_t: ss_sp=0, ss_flags=SS_DISABLE(2), ss_size=0
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_ss as *mut u8, 24) };
                    for b in buf.iter_mut() { *b = 0; }
                    buf[8..12].copy_from_slice(&2u32.to_le_bytes()); // SS_DISABLE
                }
                reply_val(ep_cap, 0);
            }

            // SYS_exit_group(status) — exit all threads in the process
            SYS_EXIT_GROUP => {
                let status = msg.regs[0] as i32;
                PROC_EXIT[pid as usize - 1].store(status as u64, Ordering::Release);
                PROC_STATE[pid as usize - 1].store(2, Ordering::Release);
                // Deliver SIGCHLD to parent
                let ppid = PROC_PARENT[pid as usize - 1].load(Ordering::Acquire) as usize;
                if ppid > 0 && ppid <= MAX_PROCS {
                    sig_send(ppid, SIGCHLD as u64);
                }
                break;
            }

            // SYS_readv(fd, iov, iovcnt) — scatter read
            SYS_READV => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -EBADF);
                } else if fds[fd].kind == FdKind::Stdin {
                    // Stdin readv: read into first iovec only
                    if iovcnt > 0 && iov_ptr < 0x0000_8000_0000_0000 {
                        let base = unsafe { *(iov_ptr as *const u64) };
                        let _len = unsafe { *((iov_ptr + 8) as *const u64) } as usize;
                        // Wait for one keystroke
                        loop {
                            match unsafe { kb_read_char() } {
                                Some(ch) => {
                                    if base != 0 { unsafe { *(base as *mut u8) = ch; } }
                                    reply_val(ep_cap, 1);
                                    break;
                                }
                                None => sys::yield_now(),
                            }
                        }
                    } else {
                        reply_val(ep_cap, 0);
                    }
                } else {
                    reply_val(ep_cap, -EBADF); // other FD types: not yet
                }
            }

            // SYS_rename(oldpath, newpath) — rename file
            SYS_RENAME => {
                let old_ptr = msg.regs[0];
                let new_ptr = msg.regs[1];
                let mut old_path = [0u8; 48];
                let mut new_path = [0u8; 48];
                let old_len = copy_guest_path(old_ptr, &mut old_path);
                let new_len = copy_guest_path(new_ptr, &mut new_path);
                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        // Read old file, create new, delete old
                        match vfs.store().resolve_path(&old_path[..old_len], cwd_oid) {
                            Ok(oid) => {
                                let mut buf = [0u8; 4096];
                                let size = vfs.store_mut().read_obj(oid, &mut buf).unwrap_or(0);
                                match vfs.store_mut().create_in(&new_path[..new_len], &buf[..size], cwd_oid) {
                                    Ok(_new_oid) => {
                                        let _ = vfs.store_mut().delete(oid);
                                        reply_val(ep_cap, 0);
                                    }
                                    Err(_) => reply_val(ep_cap, -ENOENT),
                                }
                            }
                            Err(_) => reply_val(ep_cap, -ENOENT),
                        }
                    }
                    None => reply_val(ep_cap, -ENOENT),
                }
            }

            // SYS_poll(fds_ptr, nfds, timeout) — wait for events on FDs
            SYS_POLL => {
                let fds_ptr = msg.regs[0] as *mut u8;
                let nfds = msg.regs[1] as usize;
                let timeout = msg.regs[2] as i32;
                let mut ready = 0u32;
                // struct pollfd { int fd; short events; short revents; } = 8 bytes each
                for i in 0..nfds.min(16) {
                    let pfd = unsafe { fds_ptr.add(i * 8) };
                    let pfd_fd = unsafe { *(pfd as *const i32) };
                    let events = unsafe { *((pfd.add(4)) as *const i16) };
                    let mut revents: i16 = 0;
                    if pfd_fd >= 0 && (pfd_fd as usize) < MAX_FDS && fds[pfd_fd as usize].kind != FdKind::Free {
                        let k = fds[pfd_fd as usize].kind;
                        // POLLIN = 1, POLLOUT = 4, POLLHUP = 16, POLLERR = 8
                        match k {
                            FdKind::Stdin => {
                                if events & 1 != 0 {
                                    if unsafe { kb_has_char() } { revents |= 1; }
                                }
                            }
                            FdKind::Stdout | FdKind::PipeWrite => {
                                if events & 4 != 0 { revents |= 4; }
                            }
                            FdKind::Socket => {
                                // TCP: query net service for data availability
                                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                                let conn_id = fds[pfd_fd as usize].net_conn_id;
                                if net_cap != 0 && conn_id != 0xFFFF {
                                    let req = sotos_common::IpcMsg {
                                        tag: NET_CMD_TCP_STATUS,
                                        regs: [conn_id as u64, 0, 0, 0, 0, 0, 0, 0],
                                    };
                                    if let Ok(resp) = sys::call_timeout(net_cap, &req, 50) {
                                        let recv_avail = resp.regs[0]; // bytes available to read
                                        let connected = resp.regs[1]; // 1=connected, 0=closed/error
                                        if events & 1 != 0 && (recv_avail > 0 || connected == 0) {
                                            revents |= 1; // POLLIN
                                        }
                                        if events & 4 != 0 && connected != 0 {
                                            revents |= 4; // POLLOUT (writable if connected)
                                        }
                                        if connected == 0 {
                                            revents |= 16; // POLLHUP
                                        }
                                    } else {
                                        // Net service timeout — report as ready to avoid hang
                                        if events & 1 != 0 { revents |= 1; }
                                        if events & 4 != 0 { revents |= 4; }
                                    }
                                } else {
                                    if events & 4 != 0 { revents |= 4; }
                                }
                            }
                            FdKind::SocketUdp => {
                                // UDP: always writable, check for data via recv peek
                                if events & 4 != 0 { revents |= 4; }
                                if events & 1 != 0 { revents |= 1; } // optimistic: data may be available
                            }
                            FdKind::VfsFile | FdKind::DirList | FdKind::PipeRead => {
                                if events & 1 != 0 { revents |= 1; } // always readable
                                if events & 4 != 0 { revents |= 4; }
                            }
                            _ => {}
                        }
                    } else if pfd_fd >= 0 {
                        revents = 0x20; // POLLNVAL
                    }
                    unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                    if revents != 0 { ready += 1; }
                }
                if ready > 0 || timeout == 0 {
                    reply_val(ep_cap, ready as i64);
                } else {
                    // Blocking poll — short spin then return (avoid long hangs)
                    let max_iters: u32 = if timeout > 0 { (timeout as u32).min(500) * 10 } else { 5000 };
                    for _ in 0..max_iters {
                        sys::yield_now();
                        // Quick re-check
                        let mut found = false;
                        for i in 0..nfds.min(16) {
                            let pfd = unsafe { fds_ptr.add(i * 8) };
                            let pfd_fd = unsafe { *(pfd as *const i32) };
                            if pfd_fd >= 0 && (pfd_fd as usize) < MAX_FDS {
                                let k = fds[pfd_fd as usize].kind;
                                if k == FdKind::Stdin && unsafe { kb_has_char() } { found = true; break; }
                                if k == FdKind::Socket {
                                    // Check TCP recv buffer
                                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                                    let conn_id = fds[pfd_fd as usize].net_conn_id;
                                    if net_cap != 0 && conn_id != 0xFFFF {
                                        let req = sotos_common::IpcMsg {
                                            tag: NET_CMD_TCP_STATUS,
                                            regs: [conn_id as u64, 0, 0, 0, 0, 0, 0, 0],
                                        };
                                        if let Ok(resp) = sys::call_timeout(net_cap, &req, 20) {
                                            if resp.regs[0] > 0 || resp.regs[1] == 0 { found = true; break; }
                                        }
                                    }
                                }
                            }
                        }
                        if found {
                            // Re-run the full poll to set revents
                            ready = 0;
                            for i in 0..nfds.min(16) {
                                let pfd = unsafe { fds_ptr.add(i * 8) };
                                let pfd_fd = unsafe { *(pfd as *const i32) };
                                let events = unsafe { *((pfd.add(4)) as *const i16) };
                                let mut revents: i16 = 0;
                                if pfd_fd >= 0 && (pfd_fd as usize) < MAX_FDS && fds[pfd_fd as usize].kind != FdKind::Free {
                                    let k = fds[pfd_fd as usize].kind;
                                    match k {
                                        FdKind::Stdin => { if events & 1 != 0 && unsafe { kb_has_char() } { revents |= 1; } }
                                        FdKind::Stdout | FdKind::PipeWrite => { if events & 4 != 0 { revents |= 4; } }
                                        FdKind::Socket => {
                                            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                                            let conn_id = fds[pfd_fd as usize].net_conn_id;
                                            if net_cap != 0 && conn_id != 0xFFFF {
                                                let req = sotos_common::IpcMsg {
                                                    tag: NET_CMD_TCP_STATUS, regs: [conn_id as u64, 0, 0, 0, 0, 0, 0, 0],
                                                };
                                                if let Ok(resp) = sys::call_timeout(net_cap, &req, 20) {
                                                    if events & 1 != 0 && (resp.regs[0] > 0 || resp.regs[1] == 0) { revents |= 1; }
                                                    if events & 4 != 0 && resp.regs[1] != 0 { revents |= 4; }
                                                    if resp.regs[1] == 0 { revents |= 16; }
                                                }
                                            }
                                        }
                                        _ => { if events & 1 != 0 { revents |= 1; } }
                                    }
                                }
                                unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                                if revents != 0 { ready += 1; }
                            }
                            break;
                        }
                    }
                    reply_val(ep_cap, ready as i64);
                }
            }

            // SYS_sysinfo(info) — system information
            SYS_SYSINFO => {
                let info_ptr = msg.regs[0];
                if info_ptr != 0 && info_ptr < 0x0000_8000_0000_0000 {
                    // struct sysinfo = 112 bytes
                    let buf = unsafe { core::slice::from_raw_parts_mut(info_ptr as *mut u8, 112) };
                    for b in buf.iter_mut() { *b = 0; }
                    // uptime (i64) at offset 0
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let uptime = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 };
                    buf[0..8].copy_from_slice(&(uptime as i64).to_le_bytes());
                    // totalram at offset 32 (u64)
                    let ram: u64 = 256 * 1024 * 1024; // 256 MiB
                    buf[32..40].copy_from_slice(&ram.to_le_bytes());
                    // freeram at offset 40 (u64)
                    buf[40..48].copy_from_slice(&(ram / 2).to_le_bytes());
                    // mem_unit at offset 104 (u32)
                    buf[104..108].copy_from_slice(&1u32.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_SIGNAL_TRAMPOLINE (0x7F00) — async signal delivery from timer interrupt.
            // The LAPIC timer handler redirected the thread to the vDSO trampoline,
            // which did syscall(0x7F00) to enter LUCAS for signal delivery.
            0x7F00 => {
                let child_tid = msg.regs[6];
                let pid_usize = pid as usize;
                let sig = sig_dequeue(pid_usize);
                if sig != 0 {
                    match sig_dispatch(pid_usize, sig) {
                        1 => break, // terminated
                        3 => {
                            if signal_deliver(ep_cap, pid_usize, sig, child_tid, 0, true) {
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                // No pending signal or delivery failed — resume the thread by
                // building a SignalFrame with the saved pre-interrupt state and
                // redirecting through the vDSO's rt_sigreturn restorer.
                let mut saved_regs = [0u64; 18];
                if sys::get_thread_regs(child_tid, &mut saved_regs).is_ok() {
                    let saved_rsp = saved_regs[15];
                    let frame_size = sotos_common::SIGNAL_FRAME_SIZE as u64;
                    let new_rsp = ((saved_rsp - frame_size) & !0xF) - 8;
                    let fp = new_rsp as *mut u64;
                    unsafe {
                        core::ptr::write_volatile(fp.add(0),  vdso::SIGRETURN_RESTORER_ADDR);
                        core::ptr::write_volatile(fp.add(1),  0); // signo = 0 (no signal)
                        core::ptr::write_volatile(fp.add(2),  saved_regs[0]);  // rax
                        core::ptr::write_volatile(fp.add(3),  saved_regs[1]);  // rbx
                        core::ptr::write_volatile(fp.add(4),  saved_regs[2]);  // rcx (=rip)
                        core::ptr::write_volatile(fp.add(5),  saved_regs[3]);  // rdx
                        core::ptr::write_volatile(fp.add(6),  saved_regs[4]);  // rsi
                        core::ptr::write_volatile(fp.add(7),  saved_regs[5]);  // rdi
                        core::ptr::write_volatile(fp.add(8),  saved_regs[6]);  // rbp
                        core::ptr::write_volatile(fp.add(9),  saved_regs[7]);  // r8
                        core::ptr::write_volatile(fp.add(10), saved_regs[8]);  // r9
                        core::ptr::write_volatile(fp.add(11), saved_regs[9]);  // r10
                        core::ptr::write_volatile(fp.add(12), saved_regs[10]); // r11 (=rflags)
                        core::ptr::write_volatile(fp.add(13), saved_regs[11]); // r12
                        core::ptr::write_volatile(fp.add(14), saved_regs[12]); // r13
                        core::ptr::write_volatile(fp.add(15), saved_regs[13]); // r14
                        core::ptr::write_volatile(fp.add(16), saved_regs[14]); // r15
                        core::ptr::write_volatile(fp.add(17), saved_regs[2]);  // rip
                        core::ptr::write_volatile(fp.add(18), saved_rsp);      // rsp
                        core::ptr::write_volatile(fp.add(19), saved_regs[10]); // rflags
                        core::ptr::write_volatile(fp.add(20), saved_regs[16]); // fs_base
                        core::ptr::write_volatile(fp.add(21), 0);              // old_sigmask
                    }
                    // Redirect thread to the restorer, which calls rt_sigreturn
                    let reply = sotos_common::IpcMsg {
                        tag: sotos_common::SIG_REDIRECT_TAG,
                        regs: [
                            vdso::SIGRETURN_RESTORER_ADDR, // RIP = restorer
                            0, 0, 0,
                            new_rsp, // RSP below signal frame
                            0, 0, 0,
                        ],
                    };
                    let _ = sys::send(ep_cap, &reply);
                } else {
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_bind(fd, sockaddr_ptr, addrlen) = 49
            SYS_BIND => {
                let fd = msg.regs[0] as usize;
                let sockaddr_ptr = msg.regs[1];
                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -EBADF);
                } else {
                    // For UDP: store the local port from sockaddr_in
                    let sa = unsafe { core::slice::from_raw_parts(sockaddr_ptr as *const u8, 8) };
                    let port = u16::from_be_bytes([sa[2], sa[3]]);
                    if fds[fd].kind == FdKind::SocketUdp && port != 0 {
                        fds[fd].udp_local_port = port;
                        // Tell net service to bind this UDP port
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap != 0 {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_BIND,
                                regs: [port as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 100);
                        }
                    } else if fds[fd].kind == FdKind::SocketUdp {
                        // Bind to ephemeral port
                        static NEXT_UDP_PORT: AtomicU64 = AtomicU64::new(30000);
                        let p = NEXT_UDP_PORT.fetch_add(1, Ordering::SeqCst) as u16;
                        fds[fd].udp_local_port = p;
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap != 0 {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_BIND,
                                regs: [p as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 100);
                        }
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_listen(fd, backlog) = 50 — stub for TCP
            SYS_LISTEN => reply_val(ep_cap, 0),

            // SYS_getsockname(fd, sockaddr_ptr, addrlen_ptr) = 51
            SYS_GETSOCKNAME => {
                let fd = msg.regs[0] as usize;
                let sa_ptr = msg.regs[1];
                let alen_ptr = msg.regs[2];
                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -EBADF);
                } else {
                    // Return AF_INET, local port, 0.0.0.0
                    let sa = unsafe { core::slice::from_raw_parts_mut(sa_ptr as *mut u8, 16) };
                    for b in sa.iter_mut() { *b = 0; }
                    sa[0] = 2; sa[1] = 0; // AF_INET in little-endian sa_family
                    let port = if fds[fd].kind == FdKind::SocketUdp { fds[fd].udp_local_port } else { 0 };
                    sa[2..4].copy_from_slice(&port.to_be_bytes());
                    if alen_ptr != 0 {
                        unsafe { *(alen_ptr as *mut u32) = 16; }
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_getpeername(fd, sockaddr_ptr, addrlen_ptr) = 52
            SYS_GETPEERNAME => {
                let fd = msg.regs[0] as usize;
                let sa_ptr = msg.regs[1];
                let alen_ptr = msg.regs[2];
                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -EBADF);
                } else {
                    let sa = unsafe { core::slice::from_raw_parts_mut(sa_ptr as *mut u8, 16) };
                    for b in sa.iter_mut() { *b = 0; }
                    sa[0] = 2; sa[1] = 0; // AF_INET
                    let port = fds[fd].udp_remote_port;
                    let ip = fds[fd].udp_remote_ip;
                    sa[2..4].copy_from_slice(&port.to_be_bytes());
                    sa[4..8].copy_from_slice(&ip.to_be_bytes());
                    if alen_ptr != 0 {
                        unsafe { *(alen_ptr as *mut u32) = 16; }
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_shutdown(fd, how) = 48
            SYS_SHUTDOWN => reply_val(ep_cap, 0),

            // SYS_setsockopt(fd, level, optname, optval, optlen) = 54
            SYS_SETSOCKOPT => reply_val(ep_cap, 0),

            // SYS_getsockopt(fd, level, optname, optval, optlen) = 55
            SYS_GETSOCKOPT => {
                let optval_ptr = msg.regs[3];
                let optlen_ptr = msg.regs[4];
                // Return 0 (option value = 0, length = 4)
                if optval_ptr != 0 {
                    unsafe { *(optval_ptr as *mut u32) = 0; }
                }
                if optlen_ptr != 0 {
                    unsafe { *(optlen_ptr as *mut u32) = 4; }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_epoll_create1(flags) = 291, SYS_epoll_create(size) = 213
            SYS_EPOLL_CREATE1 | SYS_EPOLL_CREATE => {
                let idx = next_epoll_idx as usize;
                if idx >= MAX_EPOLL_INSTANCES {
                    reply_val(ep_cap, -EMFILE); // -EMFILE
                } else {
                    match alloc_fd(&fds, 3) {
                        Some(fd) => {
                            let mut entry = FdEntry::new(FdKind::EpollFd, 0, 0);
                            entry.epoll_idx = next_epoll_idx;
                            fds[fd] = entry;
                            epoll_instances[idx] = EpollInstance::new();
                            next_epoll_idx += 1;
                            reply_val(ep_cap, fd as i64);
                        }
                        None => reply_val(ep_cap, -EMFILE),
                    }
                }
            }

            // SYS_epoll_ctl(epfd, op, fd, event) = 233
            SYS_EPOLL_CTL => {
                let epfd = msg.regs[0] as usize;
                let op = msg.regs[1] as u32;
                let target_fd = msg.regs[2] as u32;
                let event_ptr = msg.regs[3];
                if epfd >= MAX_FDS || fds[epfd].kind != FdKind::EpollFd {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else {
                    let idx = fds[epfd].epoll_idx as usize;
                    if idx >= MAX_EPOLL_INSTANCES {
                        reply_val(ep_cap, -EINVAL);
                    } else {
                        // Read epoll_event struct: { u32 events, u64 data } = 12 bytes
                        let (events, data) = if event_ptr != 0 && event_ptr < 0x0000_8000_0000_0000 {
                            let ev = unsafe { core::ptr::read_volatile(event_ptr as *const u32) };
                            let d = unsafe { core::ptr::read_volatile((event_ptr + 4) as *const u64) };
                            (ev, d)
                        } else {
                            (0u32, 0u64)
                        };
                        match op {
                            1 => { // EPOLL_CTL_ADD
                                if epoll_instances[idx].add(target_fd, events, data) {
                                    reply_val(ep_cap, 0);
                                } else {
                                    reply_val(ep_cap, -ENOSPC); // -ENOSPC
                                }
                            }
                            2 => { // EPOLL_CTL_DEL
                                epoll_instances[idx].remove(target_fd);
                                reply_val(ep_cap, 0);
                            }
                            3 => { // EPOLL_CTL_MOD
                                if epoll_instances[idx].add(target_fd, events, data) {
                                    reply_val(ep_cap, 0);
                                } else {
                                    reply_val(ep_cap, -ENOENT); // -ENOENT
                                }
                            }
                            _ => reply_val(ep_cap, -EINVAL), // -EINVAL
                        }
                    }
                }
            }

            // SYS_epoll_wait(epfd, events, maxevents, timeout) = 232
            // SYS_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize) = 281
            SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT => {
                let epfd = msg.regs[0] as usize;
                let events_ptr = msg.regs[1];
                let maxevents = msg.regs[2] as usize;
                let timeout = msg.regs[3] as i32;
                if epfd >= MAX_FDS || fds[epfd].kind != FdKind::EpollFd {
                    reply_val(ep_cap, -EBADF);
                } else {
                    let idx = fds[epfd].epoll_idx as usize;
                    let max_out = maxevents.min(16);
                    let mut ready_count = 0usize;
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);

                    // Poll up to timeout_iters times (each iter ~10ms)
                    let iters = if timeout < 0 { 100u32 } else if timeout == 0 { 1u32 } else { (timeout as u32 / 10).max(1).min(200) };
                    for _ in 0..iters {
                        if idx < MAX_EPOLL_INSTANCES {
                            for e in 0..epoll_instances[idx].count {
                                if ready_count >= max_out { break; }
                                let entry = &epoll_instances[idx].entries[e];
                                let tfd = entry.fd as usize;
                                if tfd >= MAX_FDS { continue; }
                                let mut revents: u32 = 0;

                                match fds[tfd].kind {
                                    FdKind::Socket => {
                                        // Query TCP status from net service
                                        if net_cap != 0 {
                                            let conn_id = fds[tfd].net_conn_id as u64;
                                            let req = sotos_common::IpcMsg {
                                                tag: NET_CMD_TCP_STATUS,
                                                regs: [conn_id, 0, 0, 0, 0, 0, 0, 0],
                                            };
                                            if let Ok(resp) = sys::call_timeout(net_cap, &req, 20) {
                                                let recv_avail = resp.regs[0];
                                                let connected = resp.regs[1];
                                                if recv_avail > 0 && (entry.events & EPOLLIN) != 0 {
                                                    revents |= EPOLLIN;
                                                }
                                                if connected != 0 && (entry.events & EPOLLOUT) != 0 {
                                                    revents |= EPOLLOUT;
                                                }
                                                if connected == 0 {
                                                    revents |= EPOLLHUP;
                                                }
                                            }
                                        }
                                    }
                                    FdKind::Stdin => {
                                        // Check if keyboard data is available
                                        if (entry.events & EPOLLIN) != 0 {
                                            if unsafe { kb_has_char() } {
                                                revents |= EPOLLIN;
                                            }
                                        }
                                    }
                                    FdKind::Stdout | FdKind::PipeWrite => {
                                        // Stdout/pipes always writable
                                        if (entry.events & EPOLLOUT) != 0 {
                                            revents |= EPOLLOUT;
                                        }
                                    }
                                    FdKind::PipeRead => {
                                        // Pipe read: signal HUP (no writer)
                                        revents |= EPOLLHUP;
                                    }
                                    _ => {}
                                }

                                if revents != 0 {
                                    // Write epoll_event: { u32 events, u64 data } at events_ptr + ready_count * 12
                                    if events_ptr != 0 && events_ptr < 0x0000_8000_0000_0000 {
                                        let out = events_ptr + (ready_count as u64) * 12;
                                        unsafe {
                                            core::ptr::write_volatile(out as *mut u32, revents);
                                            core::ptr::write_volatile((out + 4) as *mut u64, entry.data);
                                        }
                                    }
                                    ready_count += 1;
                                }
                            }
                        }
                        if ready_count > 0 || timeout == 0 { break; }
                        sys::yield_now();
                    }
                    reply_val(ep_cap, ready_count as i64);
                }
            }

            // SYS_ppoll(fds, nfds, tmo, sigmask, sigsetsize) = 271
            SYS_PPOLL => {
                // Treat like poll with 0 timeout → return 0
                reply_val(ep_cap, 0);
            }

            // SYS_select(nfds, readfds, writefds, exceptfds, timeout) = 23
            // SYS_pselect6 = 270
            SYS_SELECT | SYS_PSELECT6 => reply_val(ep_cap, 0),

            // Unknown Linux syscall → -ENOSYS (with logging)
            _ => {
                print(b"LUCAS: unhandled syscall ");
                print_u64(syscall_nr);
                print(b"\n");
                reply_val(ep_cap, -ENOSYS);
            }
        }
    }

    print(b"LUCAS: done\n");
    sys::thread_exit();
}
