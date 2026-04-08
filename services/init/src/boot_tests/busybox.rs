//! Busybox boot test — fork/exec/pipes plus a pile of emulated applets.
#![allow(unused_imports)]

use sotos_common::sys;
use sotos_common::linux_abi::*;
use core::sync::atomic::Ordering;
use crate::framebuffer::{print, print_u64};
use crate::exec::{reply_val, exec_from_initrd_argv, rdtsc,
                  EXEC_LOCK, MAX_EXEC_ARG_LEN, format_wc_output, copy_guest_path,
                  MAP_WRITABLE};
use crate::process::*;
use crate::fd::*;
use crate::syscall_log::syscall_log_dump;
use crate::net::{NET_CMD_MIRROR, NET_CMD_TCP_CONNECT, NET_CMD_TCP_SEND, NET_CMD_TCP_RECV,
                 NET_CMD_TCP_CLOSE, NET_CMD_UDP_BIND, NET_CMD_UDP_SENDTO, NET_CMD_UDP_RECV};
use crate::vdso;
use crate::{NET_EP_CAP, vfs_lock, vfs_unlock, shared_store};

/// Run busybox with argv to validate argv passing and discover needed syscalls.
pub(crate) fn run_busybox_test() {
    print(b"BUSYBOX-TEST: loading...\n");

    // Ensure vDSO page is mapped (needed for fork-restore trampoline + exit stub).
    // Only write the code stubs, not the full vDSO (LUCAS forges the complete vDSO later).
    if let Ok(vf) = sys::frame_alloc() {
        if sys::map(vdso::VDSO_BASE, vf, MAP_WRITABLE).is_ok() {
            let page = unsafe {
                core::slice::from_raw_parts_mut(vdso::VDSO_BASE as *mut u8, 4096)
            };
            for b in page.iter_mut() { *b = 0; }
            // Write fork-restore trampoline: pop rbx,rbp,r12..r15,ret
            let f = 0x720usize; // TEXT_OFF(0x600) + FORK_RESTORE_OFF(0x120)
            page[f]     = 0x5B; // pop rbx
            page[f+1]   = 0x5D; // pop rbp
            page[f+2]   = 0x41; page[f+3] = 0x5C; // pop r12
            page[f+4]   = 0x41; page[f+5] = 0x5D; // pop r13
            page[f+6]   = 0x41; page[f+7] = 0x5E; // pop r14
            page[f+8]   = 0x41; page[f+9] = 0x5F; // pop r15
            page[f+10]  = 0xC3; // ret
            // Write exit stub: mov eax,231; syscall; hlt
            let e = 0x730usize; // TEXT_OFF(0x600) + EXIT_STUB_OFF(0x130)
            page[e]     = 0xB8; page[e+1] = 0xE7; page[e+2] = 0; page[e+3] = 0; page[e+4] = 0;
            page[e+5]   = 0x0F; page[e+6] = 0x05; // syscall
            page[e+7]   = 0xF4; // hlt
            // Leave page writable so LUCAS can overwrite with full vDSO later
        }
    }

    while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    // argv = ["sh", "-c", "echo posix-ok && pwd && ls /"] — test shell + getcwd + ls
    let mut argv = [[0u8; MAX_EXEC_ARG_LEN]; 3];
    argv[0][..2].copy_from_slice(b"sh");
    argv[1][..2].copy_from_slice(b"-c");
    let cmd = b"echo posix-ok && ls / && echo done";
    argv[2][..cmd.len()].copy_from_slice(cmd);
    print(b"BUSYBOX-TEST: argv built, calling exec_from_initrd_argv\n");

    let empty_envp: [[u8; MAX_EXEC_ARG_LEN]; 0] = [];
    let ep_cap = match exec_from_initrd_argv(b"busybox", &argv, &empty_envp) {
        Ok((ep, _tc)) => {
            EXEC_LOCK.store(0, Ordering::Release);
            ep
        }
        Err(e) => {
            EXEC_LOCK.store(0, Ordering::Release);
            print(b"BUSYBOX-TEST: failed to load (errno=");
            print_u64((-e) as u64);
            print(b")\n");
            return;
        }
    };

    print(b"BUSYBOX-TEST: running...\n");

    let mut current_brk: u64 = BRK_BASE;
    let mut mmap_next: u64 = MMAP_BASE;
    // FD tracking: kind 0=free, 1=TCP, 2=UDP, 3=resolv.conf, 4=VFS file,
    //              5=VFS dir, 6=pipe_read, 7=pipe_write, 10=stdio
    let mut bb_fd_kind = [0u8; 32];
    let mut bb_fd_conn = [0u64; 32]; // net conn_id or VFS oid
    let mut bb_fd_pos = [0usize; 32]; // file/dir cursor
    let mut bb_fd_port = [0u16; 32]; // bound port for UDP sockets
    let mut bb_fd_size = [0usize; 32]; // VFS file size
    bb_fd_kind[0] = 10; bb_fd_kind[1] = 10; bb_fd_kind[2] = 10;
    // Pipe buffer (shared between pipe read/write ends)
    let mut pipe_buf = [[0u8; 4096]; 4];
    let mut pipe_len = [0usize; 4]; // bytes in each pipe buffer
    let mut pipe_wr_fd = [0usize; 4]; // which pipe buffer a write-fd uses
    let mut pipe_next = 0usize; // next free pipe slot
    // VFS directory listing buffer
    let mut dir_buf = [0u8; 2048];
    let mut dir_len = 0usize;
    let mut dir_pos = 0usize;
    let mut _cwd_oid: u64 = 0; // 0 = root

    // vfork simulation state
    let mut fork_child_phase = false;
    let mut fork_saved_rip: u64 = 0;
    let mut fork_saved_rsp: u64 = 0;
    let mut fork_saved_rbx: u64 = 0;
    let mut fork_saved_rbp: u64 = 0;
    let mut fork_saved_r12: u64 = 0;
    let mut fork_saved_r13: u64 = 0;
    let mut fork_saved_r14: u64 = 0;
    let mut fork_saved_r15: u64 = 0;
    let mut _fork_saved_fsbase: u64 = 0;
    let mut fork_saved_stack: [u8; 512] = [0; 512]; // save stack around fork point
    let mut fork_ret_addr: u64 = 0; // return address at [fork_rsp]
    let mut next_child_pid: u64 = 100;
    // child exit tracking: up to 8 children
    let mut child_pids: [u64; 8] = [0; 8];
    let mut child_statuses: [i32; 8] = [-1; 8];
    let mut child_count: usize = 0;

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let nr = msg.tag;
        match nr {
            20 => {
                // writev
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let mut total = 0usize;
                let is_tcp = fd < 32 && bb_fd_kind[fd] == 1;
                for i in 0..iovcnt.min(16) {
                    let iov = unsafe { &*((iov_ptr + i as u64 * 16) as *const [u64; 2]) };
                    let base = iov[0];
                    let len = (iov[1] as usize).min(4096);
                    if base != 0 && len > 0 {
                        if is_tcp {
                            // Send via TCP
                            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                            if net_cap != 0 {
                                let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                                let mut sent = 0;
                                while sent < len {
                                    let chunk = (len - sent).min(40);
                                    let mut dregs = [0u64; 5];
                                    for k in 0..chunk { dregs[k / 8] |= (data[sent + k] as u64) << ((k % 8) * 8); }
                                    let send_msg = sotos_common::IpcMsg {
                                        tag: NET_CMD_TCP_SEND,
                                        regs: [bb_fd_conn[fd], 0, chunk as u64, dregs[0], dregs[1], dregs[2], dregs[3], dregs[4]],
                                    };
                                    let _ = sys::call(net_cap, &send_msg);
                                    sent += chunk;
                                }
                            }
                        } else if fd == 1 || fd == 2 {
                            let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                            for &b in data { sys::debug_print(b); }
                        }
                        total += len;
                    }
                }
                reply_val(ep_cap, total as i64);
            }
            // arch_prctl
            158 => reply_val(ep_cap, 0),
            // set_tid_address
            218 => reply_val(ep_cap, 999),
            // brk
            12 => {
                let addr = msg.regs[0];
                if addr == 0 || addr <= current_brk {
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    let new_brk = (addr + 0xFFF) & !0xFFF;
                    let mut pg = (current_brk + 0xFFF) & !0xFFF;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            let _ = sys::map(pg, f, MAP_WRITABLE);
                        }
                        pg += 0x1000;
                    }
                    current_brk = new_brk;
                    reply_val(ep_cap, current_brk as i64);
                }
            }
            // mmap
            9 => {
                let len = msg.regs[1];
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                let base = mmap_next;
                for p in 0..pages {
                    if let Ok(f) = sys::frame_alloc() {
                        let _ = sys::map(base + p * 0x1000, f, MAP_WRITABLE);
                    }
                }
                mmap_next += pages * 0x1000;
                reply_val(ep_cap, base as i64);
            }
            // munmap / mprotect / madvise
            11 | 10 | 28 => reply_val(ep_cap, 0),
            // getpid / gettid / getuid / getgid / geteuid / getegid / setuid / setgid / setgroups
            39 | 186 | 102 | 104 | 107 | 108 | 105 | 106 | 116 => reply_val(ep_cap, 0),
            // rt_sigaction / rt_sigprocmask / sigaltstack
            13 | 14 | 131 => reply_val(ep_cap, 0),
            // ioctl
            16 => reply_val(ep_cap, -ENOTTY), // -ENOTTY
            // fcntl
            72 => reply_val(ep_cap, 0),
            // dup2
            33 => {
                let oldfd = msg.regs[0] as usize;
                let newfd = msg.regs[1] as usize;
                if newfd < 32 {
                    bb_fd_kind[newfd] = bb_fd_kind.get(oldfd).copied().unwrap_or(0);
                    bb_fd_conn[newfd] = bb_fd_conn.get(oldfd).copied().unwrap_or(0);
                    bb_fd_pos[newfd] = bb_fd_pos.get(oldfd).copied().unwrap_or(0);
                    bb_fd_size[newfd] = bb_fd_size.get(oldfd).copied().unwrap_or(0);
                    // For pipes, copy the pipe slot reference
                    if bb_fd_kind[newfd] == 7 {
                        pipe_wr_fd[bb_fd_conn[newfd] as usize] = newfd;
                    }
                }
                reply_val(ep_cap, newfd as i64);
            }
            // close
            3 => {
                let fd = msg.regs[0] as usize;
                if fd < 32 {
                    if bb_fd_kind[fd] == 1 {
                        // TCP close
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap != 0 {
                            let close_msg = sotos_common::IpcMsg { tag: NET_CMD_TCP_CLOSE, regs: [bb_fd_conn[fd], 0, 0, 0, 0, 0, 0, 0] };
                            let _ = sys::call(net_cap, &close_msg);
                        }
                    }
                    bb_fd_kind[fd] = 0;
                    bb_fd_conn[fd] = 0;
                }
                reply_val(ep_cap, 0);
            }
            // socket(domain, type, protocol)
            41 => {
                let sock_type = msg.regs[1];
                let mut slot = 0;
                for i in 3..32 { if bb_fd_kind[i] == 0 { slot = i; break; } }
                if slot > 0 {
                    bb_fd_kind[slot] = if sock_type & 0xFF == 1 { 1 } else { 2 }; // 1=TCP, 2=UDP
                    reply_val(ep_cap, slot as i64);
                } else {
                    reply_val(ep_cap, -EMFILE);
                }
            }
            // connect(fd, addr, addrlen)
            42 => {
                let fd = msg.regs[0] as usize;
                let addr_ptr = msg.regs[1];
                // Parse sockaddr_in: family(2), port(2), ip(4)
                let (port, ip) = unsafe {
                    let sa = addr_ptr as *const u8;
                    let port = (*sa.add(2) as u16) << 8 | *sa.add(3) as u16;
                    let ip = (*sa.add(4) as u32) << 24 | (*sa.add(5) as u32) << 16
                           | (*sa.add(6) as u32) << 8 | *sa.add(7) as u32;
                    (port, ip)
                };
                if fd < 32 && bb_fd_kind[fd] == 1 {
                    // TCP connect
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -ECONNREFUSED); continue; }
                    let conn_msg = sotos_common::IpcMsg { tag: NET_CMD_TCP_CONNECT, regs: [ip as u64, port as u64, 0, 0, 0, 0, 0, 0] };
                    if let Ok(resp) = sys::call(net_cap, &conn_msg) {
                        let conn_id = resp.regs[0];
                        if conn_id != 0 && conn_id != u64::MAX {
                            bb_fd_conn[fd] = conn_id;
                            reply_val(ep_cap, 0);
                        } else {
                            reply_val(ep_cap, -ECONNREFUSED); // -ECONNREFUSED
                        }
                    } else {
                        reply_val(ep_cap, -ECONNREFUSED);
                    }
                } else if fd < 32 && bb_fd_kind[fd] == 2 {
                    // UDP "connect" — store remote addr
                    bb_fd_conn[fd] = ((ip as u64) << 16) | port as u64;
                    reply_val(ep_cap, 0);
                } else {
                    reply_val(ep_cap, -EBADF);
                }
            }
            // sendto(fd, buf, len, flags, dest_addr, addrlen)
            44 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let dest_ptr = msg.regs[4];
                if fd < 32 && bb_fd_kind[fd] == 2 {
                    let (dst_port, dst_ip) = if dest_ptr != 0 {
                        unsafe {
                            let sa = dest_ptr as *const u8;
                            let port = (*sa.add(2) as u16) << 8 | *sa.add(3) as u16;
                            let ip = (*sa.add(4) as u32) << 24 | (*sa.add(5) as u32) << 16
                                   | (*sa.add(6) as u32) << 8 | *sa.add(7) as u32;
                            (port, ip)
                        }
                    } else {
                        let stored = bb_fd_conn[fd];
                        ((stored & 0xFFFF) as u16, (stored >> 16) as u32)
                    };
                    let src_port = bb_fd_port[fd];
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -ECONNREFUSED); continue; }
                    // Net service CMD_UDP_SENDTO layout:
                    // Packed: tag = CMD | (len<<16) | (src_port<<32) | (dst_port<<48)
                    // regs[0] = dst_ip, regs[1..7] = data (56 bytes max)
                    let copy_len = len.min(56);
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, copy_len) };
                    let packed_tag = NET_CMD_UDP_SENDTO | ((copy_len as u64) << 16);
                    let packed_r0 = (dst_ip as u64)
                        | ((dst_port as u64) << 32)
                        | ((src_port as u64) << 48);
                    let mut send_msg = sotos_common::IpcMsg {
                        tag: packed_tag,
                        regs: [packed_r0, 0, 0, 0, 0, 0, 0, 0],
                    };
                    unsafe {
                        let dst = &mut send_msg.regs[1] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, copy_len);
                    }
                    let _ = sys::call(net_cap, &send_msg);
                    reply_val(ep_cap, len as i64);
                } else {
                    reply_val(ep_cap, -EBADF);
                }
            }
            // recvfrom(fd, buf, len, flags, src_addr, addrlen)
            45 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd < 32 && bb_fd_kind[fd] == 2 {
                    let port = bb_fd_port[fd];
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EAGAIN); continue; }
                    let max_recv = len.min(512);
                    let src_addr_ptr = msg.regs[4];
                    let addrlen_ptr = msg.regs[5];
                    let mut got = 0i64;
                    for _retry in 0..500 {
                        let recv_msg = sotos_common::IpcMsg { tag: NET_CMD_UDP_RECV, regs: [port as u64, max_recv as u64, 0, 0, 0, 0, 0, 0] };
                        if let Ok(resp) = sys::call(net_cap, &recv_msg) {
                            let rlen = resp.tag as i64; // byte count in tag, data in regs[0..7]
                            if rlen > 0 {
                                let copy_len = (rlen as usize).min(len).min(64); // 8 regs * 8 = 64
                                unsafe {
                                    let dst = buf_ptr as *mut u8;
                                    for k in 0..copy_len { *dst.add(k) = resp.regs[k / 8].to_le_bytes()[k % 8]; }
                                }
                                // Fill in src_addr (sockaddr_in for DNS server 10.0.2.3:53)
                                if src_addr_ptr != 0 {
                                    unsafe {
                                        let sa = src_addr_ptr as *mut u8;
                                        core::ptr::write_bytes(sa, 0, 16);
                                        *sa.add(0) = 2; // AF_INET (little-endian u16)
                                        *sa.add(1) = 0;
                                        *sa.add(2) = 0; // port 53 big-endian
                                        *sa.add(3) = 53;
                                        *sa.add(4) = 10; // 10.0.2.3
                                        *sa.add(5) = 0;
                                        *sa.add(6) = 2;
                                        *sa.add(7) = 3;
                                    }
                                }
                                if addrlen_ptr != 0 {
                                    unsafe { *(addrlen_ptr as *mut u32) = 16; }
                                }
                                got = copy_len as i64;
                                break;
                            }
                        }
                        sys::yield_now();
                    }
                    reply_val(ep_cap, got);
                } else {
                    reply_val(ep_cap, 0);
                }
            }
            // bind(fd, addr, addrlen)
            49 => {
                let fd = msg.regs[0] as usize;
                let addr_ptr = msg.regs[1];
                if fd < 32 && bb_fd_kind[fd] == 2 {
                    // UDP bind — parse port from sockaddr_in
                    let port = unsafe {
                        let sa = addr_ptr as *const u8;
                        (*sa.add(2) as u16) << 8 | *sa.add(3) as u16
                    };
                    // If port=0, assign an ephemeral port
                    let actual_port = if port == 0 { 32768 + (rdtsc() % 10000) as u16 } else { port };
                    bb_fd_port[fd] = actual_port;
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap != 0 {
                        let bind_msg = sotos_common::IpcMsg { tag: NET_CMD_UDP_BIND, regs: [actual_port as u64, 0, 0, 0, 0, 0, 0, 0] };
                        let _ = sys::call(net_cap, &bind_msg);
                    }
                    reply_val(ep_cap, 0);
                } else {
                    reply_val(ep_cap, 0);
                }
            }
            // listen / getsockname / getpeername / shutdown / rename
            50 | 51 | 52 | 48 | 38 => reply_val(ep_cap, 0),
            // poll(fds, nfds, timeout) / ppoll
            7 | 271 => {
                let fds_ptr = msg.regs[0];
                let nfds = msg.regs[1] as usize;
                // Yield several times to let network process DNS replies
                for _ in 0..100 { sys::yield_now(); }
                let mut ready = 0i64;
                for i in 0..nfds.min(32) {
                    let pfd = (fds_ptr + i as u64 * 8) as *mut u8;
                    let fd = unsafe { *(pfd as *const i32) } as usize;
                    let events = unsafe { *((pfd as *const u8).add(4) as *const i16) };
                    if fd < 32 && (events & 1) != 0 {
                        let k = bb_fd_kind[fd];
                        if k == 1 || k == 2 || (k == 6 && pipe_len[bb_fd_conn[fd] as usize] > 0) {
                            unsafe { *((pfd).add(6) as *mut i16) = 1; } // POLLIN
                            ready += 1;
                        }
                    }
                }
                if ready == 0 { ready = 1; } // Always unblock (timeout)
                reply_val(ep_cap, ready);
            }
            // getsockopt / setsockopt
            54 | 55 => reply_val(ep_cap, 0),
            // clock_gettime
            228 => reply_val(ep_cap, 0),
            // getrandom
            318 => {
                let buf = msg.regs[0];
                let len = msg.regs[1] as usize;
                unsafe {
                    let dst = buf as *mut u8;
                    let mut seed = rdtsc();
                    for i in 0..len {
                        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                        *dst.add(i) = seed as u8;
                    }
                }
                reply_val(ep_cap, len as i64);
            }
            // uname
            63 => {
                let buf = msg.regs[0] as *mut u8;
                unsafe {
                    core::ptr::write_bytes(buf, 0, 390);
                    core::ptr::copy_nonoverlapping(b"sotOS".as_ptr(), buf, 5);
                    core::ptr::copy_nonoverlapping(b"lucas".as_ptr(), buf.add(65), 5);
                    core::ptr::copy_nonoverlapping(b"0.1.0".as_ptr(), buf.add(130), 5);
                    core::ptr::copy_nonoverlapping(b"x86_64".as_ptr(), buf.add(260), 6);
                }
                reply_val(ep_cap, 0);
            }
            // getppid
            110 => reply_val(ep_cap, 1),
            // getcwd(buf, size)
            79 => {
                let buf = msg.regs[0] as *mut u8;
                let size = msg.regs[1] as usize;
                if size >= 2 {
                    unsafe { *buf = b'/'; *buf.add(1) = 0; }
                    reply_val(ep_cap, buf as i64);
                } else {
                    reply_val(ep_cap, -ERANGE); // -ERANGE
                }
            }
            // nanosleep / sched_yield
            35 | 24 => reply_val(ep_cap, 0),
            // lseek(fd, offset, whence)
            8 => {
                let fd = msg.regs[0] as usize;
                let offset = msg.regs[1] as i64;
                let whence = msg.regs[2] as u32;
                if fd < 32 && bb_fd_kind[fd] == 4 {
                    let new_pos = match whence {
                        0 => offset as usize,                           // SEEK_SET
                        1 => (bb_fd_pos[fd] as i64 + offset) as usize,  // SEEK_CUR
                        2 => (bb_fd_size[fd] as i64 + offset) as usize, // SEEK_END
                        _ => { reply_val(ep_cap, -EINVAL); continue; }
                    };
                    bb_fd_pos[fd] = new_pos;
                    reply_val(ep_cap, new_pos as i64);
                } else {
                    reply_val(ep_cap, 0);
                }
            }
            // pipe(pipefd[2])
            22 => {
                let pipefd = msg.regs[0] as *mut i32;
                if pipe_next >= 4 {
                    reply_val(ep_cap, -EMFILE); // -EMFILE
                } else {
                    let slot = pipe_next;
                    pipe_next += 1;
                    pipe_len[slot] = 0;
                    // Allocate read and write FDs
                    let mut rfd = 0usize;
                    let mut wfd = 0usize;
                    for i in 3..32 {
                        if bb_fd_kind[i] == 0 {
                            if rfd == 0 { rfd = i; }
                            else { wfd = i; break; }
                        }
                    }
                    if rfd > 0 && wfd > 0 {
                        bb_fd_kind[rfd] = 6; // pipe read
                        bb_fd_kind[wfd] = 7; // pipe write
                        bb_fd_conn[rfd] = slot as u64;
                        bb_fd_conn[wfd] = slot as u64;
                        pipe_wr_fd[slot] = wfd;
                        unsafe { *pipefd = rfd as i32; *pipefd.add(1) = wfd as i32; }
                        reply_val(ep_cap, 0);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                }
            }
            // open(path, flags) / openat(dirfd, path, flags, mode) — enhanced with VFS
            2 | 257 => {
                let path_ptr = if nr == 257 { msg.regs[1] } else { msg.regs[0] };
                let flags = if nr == 257 { msg.regs[2] as u32 } else { msg.regs[1] as u32 };
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                if name == b"/etc/resolv.conf" {
                    let mut slot = 0;
                    for i in 3..32 { if bb_fd_kind[i] == 0 { slot = i; break; } }
                    if slot > 0 {
                        bb_fd_kind[slot] = 3;
                        bb_fd_pos[slot] = 0;
                        reply_val(ep_cap, slot as i64);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                } else if name.starts_with(b"/proc/") || name.starts_with(b"/sys/") || name.starts_with(b"/dev/") || name == b"/etc/passwd" || name == b"/etc/group" || name == b"/etc/shells" {
                    reply_val(ep_cap, -ENOENT); // -ENOENT
                } else {
                    // Try VFS
                    let fname = if name.starts_with(b"/") { &name[1..] } else { name };
                    let oflags = OFlags::from_bits_truncate(flags as u32);
                    let is_dir = oflags.contains(OFlags::DIRECTORY);
                    let o_creat = oflags.contains(OFlags::CREAT);
                    // Opening root "/" (fname is empty) — always works, even without VFS
                    if fname.is_empty() || (is_dir && name == b"/") {
                        let mut slot = 0;
                        for i in 3..32 { if bb_fd_kind[i] == 0 { slot = i; break; } }
                        if slot > 0 {
                            bb_fd_kind[slot] = 5; // dir
                            bb_fd_conn[slot] = 0; // root oid
                            bb_fd_pos[slot] = 0;
                            dir_len = 0; dir_pos = 0;
                            reply_val(ep_cap, slot as i64);
                        } else {
                            reply_val(ep_cap, -EMFILE);
                        }
                    } else {
                        vfs_lock();
                        let result = unsafe {
                            if let Some(store) = shared_store() {
                                if is_dir {
                                    match store.find(fname) {
                                        Some(oid) => {
                                            let mut slot = 0;
                                            for i in 3..32 { if bb_fd_kind[i] == 0 { slot = i; break; } }
                                            if slot > 0 {
                                                bb_fd_kind[slot] = 5;
                                                bb_fd_conn[slot] = oid;
                                                bb_fd_pos[slot] = 0;
                                                dir_len = 0; dir_pos = 0;
                                                Some(slot as i64)
                                            } else { Some(-24) }
                                        }
                                        None => Some(-2i64)
                                    }
                                } else if let Some(oid) = store.find(fname) {
                                    let mut slot = 0;
                                    for i in 3..32 { if bb_fd_kind[i] == 0 { slot = i; break; } }
                                    if slot > 0 {
                                        let size = store.stat(oid).map(|e| e.size as usize).unwrap_or(0);
                                        bb_fd_kind[slot] = 4;
                                        bb_fd_conn[slot] = oid;
                                        bb_fd_pos[slot] = 0;
                                        bb_fd_size[slot] = size;
                                        if oflags.contains(OFlags::TRUNC) {
                                            let _ = store.write_obj(oid, &[]);
                                            bb_fd_size[slot] = 0;
                                        }
                                        Some(slot as i64)
                                    } else { Some(-24) }
                                } else if o_creat {
                                    match store.create(fname, &[]) {
                                        Ok(oid) => {
                                            let mut slot = 0;
                                            for i in 3..32 { if bb_fd_kind[i] == 0 { slot = i; break; } }
                                            if slot > 0 {
                                                bb_fd_kind[slot] = 4;
                                                bb_fd_conn[slot] = oid;
                                                bb_fd_pos[slot] = 0;
                                                bb_fd_size[slot] = 0;
                                                Some(slot as i64)
                                            } else { Some(-24) }
                                        }
                                        Err(_) => Some(-28)
                                    }
                                } else {
                                    Some(-2i64)
                                }
                            } else {
                                Some(-2i64)
                            }
                        };
                        vfs_unlock();
                        if let Some(v) = result { reply_val(ep_cap, v); }
                    }
                }
            }
            // read — enhanced with VFS file + pipe
            0 => {
                let fd = msg.regs[0] as usize;
                let buf = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd < 32 && bb_fd_kind[fd] == 1 {
                    // TCP socket read — assemble multiple 64-byte IPC chunks
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EAGAIN); continue; }
                    let mut total_got = 0usize;
                    let mut empty_retries = 0usize;
                    while total_got < len && empty_retries < 500 {
                        let want = (len - total_got).min(64);
                        let recv_msg = sotos_common::IpcMsg { tag: NET_CMD_TCP_RECV, regs: [bb_fd_conn[fd], want as u64, 0, 0, 0, 0, 0, 0] };
                        if let Ok(resp) = sys::call(net_cap, &recv_msg) {
                            let rlen = resp.tag as usize;
                            if rlen > 0 {
                                let copy_len = rlen.min(want);
                                unsafe {
                                    let dst = (buf + total_got as u64) as *mut u8;
                                    for k in 0..copy_len { *dst.add(k) = resp.regs[k / 8].to_le_bytes()[k % 8]; }
                                }
                                total_got += copy_len;
                                empty_retries = 0;
                                if copy_len < want { break; }
                            } else {
                                if total_got > 0 { break; }
                                empty_retries += 1;
                                sys::yield_now();
                            }
                        } else {
                            break;
                        }
                    }
                    reply_val(ep_cap, total_got as i64);
                } else if fd < 32 && bb_fd_kind[fd] == 3 {
                    // resolv.conf virtual file
                    let content = b"nameserver 10.0.2.3\n";
                    let pos = bb_fd_pos[fd];
                    if pos >= content.len() {
                        reply_val(ep_cap, 0);
                    } else {
                        let avail = content.len() - pos;
                        let copy_len = avail.min(len);
                        unsafe { core::ptr::copy_nonoverlapping(content.as_ptr().add(pos), buf as *mut u8, copy_len); }
                        bb_fd_pos[fd] += copy_len;
                        reply_val(ep_cap, copy_len as i64);
                    }
                } else if fd < 32 && bb_fd_kind[fd] == 4 {
                    // VFS file read
                    let oid = bb_fd_conn[fd];
                    let pos = bb_fd_pos[fd];
                    let fsize = bb_fd_size[fd];
                    if pos >= fsize {
                        reply_val(ep_cap, 0); // EOF
                    } else {
                        let avail = fsize - pos;
                        let want = avail.min(len);
                        vfs_lock();
                        let got = unsafe {
                            if let Some(store) = shared_store() {
                                let dst = core::slice::from_raw_parts_mut(buf as *mut u8, want);
                                store.read_obj_range(oid, pos, dst).unwrap_or(0)
                            } else { 0 }
                        };
                        vfs_unlock();
                        bb_fd_pos[fd] += got;
                        reply_val(ep_cap, got as i64);
                    }
                } else if fd < 32 && bb_fd_kind[fd] == 6 {
                    // Pipe read
                    let slot = bb_fd_conn[fd] as usize;
                    if pipe_len[slot] > 0 {
                        let copy_len = pipe_len[slot].min(len);
                        unsafe { core::ptr::copy_nonoverlapping(pipe_buf[slot].as_ptr(), buf as *mut u8, copy_len); }
                        // Shift remaining data
                        if copy_len < pipe_len[slot] {
                            pipe_buf[slot].copy_within(copy_len..pipe_len[slot], 0);
                        }
                        pipe_len[slot] -= copy_len;
                        reply_val(ep_cap, copy_len as i64);
                    } else {
                        reply_val(ep_cap, 0); // EOF (write end may be closed)
                    }
                } else if fd == 0 {
                    reply_val(ep_cap, 0); // stdin EOF
                } else {
                    reply_val(ep_cap, 0);
                }
            }
            // write — enhanced with VFS file + pipe
            1 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd < 32 && bb_fd_kind[fd] == 1 {
                    // TCP socket write
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -ECONNREFUSED); continue; }
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    let mut sent = 0;
                    while sent < len {
                        let chunk = (len - sent).min(40);
                        let mut dregs = [0u64; 5];
                        for k in 0..chunk { dregs[k / 8] |= (data[sent + k] as u64) << ((k % 8) * 8); }
                        let send_msg = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_SEND,
                            regs: [bb_fd_conn[fd], 0, chunk as u64, dregs[0], dregs[1], dregs[2], dregs[3], dregs[4]],
                        };
                        let _ = sys::call(net_cap, &send_msg);
                        sent += chunk;
                    }
                    reply_val(ep_cap, len as i64);
                } else if fd < 32 && bb_fd_kind[fd] == 4 {
                    // VFS file write
                    let oid = bb_fd_conn[fd];
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    vfs_lock();
                    let wrote = unsafe {
                        if let Some(store) = shared_store() {
                            if store.write_obj_range(oid, bb_fd_pos[fd], data).is_ok() { data.len() } else { 0 }
                        } else { 0 }
                    };
                    vfs_unlock();
                    bb_fd_pos[fd] += wrote;
                    if bb_fd_pos[fd] > bb_fd_size[fd] { bb_fd_size[fd] = bb_fd_pos[fd]; }
                    reply_val(ep_cap, wrote as i64);
                } else if fd < 32 && bb_fd_kind[fd] == 7 {
                    // Pipe write
                    let slot = bb_fd_conn[fd] as usize;
                    let avail = 4096 - pipe_len[slot];
                    let copy_len = len.min(avail);
                    if copy_len > 0 {
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, copy_len) };
                        pipe_buf[slot][pipe_len[slot]..pipe_len[slot] + copy_len].copy_from_slice(data);
                        pipe_len[slot] += copy_len;
                    }
                    reply_val(ep_cap, copy_len as i64);
                } else {
                    // stdout/stderr — print to serial
                    if len > 0 {
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                        for &b in data { sys::debug_print(b); }
                    }
                    reply_val(ep_cap, len as i64);
                }
            }
            // fstat(fd, buf) — enhanced
            5 => {
                let fd = msg.regs[0] as usize;
                let stat_ptr = msg.regs[1];
                unsafe { core::ptr::write_bytes(stat_ptr as *mut u8, 0, 144); }
                if fd < 32 && bb_fd_kind[fd] == 4 {
                    // VFS file: fill in size + mode (regular file)
                    let sp = stat_ptr as *mut u8;
                    unsafe {
                        let size = bb_fd_size[fd] as u64;
                        core::ptr::copy_nonoverlapping(&size.to_le_bytes()[0], sp.add(48), 8); // st_size at offset 48
                        let mode: u32 = 0o100644; // S_IFREG | rw-r--r--
                        core::ptr::copy_nonoverlapping(&mode.to_le_bytes()[0], sp.add(24), 4); // st_mode at offset 24
                    }
                } else if fd < 32 && bb_fd_kind[fd] == 5 {
                    let sp = stat_ptr as *mut u8;
                    unsafe {
                        let mode: u32 = 0o40755; // S_IFDIR | rwxr-xr-x
                        core::ptr::copy_nonoverlapping(&mode.to_le_bytes()[0], sp.add(24), 4);
                    }
                } else if fd < 32 && bb_fd_kind[fd] == 6 {
                    let sp = stat_ptr as *mut u8;
                    unsafe {
                        let mode: u32 = 0o10600; // S_IFIFO | rw-------
                        core::ptr::copy_nonoverlapping(&mode.to_le_bytes()[0], sp.add(24), 4);
                    }
                }
                reply_val(ep_cap, 0);
            }
            // access / faccessat — check file accessibility
            21 | 269 => {
                let path_ptr = if nr == 269 { msg.regs[1] } else { msg.regs[0] };
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                // Recognize /bin/* and /usr/bin/* as valid busybox applets
                let is_applet = if name.starts_with(b"/bin/") || name.starts_with(b"/usr/bin/") {
                    let base = if name.starts_with(b"/usr/bin/") { &name[9..] } else { &name[5..] };
                    base == b"ls" || base == b"cat" || base == b"mkdir" || base == b"rm" || base == b"grep" || base == b"wc" || base == b"echo" || base == b"true" || base == b"false" || base == b"pwd" || base == b"busybox" || base == b"syslog" || base == b"netmirror" || base == b"snapshot"
                } else { false };
                if name == b"/" || name == b"." || is_applet {
                    reply_val(ep_cap, 0);
                } else {
                    let fname = if name.starts_with(b"/") { &name[1..] } else { name };
                    vfs_lock();
                    let found = unsafe { shared_store().and_then(|s| s.find(fname)).is_some() };
                    vfs_unlock();
                    if found || fname.is_empty() { reply_val(ep_cap, 0); } else { reply_val(ep_cap, -ENOENT); }
                }
            }
            // stat(path, buf) / lstat / newfstatat / fstatat
            4 | 6 | 262 => {
                let path_ptr = if nr == 262 { msg.regs[1] } else { msg.regs[0] };
                let stat_ptr = if nr == 262 { msg.regs[2] } else { msg.regs[1] };
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                let fname = if name.starts_with(b"/") { &name[1..] } else { name };
                unsafe { core::ptr::write_bytes(stat_ptr as *mut u8, 0, 144); }
                // Recognize /bin/* and /usr/bin/* as valid busybox applets
                let is_applet = if name.starts_with(b"/bin/") || name.starts_with(b"/usr/bin/") {
                    let base = if name.starts_with(b"/usr/bin/") { &name[9..] } else { &name[5..] };
                    base == b"ls" || base == b"cat" || base == b"mkdir" || base == b"rm" || base == b"grep" || base == b"wc" || base == b"echo" || base == b"true" || base == b"false" || base == b"pwd" || base == b"busybox" || base == b"syslog" || base == b"netmirror" || base == b"snapshot"
                } else { false };
                if name == b"/" || name == b"." || fname.is_empty() || is_applet {
                    let sp = stat_ptr as *mut u8;
                    unsafe {
                        let mode: u32 = if is_applet { 0o100755 } else { 0o40755 };
                        core::ptr::copy_nonoverlapping(&mode.to_le_bytes()[0], sp.add(24), 4);
                        if is_applet {
                            // Set a non-zero size so it looks like a real file
                            let size: u64 = 1024;
                            core::ptr::copy_nonoverlapping(&size.to_le_bytes()[0], sp.add(48), 8);
                        }
                    }
                    reply_val(ep_cap, 0);
                } else {
                    vfs_lock();
                    let found = unsafe {
                        if let Some(store) = shared_store() {
                            if let Some(oid) = store.find(fname) {
                                let sp = stat_ptr as *mut u8;
                                let entry = store.stat(oid);
                                if let Some(e) = entry {
                                    let (mode, size) = if e.is_dir() {
                                        (0o40755u32, 0u64)
                                    } else {
                                        (0o100644u32, e.size as u64)
                                    };
                                    core::ptr::copy_nonoverlapping(&mode.to_le_bytes()[0], sp.add(24), 4);
                                    core::ptr::copy_nonoverlapping(&size.to_le_bytes()[0], sp.add(48), 8);
                                }
                                true
                            } else { false }
                        } else { false }
                    };
                    vfs_unlock();
                    if found { reply_val(ep_cap, 0); } else { reply_val(ep_cap, -ENOENT); }
                }
            }
            // getdents64(fd, dirp, count)
            217 => {
                use sotos_common::linux_abi::{DT_REG, DT_DIR};
                let fd = msg.regs[0] as usize;
                let dirp = msg.regs[1];
                let count = msg.regs[2] as usize;
                if fd >= 32 || bb_fd_kind[fd] != 5 {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else {
                    if dir_pos >= dir_len {
                        dir_len = 0;
                        dir_pos = 0;
                        let dir_oid = bb_fd_conn[fd];
                        vfs_lock();
                        unsafe {
                            if let Some(store) = shared_store() {
                                let mut entries = [sotos_objstore::DirEntry::zeroed(); 32];
                                let n = store.list_dir(dir_oid, &mut entries);
                                for i in 0..n {
                                    let entry = &entries[i];
                                    let ename = entry.name_as_str();
                                    let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8;
                                    if dir_len + reclen > dir_buf.len() { break; }
                                    let d = &mut dir_buf[dir_len..dir_len + reclen];
                                    for b in d.iter_mut() { *b = 0; }
                                    d[0..8].copy_from_slice(&entry.oid.to_le_bytes());
                                    d[8..16].copy_from_slice(&((dir_len + reclen) as u64).to_le_bytes());
                                    d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                                    d[18] = if entry.is_dir() { DT_DIR } else { DT_REG };
                                    let nlen = ename.len().min(reclen - 19);
                                    d[19..19 + nlen].copy_from_slice(&ename[..nlen]);
                                    dir_len += reclen;
                                }
                            }
                        }
                        vfs_unlock();
                    }
                    let remaining = if dir_pos < dir_len { dir_len - dir_pos } else { 0 };
                    if remaining == 0 {
                        reply_val(ep_cap, 0); // EOF
                    } else {
                        let copy_len = remaining.min(count);
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                dir_buf[dir_pos..].as_ptr(),
                                dirp as *mut u8,
                                copy_len,
                            );
                        }
                        dir_pos += copy_len;
                        reply_val(ep_cap, copy_len as i64);
                    }
                }
            }
            // mkdir(path, mode)
            83 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                let fname = if name.starts_with(b"/") { &name[1..] } else { name };
                vfs_lock();
                let result = unsafe {
                    if let Some(store) = shared_store() {
                        match store.mkdir(fname, 0) {
                            Ok(_) => 0i64,
                            Err(_) => -17, // -EEXIST
                        }
                    } else { -2 }
                };
                vfs_unlock();
                reply_val(ep_cap, result);
            }
            // unlink(path)
            87 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                let fname = if name.starts_with(b"/") { &name[1..] } else { name };
                vfs_lock();
                let result = unsafe {
                    if let Some(store) = shared_store() {
                        if let Some(oid) = store.find(fname) {
                            match store.delete(oid) {
                                Ok(()) => 0i64,
                                Err(_) => -2,
                            }
                        } else { -2 }
                    } else { -2 }
                };
                vfs_unlock();
                reply_val(ep_cap, result);
            }
            // rmdir(path)
            84 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                let fname = if name.starts_with(b"/") { &name[1..] } else { name };
                vfs_lock();
                let result = unsafe {
                    if let Some(store) = shared_store() {
                        if let Some(oid) = store.find(fname) {
                            match store.rmdir(oid) {
                                Ok(()) => 0i64,
                                Err(_) => -2,
                            }
                        } else { -2 }
                    } else { -2 }
                };
                vfs_unlock();
                reply_val(ep_cap, result);
            }
            // dup3(oldfd, newfd, flags) — like dup2 but with flags
            292 => {
                let oldfd = msg.regs[0] as usize;
                let newfd = msg.regs[1] as usize;
                if newfd < 32 && oldfd < 32 {
                    bb_fd_kind[newfd] = bb_fd_kind[oldfd];
                    bb_fd_conn[newfd] = bb_fd_conn[oldfd];
                    bb_fd_pos[newfd] = bb_fd_pos[oldfd];
                    bb_fd_size[newfd] = bb_fd_size[oldfd];
                }
                reply_val(ep_cap, newfd as i64);
            }
            // readv(fd, iov, iovcnt)
            19 => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let mut total = 0usize;
                for i in 0..iovcnt.min(16) {
                    let iov = unsafe { &*((iov_ptr + i as u64 * 16) as *const [u64; 2]) };
                    let base = iov[0];
                    let iov_len = (iov[1] as usize).min(4096);
                    if base != 0 && iov_len > 0 && fd < 32 && bb_fd_kind[fd] == 6 {
                        let slot = bb_fd_conn[fd] as usize;
                        let copy_len = pipe_len[slot].min(iov_len);
                        if copy_len > 0 {
                            unsafe { core::ptr::copy_nonoverlapping(pipe_buf[slot].as_ptr(), base as *mut u8, copy_len); }
                            if copy_len < pipe_len[slot] {
                                pipe_buf[slot].copy_within(copy_len..pipe_len[slot], 0);
                            }
                            pipe_len[slot] -= copy_len;
                            total += copy_len;
                        }
                    }
                }
                reply_val(ep_cap, total as i64);
            }
            // clone/fork/vfork — vfork simulation
            56 | 57 | 58 => {
                // Return child_pid immediately (parent path).
                // Pre-record child as exited with status 0.
                let child_pid = next_child_pid;
                next_child_pid += 1;
                if child_count < 8 {
                    child_pids[child_count] = child_pid;
                    child_statuses[child_count] = 0;
                    child_count += 1;
                }
                fork_child_phase = false;
                // Save fork context for potential future use
                let tid = msg.regs[6];
                let mut saved_regs = [0u64; 20];
                let _ = sys::get_thread_regs(tid, &mut saved_regs);
                fork_saved_rip = saved_regs[2];
                fork_saved_rsp = msg.regs[7];
                fork_saved_rbx = saved_regs[1];
                fork_saved_rbp = saved_regs[6];
                fork_saved_r12 = saved_regs[11];
                fork_saved_r13 = saved_regs[12];
                fork_saved_r14 = saved_regs[13];
                fork_saved_r15 = saved_regs[14];
                _fork_saved_fsbase = saved_regs[16];
                // Save return address at [fork_rsp] before child corrupts it
                fork_ret_addr = unsafe { core::ptr::read_volatile(fork_saved_rsp as *const u64) };
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        fork_saved_rsp as *const u8,
                        fork_saved_stack.as_mut_ptr(),
                        512,
                    );
                }
                reply_val(ep_cap, child_pid as i64); // parent path immediately
            }
            // execve — emulate child command inline
            59 => {
                let exec_in_fork = fork_child_phase;
                if fork_child_phase {
                    fork_child_phase = false;
                }

                // Parse argv from guest memory
                let argv_ptr = msg.regs[1];
                let mut child_argv = [[0u8; 128]; 4];
                let mut _child_argc = 0usize;
                if argv_ptr != 0 {
                    for a in 0..4 {
                        let argp = unsafe { *((argv_ptr + a as u64 * 8) as *const u64) };
                        if argp == 0 { break; }
                        let plen = copy_guest_path(argp, &mut child_argv[a]);
                        let _ = plen;
                        _child_argc += 1;
                    }
                }

                // Determine command from argv[0] (basename)
                let cmd = &child_argv[0];
                let cmd_len = cmd.iter().position(|&b| b == 0).unwrap_or(128);
                let cmd_name = &cmd[..cmd_len];
                // Strip path prefix (e.g. "/proc/self/exe" → use argv[0] as applet name)
                let basename = if let Some(pos) = cmd_name.iter().rposition(|&b| b == b'/') {
                    &cmd_name[pos + 1..]
                } else { cmd_name };

                // Get the directory argument (argv[1]) if any
                let arg1_len = child_argv[1].iter().position(|&b| b == 0).unwrap_or(0);
                let arg1 = &child_argv[1][..arg1_len];

                // Helper: write output to FD 1 (pipe or serial)
                let child_pid = next_child_pid;
                next_child_pid += 1;
                let mut child_exit: i64 = 0;

                // --- Emulate busybox applets ---
                if basename == b"ls" {
                    // ls [path] — list directory contents
                    let dir_path = if arg1.is_empty() || arg1 == b"." { b"/" as &[u8] } else { arg1 };
                    let fname = if dir_path.starts_with(b"/") { &dir_path[1..] } else { dir_path };
                    let dir_oid = if fname.is_empty() { 0u64 } else {
                        vfs_lock();
                        let oid = unsafe { shared_store().and_then(|s| s.find(fname)) };
                        vfs_unlock();
                        oid.unwrap_or(0)
                    };
                    // List entries
                    let mut entries = [sotos_objstore::DirEntry::zeroed(); 32];
                    let mut n = 0;
                    vfs_lock();
                    unsafe {
                        if let Some(store) = shared_store() {
                            n = store.list_dir(dir_oid, &mut entries);
                        }
                    }
                    vfs_unlock();
                    // Write names to stdout (FD 1)
                    for i in 0..n {
                        let ename = entries[i].name_as_str();
                        if bb_fd_kind[1] == 7 {
                            let slot = bb_fd_conn[1] as usize;
                            let avail = 4096 - pipe_len[slot];
                            let cl = ename.len().min(avail);
                            pipe_buf[slot][pipe_len[slot]..pipe_len[slot] + cl].copy_from_slice(&ename[..cl]);
                            pipe_len[slot] += cl;
                            if pipe_len[slot] < 4096 { pipe_buf[slot][pipe_len[slot]] = b'\n'; pipe_len[slot] += 1; }
                        } else {
                            for &b in ename { sys::debug_print(b); }
                            sys::debug_print(b'\n');
                        }
                    }
                } else if basename == b"cat" {
                    // cat [file] — read file and write to stdout
                    if !arg1.is_empty() {
                        let fname = if arg1.starts_with(b"/") { &arg1[1..] } else { arg1 };
                        vfs_lock();
                        let data_opt = unsafe {
                            if let Some(store) = shared_store() {
                                if let Some(oid) = store.find(fname) {
                                    let mut buf = [0u8; 4096];
                                    let n = store.read_obj(oid, &mut buf).unwrap_or(0);
                                    Some((buf, n))
                                } else { None }
                            } else { None }
                        };
                        vfs_unlock();
                        if let Some((buf, n)) = data_opt {
                            if bb_fd_kind[1] == 7 {
                                let slot = bb_fd_conn[1] as usize;
                                let avail = 4096 - pipe_len[slot];
                                let cl = n.min(avail);
                                pipe_buf[slot][pipe_len[slot]..pipe_len[slot] + cl].copy_from_slice(&buf[..cl]);
                                pipe_len[slot] += cl;
                            } else {
                                for i in 0..n { sys::debug_print(buf[i]); }
                            }
                        } else {
                            child_exit = 1; // file not found
                        }
                    } else {
                        // cat with no args reads from stdin (pipe)
                        if bb_fd_kind[0] == 6 {
                            let slot = bb_fd_conn[0] as usize;
                            let n = pipe_len[slot];
                            if n > 0 {
                                if bb_fd_kind[1] == 7 {
                                    let out_slot = bb_fd_conn[1] as usize;
                                    let avail = 4096 - pipe_len[out_slot];
                                    let cl = n.min(avail);
                                    // Copy from input pipe to output pipe
                                    let mut tmp = [0u8; 4096];
                                    tmp[..cl].copy_from_slice(&pipe_buf[slot][..cl]);
                                    pipe_buf[out_slot][pipe_len[out_slot]..pipe_len[out_slot] + cl].copy_from_slice(&tmp[..cl]);
                                    pipe_len[out_slot] += cl;
                                } else {
                                    for i in 0..n { sys::debug_print(pipe_buf[slot][i]); }
                                }
                                pipe_len[slot] = 0;
                            }
                        }
                    }
                } else if basename == b"mkdir" {
                    if !arg1.is_empty() {
                        let fname = if arg1.starts_with(b"/") { &arg1[1..] } else { arg1 };
                        vfs_lock();
                        child_exit = unsafe {
                            if let Some(store) = shared_store() {
                                match store.mkdir(fname, 0) { Ok(_) => 0, Err(_) => 1 }
                            } else { 1 }
                        };
                        vfs_unlock();
                    } else { child_exit = 1; }
                } else if basename == b"rm" {
                    if !arg1.is_empty() {
                        let fname = if arg1.starts_with(b"/") { &arg1[1..] } else { arg1 };
                        vfs_lock();
                        child_exit = unsafe {
                            if let Some(store) = shared_store() {
                                if let Some(oid) = store.find(fname) {
                                    match store.delete(oid) { Ok(()) => 0, Err(_) => 1 }
                                } else { 1 }
                            } else { 1 }
                        };
                        vfs_unlock();
                    } else { child_exit = 1; }
                } else if basename == b"grep" {
                    // grep pattern — filter stdin lines matching pattern
                    if !arg1.is_empty() && bb_fd_kind[0] == 6 {
                        let slot = bb_fd_conn[0] as usize;
                        let n = pipe_len[slot];
                        // Copy input to temp buf to avoid borrow conflict with output pipe
                        let mut tmp = [0u8; 4096];
                        tmp[..n].copy_from_slice(&pipe_buf[slot][..n]);
                        // Process line by line
                        let mut start = 0;
                        while start < n {
                            let mut end = start;
                            while end < n && tmp[end] != b'\n' { end += 1; }
                            let line = &tmp[start..end];
                            // Simple substring match
                            let matches = line.windows(arg1.len()).any(|w| w == arg1);
                            if matches {
                                if bb_fd_kind[1] == 7 {
                                    let out_slot = bb_fd_conn[1] as usize;
                                    let avail = 4096 - pipe_len[out_slot];
                                    let cl = line.len().min(avail);
                                    pipe_buf[out_slot][pipe_len[out_slot]..pipe_len[out_slot] + cl].copy_from_slice(&line[..cl]);
                                    pipe_len[out_slot] += cl;
                                    if pipe_len[out_slot] < 4096 { pipe_buf[out_slot][pipe_len[out_slot]] = b'\n'; pipe_len[out_slot] += 1; }
                                } else {
                                    for &b in line { sys::debug_print(b); }
                                    sys::debug_print(b'\n');
                                }
                            }
                            start = end + 1;
                        }
                        pipe_len[slot] = 0;
                    } else { child_exit = 1; }
                } else if basename == b"wc" {
                    // wc — count lines/words/bytes from stdin
                    if bb_fd_kind[0] == 6 {
                        let slot = bb_fd_conn[0] as usize;
                        let n = pipe_len[slot];
                        let mut lines = 0u64;
                        let mut words = 0u64;
                        let mut in_word = false;
                        for i in 0..n {
                            if pipe_buf[slot][i] == b'\n' { lines += 1; }
                            if pipe_buf[slot][i] == b' ' || pipe_buf[slot][i] == b'\n' || pipe_buf[slot][i] == b'\t' {
                                in_word = false;
                            } else if !in_word { words += 1; in_word = true; }
                        }
                        let mut out = [0u8; 64];
                        let pos = format_wc_output(&mut out, lines, words, n as u64);
                        if bb_fd_kind[1] == 7 {
                            let out_slot = bb_fd_conn[1] as usize;
                            let avail = 4096 - pipe_len[out_slot];
                            let cl = pos.min(avail);
                            pipe_buf[out_slot][pipe_len[out_slot]..pipe_len[out_slot] + cl].copy_from_slice(&out[..cl]);
                            pipe_len[out_slot] += cl;
                        } else {
                            for i in 0..pos { sys::debug_print(out[i]); }
                        }
                        pipe_len[slot] = 0;
                    }
                } else if basename == b"echo" {
                    // echo args — print arguments
                    for a in 1..4 {
                        let al = child_argv[a].iter().position(|&b| b == 0).unwrap_or(0);
                        if al == 0 { break; }
                        if a > 1 { sys::debug_print(b' '); }
                        for i in 0..al { sys::debug_print(child_argv[a][i]); }
                    }
                    sys::debug_print(b'\n');
                } else if basename == b"true" {
                    child_exit = 0;
                } else if basename == b"false" {
                    child_exit = 1;
                } else if basename == b"pwd" {
                    sys::debug_print(b'/');
                    sys::debug_print(b'\n');
                } else if basename == b"syslog" {
                    // Phase 5: Dump last N syscall log entries
                    let n = if arg1.is_empty() { 20 } else {
                        let mut v = 0u64;
                        for &b in arg1 { if b >= b'0' && b <= b'9' { v = v * 10 + (b - b'0') as u64; } }
                        if v == 0 { 20 } else { v as usize }
                    };
                    syscall_log_dump(n);
                } else if basename == b"netmirror" {
                    // Phase 5: Toggle network packet mirroring
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 {
                        print(b"netmirror: no net service\n");
                    } else {
                        let enable: u64 = if arg1 == b"off" { 0 } else { 1 };
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_MIRROR,
                            regs: [enable, 0, 0, 0, 0, 0, 0, 0],
                        };
                        let _ = sys::call_timeout(net_cap, &req, 100);
                        if enable == 1 { print(b"netmirror: ON\n"); }
                        else { print(b"netmirror: OFF\n"); }
                    }
                } else if basename == b"snapshot" {
                    // Phase 5: Snapshot create/list/restore/delete
                    if arg1 == b"list" || arg1.is_empty() {
                        vfs_lock();
                        let result = unsafe { shared_store() }.map(|store| {
                            let mut snaps = [sotos_objstore::SnapMeta::zeroed(); sotos_objstore::MAX_SNAPSHOTS];
                            let count = store.snap_list(&mut snaps);
                            if count == 0 {
                                print(b"no snapshots\n");
                            } else {
                                for i in 0..count {
                                    let sname = snaps[i].name_as_str();
                                    print(sname);
                                    print(b"\n");
                                }
                            }
                        });
                        vfs_unlock();
                        if result.is_none() { print(b"snapshot: no VFS\n"); }
                    } else if arg1.starts_with(b"create ") && arg1.len() > 7 {
                        let snap_name = &arg1[7..];
                        vfs_lock();
                        let result = unsafe { shared_store() }.and_then(|store| store.snap_create(snap_name).ok());
                        vfs_unlock();
                        match result {
                            Some(_) => print(b"snapshot created\n"),
                            None => print(b"snapshot: failed\n"),
                        }
                    } else if arg1.starts_with(b"restore ") && arg1.len() > 8 {
                        let snap_name = &arg1[8..];
                        vfs_lock();
                        let result = unsafe { shared_store() }.and_then(|store| {
                            store.snap_find(snap_name).and_then(|slot| store.snap_restore(slot).ok())
                        });
                        vfs_unlock();
                        match result {
                            Some(_) => print(b"snapshot restored\n"),
                            None => print(b"snapshot: failed\n"),
                        }
                    } else if arg1.starts_with(b"delete ") && arg1.len() > 7 {
                        let snap_name = &arg1[7..];
                        vfs_lock();
                        let result = unsafe { shared_store() }.and_then(|store| {
                            store.snap_find(snap_name).and_then(|slot| store.snap_delete(slot).ok())
                        });
                        vfs_unlock();
                        match result {
                            Some(_) => print(b"snapshot deleted\n"),
                            None => print(b"snapshot: failed\n"),
                        }
                    } else {
                        print(b"usage: snapshot [list|create NAME|restore NAME|delete NAME]\n");
                    }
                } else {
                    // Unknown command
                    print(b"BB-CHILD: unknown applet: ");
                    for &b in basename { sys::debug_print(b); }
                    print(b"\n");
                    child_exit = 127;
                }

                if exec_in_fork {
                    // Record child exit status
                    if child_count < 8 {
                        child_pids[child_count] = child_pid;
                        child_statuses[child_count] = child_exit as i32;
                        child_count += 1;
                    }
                    // Restore stack contents (child may have clobbered them)
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            fork_saved_stack.as_ptr(),
                            fork_saved_rsp as *mut u8,
                            512,
                        );
                        // Restore return address at [fork_rsp] explicitly
                        core::ptr::write_volatile(fork_saved_rsp as *mut u64, fork_ret_addr);
                    }
                    // Build a restore frame on the fork-time stack:
                    // [rbx, rbp, r12, r13, r14, r15, return_rip]
                    // Then redirect to the vDSO fork-restore trampoline which pops them all.
                    let mut rsp = fork_saved_rsp;
                    // Push in reverse order (stack grows down)
                    rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_rip; }
                    rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r15; }
                    rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r14; }
                    rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r13; }
                    rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r12; }
                    rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_rbp; }
                    rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_rbx; }
                    let redirect = sotos_common::IpcMsg {
                        tag: sotos_common::SIG_REDIRECT_TAG,
                        regs: [vdso::FORK_RESTORE_ADDR, 0, 0, 0, rsp, child_pid, 0, 0],
                    };
                    let _ = sys::send(ep_cap, &redirect);
                } else {
                    // execve without fork (exec optimization): emulate command + exit.
                    // Redirect thread to vDSO exit stub with exit code in rdi.
                    let redirect = sotos_common::IpcMsg {
                        tag: sotos_common::SIG_REDIRECT_TAG,
                        regs: [vdso::EXIT_STUB_ADDR, child_exit as u64, 0, 0, msg.regs[7], 0, 0, 0],
                    };
                    let _ = sys::send(ep_cap, &redirect);
                }
            }
            // wait4(pid, status, options, rusage)
            61 => {
                let wait_pid = msg.regs[0] as i64;
                let status_ptr = msg.regs[1];
                let options = msg.regs[2];
                let mut found = false;
                for i in 0..child_count {
                    if wait_pid == -1 || wait_pid == child_pids[i] as i64 || wait_pid == 0 {
                        let pid = child_pids[i];
                        let status = child_statuses[i] as u32;
                        // Write wait status: (exit_code << 8) | 0 (exited normally)
                        if status_ptr != 0 {
                            let ws = (status << 8) & 0xFF00;
                            unsafe { *(status_ptr as *mut u32) = ws; }
                        }
                        // Remove from array
                        for j in i..child_count - 1 {
                            child_pids[j] = child_pids[j + 1];
                            child_statuses[j] = child_statuses[j + 1];
                        }
                        child_count -= 1;
                        reply_val(ep_cap, pid as i64);
                        found = true;
                        break;
                    }
                }
                if !found {
                    if options & 1 != 0 { // WNOHANG
                        reply_val(ep_cap, 0);
                    } else {
                        reply_val(ep_cap, -ECHILD); // -ECHILD
                    }
                }
            }
            // _exit in fork child phase (execve failed)
            60 | 231 if fork_child_phase => {
                fork_child_phase = false;
                let child_pid = next_child_pid;
                next_child_pid += 1;
                if child_count < 8 {
                    child_pids[child_count] = child_pid;
                    child_statuses[child_count] = 127;
                    child_count += 1;
                }
                // Restore stack + same restore trampoline as execve redirect
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        fork_saved_stack.as_ptr(),
                        fork_saved_rsp as *mut u8,
                        512,
                    );
                    // Restore return address at [fork_rsp] explicitly
                    core::ptr::write_volatile(fork_saved_rsp as *mut u64, fork_ret_addr);
                }
                let mut rsp = fork_saved_rsp;
                rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_rip; }
                rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r15; }
                rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r14; }
                rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r13; }
                rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_r12; }
                rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_rbp; }
                rsp -= 8; unsafe { *(rsp as *mut u64) = fork_saved_rbx; }
                let redirect = sotos_common::IpcMsg {
                    tag: sotos_common::SIG_REDIRECT_TAG,
                    regs: [vdso::FORK_RESTORE_ADDR, 0, 0, 0, rsp, child_pid, 0, 0],
                };
                let _ = sys::send(ep_cap, &redirect);
            }
            // exit / exit_group (normal, not in fork child phase)
            60 | 231 => {
                let status = msg.regs[0] as i64;
                print(b"BUSYBOX-TEST: exited with status ");
                print_u64(status as u64);
                print(b"\n");
                if status == 0 {
                    print(b"BUSYBOX-TEST: SUCCESS\n");
                }
                break;
            }
            // Catch-all: log unhandled syscalls
            _ => {
                print(b"BUSYBOX: unhandled syscall ");
                print_u64(nr);
                print(b"\n");
                reply_val(ep_cap, -ENOSYS); // -ENOSYS
            }
        }
    }

    print(b"BUSYBOX-TEST: complete\n");
}
