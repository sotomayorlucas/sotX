// ---------------------------------------------------------------------------
// Network + poll/select/epoll syscalls
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::exec::{reply_val, rdtsc};
use crate::process::{sig_dequeue, sig_dispatch};
use crate::fd::*;
use crate::NET_EP_CAP;
use crate::child_handler::mark_pipe_retry_on;
use crate::net::{NET_CMD_TCP_CONNECT, NET_CMD_TCP_SEND, NET_CMD_TCP_RECV,
                 NET_CMD_UDP_BIND, NET_CMD_UDP_SENDTO, NET_CMD_UDP_RECV};
use crate::framebuffer::{print, print_u64, print_hex64, kb_has_char};
use super::context::{SyscallContext, MAX_EPOLL_ENTRIES};

static NEXT_UDP_PORT: AtomicU64 = AtomicU64::new(49152);

// Per-process poll deadline tracking (TSC-based)
// When poll starts with timeout > 0, we record rdtsc(). On PIPE_RETRY_TAG
// retries, we check elapsed TSC against the timeout and return 0 if expired.
// Assuming ~2 GHz TSC: 1ms ≈ 2_000_000 ticks.
const TSC_PER_MS: u64 = 2_000_000;
static POLL_START_TSC: [AtomicU64; 64] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 64]
};

/// Check if an fd is poll-readable (has data or is at EOF).
fn poll_fd_readable(ctx: &SyscallContext, fd: usize) -> bool {
    let kind = ctx.child_fds[fd];
    match kind {
        1 => unsafe { kb_has_char() }, // stdin
        10 => {
            // Pipe read: check if buffer has data OR writer is closed (EOF)
            let pipe_id = ctx.sock_conn_id[fd] as usize;
            pipe_has_data(pipe_id) || pipe_writer_closed(pipe_id)
        }
        26 => {
            // AF_UNIX listening socket: readable if pending connections
            let listener = ctx.sock_conn_id[fd] as usize;
            unix_listener_has_pending(listener)
        }
        27 => {
            // AF_UNIX client: readable if pipe_b (server→client) has data
            let conn = ctx.sock_conn_id[fd] as usize;
            if conn < MAX_UNIX_CONNS {
                let pipe_b = unsafe { UNIX_CONN_PIPE_B[conn] as usize };
                pipe_has_data(pipe_b) || pipe_writer_closed(pipe_b)
            } else { false }
        }
        28 => {
            // AF_UNIX server: readable if pipe_a (client→server) has data
            let conn = ctx.sock_conn_id[fd] as usize;
            if conn < MAX_UNIX_CONNS {
                let pipe_a = unsafe { UNIX_CONN_PIPE_A[conn] as usize };
                pipe_has_data(pipe_a) || pipe_writer_closed(pipe_a)
            } else { false }
        }
        2 | 8 | 12 | 13 | 14 | 15 | 16 | 22 | 23 | 25 => true, // always "ready"
        _ => true, // default: report readable
    }
}

pub(crate) fn sys_poll(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fds_ptr = msg.regs[0];
    let nfds = msg.regs[1] as usize;
    let timeout = msg.regs[2] as i32;
    let nfds_clamped = nfds.min(16);
    // Read pollfd array from child memory (8 bytes per pollfd)
    let mut local_pfds = [0u8; 128]; // 16 * 8
    let bytes = nfds_clamped * 8;
    if bytes > 0 {
        ctx.guest_read(fds_ptr, &mut local_pfds[..bytes]);
    }
    let mut ready = 0u32;
    for i in 0..nfds_clamped {
        let off = i * 8;
        let fd = i32::from_le_bytes([local_pfds[off], local_pfds[off+1], local_pfds[off+2], local_pfds[off+3]]);
        let events = i16::from_le_bytes([local_pfds[off+4], local_pfds[off+5]]);
        let mut revents: i16 = 0;
        if fd >= 0 && (fd as usize) < GRP_MAX_FDS && ctx.child_fds[fd as usize] != 0 {
            if events & 1 != 0 { // POLLIN
                if poll_fd_readable(ctx, fd as usize) { revents |= 1; }
            }
            if events & 4 != 0 { revents |= 4; } // POLLOUT: always writable
        } else if fd >= 0 {
            revents = 0x20; // POLLNVAL
        }
        let rb = revents.to_le_bytes();
        local_pfds[off+6] = rb[0];
        local_pfds[off+7] = rb[1];
        if revents != 0 { ready += 1; }
    }
    // Write revents back to child memory
    if bytes > 0 {
        ctx.guest_write(fds_ptr, &local_pfds[..bytes]);
    }
    if ready > 0 || timeout == 0 {
        // Clear poll start time on completion
        if ctx.pid < 64 { POLL_START_TSC[ctx.pid].store(0, Ordering::Release); }
        reply_val(ep_cap, ready as i64);
    } else if timeout > 0 {
        // Positive timeout: check TSC deadline
        let now = rdtsc();
        let pid = ctx.pid;
        if pid < 64 {
            let start = POLL_START_TSC[pid].load(Ordering::Acquire);
            if start == 0 {
                // First call — record start time
                POLL_START_TSC[pid].store(now, Ordering::Release);
            } else {
                // Retry — check if timeout has elapsed
                let elapsed_ms = (now.wrapping_sub(start)) / TSC_PER_MS;
                if elapsed_ms >= timeout as u64 {
                    // Timeout expired: return 0 (no ready fds)
                    POLL_START_TSC[pid].store(0, Ordering::Release);
                    // Write back zero revents
                    if bytes > 0 {
                        ctx.guest_write(fds_ptr, &local_pfds[..bytes]);
                    }
                    reply_val(ep_cap, 0);
                    return;
                }
            }
        }
        // Not yet timed out — retry
        mark_pipe_retry_on(ctx.pid, 0xFF);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    } else {
        // timeout == -1: infinite wait, retry forever
        mark_pipe_retry_on(ctx.pid, 0xFF);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    }
}

pub(crate) fn sys_ppoll(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fds_ptr = msg.regs[0];
    let nfds = msg.regs[1] as usize;
    let tmo_ptr = msg.regs[2]; // timespec pointer (0 = infinite)
    let nfds_clamped = nfds.min(16);
    let mut local_pfds = [0u8; 128];
    let bytes = nfds_clamped * 8;
    if bytes > 0 {
        ctx.guest_read(fds_ptr, &mut local_pfds[..bytes]);
    }
    // Read timeout from timespec if present
    let timeout_ms: i64 = if tmo_ptr != 0 {
        let mut ts = [0u8; 16];
        ctx.guest_read(tmo_ptr, &mut ts);
        let sec = i64::from_le_bytes(ts[..8].try_into().unwrap_or([0;8]));
        let nsec = i64::from_le_bytes(ts[8..16].try_into().unwrap_or([0;8]));
        sec * 1000 + nsec / 1_000_000
    } else {
        -1 // infinite
    };
    let mut ready = 0u32;
    for i in 0..nfds_clamped {
        let off = i * 8;
        let fd = i32::from_le_bytes([local_pfds[off], local_pfds[off+1], local_pfds[off+2], local_pfds[off+3]]);
        let events = i16::from_le_bytes([local_pfds[off+4], local_pfds[off+5]]);
        let mut revents: i16 = 0;
        if fd >= 0 && (fd as usize) < GRP_MAX_FDS && ctx.child_fds[fd as usize] != 0 {
            if events & 1 != 0 {
                if poll_fd_readable(ctx, fd as usize) { revents |= 1; }
            }
            if events & 4 != 0 { revents |= 4; }
        } else if fd >= 0 { revents = 0x20; }
        let rb = revents.to_le_bytes();
        local_pfds[off+6] = rb[0];
        local_pfds[off+7] = rb[1];
        if revents != 0 { ready += 1; }
    }
    if bytes > 0 {
        ctx.guest_write(fds_ptr, &local_pfds[..bytes]);
    }
    if ready > 0 || timeout_ms == 0 {
        if ctx.pid < 64 { POLL_START_TSC[ctx.pid].store(0, Ordering::Release); }
        reply_val(ep_cap, ready as i64);
    } else if timeout_ms > 0 {
        let now = rdtsc();
        let pid = ctx.pid;
        if pid < 64 {
            let start = POLL_START_TSC[pid].load(Ordering::Acquire);
            if start == 0 {
                POLL_START_TSC[pid].store(now, Ordering::Release);
            } else {
                let elapsed_ms = (now.wrapping_sub(start)) / TSC_PER_MS;
                if elapsed_ms >= timeout_ms as u64 {
                    POLL_START_TSC[pid].store(0, Ordering::Release);
                    if bytes > 0 {
                        ctx.guest_write(fds_ptr, &local_pfds[..bytes]);
                    }
                    reply_val(ep_cap, 0);
                    return;
                }
            }
        }
        mark_pipe_retry_on(ctx.pid, 0xFF);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    } else {
        // timeout_ms == -1: infinite wait
        mark_pipe_retry_on(ctx.pid, 0xFF);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    }
}

pub(crate) fn sys_socket(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let domain = msg.regs[0] as u32;
    let sock_type = msg.regs[1] as u32;
    let base_type = sock_type & 0xFF;
    let sock_nonblock = sock_type & 0x800; // SOCK_NONBLOCK
    let sock_cloexec = sock_type & 0x80000; // SOCK_CLOEXEC
    if domain == 1 {
        // AF_UNIX: allocate a local-only socket FD (kind=26).
        // No net service IPC needed — Wine just needs a valid FD.
        let mut fd = None;
        for f in 3..GRP_MAX_FDS {
            if ctx.child_fds[f] == 0 { fd = Some(f); break; }
        }
        match fd {
            Some(f) => {
                ctx.child_fds[f] = 26; // kind 26 = AF_UNIX socket
                if sock_nonblock != 0 {
                    ctx.fd_flags[f] = 0x800; // O_NONBLOCK
                }
                if sock_cloexec != 0 && f < 128 {
                    *ctx.fd_cloexec |= 1u128 << f;
                }
                ctx.sock_conn_id[f] = 0xFFFF;
                reply_val(ep_cap, f as i64);
            }
            None => reply_val(ep_cap, -EMFILE),
        }
    } else if domain == 2 && (base_type == 1 || base_type == 2 || base_type == 3) {
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 {
            reply_val(ep_cap, -EADDRNOTAVAIL);
        } else {
            let mut fd = None;
            for f in 3..GRP_MAX_FDS {
                if ctx.child_fds[f] == 0 { fd = Some(f); break; }
            }
            match fd {
                Some(f) => {
                    // Propagate SOCK_NONBLOCK to fd_flags
                    if sock_nonblock != 0 {
                        ctx.fd_flags[f] = 0x800; // O_NONBLOCK
                    }
                    if sock_cloexec != 0 && f < 128 {
                        *ctx.fd_cloexec |= 1u128 << f;
                    }
                    if base_type == 1 {
                        ctx.child_fds[f] = 16; // TCP
                        ctx.sock_conn_id[f] = 0xFFFF;
                    } else {
                        ctx.child_fds[f] = 17; // UDP
                        let port = NEXT_UDP_PORT.fetch_add(1, Ordering::SeqCst) as u16;
                        ctx.sock_udp_local_port[f] = port;
                        let bind_req = IpcMsg {
                            tag: NET_CMD_UDP_BIND,
                            regs: [port as u64, 0, 0, 0, 0, 0, 0, 0],
                        };
                        let _ = sys::call_timeout(net_cap, &bind_req, 500);
                    }
                    reply_val(ep_cap, f as i64);
                }
                None => reply_val(ep_cap, -EMFILE),
            }
        }
    } else {
        reply_val(ep_cap, -EAFNOSUPPORT);
    }
}

pub(crate) fn sys_connect(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let pid = ctx.pid;
    let fd = msg.regs[0] as usize;
    let sockaddr_ptr = msg.regs[1];
    if fd >= GRP_MAX_FDS || (ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17 && ctx.child_fds[fd] != 26) {
        reply_val(ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 26 {
        // AF_UNIX connect: find listener by path, create bidirectional pipe pair
        let addrlen = msg.regs[2] as usize;
        let mut sa_buf = [0u8; 110];
        let copy = addrlen.min(110).max(2);
        ctx.guest_read(sockaddr_ptr, &mut sa_buf[..copy]);
        let path_bytes = &sa_buf[2..copy];
        let plen = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        // Resolve relative path
        let mut abs_full = [0u8; 256];
        let alen = if plen > 0 {
            crate::fd::resolve_with_cwd(ctx.cwd, &path_bytes[..plen], &mut abs_full)
        } else { 0 };
        let mut abs = [0u8; 128];
        abs[..alen.min(127)].copy_from_slice(&abs_full[..alen.min(127)]);
        // Find matching listener
        let mut found_listener: Option<usize> = None;
        for i in 0..MAX_UNIX_LISTENERS {
            if UNIX_LISTEN_ACTIVE[i].load(Ordering::Acquire) == 0 { continue; }
            let lpath = unsafe { &UNIX_LISTEN_PATH[i] };
            let llen = lpath.iter().position(|&b| b == 0).unwrap_or(128);
            if llen == alen && lpath[..llen] == abs[..alen] {
                found_listener = Some(i);
                break;
            }
        }
        if let Some(listener) = found_listener {
            // Create connection: 2 pipes
            if let Some((conn_slot, _pipe_a, _pipe_b)) = unix_conn_alloc() {
                // Push pending connection for the listener
                if unix_pending_push(listener, conn_slot) {
                    // Client side: kind=27, reads from pipe_b, writes to pipe_a
                    ctx.child_fds[fd] = 27;
                    ctx.sock_conn_id[fd] = conn_slot as u32;
                    print(b"UNIX-CONN P"); print_u64(pid as u64);
                    print(b" fd="); print_u64(fd as u64);
                    print(b" conn="); print_u64(conn_slot as u64);
                    print(b"\n");
                    reply_val(ep_cap, 0);
                } else {
                    reply_val(ep_cap, -ECONNREFUSED);
                }
            } else {
                reply_val(ep_cap, -ENOMEM);
            }
        } else {
            print(b"UNIX-CONN-REFUSE P"); print_u64(pid as u64);
            print(b" [");
            for &b in &abs[..alen] { if b != 0 { sys::debug_print(b); } }
            print(b"]\n");
            reply_val(ep_cap, -ECONNREFUSED);
        }
    } else {
        let mut sa = [0u8; 8];
        ctx.guest_read(sockaddr_ptr, &mut sa);
        let port = u16::from_be_bytes([sa[2], sa[3]]);
        let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

        if ctx.child_fds[fd] == 17 {
            ctx.sock_udp_remote_ip[fd] = ip;
            ctx.sock_udp_remote_port[fd] = port;
            reply_val(ep_cap, 0);
        } else {
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
            let req = IpcMsg {
                tag: NET_CMD_TCP_CONNECT,
                regs: [ip as u64, port as u64, 0, 0, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 20000) {
                Ok(resp) => {
                    let conn_id = resp.regs[0];
                    if conn_id as i64 >= 0 {
                        ctx.sock_conn_id[fd] = conn_id as u32;
                        if pid > 1 {
                            print(b"TCP-CONN: fd=");
                            print_u64(fd as u64);
                            print(b" conn=");
                            print_u64(conn_id);
                            print(b" ip=");
                            print_u64(ip as u64);
                            print(b":"); print_u64(port as u64);
                            print(b"\n");
                        }
                        reply_val(ep_cap, 0);
                    } else {
                        if pid > 1 {
                            print(b"TCP-CONN-REFUSED ip=");
                            print_u64(ip as u64);
                            print(b":"); print_u64(port as u64);
                            print(b"\n");
                        }
                        reply_val(ep_cap, -ECONNREFUSED);
                    }
                }
                Err(_) => {
                    if pid > 1 {
                        print(b"TCP-CONN-TIMEOUT ip=");
                        print_u64(ip as u64);
                        print(b":"); print_u64(port as u64);
                        print(b"\n");
                    }
                    reply_val(ep_cap, -ETIMEDOUT);
                }
            }
        }
    }
}

pub(crate) fn sys_sendto(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    let dest_ptr = msg.regs[4];

    if fd >= GRP_MAX_FDS {
        reply_val(ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 26 {
        // AF_UNIX sendto: no peer connected
        reply_val(ep_cap, -EAGAIN);
    } else if ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17 {
        reply_val(ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 17 {
        // UDP sendto
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let (dst_ip, dst_port) = if dest_ptr != 0 {
            let mut sa = [0u8; 8];
            ctx.guest_read(dest_ptr, &mut sa);
            let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);
            let port = u16::from_be_bytes([sa[2], sa[3]]);
            ctx.sock_udp_remote_ip[fd] = ip;
            ctx.sock_udp_remote_port[fd] = port;
            (ip, port)
        } else {
            (ctx.sock_udp_remote_ip[fd], ctx.sock_udp_remote_port[fd])
        };
        let src_port = ctx.sock_udp_local_port[fd];
        // Pack: tag(32-bit) = CMD | (data_len << 16)
        // regs[0] = dst_ip | (dst_port << 32) | (src_port << 48)
        // regs[1..7] = data (56 bytes max)
        let send_len = len.min(56);
        let packed_tag = NET_CMD_UDP_SENDTO | ((send_len as u64) << 16);
        let packed_r0 = (dst_ip as u64)
            | ((dst_port as u64) << 32)
            | ((src_port as u64) << 48);
        let mut req = IpcMsg {
            tag: packed_tag,
            regs: [packed_r0, 0, 0, 0, 0, 0, 0, 0],
        };
        let mut data_buf = [0u8; 56];
        ctx.guest_read(buf_ptr, &mut data_buf[..send_len]);
        unsafe {
            let dst = &mut req.regs[1] as *mut u64 as *mut u8;
            core::ptr::copy_nonoverlapping(data_buf.as_ptr(), dst, send_len);
        }
        match sys::call_timeout(net_cap, &req, 500) {
            Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
            Err(_) => reply_val(ep_cap, -EIO),
        }
    } else {
        // TCP send — multi-chunk loop (same as sys_write for kind=16)
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let mut total_sent = 0usize;
        let mut off = 0usize;
        while off < len {
            let chunk = (len - off).min(40);
            let mut req = IpcMsg {
                tag: NET_CMD_TCP_SEND,
                regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
            };
            let mut data_buf = [0u8; 40];
            ctx.guest_read(buf_ptr + off as u64, &mut data_buf[..chunk]);
            unsafe {
                let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                core::ptr::copy_nonoverlapping(data_buf.as_ptr(), dst, chunk);
            }
            match sys::call_timeout(net_cap, &req, 500) {
                Ok(resp) => {
                    let n = resp.regs[0] as i64;
                    if n <= 0 { break; }
                    let n = n as usize;
                    total_sent += n;
                    off += n;
                }
                Err(_) => break,
            }
        }
        // (SENDTO-TCP debug logging removed)
        if total_sent > 0 {
            reply_val(ep_cap, total_sent as i64);
        } else {
            reply_val(ep_cap, -EIO);
        }
    }
}

pub(crate) fn sys_sendmsg(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let msghdr_ptr = msg.regs[1];

    if fd >= GRP_MAX_FDS {
        reply_val(ep_cap, -EBADF);
        return;
    }
    // AF_UNIX listener: no peer connected
    if ctx.child_fds[fd] == 26 {
        reply_val(ep_cap, -EAGAIN);
        return;
    }
    // AF_UNIX connected socket: write to pipe + SCM_RIGHTS
    if ctx.child_fds[fd] == 27 || ctx.child_fds[fd] == 28 {
        let conn = ctx.sock_conn_id[fd] as usize;
        // Read msghdr (56 bytes)
        let mut hdr = [0u8; 56];
        ctx.guest_read(msghdr_ptr, &mut hdr);
        let msg_iov = u64::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23]]);
        let msg_iovlen = u64::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31]]) as usize;
        let msg_control = u64::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39]]);
        let msg_controllen = u64::from_le_bytes([hdr[40], hdr[41], hdr[42], hdr[43], hdr[44], hdr[45], hdr[46], hdr[47]]) as usize;
        // Process SCM_RIGHTS in msg_control
        let mut msg_scm_count = 0u8;
        if msg_control != 0 && msg_controllen >= 16 && conn < crate::fd::MAX_UNIX_CONNS {
            let mut cmsg_buf = [0u8; 128];
            let clen = msg_controllen.min(128);
            ctx.guest_read(msg_control, &mut cmsg_buf[..clen]);
            // Parse cmsghdr: len(8), level(4), type(4), then data
            let cmsg_len = u64::from_le_bytes([cmsg_buf[0], cmsg_buf[1], cmsg_buf[2], cmsg_buf[3], cmsg_buf[4], cmsg_buf[5], cmsg_buf[6], cmsg_buf[7]]) as usize;
            let cmsg_level = i32::from_le_bytes([cmsg_buf[8], cmsg_buf[9], cmsg_buf[10], cmsg_buf[11]]);
            let cmsg_type = i32::from_le_bytes([cmsg_buf[12], cmsg_buf[13], cmsg_buf[14], cmsg_buf[15]]);
            if cmsg_level == 1 && cmsg_type == 1 && cmsg_len > 16 {
                // SCM_RIGHTS: fds start at offset 16
                let nfds = (cmsg_len - 16) / 4;
                let direction = if ctx.child_fds[fd] == 27 { 0usize } else { 1 };
                for fi in 0..nfds.min(crate::fd::MAX_SCM_FDS) {
                    let off = 16 + fi * 4;
                    let sfd = i32::from_le_bytes([cmsg_buf[off], cmsg_buf[off+1], cmsg_buf[off+2], cmsg_buf[off+3]]) as usize;
                    if sfd < GRP_MAX_FDS {
                        let kind = ctx.child_fds[sfd];
                        let cid = ctx.sock_conn_id[sfd];
                        // For VFS files (kind=13), pack OID and size
                        let mut oid = 0u64;
                        let mut fsize = 0u64;
                        if kind == 13 {
                            for s in 0..GRP_MAX_VFS {
                                if ctx.vfs_files[s][0] != 0 && ctx.vfs_files[s][3] == sfd as u64 {
                                    oid = ctx.vfs_files[s][0];
                                    fsize = ctx.vfs_files[s][1];
                                    break;
                                }
                            }
                        }
                        crate::fd::scm_push_fd(conn, direction, kind, cid, oid, fsize);
                        msg_scm_count += 1;
                        print(b"SCM-SEND P"); print_u64(ctx.pid as u64);
                        print(b" fd="); print_u64(sfd as u64);
                        print(b" k="); print_u64(kind as u64);
                        if kind == 13 {
                            print(b" oid="); print_hex64(oid);
                        }
                        print(b"\n");
                    }
                }
            }
        }
        if msg_iovlen == 0 {
            // Even with no data, record the message boundary for SCM
            if msg_scm_count > 0 && conn < crate::fd::MAX_UNIX_CONNS {
                let direction = if ctx.child_fds[fd] == 27 { 0usize } else { 1 };
                crate::fd::msg_queue_push(conn, direction, 0, msg_scm_count);
            }
            reply_val(ep_cap, 0); return;
        }
        // Read first iovec
        let mut iov_buf = [0u8; 16];
        ctx.guest_read(msg_iov, &mut iov_buf);
        let iov_base = u64::from_le_bytes([iov_buf[0], iov_buf[1], iov_buf[2], iov_buf[3], iov_buf[4], iov_buf[5], iov_buf[6], iov_buf[7]]);
        let iov_len = u64::from_le_bytes([iov_buf[8], iov_buf[9], iov_buf[10], iov_buf[11], iov_buf[12], iov_buf[13], iov_buf[14], iov_buf[15]]) as usize;
        if conn < crate::fd::MAX_UNIX_CONNS {
            let pipe_id = if ctx.child_fds[fd] == 27 {
                unsafe { crate::fd::UNIX_CONN_PIPE_A[conn] as usize }
            } else {
                unsafe { crate::fd::UNIX_CONN_PIPE_B[conn] as usize }
            };
            let safe_len = iov_len.min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(iov_base, &mut local_buf[..safe_len]);
            let mut written = 0usize;
            let mut retries = 0u32;
            while written < safe_len {
                let n = pipe_write(pipe_id, &local_buf[written..safe_len]);
                written += n;
                if n == 0 { retries += 1; if retries > 10000 { break; } sys::yield_now(); }
            }
            // Record message boundary so recvmsg reads exactly one sendmsg worth
            let direction = if ctx.child_fds[fd] == 27 { 0usize } else { 1 };
            crate::fd::msg_queue_push(conn, direction, written as u16, msg_scm_count);
            reply_val(ep_cap, written as i64);
        } else {
            reply_val(ep_cap, -EBADF);
        }
        return;
    }
    if ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17 {
        reply_val(ep_cap, -EBADF);
        return;
    }

    let (msg_name, _msg_namelen, msg_iov, msg_iovlen) = unsafe {
        let p = msghdr_ptr as *const u64;
        (*p, *p.add(1) as u32, *p.add(2), *p.add(3) as usize)
    };
    if msg_iovlen == 0 {
        reply_val(ep_cap, 0);
        return;
    }
    let (iov_base, iov_len) = unsafe {
        let iov = msg_iov as *const u64;
        (*iov, *iov.add(1) as usize)
    };

    if ctx.child_fds[fd] == 17 {
        // UDP sendmsg
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let (dst_ip, dst_port) = if msg_name != 0 {
            let sa = unsafe { core::slice::from_raw_parts(msg_name as *const u8, 8) };
            let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);
            let port = u16::from_be_bytes([sa[2], sa[3]]);
            ctx.sock_udp_remote_ip[fd] = ip;
            ctx.sock_udp_remote_port[fd] = port;
            (ip, port)
        } else {
            (ctx.sock_udp_remote_ip[fd], ctx.sock_udp_remote_port[fd])
        };
        let src_port = ctx.sock_udp_local_port[fd];
        let send_len = iov_len.min(56);
        let packed_tag = NET_CMD_UDP_SENDTO | ((send_len as u64) << 16);
        let packed_r0 = (dst_ip as u64)
            | ((dst_port as u64) << 32)
            | ((src_port as u64) << 48);
        let mut req = IpcMsg {
            tag: packed_tag,
            regs: [packed_r0, 0, 0, 0, 0, 0, 0, 0],
        };
        let data = unsafe { core::slice::from_raw_parts(iov_base as *const u8, send_len) };
        unsafe {
            let dst = &mut req.regs[1] as *mut u64 as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
        }
        match sys::call_timeout(net_cap, &req, 500) {
            Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
            Err(_) => reply_val(ep_cap, -EIO),
        }
    } else {
        // TCP sendmsg — multi-chunk loop
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let mut total_sent = 0usize;
        let mut off = 0usize;
        while off < iov_len {
            let chunk = (iov_len - off).min(40);
            let mut req = IpcMsg {
                tag: NET_CMD_TCP_SEND,
                regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
            };
            let data = unsafe { core::slice::from_raw_parts((iov_base + off as u64) as *const u8, chunk) };
            unsafe {
                let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, chunk);
            }
            match sys::call_timeout(net_cap, &req, 500) {
                Ok(resp) => {
                    let n = resp.regs[0] as i64;
                    if n <= 0 { break; }
                    let n = n as usize;
                    total_sent += n;
                    off += n;
                }
                Err(_) => break,
            }
        }
        if total_sent > 0 {
            reply_val(ep_cap, total_sent as i64);
        } else {
            reply_val(ep_cap, -EIO);
        }
    }
}

pub(crate) fn sys_recvfrom(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    let src_addr_ptr = msg.regs[4];
    let addrlen_ptr = msg.regs[5];

    if fd >= GRP_MAX_FDS {
        reply_val(ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 26 {
        // AF_UNIX recvfrom: no data
        reply_val(ep_cap, -EAGAIN);
    } else if ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17 {
        reply_val(ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 17 {
        // UDP recvfrom — multi-chunk: DNS responses can be >64 bytes
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let src_port = ctx.sock_udp_local_port[fd];
        let max_recv = len.min(512); // DNS responses up to 512 bytes
        let mut got = 0usize;
        // First call: offset=0, triggers net service to poll for new datagram
        for _attempt in 0..50u32 {
            let req = IpcMsg {
                tag: NET_CMD_UDP_RECV,
                regs: [src_port as u64, max_recv as u64, 0, 0, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 5000) {
                Ok(resp) => {
                    let chunk = resp.tag as usize; // bytes in this chunk (0-64)
                    if chunk > 0 {
                        // Write first chunk to child buffer
                        let src = unsafe {
                            core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, chunk)
                        };
                        ctx.guest_write(buf_ptr, src);
                        got = chunk;
                        // Fetch remaining chunks if datagram > 64 bytes
                        // resp.regs[0] was overwritten with data, but the net service
                        // stored total in IPC_UDP_RECV_TOTAL. We can compute: if
                        // chunk == 64 and we need more, keep fetching with offset.
                        let mut offset = chunk;
                        while offset < max_recv && chunk == 64 {
                            let cont_req = IpcMsg {
                                tag: NET_CMD_UDP_RECV,
                                regs: [src_port as u64, max_recv as u64, offset as u64, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &cont_req, 500) {
                                Ok(cont_resp) => {
                                    let cont_n = cont_resp.tag as usize;
                                    if cont_n == 0 { break; }
                                    let cont_src = unsafe {
                                        core::slice::from_raw_parts(&cont_resp.regs[0] as *const u64 as *const u8, cont_n)
                                    };
                                    ctx.guest_write(buf_ptr + offset as u64, cont_src);
                                    got += cont_n;
                                    offset += cont_n;
                                    if cont_n < 64 { break; } // last chunk
                                }
                                Err(_) => break,
                            }
                        }
                        break;
                    }
                }
                Err(_) => {}
            }
            sys::yield_now();
        }
        if got > 0 {
            if src_addr_ptr != 0 {
                let remote_ip = ctx.sock_udp_remote_ip[fd];
                let remote_port = ctx.sock_udp_remote_port[fd];
                let mut sa_buf = [0u8; 16];
                sa_buf[0] = 2; // AF_INET
                sa_buf[2] = (remote_port >> 8) as u8;
                sa_buf[3] = (remote_port & 0xFF) as u8;
                sa_buf[4] = ((remote_ip >> 24) & 0xFF) as u8;
                sa_buf[5] = ((remote_ip >> 16) & 0xFF) as u8;
                sa_buf[6] = ((remote_ip >> 8) & 0xFF) as u8;
                sa_buf[7] = (remote_ip & 0xFF) as u8;
                ctx.guest_write(src_addr_ptr, &sa_buf);
                if addrlen_ptr != 0 {
                    ctx.guest_write(addrlen_ptr, &16u32.to_le_bytes());
                }
            }
            reply_val(ep_cap, got as i64);
        } else {
            reply_val(ep_cap, -EAGAIN);
        }
    } else {
        // TCP recvfrom
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let recv_len = len.min(64);
        let nonblock = fd < GRP_MAX_FDS && (ctx.fd_flags[fd] & 0x800) != 0; // O_NONBLOCK
        let max_attempts = if nonblock { 10u32 } else { 5000u32 };
        let mut got = 0usize;
        for _attempt in 0..max_attempts {
            let req = IpcMsg {
                tag: NET_CMD_TCP_RECV,
                regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 200) {
                Ok(resp) => {
                    let n = resp.tag as usize;
                    if n > 0 && n <= recv_len {
                        let src = unsafe {
                            core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, n)
                        };
                        ctx.guest_write(buf_ptr, src);
                        got = n;
                        break;
                    }
                }
                Err(_) => {}
            }
            sys::yield_now();
        }
        if got > 0 { reply_val(ep_cap, got as i64); }
        else {
            reply_val(ep_cap, -EAGAIN);
        }
    }
}

pub(crate) fn sys_recvmsg(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let msghdr_ptr = msg.regs[1];

    if fd >= GRP_MAX_FDS {
        reply_val(ep_cap, -EBADF);
        return;
    }
    // AF_UNIX listener socket: no data to receive
    if ctx.child_fds[fd] == 26 {
        reply_val(ep_cap, -EAGAIN);
        return;
    }
    // AF_UNIX connected socket: read from pipe + SCM_RIGHTS
    if ctx.child_fds[fd] == 27 || ctx.child_fds[fd] == 28 {
        let conn = ctx.sock_conn_id[fd] as usize;
        // Read msghdr (56 bytes)
        let mut hdr = [0u8; 56];
        ctx.guest_read(msghdr_ptr, &mut hdr);
        let msg_iov = u64::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23]]);
        let msg_iovlen = u64::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31]]) as usize;
        let msg_control = u64::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39]]);
        let msg_controllen = u64::from_le_bytes([hdr[40], hdr[41], hdr[42], hdr[43], hdr[44], hdr[45], hdr[46], hdr[47]]) as usize;
        if msg_iovlen == 0 { reply_val(ep_cap, 0); return; }
        // Read first iovec
        let mut iov_buf = [0u8; 16];
        ctx.guest_read(msg_iov, &mut iov_buf);
        let iov_base = u64::from_le_bytes([iov_buf[0], iov_buf[1], iov_buf[2], iov_buf[3], iov_buf[4], iov_buf[5], iov_buf[6], iov_buf[7]]);
        let iov_len = u64::from_le_bytes([iov_buf[8], iov_buf[9], iov_buf[10], iov_buf[11], iov_buf[12], iov_buf[13], iov_buf[14], iov_buf[15]]) as usize;
        if conn < crate::fd::MAX_UNIX_CONNS {
            let pipe_id = if ctx.child_fds[fd] == 27 {
                unsafe { crate::fd::UNIX_CONN_PIPE_B[conn] as usize }
            } else {
                unsafe { crate::fd::UNIX_CONN_PIPE_A[conn] as usize }
            };
            // Respect message boundary: read only one sendmsg worth
            let direction = if ctx.child_fds[fd] == 27 { 1usize } else { 0 };
            let msg_len = crate::fd::msg_queue_peek(conn, direction) as usize;
            let want = if msg_len > 0 { iov_len.min(msg_len).min(4096) } else { iov_len.min(4096) };
            let mut tmp = [0u8; 4096];
            let n = pipe_read(pipe_id, &mut tmp[..want]);
            if n > 0 {
                // Pop the boundary marker and get per-message SCM count
                let msg_scm_limit = if msg_len > 0 && n >= msg_len {
                    let (_len, scm_n) = crate::fd::msg_queue_pop(conn, direction);
                    scm_n as usize
                } else {
                    // No message boundary or partial read: pop all available SCM fds
                    crate::fd::MAX_SCM_FDS
                };
                ctx.guest_write(iov_base, &tmp[..n]);
                // Deliver SCM_RIGHTS fds (only those belonging to this message)
                let mut scm_kinds = [0u8; crate::fd::MAX_SCM_FDS];
                let mut scm_conns = [0u32; crate::fd::MAX_SCM_FDS];
                let mut scm_oids = [0u64; crate::fd::MAX_SCM_FDS];
                let mut scm_sizes = [0u64; crate::fd::MAX_SCM_FDS];
                let scm_count = crate::fd::scm_pop_fds(conn, direction, &mut scm_kinds, &mut scm_conns, &mut scm_oids, &mut scm_sizes, msg_scm_limit);
                if scm_count > 0 && msg_control != 0 && msg_controllen >= 16 + scm_count * 4 {
                    // Allocate new fds in receiver's fd table and build cmsg
                    let mut new_fds = [0i32; crate::fd::MAX_SCM_FDS];
                    for fi in 0..scm_count {
                        // Find free fd in receiver
                        let mut nfd = -1i32;
                        for j in 3..GRP_MAX_FDS {
                            if ctx.child_fds[j] == 0 {
                                ctx.child_fds[j] = scm_kinds[fi];
                                ctx.sock_conn_id[j] = scm_conns[fi];
                                nfd = j as i32;
                                // Increment pipe refcounts if applicable
                                let p = scm_conns[fi] as usize;
                                if scm_kinds[fi] == 10 && p < MAX_PIPES { PIPE_READ_REFS[p].fetch_add(1, Ordering::AcqRel); }
                                if scm_kinds[fi] == 11 && p < MAX_PIPES { PIPE_WRITE_REFS[p].fetch_add(1, Ordering::AcqRel); }
                                // For VFS files (kind=13), create a vfs_files entry in receiver
                                if scm_kinds[fi] == 13 && scm_oids[fi] != 0 {
                                    for vs in 0..GRP_MAX_VFS {
                                        if ctx.vfs_files[vs][0] == 0 {
                                            ctx.vfs_files[vs][0] = scm_oids[fi]; // OID
                                            ctx.vfs_files[vs][1] = scm_sizes[fi]; // size
                                            ctx.vfs_files[vs][2] = 0; // offset
                                            ctx.vfs_files[vs][3] = j as u64; // fd
                                            break;
                                        }
                                    }
                                }
                                print(b"SCM-RECV P"); print_u64(ctx.pid as u64);
                                print(b" fd="); print_u64(j as u64);
                                print(b" k="); print_u64(scm_kinds[fi] as u64);
                                print(b"\n");
                                break;
                            }
                        }
                        new_fds[fi] = nfd;
                    }
                    // Build cmsghdr: len(8) + level(4) + type(4) + fds(4*N)
                    let cmsg_len = 16 + scm_count * 4;
                    let mut cmsg_buf = [0u8; 128];
                    cmsg_buf[..8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
                    cmsg_buf[8..12].copy_from_slice(&1i32.to_le_bytes()); // SOL_SOCKET
                    cmsg_buf[12..16].copy_from_slice(&1i32.to_le_bytes()); // SCM_RIGHTS
                    for fi in 0..scm_count {
                        let off = 16 + fi * 4;
                        cmsg_buf[off..off+4].copy_from_slice(&new_fds[fi].to_le_bytes());
                    }
                    ctx.guest_write(msg_control, &cmsg_buf[..cmsg_len]);
                    // Update msg_controllen in msghdr
                    ctx.guest_write(msghdr_ptr + 40, &(cmsg_len as u64).to_le_bytes());
                } else {
                    // No SCM fds: set msg_controllen = 0
                    ctx.guest_write(msghdr_ptr + 40, &0u64.to_le_bytes());
                }
                reply_val(ep_cap, n as i64);
            } else if pipe_writer_closed(pipe_id) {
                reply_val(ep_cap, 0); // EOF
            } else {
                // Non-blocking: return -EAGAIN immediately
                let nonblock = fd < GRP_MAX_FDS && (ctx.fd_flags[fd] & 0x800) != 0;
                if nonblock {
                    reply_val(ep_cap, -EAGAIN);
                } else {
                    // Block: retry via PIPE_RETRY_TAG
                    mark_pipe_retry_on(ctx.pid, pipe_id);
                    let reply = sotos_common::IpcMsg { tag: sotos_common::PIPE_RETRY_TAG, regs: [0; 8] };
                    let _ = sys::send(ep_cap, &reply);
                }
            }
        } else {
            reply_val(ep_cap, -EBADF);
        }
        return;
    }
    if ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17 {
        reply_val(ep_cap, -EBADF);
        return;
    }

    let (msg_name, msg_namelen, msg_iov, msg_iovlen) = unsafe {
        let p = msghdr_ptr as *const u64;
        (
            *p,
            *p.add(1) as u32,
            *p.add(2),
            *p.add(3) as usize,
        )
    };

    if msg_iovlen == 0 {
        reply_val(ep_cap, 0);
        return;
    }
    let (iov_base, iov_len) = unsafe {
        let iov = msg_iov as *const u64;
        (*iov, *iov.add(1) as usize)
    };

    if ctx.child_fds[fd] == 17 {
        // UDP recvmsg
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let src_port = ctx.sock_udp_local_port[fd];
        let recv_len = iov_len.min(64);
        let mut total_n = 0usize;
        for _attempt in 0..50u32 {
            let req = IpcMsg {
                tag: NET_CMD_UDP_RECV,
                regs: [src_port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 5000) {
                Ok(resp) => {
                    let n = resp.tag as usize;
                    if n > 0 && n <= recv_len {
                        unsafe {
                            let src = &resp.regs[0] as *const u64 as *const u8;
                            core::ptr::copy_nonoverlapping(src, iov_base as *mut u8, n);
                        }
                        total_n = n;
                        break;
                    }
                }
                Err(_) => {}
            }
        }
        if total_n > 0 {
            if msg_name != 0 && msg_namelen >= 16 {
                let remote_ip = ctx.sock_udp_remote_ip[fd];
                let remote_port = ctx.sock_udp_remote_port[fd];
                unsafe {
                    let sa = msg_name as *mut u8;
                    *sa.add(0) = 2; *sa.add(1) = 0;
                    *sa.add(2) = (remote_port >> 8) as u8;
                    *sa.add(3) = (remote_port & 0xFF) as u8;
                    *sa.add(4) = ((remote_ip >> 24) & 0xFF) as u8;
                    *sa.add(5) = ((remote_ip >> 16) & 0xFF) as u8;
                    *sa.add(6) = ((remote_ip >> 8) & 0xFF) as u8;
                    *sa.add(7) = (remote_ip & 0xFF) as u8;
                    for i in 8..16 { *sa.add(i) = 0; }
                }
                unsafe { *((msghdr_ptr + 8) as *mut u32) = 16; }
            }
            unsafe {
                *((msghdr_ptr + 40) as *mut u64) = 0;
                *((msghdr_ptr + 48) as *mut i32) = 0;
            }
            reply_val(ep_cap, total_n as i64);
        } else {
            reply_val(ep_cap, -EAGAIN);
        }
    } else {
        // TCP recvmsg
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let recv_len = iov_len.min(64);
        let nonblock = fd < GRP_MAX_FDS && (ctx.fd_flags[fd] & 0x800) != 0;
        let max_attempts = if nonblock { 10u32 } else { 5000u32 };
        let mut got = 0usize;
        for _ in 0..max_attempts {
            let req = IpcMsg {
                tag: NET_CMD_TCP_RECV,
                regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 200) {
                Ok(resp) => {
                    let n = resp.tag as usize;
                    if n > 0 && n <= recv_len {
                        unsafe {
                            let src = &resp.regs[0] as *const u64 as *const u8;
                            core::ptr::copy_nonoverlapping(src, iov_base as *mut u8, n);
                        }
                        got = n;
                        break;
                    }
                }
                Err(_) => {}
            }
            sys::yield_now();
        }
        unsafe {
            *((msghdr_ptr + 40) as *mut u64) = 0;
            *((msghdr_ptr + 48) as *mut i32) = 0;
        }
        if got > 0 { reply_val(ep_cap, got as i64); }
        else { reply_val(ep_cap, -EAGAIN); }
    }
}

pub(crate) fn sys_bind(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let addr_ptr = msg.regs[1];
    let addrlen = msg.regs[2] as usize;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }
    if ctx.child_fds[fd] == 26 && addrlen > 2 {
        // AF_UNIX bind: extract path from sockaddr_un (family=2 bytes, then path)
        let mut sa_buf = [0u8; 110];
        let copy = addrlen.min(110);
        ctx.guest_read(addr_ptr, &mut sa_buf[..copy]);
        // Path starts at offset 2, null-terminated
        let path_bytes = &sa_buf[2..copy];
        let plen = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        if plen == 0 {
            reply_val(ctx.ep_cap, -EINVAL);
            return;
        }
        // Resolve relative path with CWD
        let mut abs_full = [0u8; 256];
        let alen = crate::fd::resolve_with_cwd(ctx.cwd, &path_bytes[..plen], &mut abs_full);
        let mut abs = [0u8; 128];
        abs[..alen.min(127)].copy_from_slice(&abs_full[..alen.min(127)]);
        // Find a free listener slot and register
        for i in 0..MAX_UNIX_LISTENERS {
            if UNIX_LISTEN_ACTIVE[i].compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                unsafe {
                    UNIX_LISTEN_PATH[i] = [0; 128];
                    UNIX_LISTEN_PATH[i][..alen.min(127)].copy_from_slice(&abs[..alen.min(127)]);
                }
                // Store listener slot in sock_conn_id
                ctx.sock_conn_id[fd] = i as u32;
                print(b"UNIX-BIND P"); print_u64(ctx.pid as u64);
                print(b" fd="); print_u64(fd as u64);
                print(b" [");
                for &b in &abs[..alen] { if b != 0 { sys::debug_print(b); } }
                print(b"] slot="); print_u64(i as u64);
                print(b"\n");
                reply_val(ctx.ep_cap, 0);
                return;
            }
        }
        reply_val(ctx.ep_cap, -98); // EADDRINUSE
    } else {
        reply_val(ctx.ep_cap, 0); // non-UNIX bind: stub OK
    }
}

pub(crate) fn sys_listen(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 26 {
        let slot = ctx.sock_conn_id[fd] as usize;
        if slot < MAX_UNIX_LISTENERS {
            print(b"UNIX-LISTEN P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" slot="); print_u64(slot as u64);
            print(b"\n");
        }
    }
    reply_val(ctx.ep_cap, 0);
}

pub(crate) fn sys_setsockopt(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

pub(crate) fn sys_getsockname(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let sockaddr_ptr = msg.regs[1];
    let addrlen_ptr = msg.regs[2];

    // AF_UNIX getpeername → -ENOTCONN (no peer), getsockname → 0 with zeroed addr
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 26 {
        if syscall_nr == SYS_GETPEERNAME {
            reply_val(ep_cap, -ENOTCONN);
            return;
        }
        // getsockname: return zeroed AF_UNIX sockaddr
        if sockaddr_ptr != 0 {
            let mut sa = [0u8; 110];
            sa[0] = 1; // AF_UNIX (little-endian u16)
            ctx.guest_write(sockaddr_ptr, &sa);
        }
        if addrlen_ptr != 0 {
            ctx.guest_write(addrlen_ptr, &2u32.to_le_bytes());
        }
        reply_val(ep_cap, 0);
        return;
    }

    if sockaddr_ptr != 0 {
        let mut sa = [0u8; 16];
        sa[0] = 2; // AF_INET (little-endian u16)
        if syscall_nr == SYS_GETSOCKNAME {
            sa[4] = 10; sa[5] = 0; sa[6] = 2; sa[7] = 15;
        }
        ctx.guest_write(sockaddr_ptr, &sa);
    }
    if addrlen_ptr != 0 {
        ctx.guest_write(addrlen_ptr, &16u32.to_le_bytes());
    }
    reply_val(ep_cap, 0);
}

pub(crate) fn sys_getsockopt(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let optval_ptr = msg.regs[3];
    let optlen_ptr = msg.regs[4];
    if optval_ptr != 0 {
        ctx.guest_write(optval_ptr, &0i32.to_le_bytes());
    }
    if optlen_ptr != 0 {
        ctx.guest_write(optlen_ptr, &4u32.to_le_bytes());
    }
    reply_val(ep_cap, 0);
}

pub(crate) fn sys_shutdown(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

pub(crate) fn sys_select(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let pid = ctx.pid;
    let ep_cap = ctx.ep_cap;
    let nfds = (msg.regs[0] as usize).min(GRP_MAX_FDS);
    let readfds_ptr = msg.regs[1];
    let writefds_ptr = msg.regs[2];
    let exceptfds_ptr = msg.regs[3];
    let timeout_ptr = msg.regs[4];

    let timeout_ms: i64 = if timeout_ptr == 0 {
        -1
    } else {
        let sec = ctx.guest_read_u64(timeout_ptr) as i64;
        let sub = ctx.guest_read_u64(timeout_ptr + 8) as i64;
        if syscall_nr == SYS_SELECT { sec * 1000 + sub / 1000 } else { sec * 1000 + sub / 1_000_000 }
    };

    if exceptfds_ptr != 0 { ctx.guest_write(exceptfds_ptr, &0u64.to_le_bytes()); }

    let rfds_in = if readfds_ptr != 0 { ctx.guest_read_u64(readfds_ptr) } else { 0 };
    let wfds_in = if writefds_ptr != 0 { ctx.guest_read_u64(writefds_ptr) } else { 0 };

    let mut rfds_out: u64 = 0;
    let mut wfds_out: u64 = 0;
    let mut ready: u32 = 0;
    for fd in 0..nfds {
        let bit = 1u64 << fd;
        if fd < GRP_MAX_FDS && ctx.child_fds[fd] != 0 {
            if rfds_in & bit != 0 {
                if poll_fd_readable(ctx, fd) { rfds_out |= bit; ready += 1; }
            }
            if wfds_in & bit != 0 {
                wfds_out |= bit; ready += 1;
            }
        }
    }

    if ready > 0 || timeout_ms == 0 {
        if readfds_ptr != 0 { ctx.guest_write(readfds_ptr, &rfds_out.to_le_bytes()); }
        if writefds_ptr != 0 { ctx.guest_write(writefds_ptr, &wfds_out.to_le_bytes()); }
        reply_val(ep_cap, ready as i64);
    } else {
        // No fds ready — use PIPE_RETRY_TAG for kernel-side retry
        mark_pipe_retry_on(ctx.pid, 0xFF);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    }
}

pub(crate) fn sys_epoll_create(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let mut efd: i64 = -24; // -EMFILE
    for f in 3..GRP_MAX_FDS {
        if ctx.child_fds[f] == 0 {
            ctx.child_fds[f] = 21; // kind 21 = epoll
            efd = f as i64;
            break;
        }
    }
    reply_val(ep_cap, efd);
}

pub(crate) fn sys_epoll_ctl(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let _epfd = msg.regs[0] as usize;
    let op = msg.regs[1] as u32;
    let fd = msg.regs[2] as i32;
    let event_ptr = msg.regs[3];
    let (events, data) = if event_ptr != 0 {
        let mut evbuf = [0u8; 12];
        ctx.guest_read(event_ptr, &mut evbuf);
        let ev = u32::from_le_bytes([evbuf[0], evbuf[1], evbuf[2], evbuf[3]]);
        let d = u64::from_le_bytes([evbuf[4], evbuf[5], evbuf[6], evbuf[7], evbuf[8], evbuf[9], evbuf[10], evbuf[11]]);
        (ev, d)
    } else { (0, 0) };
    match op {
        1 => { // EPOLL_CTL_ADD
            if let Some(i) = ctx.epoll_reg_fd.iter().position(|&x| x == -1) {
                ctx.epoll_reg_fd[i] = fd;
                ctx.epoll_reg_events[i] = events;
                ctx.epoll_reg_data[i] = data;
                let kind = if (fd as usize) < GRP_MAX_FDS { ctx.child_fds[fd as usize] } else { 0 };
                print(b"EPOLL-ADD P"); print_u64(ctx.pid as u64);
                print(b" fd="); print_u64(fd as u64);
                print(b" ev="); crate::framebuffer::print_hex64(events as u64);
                print(b" k="); print_u64(kind as u64);
                print(b"\n");
            }
            reply_val(ep_cap, 0);
        }
        2 => { // EPOLL_CTL_DEL
            if let Some(i) = ctx.epoll_reg_fd.iter().position(|&x| x == fd) {
                ctx.epoll_reg_fd[i] = -1;
            }
            reply_val(ep_cap, 0);
        }
        3 => { // EPOLL_CTL_MOD
            if let Some(i) = ctx.epoll_reg_fd.iter().position(|&x| x == fd) {
                ctx.epoll_reg_events[i] = events;
                ctx.epoll_reg_data[i] = data;
            }
            reply_val(ep_cap, 0);
        }
        _ => reply_val(ep_cap, -EINVAL),
    }
}

pub(crate) fn sys_epoll_wait(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let events_ptr = msg.regs[1];
    let max_events = (msg.regs[2] as usize).min(32);
    let timeout = msg.regs[3] as i32;

    // Debug: first epoll_wait call per-process, dump registered fds
    static mut EPOLL_DBG_DONE: [bool; 16] = [false; 16];
    if ctx.pid < 16 && !unsafe { EPOLL_DBG_DONE[ctx.pid] } {
        unsafe { EPOLL_DBG_DONE[ctx.pid] = true; }
        print(b"EPOLL-WAIT-DBG P"); print_u64(ctx.pid as u64);
        print(b" timeout="); print_u64(timeout as u64);
        print(b" regs:");
        for i in 0..MAX_EPOLL_ENTRIES {
            if ctx.epoll_reg_fd[i] >= 0 {
                let rfd = ctx.epoll_reg_fd[i] as usize;
                let kind = if rfd < GRP_MAX_FDS { ctx.child_fds[rfd] } else { 0 };
                print(b" [fd="); print_u64(rfd as u64);
                print(b" k="); print_u64(kind as u64);
                print(b" ev="); crate::framebuffer::print_hex64(ctx.epoll_reg_events[i] as u64);
                print(b"]");
            }
        }
        // Check listener status
        for i in 0..MAX_EPOLL_ENTRIES {
            if ctx.epoll_reg_fd[i] >= 0 {
                let rfd = ctx.epoll_reg_fd[i] as usize;
                if rfd < GRP_MAX_FDS && ctx.child_fds[rfd] == 26 {
                    let listener = ctx.sock_conn_id[rfd] as usize;
                    let has_pending = crate::fd::unix_listener_has_pending(listener);
                    print(b" LISTENER-fd="); print_u64(rfd as u64);
                    print(b" slot="); print_u64(listener as u64);
                    print(b" pending="); print_u64(has_pending as u64);
                }
            }
        }
        print(b"\n");
    }

    let mut ready_count = 0usize;
    for i in 0..MAX_EPOLL_ENTRIES {
        if ctx.epoll_reg_fd[i] < 0 { continue; }
        if ready_count >= max_events { break; }
        let rfd = ctx.epoll_reg_fd[i] as usize;
        let wanted = ctx.epoll_reg_events[i];
        let mut revents = 0u32;
        if rfd < GRP_MAX_FDS {
            let kind = ctx.child_fds[rfd];
            if kind == 0 {
                revents |= 0x10; // EPOLLHUP
            } else {
                if wanted & 1 != 0 {
                    if kind == 1 {
                        if unsafe { kb_has_char() } { revents |= 1; }
                    } else if kind == 22 {
                        if let Some(s) = ctx.eventfd_slot_fd.iter().position(|&x| x == rfd) {
                            if ctx.eventfd_counter[s] > 0 { revents |= 1; }
                        }
                    } else if kind == 23 {
                        if let Some(s) = ctx.timerfd_slot_fd.iter().position(|&x| x == rfd) {
                            let exp = ctx.timerfd_expiry_tsc[s];
                            if exp != 0 && rdtsc() >= exp { revents |= 1; }
                        }
                    } else if kind == 10 {
                        if poll_fd_readable(ctx, rfd) { revents |= 1; }
                    } else if kind == 13 || kind == 12 || kind == 15 {
                        revents |= 1;
                    } else if kind == 16 {
                        revents |= 1;
                    } else if kind == 26 || kind == 27 || kind == 28 {
                        if poll_fd_readable(ctx, rfd) { revents |= 1; }
                    }
                }
                if wanted & 4 != 0 {
                    if kind == 2 || kind == 8 || kind == 11 || kind == 16 || kind == 17 || kind == 22 || kind == 27 || kind == 28 {
                        revents |= 4;
                    }
                }
            }
        }
        if revents != 0 {
            let ep = events_ptr + (ready_count as u64) * 12;
            let mut evbuf = [0u8; 12];
            evbuf[..4].copy_from_slice(&revents.to_le_bytes());
            evbuf[4..12].copy_from_slice(&ctx.epoll_reg_data[i].to_le_bytes());
            ctx.guest_write(ep, &evbuf);
            ready_count += 1;
        }
    }
    if ready_count > 0 || timeout == 0 {
        reply_val(ep_cap, ready_count as i64);
    } else {
        let deadline = rdtsc() + (timeout as u64).min(30000) * 2_000_000;
        loop {
            let mut found = false;
            for i in 0..MAX_EPOLL_ENTRIES {
                if ctx.epoll_reg_fd[i] < 0 { continue; }
                let rfd = ctx.epoll_reg_fd[i] as usize;
                let wanted = ctx.epoll_reg_events[i];
                if rfd < GRP_MAX_FDS {
                    let kind = ctx.child_fds[rfd];
                    let mut rev = 0u32;
                    if wanted & 1 != 0 && kind == 1 && unsafe { kb_has_char() } { rev |= 1; }
                    if wanted & 1 != 0 && kind == 22 {
                        if let Some(s) = ctx.eventfd_slot_fd.iter().position(|&x| x == rfd) {
                            if ctx.eventfd_counter[s] > 0 { rev |= 1; }
                        }
                    }
                    if wanted & 1 != 0 && kind == 23 {
                        if let Some(s) = ctx.timerfd_slot_fd.iter().position(|&x| x == rfd) {
                            if ctx.timerfd_expiry_tsc[s] != 0 && rdtsc() >= ctx.timerfd_expiry_tsc[s] { rev |= 1; }
                        }
                    }
                    if wanted & 1 != 0 && (kind == 26 || kind == 27 || kind == 28) {
                        if poll_fd_readable(ctx, rfd) { rev |= 1; }
                    }
                    if rev != 0 {
                        let ep = events_ptr + (ready_count as u64) * 12;
                        let mut evbuf = [0u8; 12];
                        evbuf[..4].copy_from_slice(&rev.to_le_bytes());
                        evbuf[4..12].copy_from_slice(&ctx.epoll_reg_data[i].to_le_bytes());
                        ctx.guest_write(ep, &evbuf);
                        ready_count += 1;
                        found = true;
                        if ready_count >= max_events { break; }
                    }
                }
            }
            if found || rdtsc() >= deadline { break; }
            sys::yield_now();
        }
        reply_val(ep_cap, ready_count as i64);
    }
}

pub(crate) fn sys_socketpair(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let domain = msg.regs[0] as u32;
    let sock_type = msg.regs[1] as u32;
    let sv_ptr = msg.regs[3];
    let sock_cloexec = sock_type & 0x80000;

    if domain != 1 {
        // Only AF_UNIX supported
        reply_val(ep_cap, -EAFNOSUPPORT);
        return;
    }

    // Allocate a proper AF_UNIX connection (two pipes for bidirectional I/O)
    let conn = crate::fd::unix_conn_alloc();
    if conn.is_none() {
        reply_val(ep_cap, -ENOMEM);
        return;
    }
    let (conn_slot, _pipe_a, _pipe_b) = conn.unwrap();

    let mut fd1 = None;
    let mut fd2 = None;
    for i in 3..GRP_MAX_FDS {
        if ctx.child_fds[i] == 0 {
            if fd1.is_none() { fd1 = Some(i); }
            else if fd2.is_none() { fd2 = Some(i); break; }
        }
    }
    if let (Some(f1), Some(f2)) = (fd1, fd2) {
        // f1 = client end (kind=27): writes to pipe_a, reads from pipe_b
        // f2 = server end (kind=28): writes to pipe_b, reads from pipe_a
        ctx.child_fds[f1] = 27;
        ctx.child_fds[f2] = 28;
        ctx.sock_conn_id[f1] = conn_slot as u32;
        ctx.sock_conn_id[f2] = conn_slot as u32;
        if sock_cloexec != 0 {
            if f1 < 128 { *ctx.fd_cloexec |= 1u128 << f1; }
            if f2 < 128 { *ctx.fd_cloexec |= 1u128 << f2; }
        }
        if sv_ptr != 0 {
            let buf: [u8; 8] = {
                let mut b = [0u8; 8];
                b[..4].copy_from_slice(&(f1 as i32).to_le_bytes());
                b[4..].copy_from_slice(&(f2 as i32).to_le_bytes());
                b
            };
            ctx.guest_write(sv_ptr, &buf);
        }
        reply_val(ep_cap, 0);
    } else {
        // Free the conn slot if we can't allocate fds
        crate::fd::UNIX_CONN_ACTIVE[conn_slot].store(0, core::sync::atomic::Ordering::Release);
        reply_val(ep_cap, -EMFILE);
    }
}

pub(crate) fn sys_accept(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let addr_ptr = msg.regs[1];
    let addrlen_ptr = msg.regs[2];
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 26 {
        let listener = ctx.sock_conn_id[fd] as usize;
        if listener < MAX_UNIX_LISTENERS {
            if let Some(conn_slot) = unix_pending_pop(listener) {
                // Allocate new fd for the accepted connection
                let mut new_fd = None;
                for f in 3..GRP_MAX_FDS {
                    if ctx.child_fds[f] == 0 { new_fd = Some(f); break; }
                }
                if let Some(nf) = new_fd {
                    // Server side: kind=28, reads from pipe_a, writes to pipe_b
                    ctx.child_fds[nf] = 28;
                    ctx.sock_conn_id[nf] = conn_slot as u32;
                    // Write sockaddr_un if requested
                    if addr_ptr != 0 {
                        let mut sa = [0u8; 2];
                        sa[0] = 1; // AF_UNIX
                        ctx.guest_write(addr_ptr, &sa);
                    }
                    if addrlen_ptr != 0 {
                        ctx.guest_write(addrlen_ptr, &2u32.to_le_bytes());
                    }
                    print(b"UNIX-ACCEPT P"); print_u64(ctx.pid as u64);
                    print(b" fd="); print_u64(nf as u64);
                    print(b" conn="); print_u64(conn_slot as u64);
                    print(b"\n");
                    reply_val(ctx.ep_cap, nf as i64);
                } else {
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            } else {
                reply_val(ctx.ep_cap, -EAGAIN);
            }
        } else {
            reply_val(ctx.ep_cap, -EINVAL);
        }
    } else {
        reply_val(ctx.ep_cap, -EAGAIN);
    }
}
