// ---------------------------------------------------------------------------
// fs_pipe.rs — Pipe operations: sys_pipe, sys_pipe2, pipe read/write,
//              AF_UNIX socket read/write, deadlock detection
// Extracted from fs.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::fd::*;
use crate::child_handler::mark_pipe_retry_on;
use crate::framebuffer::{print, print_u64};
use crate::syscalls::context::SyscallContext;

/// Handle sys_read for pipe read end (kind=10).
pub(crate) fn read_pipe(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let pipe_id = ctx.sock_conn_id[fd] as usize;
    let want = len.min(4096);
    let mut tmp = [0u8; 4096];
    let n = pipe_read(pipe_id, &mut tmp[..want]);
    trace!(Trace, FS, {
        let wc = pipe_writer_closed(pipe_id);
        print(b"PIPE-RD P"); print_u64(ctx.pid as u64);
        print(b" fd="); print_u64(fd as u64);
        print(b" pipe="); print_u64(pipe_id as u64);
        print(b" n="); print_u64(n as u64);
        print(b" wc="); print_u64(wc as u64);
        if n > 0 {
            print(b" [");
            for i in 0..n.min(16) {
                let hi = tmp[i] >> 4;
                let lo = tmp[i] & 0xF;
                let hc = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                let lc = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                print(&[hc, lc]);
            }
            print(b"]");
        }
    });
    if n > 0 {
        crate::child_handler::clear_pipe_stall(ctx.pid);
        ctx.guest_write(buf_ptr, &tmp[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else if pipe_writer_closed(pipe_id) {
        // Track consecutive EOF reads on this pipe. After 500 EOFs,
        // return -EIO to break infinite retry loops (e.g., Wine's
        // glibc init spinning on read(0) after fork).
        static mut PIPE_EOF_COUNT: [u32; 64] = [0; 64];
        let eof_count = unsafe { &mut PIPE_EOF_COUNT[fd.min(63)] };
        *eof_count += 1;
        if *eof_count > 100 {
            // Keep returning -EIO permanently (don't reset counter)
            reply_val(ctx.ep_cap, -5); // -EIO
        } else {
            reply_val(ctx.ep_cap, 0); // EOF
        }
    } else {
        // No data, writer alive — ask kernel to retry after yielding.
        // Deadlock detection: only trigger on REAL cycles where two
        // processes each hold the write end of the other's pipe.
        // Two processes waiting for a third (e.g., wineserver) is NOT
        // a deadlock — just a temporary stall.
        let stall = unsafe { crate::child_handler::PIPE_STALL[ctx.pid] };
        if stall > 50000 {
            // Find another process also stalled for a long time
            let mut other_pid = 0usize;
            for p in 1..16usize {
                if p != ctx.pid && unsafe { crate::child_handler::PIPE_STALL[p] } > 50000 {
                    other_pid = p;
                    break;
                }
            }
            if other_pid != 0 {
                let other_pipe = unsafe { crate::child_handler::PIPE_STALL_ID[other_pid] } as usize;
                // Verify REAL cycle: the writer of MY pipe must be other_pid,
                // AND the writer of THEIR pipe must be me. If either pipe's
                // writer is a third process, this is NOT a deadlock cycle.
                let my_writer = crate::fd::pipe_write_owner(pipe_id);
                let their_writer = if other_pipe < crate::fd::MAX_PIPES {
                    crate::fd::pipe_write_owner(other_pipe)
                } else { 0 };
                let is_cycle = my_writer == other_pid && their_writer == ctx.pid;
                if is_cycle {
                    trace!(Error, FS, {
                        print(b"PIPE-DEADLOCK pid="); print_u64(ctx.pid as u64);
                        print(b" pipe="); print_u64(pipe_id as u64);
                        print(b" other="); print_u64(other_pid as u64);
                        print(b" other_pipe="); print_u64(other_pipe as u64);
                    });
                    crate::fd::pipe_close_all_writers(pipe_id);
                    if other_pipe < crate::fd::MAX_PIPES && other_pipe != pipe_id {
                        crate::fd::pipe_close_all_writers(other_pipe);
                    }
                    crate::child_handler::clear_pipe_stall(ctx.pid);
                    crate::child_handler::clear_pipe_stall(other_pid);
                    unsafe {
                        crate::child_handler::DEADLOCK_EOF[ctx.pid] = true;
                        crate::child_handler::DEADLOCK_EOF[other_pid] = true;
                    }
                } else {
                    // Not a real cycle — just two processes waiting for a
                    // third (e.g., wineserver). Log but don't kill pipes.
                    if stall % 10000 == 0 {
                        trace!(Warn, FS, {
                            print(b"PIPE-STALL pid="); print_u64(ctx.pid as u64);
                            print(b" pipe="); print_u64(pipe_id as u64);
                            print(b" writer="); print_u64(my_writer as u64);
                            print(b" stall="); print_u64(stall);
                        });
                    }
                }
            }
        }
        // Yield before retry to avoid starving other processes
        for _ in 0..8 { sys::yield_now(); }
        mark_pipe_retry_on(ctx.pid, pipe_id);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ctx.ep_cap, &reply);
    }
}

/// Handle sys_read for AF_UNIX connected socket (kind=27|28).
pub(crate) fn read_unix_socket(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let conn = ctx.sock_conn_id[fd] as usize;
    if conn < crate::fd::MAX_UNIX_CONNS {
        let pipe_id = if ctx.child_fds[fd] == 27 {
            unsafe { crate::fd::UNIX_CONN_PIPE_B[conn] as usize }
        } else {
            unsafe { crate::fd::UNIX_CONN_PIPE_A[conn] as usize }
        };
        let want = len.min(4096);
        let mut tmp = [0u8; 4096];
        let n = pipe_read(pipe_id, &mut tmp[..want]);
        if n > 0 {
            trace!(Trace, FS, {
                print(b"UXRD P"); print_u64(ctx.pid as u64);
                print(b" fd="); print_u64(fd as u64);
                print(b" n="); print_u64(n as u64);
                print(b" [");
                for i in 0..n.min(16) {
                    let hi = tmp[i] >> 4;
                    let lo = tmp[i] & 0xF;
                    let hc = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                    let lc = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                    print(&[hc, lc]);
                }
                print(b"]");
            });
        }
        if n > 0 {
            ctx.guest_write(buf_ptr, &tmp[..n]);
            reply_val(ctx.ep_cap, n as i64);
        } else if pipe_writer_closed(pipe_id) {
            reply_val(ctx.ep_cap, 0); // EOF
        } else {
            for _ in 0..8 { sys::yield_now(); }
            mark_pipe_retry_on(ctx.pid, pipe_id);
            let reply = sotos_common::IpcMsg {
                tag: sotos_common::PIPE_RETRY_TAG,
                regs: [0; 8],
            };
            let _ = sys::send(ctx.ep_cap, &reply);
        }
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// Handle sys_write for pipe write end (kind=11).
pub(crate) fn write_pipe(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let pipe_id = ctx.sock_conn_id[fd] as usize;
    trace!(Trace, FS, {
        print(b"PIPE-WR P"); print_u64(ctx.pid as u64);
        print(b" fd="); print_u64(fd as u64);
        print(b" pipe="); print_u64(pipe_id as u64);
        print(b" len="); print_u64(len as u64);
    });
    let mut total_written = 0usize;
    let mut broken = false;
    while total_written < len && !broken {
        let chunk = (len - total_written).min(4096);
        let mut local_buf = [0u8; 4096];
        ctx.guest_read(buf_ptr + total_written as u64, &mut local_buf[..chunk]);
        let mut off = 0usize;
        while off < chunk {
            let n = pipe_write(pipe_id, &local_buf[off..chunk]);
            if n > 0 { off += n; }
            else {
                sys::yield_now(); // reader may be slow, keep trying
                sys::yield_now();
            }
        }
        total_written += off;
    }
    if total_written != len {
        trace!(Error, FS, {
            print(b"PW-PARTIAL P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" wrote="); print_u64(total_written as u64);
            print(b"/"); print_u64(len as u64);
        });
    }
    if total_written > 0 {
        reply_val(ctx.ep_cap, total_written as i64);
    } else if broken {
        reply_val(ctx.ep_cap, -EPIPE);
    } else {
        reply_val(ctx.ep_cap, 0);
    }
}

/// Handle sys_write for AF_UNIX connected socket (kind=27|28).
pub(crate) fn write_unix_socket(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let conn = ctx.sock_conn_id[fd] as usize;
    if conn < crate::fd::MAX_UNIX_CONNS {
        let pipe_id = if ctx.child_fds[fd] == 27 {
            unsafe { crate::fd::UNIX_CONN_PIPE_A[conn] as usize }
        } else {
            unsafe { crate::fd::UNIX_CONN_PIPE_B[conn] as usize }
        };
        // UXW tracing disabled for clean output
        // Write ALL bytes (blocking socket semantics). Retry indefinitely
        // until the reader drains the pipe. Wine's wineserver IPC requires
        // full writes -- partial writes cause fatal "wine client error".
        let mut total_written = 0usize;
        let mut broken = false;
        while total_written < len && !broken {
            let chunk = (len - total_written).min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(buf_ptr + total_written as u64, &mut local_buf[..chunk]);
            let mut chunk_off = 0usize;
            while chunk_off < chunk {
                let n = pipe_write(pipe_id, &local_buf[chunk_off..chunk]);
                if n > 0 {
                    chunk_off += n;
                } else {
                    sys::yield_now(); // reader may be slow, keep trying
                    sys::yield_now();
                }
            }
            total_written += chunk_off;
        }
        if total_written > 0 {
            reply_val(ctx.ep_cap, total_written as i64);
        } else if broken {
            reply_val(ctx.ep_cap, -EPIPE);
        } else {
            reply_val(ctx.ep_cap, 0);
        }
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// Handle readv for pipe read end (kind=10).
pub(crate) fn readv_pipe(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let pipe_id = ctx.sock_conn_id[fd] as usize;
    let cnt = iovcnt.min(16);
    let mut total = 0usize;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        // Read pipe data into local buffer, then guest_write to child
        let safe_len = ilen.min(4096);
        let mut local_buf = [0u8; 4096];
        let n = pipe_read(pipe_id, &mut local_buf[..safe_len]);
        if n > 0 {
            trace!(Trace, FS, {
                print(b"PIPE-RV P"); print_u64(ctx.pid as u64);
                print(b" base="); crate::framebuffer::print_hex64(base);
                print(b" ilen="); print_u64(ilen as u64);
                print(b" n="); print_u64(n as u64);
                print(b" iov="); print_u64(i as u64);
            });
            ctx.guest_write(base, &local_buf[..n]);
        }
        total += n;
        if n < safe_len { break; }
    }
    if total > 0 {
        trace!(Debug, FS, {
            print(b"PIPEV-R P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" total="); print_u64(total as u64);
            print(b" pipe="); print_u64(pipe_id as u64);
        });
        reply_val(ctx.ep_cap, total as i64);
    } else if pipe_writer_closed(pipe_id) {
        trace!(Debug, FS, {
            print(b"PIPEV-R P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" pipe="); print_u64(pipe_id as u64);
            print(b" EOF");
        });
        reply_val(ctx.ep_cap, 0); // EOF
    } else {
        // No data, writer alive -- yield then ask kernel to retry
        for _ in 0..8 { sys::yield_now(); }
        mark_pipe_retry_on(ctx.pid, pipe_id);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ctx.ep_cap, &reply);
    }
}

/// Handle writev for pipe write end (kind=11).
pub(crate) fn writev_pipe(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let pipe_id = ctx.sock_conn_id[fd] as usize;
    let cnt = iovcnt.min(16);
    let mut total = 0usize;
    trace!(Trace, FS, {
        if cnt > 0 {
            let mut tlen = 0usize;
            for j in 0..cnt {
                let e = iov_ptr + (j as u64) * 16;
                if e + 16 > 0x0000_8000_0000_0000 { break; }
                let il = ctx.guest_read_u64(e + 8) as usize;
                tlen += il;
            }
            print(b"PIPEV-W P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" pipe="); print_u64(pipe_id as u64);
            print(b" len="); print_u64(tlen as u64);
            print(b" iov="); crate::framebuffer::print_hex64(iov_ptr);
            print(b" cnt="); print_u64(cnt as u64);
        }
    });
    // Compute expected total for partial-write detection
    let mut expected_total = 0usize;
    for j in 0..cnt {
        let e = iov_ptr + (j as u64) * 16;
        if e + 16 > 0x0000_8000_0000_0000 { break; }
        let il = ctx.guest_read_u64(e + 8) as usize;
        expected_total += il;
    }
    trace!(Trace, FS, {
        for j in 0..cnt.min(4) {
            let e = iov_ptr + (j as u64) * 16;
            if e + 16 > 0x0000_8000_0000_0000 { break; }
            let b = ctx.guest_read_u64(e);
            let l = ctx.guest_read_u64(e + 8);
            print(b"IOV P"); print_u64(ctx.pid as u64);
            print(b" ["); print_u64(j as u64);
            print(b"] b="); crate::framebuffer::print_hex64(b);
            print(b" l="); print_u64(l);
        }
    });
    // Pre-read ALL iovec entries in one bulk guest_read to avoid
    // per-entry vm_read races with CoW page faults.
    let mut iov_raw = [0u8; 16 * 16]; // max 16 iovecs * 16 bytes each
    let iov_bytes = cnt * 16;
    if iov_ptr + iov_bytes as u64 <= 0x0000_8000_0000_0000 {
        ctx.guest_read(iov_ptr, &mut iov_raw[..iov_bytes]);
    }
    for i in 0..cnt {
        let off = i * 16;
        let base = u64::from_le_bytes(iov_raw[off..off+8].try_into().unwrap());
        let ilen = u64::from_le_bytes(iov_raw[off+8..off+16].try_into().unwrap()) as usize;
        if ilen == 0 || base == 0 { continue; }
        // Write full iovec in 4096-byte chunks (blocking).
        // Previous code truncated to 4096 -- Wine requests can be larger.
        let mut iov_written = 0usize;
        while iov_written < ilen {
            let chunk = (ilen - iov_written).min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(base + iov_written as u64, &mut local_buf[..chunk]);
            let mut off = 0usize;
            while off < chunk {
                let n = pipe_write(pipe_id, &local_buf[off..chunk]);
                if n > 0 { off += n; }
                else {
                    sys::yield_now();
                    sys::yield_now();
                }
            }
            iov_written += off;
            if off < chunk { break; }
        }
        total += iov_written;
        if iov_written < ilen { break; }
    }
    if total != expected_total && expected_total > 0 {
        trace!(Error, FS, {
            print(b"PIPEV-PARTIAL P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b" wrote="); print_u64(total as u64);
            print(b"/"); print_u64(expected_total as u64);
            print(b" as="); print_u64(ctx.child_as_cap);
            print(b" cnt="); print_u64(cnt as u64);
            for j in 0..cnt.min(4) {
                let e = iov_ptr + (j as u64) * 16;
                if e + 16 > 0x0000_8000_0000_0000 { break; }
                let b = ctx.guest_read_u64(e);
                let l = ctx.guest_read_u64(e + 8);
                print(b" ["); print_u64(b); print(b","); print_u64(l); print(b"]");
            }
        });
    }
    trace!(Trace, FS, {
        print(b"WRITEV-RET P"); print_u64(ctx.pid as u64);
        print(b" total="); print_u64(total as u64);
        print(b" exp="); print_u64(expected_total as u64);
    });
    reply_val(ctx.ep_cap, total as i64);
}

/// Handle writev for AF_UNIX connected socket (kind=27|28).
pub(crate) fn writev_unix_socket(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let conn = ctx.sock_conn_id[fd] as usize;
    if conn < crate::fd::MAX_UNIX_CONNS {
        let pipe_id = if ctx.child_fds[fd] == 27 {
            unsafe { crate::fd::UNIX_CONN_PIPE_A[conn] as usize }
        } else {
            unsafe { crate::fd::UNIX_CONN_PIPE_B[conn] as usize }
        };
        let cnt = iovcnt.min(16);
        let mut total = 0usize;
        // Bulk-read iovec array to avoid per-entry vm_read races
        let mut iov_unix = [0u8; 16 * 16];
        let iov_sz = cnt * 16;
        if iov_ptr + iov_sz as u64 <= 0x0000_8000_0000_0000 {
            ctx.guest_read(iov_ptr, &mut iov_unix[..iov_sz]);
        }
        for i in 0..cnt {
            let off = i * 16;
            let base = u64::from_le_bytes(iov_unix[off..off+8].try_into().unwrap());
            let ilen = u64::from_le_bytes(iov_unix[off+8..off+16].try_into().unwrap()) as usize;
            if base == 0 || ilen == 0 { continue; }
            // Write full iovec (blocking)
            let mut iov_written = 0usize;
            while iov_written < ilen {
                let chunk = (ilen - iov_written).min(4096);
                let mut local_buf = [0u8; 4096];
                ctx.guest_read(base + iov_written as u64, &mut local_buf[..chunk]);
                let mut off = 0usize;
                while off < chunk {
                    let n = pipe_write(pipe_id, &local_buf[off..chunk]);
                    if n > 0 { off += n; }
                    else {
                        sys::yield_now(); // reader may be slow, keep trying
                        sys::yield_now();
                    }
                }
                iov_written += off;
                if off < chunk { break; }
            }
            total += iov_written;
            if iov_written < ilen { break; }
        }
        // Diagnostic: detect partial writes on Unix socket (Wine IPC)
        let mut expected = 0usize;
        for i in 0..cnt {
            let off = i * 16;
            let il = u64::from_le_bytes(iov_unix[off+8..off+16].try_into().unwrap()) as usize;
            expected += il;
        }
        if total != expected && expected > 0 {
            trace!(Error, FS, {
                print(b"UXW-PARTIAL P"); print_u64(ctx.pid as u64);
                print(b" wrote="); print_u64(total as u64);
                print(b"/"); print_u64(expected as u64);
                print(b" cnt="); print_u64(cnt as u64);
            });
        }
        reply_val(ctx.ep_cap, total as i64);
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// Handle close for pipe write end (kind=11).
pub(crate) fn close_pipe_write(ctx: &mut SyscallContext, fd: usize) {
    let pipe_id = ctx.sock_conn_id[fd] as usize;
    if pipe_id < MAX_PIPES {
        let prev = PIPE_WRITE_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
        if ctx.pid >= 3 {
            // CLOSE-PW tracing disabled for clean output
        }
        if prev <= 1 {
            PIPE_WRITE_CLOSED[pipe_id].store(1, Ordering::Release);
            if PIPE_READ_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                pipe_free(pipe_id);
            }
        }
    }
    ctx.sock_conn_id[fd] = 0xFFFF;
}

/// Handle close for pipe read end (kind=10).
pub(crate) fn close_pipe_read(ctx: &mut SyscallContext, fd: usize) {
    let pipe_id = ctx.sock_conn_id[fd] as usize;
    if pipe_id < MAX_PIPES {
        let prev = PIPE_READ_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            PIPE_READ_CLOSED[pipe_id].store(1, Ordering::Release);
            if PIPE_WRITE_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                pipe_free(pipe_id);
            }
        }
    }
    ctx.sock_conn_id[fd] = 0xFFFF;
}

/// Handle close for AF_UNIX listener (kind=26).
pub(crate) fn close_unix_listener(ctx: &mut SyscallContext, fd: usize) {
    let slot = ctx.sock_conn_id[fd] as usize;
    if slot < crate::fd::MAX_UNIX_LISTENERS {
        crate::fd::UNIX_LISTEN_ACTIVE[slot].store(0, Ordering::Release);
        unsafe { crate::fd::UNIX_LISTEN_PATH[slot] = [0; 128]; }
    }
    ctx.sock_conn_id[fd] = 0xFFFF;
}

/// Handle close for AF_UNIX connected socket (kind=27|28).
pub(crate) fn close_unix_socket(ctx: &mut SyscallContext, fd: usize) {
    let conn = ctx.sock_conn_id[fd] as usize;
    if conn < crate::fd::MAX_UNIX_CONNS {
        let old_refs = crate::fd::UNIX_CONN_REFS[conn].fetch_sub(1, Ordering::AcqRel);
        if old_refs <= 1 {
            // Last reference — actually close the connection
            let pipe_a = unsafe { crate::fd::UNIX_CONN_PIPE_A[conn] } as usize;
            let pipe_b = unsafe { crate::fd::UNIX_CONN_PIPE_B[conn] } as usize;
            // Mark both pipes as writer-closed so the other side gets EOF
            if ctx.child_fds[fd] == 27 {
                // Client closing: client writes to pipe_a, reads from pipe_b
                if pipe_a < MAX_PIPES { PIPE_WRITE_CLOSED[pipe_a].store(1, Ordering::Release); }
                if pipe_b < MAX_PIPES { PIPE_READ_CLOSED[pipe_b].store(1, Ordering::Release); }
            } else {
                // Server closing: server writes to pipe_b, reads from pipe_a
                if pipe_b < MAX_PIPES { PIPE_WRITE_CLOSED[pipe_b].store(1, Ordering::Release); }
                if pipe_a < MAX_PIPES { PIPE_READ_CLOSED[pipe_a].store(1, Ordering::Release); }
            }
            // Free pipes if both sides closed
            if pipe_a < MAX_PIPES
                && PIPE_WRITE_CLOSED[pipe_a].load(Ordering::Acquire) != 0
                && PIPE_READ_CLOSED[pipe_a].load(Ordering::Acquire) != 0
            { pipe_free(pipe_a); }
            if pipe_b < MAX_PIPES
                && PIPE_WRITE_CLOSED[pipe_b].load(Ordering::Acquire) != 0
                && PIPE_READ_CLOSED[pipe_b].load(Ordering::Acquire) != 0
            { pipe_free(pipe_b); }
            crate::fd::UNIX_CONN_ACTIVE[conn].store(0, Ordering::Release);
        }
    }
    ctx.sock_conn_id[fd] = 0xFFFF;
}

/// SYS_PIPE (22): create pipe.
pub(crate) fn sys_pipe(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let mut r_fd = None;
    let mut w_fd = None;
    for i in 3..GRP_MAX_FDS {
        if ctx.child_fds[i] == 0 {
            if r_fd.is_none() { r_fd = Some(i); }
            else if w_fd.is_none() { w_fd = Some(i); break; }
        }
    }
    if let (Some(r), Some(w)) = (r_fd, w_fd) {
        if let Some(pipe_id) = pipe_alloc() {
            ctx.child_fds[r] = 10;
            ctx.child_fds[w] = 11;
            ctx.sock_conn_id[r] = pipe_id as u32;
            ctx.sock_conn_id[w] = pipe_id as u32;
            {
                let mut buf = [0u8; 8];
                buf[..4].copy_from_slice(&(r as i32).to_le_bytes());
                buf[4..].copy_from_slice(&(w as i32).to_le_bytes());
                ctx.guest_write(msg.regs[0], &buf);
            }
            trace!(Debug, FS, {
                print(b"FD-PIPE P"); print_u64(ctx.pid as u64);
                print(b" r="); print_u64(r as u64);
                print(b" w="); print_u64(w as u64);
                print(b" pipe="); print_u64(pipe_id as u64);
            });
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else {
        reply_val(ctx.ep_cap, -EMFILE);
    }
}

/// SYS_PIPE2 (293): pipe with flags.
pub(crate) fn sys_pipe2(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let pipefd_ptr = msg.regs[0];
    let flags = msg.regs[1] as u32;
    let mut rfd = None;
    let mut wfd = None;
    for i in 3..GRP_MAX_FDS {
        if ctx.child_fds[i] == 0 {
            if rfd.is_none() { rfd = Some(i); }
            else if wfd.is_none() { wfd = Some(i); break; }
        }
    }
    if let (Some(r), Some(w)) = (rfd, wfd) {
        if let Some(pipe_id) = pipe_alloc() {
            ctx.child_fds[r] = 10;
            ctx.child_fds[w] = 11;
            ctx.sock_conn_id[r] = pipe_id as u32;
            ctx.sock_conn_id[w] = pipe_id as u32;
            // Set close-on-exec if O_CLOEXEC requested
            if flags & O_CLOEXEC != 0 {
                if r < 128 { *ctx.fd_cloexec |= 1u128 << r; }
                if w < 128 { *ctx.fd_cloexec |= 1u128 << w; }
            }
            {
                let mut buf = [0u8; 8];
                buf[..4].copy_from_slice(&(r as i32).to_le_bytes());
                buf[4..].copy_from_slice(&(w as i32).to_le_bytes());
                ctx.guest_write(pipefd_ptr, &buf);
            }
            trace!(Debug, FS, {
                print(b"PIPE2 P"); print_u64(ctx.pid as u64); print(b" r="); print_u64(r as u64);
                print(b"(k="); print_u64(ctx.child_fds[r] as u64);
                print(b") w="); print_u64(w as u64);
                print(b"(k="); print_u64(ctx.child_fds[w] as u64);
                print(b") pipe="); print_u64(pipe_id as u64);
            });
            reply_val(ctx.ep_cap, 0);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
    } else { reply_val(ctx.ep_cap, -EMFILE); }
}
