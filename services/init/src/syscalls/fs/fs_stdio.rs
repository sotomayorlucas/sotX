// ---------------------------------------------------------------------------
// fs_stdio.rs — stdin/stdout/stderr read/write + ioctl (terminal)
// Extracted from fs.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use crate::exec::reply_val;
use crate::process::*;
use crate::fd::*;
use crate::framebuffer::{print, print_u64, fb_putchar, kb_has_char, kb_read_char};
use crate::syscalls::context::SyscallContext;

/// Handle sys_read for stdin (kind=1).
pub(crate) fn read_stdin(ctx: &mut SyscallContext, buf_ptr: u64, len: usize) {
    if len == 0 { reply_val(ctx.ep_cap, 0); return; }
    loop {
        let s = sig_dequeue(ctx.pid);
        if s != 0 && sig_dispatch(ctx.pid, s) >= 1 {
            reply_val(ctx.ep_cap, -EINTR); break;
        }
        match unsafe { kb_read_char() } {
            Some(0x03) => { reply_val(ctx.ep_cap, -EINTR); break; }
            Some(ch) => {
                ctx.guest_write(buf_ptr, &[ch]);
                let reply = IpcMsg {
                    tag: 0,
                    regs: [1, ch as u64, 0, 0, 0, 0, 0, 0],
                };
                let _ = sys::send(ctx.ep_cap, &reply);
                break;
            }
            None => { sys::yield_now(); }
        }
    }
}

/// Handle sys_write for stdout/stderr (kind=2).
pub(crate) fn write_stdout(ctx: &mut SyscallContext, msg: &IpcMsg, buf_ptr: u64, len: usize) {
    let safe_len = len.min(4096);
    let mut local_buf = [0u8; 4096];
    ctx.guest_read(buf_ptr, &mut local_buf[..safe_len]);
    for i in 0..safe_len { sys::debug_print(local_buf[i]); unsafe { fb_putchar(local_buf[i]); } }
    // Detect "partial write" from Wine's server_protocol_error
    if safe_len >= 7 {
        for j in 0..safe_len.saturating_sub(6) {
            if &local_buf[j..j+7] == b"partial" {
                let tid = msg.regs[6];
                let mut regs = [0u64; 20];
                let _ = sys::get_thread_regs(tid, &mut regs);
                let rip = if regs[18] != 0 { regs[18] } else { regs[2] };
                print(b"\n!!! PARTIAL-SRC P"); print_u64(ctx.pid as u64);
                print(b" tid="); print_u64(tid);
                print(b" rip="); crate::framebuffer::print_hex64(rip);
                print(b" rsp="); crate::framebuffer::print_hex64(regs[15]);
                print(b" rax="); print_u64(regs[0]);
                print(b" rbp="); crate::framebuffer::print_hex64(regs[6]);
                // Read return address from stack
                let rbp = regs[6];
                if rbp > 0x1000 && rbp < 0x800000000000 {
                    let mut ret_buf = [0u8; 8];
                    ctx.guest_read(rbp + 8, &mut ret_buf);
                    let ret_addr = u64::from_le_bytes(ret_buf);
                    print(b" ret="); crate::framebuffer::print_hex64(ret_addr);
                }
                print(b"\n");
                break;
            }
        }
    }
    reply_val(ctx.ep_cap, safe_len as i64);
}

// ---------------------------------------------------------------------------
// SYS_ioctl -- terminal emulation
// ---------------------------------------------------------------------------
pub(crate) fn sys_ioctl(ctx: &mut SyscallContext, msg: &IpcMsg) {
    use sotos_common::linux_abi::*;
    let fd = msg.regs[0] as usize;
    let req = msg.regs[1] as u32;
    if fd <= 2 {
        match req {
            TCGETS => {
                let buf_addr = msg.regs[2];
                if buf_addr != 0 {
                    // Kernel TCGETS writes struct __kernel_termios (36 bytes on x86_64).
                    // Layout: c_iflag(4) c_oflag(4) c_cflag(4) c_lflag(4) c_line(1) c_cc[19].
                    let mut termios = [0u8; 36];
                    let ciflag = 0x0100u32 | 0x0400; // ICRNL | IXON
                    let coflag = 0x0001u32 | 0x0004; // OPOST | ONLCR
                    let ccflag = 0x0030u32 | 0x0080 | 0x000F; // CS8|CREAD|B38400
                    let clflag = 0x0008u32 | 0x0010 | 0x0020 | 0x0002 | 0x0001 | 0x8000 | 0x0200 | 0x0800;
                    termios[0..4].copy_from_slice(&ciflag.to_le_bytes());
                    termios[4..8].copy_from_slice(&coflag.to_le_bytes());
                    termios[8..12].copy_from_slice(&ccflag.to_le_bytes());
                    termios[12..16].copy_from_slice(&clflag.to_le_bytes());
                    // c_line at byte 16 = 0, c_cc starts at byte 17
                    termios[17] = 0x03;    // VINTR = Ctrl-C
                    termios[18] = 0x1C;    // VQUIT
                    termios[19] = 0x7F;    // VERASE
                    termios[20] = 0x15;    // VKILL
                    termios[21] = 0x04;    // VEOF
                    termios[23] = 0x01;    // VMIN
                    termios[30] = 0x1A;    // VSUSP
                    ctx.guest_write(buf_addr, &termios);
                }
                reply_val(ctx.ep_cap, 0);
            }
            TCSETS | TCSETSW | TCSETSF => reply_val(ctx.ep_cap, 0),
            TIOCGWINSZ => {
                let (cols, rows, xpix, ypix) = crate::framebuffer::con_dimensions();
                let ws = Winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: xpix,
                    ws_ypixel: ypix,
                };
                let buf_addr = msg.regs[2];
                if buf_addr != 0 {
                    let bytes: [u8; 8] = unsafe { core::mem::transmute(ws) };
                    ctx.guest_write(buf_addr, &bytes);
                }
                reply_val(ctx.ep_cap, 0);
            }
            TIOCSWINSZ => reply_val(ctx.ep_cap, 0),
            TIOCGPGRP | TIOCSPGRP => {
                if req == TIOCGPGRP {
                    let buf_addr = msg.regs[2];
                    if buf_addr != 0 { ctx.guest_write(buf_addr, &(ctx.pid as i32).to_le_bytes()); }
                }
                reply_val(ctx.ep_cap, 0);
            }
            FIONREAD => {
                let buf_addr = msg.regs[2];
                if buf_addr != 0 {
                    let avail: i32 = if unsafe { kb_has_char() } { 1 } else { 0 };
                    ctx.guest_write(buf_addr, &avail.to_le_bytes());
                }
                reply_val(ctx.ep_cap, 0);
            }
            _ => reply_val(ctx.ep_cap, -ENOTTY), // -ENOTTY
        }
    } else {
        // Check FD kind for DRM or evdev ioctls
        let kind = ctx.child_fds[fd];
        if kind == 30 {
            // DRM device ioctl
            let ret = crate::drm::drm_ioctl(ctx, msg.regs[1], msg.regs[2]);
            reply_val(ctx.ep_cap, ret);
        } else if kind == 31 || kind == 32 {
            // evdev device ioctl
            let device = if kind == 31 { 0u8 } else { 1u8 };
            let ret = crate::evdev::evdev_ioctl(ctx, fd, msg.regs[1], msg.regs[2], device);
            reply_val(ctx.ep_cap, ret);
        } else {
            reply_val(ctx.ep_cap, -ENOTTY);
        }
    }
}

/// Handle readv for stdin (kind=1).
pub(crate) fn readv_stdin(ctx: &mut SyscallContext, iov_ptr: u64, iovcnt: usize) {
    if iovcnt > 0 && iov_ptr < 0x0000_8000_0000_0000 {
        let base = unsafe { *(iov_ptr as *const u64) };
        loop {
            let s = sig_dequeue(ctx.pid);
            if s != 0 && sig_dispatch(ctx.pid, s) >= 1 {
                reply_val(ctx.ep_cap, -EINTR); break;
            }
            match unsafe { kb_read_char() } {
                Some(ch) => {
                    if base != 0 { unsafe { *(base as *mut u8) = ch; } }
                    reply_val(ctx.ep_cap, 1); break;
                }
                None => { sys::yield_now(); }
            }
        }
    } else {
        reply_val(ctx.ep_cap, 0);
    }
}

/// Handle writev for stdout/stderr (kind=2).
pub(crate) fn writev_stdout(ctx: &mut SyscallContext, msg: &IpcMsg, iov_ptr: u64, iovcnt: usize) {
    let mut total: usize = 0;
    let cnt = iovcnt.min(16);
    let mut saw_partial = false;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        if entry + 16 > 0x0000_8000_0000_0000 { break; }
        let base = ctx.guest_read_u64(entry);
        let len = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || len == 0 { continue; }
        let safe_len = len.min(4096);
        let mut local_buf = [0u8; 4096];
        ctx.guest_read(base, &mut local_buf[..safe_len]);
        for j in 0..safe_len { sys::debug_print(local_buf[j]); unsafe { fb_putchar(local_buf[j]); } }
        // Detect "partial write" in stderr output
        if safe_len >= 7 {
            for j in 0..safe_len.saturating_sub(6) {
                if &local_buf[j..j+7] == b"partial" { saw_partial = true; break; }
            }
        }
        total += safe_len;
    }
    if saw_partial {
        // Dump caller's saved registers to identify which writev failed
        let tid = msg.regs[6];
        let mut regs = [0u64; 20];
        let _ = sys::get_thread_regs(tid, &mut regs);
        print(b"\n!!! PARTIAL-WRITE-CALLER P"); print_u64(ctx.pid as u64);
        print(b" tid="); print_u64(tid);
        print(b" rip="); crate::framebuffer::print_hex64(if regs[18] != 0 { regs[18] } else { regs[2] });
        print(b" rsp="); crate::framebuffer::print_hex64(regs[15]);
        print(b" rax="); print_u64(regs[0]);
        // Dump return addresses from stack (rbp chain)
        let rbp = regs[6]; // saved rbp
        print(b" rbp="); crate::framebuffer::print_hex64(rbp);
        // Read return address at [rbp+8]
        if rbp > 0x1000 && rbp < 0x800000000000 {
            let mut ret_buf = [0u8; 8];
            ctx.guest_read(rbp + 8, &mut ret_buf);
            let ret_addr = u64::from_le_bytes(ret_buf);
            print(b" ret="); crate::framebuffer::print_hex64(ret_addr);
        }
        print(b"\n");
    }
    reply_val(ctx.ep_cap, total as i64);
}
