//! System-inspection and process-control built-ins:
//! ls, ps, uptime, top, threads, meminfo, syslog, netmirror, kill, fork.

use crate::syscall::*;
use crate::util::*;
use crate::err;
use super::util::{kernel_syscall0};

// --- top ---

/// top -list threads with CPU usage.
pub fn cmd_top() {
    // Use custom syscall 142 to get thread count, 140 to get thread info.
    print(b"  TID  STATE   PRI  CPU_TICKS  MEM  TYPE\n");
    // Iterate up to 256 thread pool slots.
    for idx in 0..256u64 {
        let ret: u64;
        let tid: u64;
        let state: u64;
        let pri: u64;
        let ticks: u64;
        let mem: u64;
        let is_user: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 140u64 => ret,
                inlateout("rdi") idx => tid,
                lateout("rsi") state,
                lateout("rdx") pri,
                lateout("rcx") _,
                lateout("r11") _,
                lateout("r8") ticks,
                lateout("r9") mem,
                lateout("r10") is_user,
                options(nostack),
            );
        }
        if (ret as i64) < 0 { continue; }
        // Format: TID STATE PRI CPU_TICKS MEM TYPE
        print(b"  ");
        if tid < 10 { print(b"  "); } else if tid < 100 { print(b" "); }
        print_u64(tid);
        print(b"  ");
        match state {
            0 => print(b"READY  "),
            1 => print(b"RUN    "),
            2 => print(b"BLOCK  "),
            3 => print(b"FAULT  "),
            _ => print(b"DEAD   "),
        }
        if pri < 10 { print(b"  "); } else if pri < 100 { print(b" "); }
        print_u64(pri);
        print(b"  ");
        // Right-align ticks in 9 chars.
        let mut tstr = [b' '; 9];
        let mut t = ticks;
        let mut ti = 8;
        if t == 0 { tstr[ti] = b'0'; }
        while t > 0 { tstr[ti] = b'0' + (t % 10) as u8; t /= 10; if ti > 0 { ti -= 1; } }
        print(&tstr);
        print(b"  ");
        if mem < 10 { print(b"  "); } else if mem < 100 { print(b" "); }
        print_u64(mem);
        print(b"  ");
        if is_user != 0 { print(b"user\n"); } else { print(b"kern\n"); }
    }
}

// --- ls ---

pub fn cmd_ls() {
    let mut path_buf = [0u8; 4];
    let path = null_terminate(b".", &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        err!(b"ls", b"cannot open directory");
        return;
    }
    let mut buf = [0u8; 1024];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    linux_close(fd as u64);
}

pub fn cmd_ls_path(path: &[u8]) {
    // Save cwd, cd to path, ls, cd back
    let mut old_cwd = [0u8; 128];
    let cwd_ret = linux_getcwd(old_cwd.as_mut_ptr(), old_cwd.len() as u64);

    let mut path_buf = [0u8; 64];
    let p = null_terminate(path, &mut path_buf);
    if linux_chdir(p) < 0 {
        err!(b"ls", b"cannot access", path);
        return;
    }
    cmd_ls();
    // Restore cwd
    if cwd_ret > 0 {
        linux_chdir(old_cwd.as_ptr());
    }
}

// --- ps ---

pub fn cmd_ps() {
    let mut path_buf = [0u8; 8];
    let path = null_terminate(b"/proc", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        err!(b"ps", b"cannot open /proc");
        return;
    }
    let mut buf = [0u8; 1024];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 { break; }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    linux_close(fd as u64);
}

// --- uptime ---

pub fn cmd_uptime() {
    let mut path_buf = [0u8; 16];
    let path = null_terminate(b"/proc/uptime", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        err!(b"uptime", b"cannot read /proc/uptime");
        return;
    }
    let mut buf = [0u8; 64];
    let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
    if n > 0 {
        print(b"up ");
        linux_write(1, buf.as_ptr(), n as usize);
        print(b" ticks\n");
    }
    linux_close(fd as u64);
}

// --- kill ---

pub fn cmd_kill(args: &[u8]) {
    match find_space(args) {
        Some(sp) => {
            let pid = parse_u64_simple(&args[..sp]);
            let sig = parse_u64_simple(trim(&args[sp + 1..]));
            let ret = linux_kill(pid, sig);
            if ret < 0 {
                err!(b"kill", b"no such process");
            }
        }
        None => {
            // No signal specified, default to SIGKILL(9)
            let pid = parse_u64_simple(args);
            let ret = linux_kill(pid, 9);
            if ret < 0 {
                err!(b"kill", b"no such process");
            }
        }
    }
}

// --- fork ---

pub fn cmd_fork() {
    let child_fn = crate::exec::child_shell_main as *const () as u64;
    let child_pid = linux_clone(child_fn);
    if child_pid < 0 {
        err!(b"fork", b"failed");
        return;
    }
    print(b"forked child pid=");
    print_u64(child_pid as u64);
    print(b"\nwaiting...\n");
    let status = linux_waitpid(child_pid as u64);
    print(b"child exited status=");
    print_u64(status as u64);
    print(b"\n");
}

// --- syslog ---

pub fn cmd_syslog(max_entries: u64) {
    let mut num_buf = [0u8; 10];
    let num_len = u64_to_dec(max_entries, &mut num_buf);
    if !open_virtual_and_print(b"/proc/syslog/", &num_buf[..num_len]) {
        err!(b"syslog", b"cannot read /proc/syslog");
    }
}

// --- netmirror ---

pub fn cmd_netmirror(arg: &[u8]) {
    if !open_virtual_and_print(b"/proc/netmirror/", arg) {
        err!(b"netmirror", b"failed");
    }
}

// --- threads ---

/// Show total kernel thread count (syscall 142 = ThreadCount).
pub fn cmd_threads() {
    let count = kernel_syscall0(142) as u64;
    print(b"Total threads: ");
    print_u64(count);
    print(b"\n");
}

// --- meminfo ---

/// Show free physical memory (syscall 252 = DebugFreeFrames).
pub fn cmd_meminfo() {
    let frames = kernel_syscall0(252) as u64;
    let bytes = frames * 4096;
    let mb = bytes / (1024 * 1024);
    print(b"Free frames: ");
    print_u64(frames);
    print(b"\nFree memory: ");
    print_u64(mb);
    print(b" MiB (");
    print_u64(bytes / 1024);
    print(b" KiB)\n");
}
