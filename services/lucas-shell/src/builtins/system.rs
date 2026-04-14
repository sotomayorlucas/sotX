//! System-inspection and process-control built-ins:
//! ls, ps, uptime, top, threads, meminfo, syslog, netmirror, kill, fork.

use crate::syscall::*;
use crate::util::*;
use crate::err;
use crate::color;
use super::util::{kernel_syscall0};

// ---------------------------------------------------------------------------
// Linux dirent64 field offsets (packed struct in kernel ABI)
//   d_ino:    offset 0,  8 bytes
//   d_off:    offset 8,  8 bytes
//   d_reclen: offset 16, 2 bytes
//   d_type:   offset 18, 1 byte
//   d_name:   offset 19, variable (NUL-terminated)
// ---------------------------------------------------------------------------
const DIRENT_NAME_OFF: usize = 19;
const DT_DIR: u8 = 4;
const DT_CHR: u8 = 2;
const DT_BLK: u8 = 6;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;
const DT_FIFO: u8 = 1;

// --- top ---

/// top - list threads with CPU usage.
pub fn cmd_top() {
    // Header: bold
    color::color(color::BOLD);
    print(b"  TID  STATE   PRI  CPU_TICKS  MEM  TYPE\n");
    color::reset();

    // Collect entries so we can find the highest-CPU thread.
    // Limited to 64 to keep stack usage reasonable (~3KB).
    const MAX_TOP: usize = 64;
    struct Entry { tid: u64, state: u64, pri: u64, ticks: u64, mem: u64, is_user: u64 }
    let mut entries: [Entry; MAX_TOP] = unsafe { core::mem::zeroed() };
    let mut count = 0usize;
    let mut max_ticks: u64 = 0;
    let mut max_idx: usize = 0;

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
        if count < MAX_TOP {
            entries[count] = Entry { tid, state, pri, ticks, mem, is_user };
            if ticks > max_ticks { max_ticks = ticks; max_idx = count; }
            count += 1;
        }
    }

    for i in 0..count {
        let e = &entries[i];
        // Row coloring: zombie/dead=red, highest-CPU=yellow, odd rows dim
        let is_dead = e.state >= 4;
        let is_max = i == max_idx && max_ticks > 0;
        if is_dead {
            color::color(color::FG_RED);
        } else if is_max {
            color::color(color::FG_YELLOW);
        } else if i & 1 != 0 {
            color::color(color::FG_DIM);
        }

        print(b"  ");
        if e.tid < 10 { print(b"  "); } else if e.tid < 100 { print(b" "); }
        print_u64(e.tid);
        print(b"  ");
        match e.state {
            0 => print(b"READY  "),
            1 => print(b"RUN    "),
            2 => print(b"BLOCK  "),
            3 => print(b"FAULT  "),
            _ => print(b"DEAD   "),
        }
        if e.pri < 10 { print(b"  "); } else if e.pri < 100 { print(b" "); }
        print_u64(e.pri);
        print(b"  ");
        // Right-align ticks in 9 chars.
        let mut tstr = [b' '; 9];
        let mut t = e.ticks;
        let mut ti = 8;
        if t == 0 { tstr[ti] = b'0'; }
        while t > 0 { tstr[ti] = b'0' + (t % 10) as u8; t /= 10; if ti > 0 { ti -= 1; } }
        print(&tstr);
        print(b"  ");
        if e.mem < 10 { print(b"  "); } else if e.mem < 100 { print(b" "); }
        print_u64(e.mem);
        print(b"  ");
        if e.is_user != 0 { print(b"user"); } else { print(b"kern"); }

        color::reset();
        print(b"\n");
    }
}

// --- ls ---

/// List directory contents using getdents64, with color by file type.
pub fn cmd_ls() {
    let mut path_buf = [0u8; 4];
    let path = null_terminate(b".", &mut path_buf);
    // O_RDONLY | O_DIRECTORY (0x10000)
    let fd = linux_open(path, 0x10000);
    if fd < 0 {
        err!(b"ls", b"cannot open directory");
        // Fallback: try plain O_RDONLY for virtual dirs (/proc etc.)
        let fd2 = linux_open(path, 0);
        if fd2 < 0 {
            print(b"ls: cannot open directory\n");
            return;
        }
        ls_from_fd(fd2 as u64);
        linux_close(fd2 as u64);
        return;
    }
    ls_from_fd(fd as u64);
    linux_close(fd as u64);
}

pub fn cmd_ls_path(path: &[u8]) {
    // Handle --color=never / --color=auto flags
    let actual_path = strip_ls_flags(path);

    if actual_path.is_empty() {
        cmd_ls();
        return;
    }

    // Save cwd, cd to path, ls, cd back
    let mut old_cwd = [0u8; 128];
    let cwd_ret = linux_getcwd(old_cwd.as_mut_ptr(), old_cwd.len() as u64);

    let mut path_buf = [0u8; 64];
    let p = null_terminate(actual_path, &mut path_buf);
    if linux_chdir(p) < 0 {
        err!(b"ls", b"cannot access", path);
        print(b"ls: cannot access ");
        print(actual_path);
        print(b"\n");
        return;
    }
    cmd_ls();
    // Restore cwd
    if cwd_ret > 0 {
        linux_chdir(old_cwd.as_ptr());
    }
}

/// Strip --color=auto / --color=never / --color and common short flags
/// from ls arguments, returning the remaining path (if any).
fn strip_ls_flags(args: &[u8]) -> &[u8] {
    let mut rest = args;
    loop {
        rest = trim(rest);
        if starts_with(rest, b"--color=never") {
            rest = trim(&rest[13..]);
        } else if starts_with(rest, b"--color=auto") {
            rest = trim(&rest[12..]);
        } else if starts_with(rest, b"--color") {
            rest = trim(&rest[7..]);
        } else if rest.len() >= 2 && rest[0] == b'-' && rest[1] != b'-' {
            // Skip short flags like -a, -l, -la, etc.
            let mut end = 1;
            while end < rest.len() && rest[end] != b' ' { end += 1; }
            rest = trim(&rest[end..]);
        } else {
            break;
        }
    }
    rest
}

/// Read directory entries from an open fd using getdents64 and print
/// colorized names.
fn ls_from_fd(fd: u64) {
    let mut buf = [0u8; 2048];
    loop {
        let n = linux_getdents64(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 { break; }
        let total = n as usize;
        let mut off = 0usize;
        while off + DIRENT_NAME_OFF < total {
            // d_reclen at offset 16 (u16 LE)
            let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > total { break; }
            // d_type at offset 18
            let d_type = buf[off + 18];
            // d_name at offset 19, NUL-terminated
            let name_start = off + DIRENT_NAME_OFF;
            let mut name_end = name_start;
            while name_end < off + reclen && buf[name_end] != 0 { name_end += 1; }
            let name = &buf[name_start..name_end];

            // Skip . and ..
            if name == b"." || name == b".." {
                off += reclen;
                continue;
            }

            // Color by d_type
            match d_type {
                DT_DIR  => color::color(color::FG_BLUE),
                DT_LNK  => color::color(color::FG_CYAN),
                DT_SOCK => color::color(color::FG_MAGENTA),
                DT_CHR | DT_BLK => color::color(color::FG_YELLOW),
                DT_FIFO => color::color(color::FG_YELLOW),
                _ => {
                    // DT_REG (8) or unknown: check for executable-looking names
                    if name_looks_executable(name) {
                        color::color(color::FG_GREEN);
                    }
                    // else: default color (no escape)
                }
            }
            print(name);
            color::reset();

            // Append / for directories
            if d_type == DT_DIR { print(b"/"); }

            print(b"  ");
            off += reclen;
        }
    }
    print(b"\n");
}

/// Heuristic: does the filename look like an executable?
/// Checks for common executable suffixes.
fn name_looks_executable(name: &[u8]) -> bool {
    // Find last dot
    let mut last_dot = None;
    for i in 0..name.len() {
        if name[i] == b'.' { last_dot = Some(i); }
    }
    match last_dot {
        None => false, // no extension: could be anything, default color
        Some(pos) => {
            let ext = &name[pos..];
            ext == b".sh" || ext == b".py" || ext == b".elf"
        }
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
    // ps reads a text blob from /proc — colorize header line
    let mut buf = [0u8; 1024];
    let mut first_line = true;
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 { break; }
        let data = &buf[..n as usize];
        if first_line {
            // Bold the first line (header)
            color::color(color::BOLD);
            // Find first newline
            let mut nl = data.len();
            for i in 0..data.len() {
                if data[i] == b'\n' { nl = i + 1; break; }
            }
            print(&data[..nl]);
            color::reset();
            if nl < data.len() {
                print(&data[nl..]);
            }
            first_line = false;
        } else {
            linux_write(1, data.as_ptr(), data.len());
        }
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
    color::color(color::FG_CYAN);
    print(b"Total threads: ");
    color::reset();
    print_u64(count);
    print(b"\n");
}

// --- meminfo ---

/// Show free physical memory (syscall 252 = DebugFreeFrames).
pub fn cmd_meminfo() {
    let raw = kernel_syscall0(252);
    if raw < 0 {
        // -ENOSYS or other error from the kernel/lucas_handler. Degrade to
        // an error print instead of multiplying a negative-cast-to-u64 by
        // 4096 (which overflows and panics on debug builds).
        color::color(color::FG_CYAN);
        print(b"meminfo: ");
        color::reset();
        print(b"kernel syscall 252 unavailable (err=");
        print_u64((-raw) as u64);
        print(b")\n");
        return;
    }
    let frames = raw as u64;
    let bytes = frames.saturating_mul(4096);
    let mb = bytes / (1024 * 1024);
    color::color(color::FG_CYAN);
    print(b"Free frames: ");
    color::reset();
    print_u64(frames);
    color::color(color::FG_CYAN);
    print(b"\nFree memory: ");
    color::reset();
    print_u64(mb);
    print(b" MiB (");
    print_u64(bytes / 1024);
    print(b" KiB)\n");
}
