#![no_std]
#![no_main]

// ---------------------------------------------------------------------------
// Linux syscall wrappers (raw inline asm — the kernel redirects these via LUCAS)
// ---------------------------------------------------------------------------

#[inline(always)]
fn linux_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 1u64 => ret,
            in("rdi") fd,
            in("rsi") buf as u64,
            in("rdx") len as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 0u64 => ret,
            in("rdi") fd,
            in("rsi") buf as u64,
            in("rdx") len as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_open(path: *const u8, flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 2u64 => ret,
            in("rdi") path as u64,
            in("rsi") flags,
            in("rdx") 0u64, // mode (unused)
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_close(fd: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 3u64 => ret,
            in("rdi") fd,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_unlink(path: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 87u64 => ret,
            in("rdi") path as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_stat(path: *const u8, statbuf: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 4u64 => ret,
            in("rdi") path as u64,
            in("rsi") statbuf as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_fstat(fd: u64, statbuf: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 5u64 => ret,
            in("rdi") fd,
            in("rsi") statbuf as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_lseek(fd: u64, offset: i64, whence: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 8u64 => ret,
            in("rdi") fd,
            in("rsi") offset as u64,
            in("rdx") whence,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_brk(addr: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 12u64 => ret,
            in("rdi") addr,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 9u64 => ret,
            in("rdi") addr,
            in("rsi") len,
            in("rdx") prot,
            in("r10") flags,
            in("r8") fd,
            in("r9") offset,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_exit(status: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 60u64,
            in("rdi") status,
            options(nostack, noreturn),
        );
    }
}

fn linux_clone(child_fn: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 56u64 => ret,
            in("rdi") child_fn,
            in("rsi") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_waitpid(pid: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 61u64 => ret,
            in("rdi") pid,
            in("rsi") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_getpid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 39u64 => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_getppid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 110u64 => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_execve(path: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 59u64 => ret,
            in("rdi") path as u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_kill(pid: u64, sig: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 62u64 => ret,
            in("rdi") pid,
            in("rsi") sig,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    linux_write(1, s.as_ptr(), s.len());
}

fn print_u64(mut n: u64) {
    if n == 0 {
        print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    // Print in reverse
    while i > 0 {
        i -= 1;
        linux_write(1, &buf[i] as *const u8, 1);
    }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    &hay[..needle.len()] == needle
}

fn trim(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a == b
}

/// Copy name into buf with NUL terminator. Returns pointer to buf.
fn null_terminate<'a>(name: &[u8], buf: &'a mut [u8]) -> *const u8 {
    let len = name.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&name[..len]);
    buf[len] = 0;
    buf.as_ptr()
}

/// Find the first space in a byte slice, returning the index or None.
fn find_space(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b' ' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse a decimal u64 from byte slice.
fn parse_u64_simple(s: &[u8]) -> u64 {
    let mut val: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        val = val * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    val
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

fn shell_loop() {
    let mut line_buf = [0u8; 256];

    loop {
        // Prompt
        print(b"$ ");

        // Read line
        let mut pos: usize = 0;
        loop {
            let mut ch = [0u8; 1];
            let n = linux_read(0, ch.as_mut_ptr(), 1);
            if n == -4 {
                // -EINTR (Ctrl+C)
                print(b"^C\n");
                pos = 0;
                break;
            }
            if n <= 0 {
                continue;
            }
            let c = ch[0];

            match c {
                // Enter
                b'\r' | b'\n' => {
                    print(b"\n");
                    break;
                }
                // Backspace (0x08) or DEL (0x7F)
                0x08 | 0x7F => {
                    if pos > 0 {
                        pos -= 1;
                        // Erase character on terminal: BS + space + BS
                        print(b"\x08 \x08");
                    }
                }
                // Printable character
                0x20..=0x7E => {
                    if pos < line_buf.len() - 1 {
                        line_buf[pos] = c;
                        pos += 1;
                        // Echo
                        linux_write(1, &c as *const u8, 1);
                    }
                }
                // Ignore other control chars
                _ => {}
            }
        }

        let line = trim(&line_buf[..pos]);
        if line.is_empty() {
            continue;
        }

        // --- Command dispatch ---
        if eq(line, b"help") {
            print(b"commands: help, echo, uname, uptime, caps, ls, cat, write, rm,\n         stat, hexdump, fork, getpid, exec, ps, kill, exit\n");
        } else if eq(line, b"uname") {
            print(b"sotOS 0.1.0 x86_64 LUCAS\n");
        } else if eq(line, b"uptime") {
            cmd_uptime();
        } else if eq(line, b"ps") {
            cmd_ps();
        } else if starts_with(line, b"kill ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                print(b"usage: kill <pid> [signal]\n");
            } else {
                cmd_kill(args);
            }
        } else if eq(line, b"caps") {
            print(b"capability system active (query via sotOS ABI)\n");
        } else if starts_with(line, b"echo ") {
            let rest = &line[5..];
            print(rest);
            print(b"\n");
        } else if eq(line, b"echo") {
            print(b"\n");
        } else if eq(line, b"ls") {
            cmd_ls();
        } else if starts_with(line, b"cat ") {
            let name = trim(&line[4..]);
            if name.is_empty() {
                print(b"usage: cat <file>\n");
            } else {
                cmd_cat(name);
            }
        } else if starts_with(line, b"write ") {
            let args = trim(&line[6..]);
            match find_space(args) {
                Some(sp) => {
                    let name = &args[..sp];
                    let text = trim(&args[sp + 1..]);
                    cmd_write(name, text);
                }
                None => {
                    print(b"usage: write <file> <text>\n");
                }
            }
        } else if starts_with(line, b"rm ") {
            let name = trim(&line[3..]);
            if name.is_empty() {
                print(b"usage: rm <file>\n");
            } else {
                cmd_rm(name);
            }
        } else if starts_with(line, b"stat ") {
            let name = trim(&line[5..]);
            if name.is_empty() {
                print(b"usage: stat <file>\n");
            } else {
                cmd_stat(name);
            }
        } else if eq(line, b"stat") {
            cmd_stat(b".");
        } else if starts_with(line, b"hexdump ") {
            let name = trim(&line[8..]);
            if name.is_empty() {
                print(b"usage: hexdump <file>\n");
            } else {
                cmd_hexdump(name);
            }
        } else if eq(line, b"fork") {
            cmd_fork();
        } else if eq(line, b"getpid") {
            print(b"pid=");
            print_u64(linux_getpid() as u64);
            print(b"\n");
        } else if starts_with(line, b"exec ") {
            let name = trim(&line[5..]);
            if name.is_empty() {
                print(b"usage: exec <program>\n");
            } else {
                cmd_exec(name);
            }
        } else if eq(line, b"exit") {
            print(b"bye!\n");
            return;
        } else {
            print(b"unknown command: ");
            print(line);
            print(b"\n");
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sotOS LUCAS shell v0.1\n");
    shell_loop();
    linux_exit(0);
}

#[unsafe(no_mangle)]
pub extern "C" fn child_shell_main() -> ! {
    let pid = linux_getpid();
    print(b"[child shell pid=");
    print_u64(pid as u64);
    print(b"]\n");
    shell_loop();
    linux_exit(0);
}

// ---------------------------------------------------------------------------
// File commands
// ---------------------------------------------------------------------------

fn cmd_ls() {
    let mut path_buf = [0u8; 4];
    let path = null_terminate(b".", &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"ls: cannot open directory\n");
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

fn cmd_cat(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"cat: file not found\n");
        return;
    }
    let mut buf = [0u8; 512];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    print(b"\n");
    linux_close(fd as u64);
}

fn cmd_write(name: &[u8], text: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    // O_WRONLY(1) | O_CREAT(0x40) = 0x41
    let fd = linux_open(path, 0x41);
    if fd < 0 {
        print(b"write: cannot open file\n");
        return;
    }
    let n = linux_write(fd as u64, text.as_ptr(), text.len());
    if n > 0 {
        print(b"wrote ");
        print_u64(n as u64);
        print(b" bytes\n");
    } else {
        print(b"write: error\n");
    }
    linux_close(fd as u64);
}

fn cmd_stat(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let mut stat_buf = [0u8; 144];
    let ret = linux_stat(path, stat_buf.as_mut_ptr());
    if ret < 0 {
        print(b"stat: not found\n");
        return;
    }
    // st_mode at offset 24 (u32)
    let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
    // st_size at offset 48 (u64)
    let size = u64::from_le_bytes([
        stat_buf[48], stat_buf[49], stat_buf[50], stat_buf[51],
        stat_buf[52], stat_buf[53], stat_buf[54], stat_buf[55],
    ]);
    // st_ino at offset 8 (u64)
    let ino = u64::from_le_bytes([
        stat_buf[8], stat_buf[9], stat_buf[10], stat_buf[11],
        stat_buf[12], stat_buf[13], stat_buf[14], stat_buf[15],
    ]);

    print(b"  file: ");
    print(name);
    print(b"\n  size: ");
    print_u64(size);
    print(b"\n  inode: ");
    print_u64(ino);
    print(b"\n  type: ");
    if mode & 0o170000 == 0o40000 {
        print(b"directory");
    } else if mode & 0o170000 == 0o100000 {
        print(b"regular file");
    } else if mode & 0o170000 == 0o20000 {
        print(b"character device");
    } else {
        print(b"unknown");
    }
    print(b"\n");
}

fn cmd_hexdump(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"hexdump: file not found\n");
        return;
    }
    let hex = b"0123456789abcdef";
    let mut offset: u64 = 0;
    let mut buf = [0u8; 16];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), 16);
        if n <= 0 {
            break;
        }
        let count = n as usize;
        // Print offset (8 hex digits)
        for i in (0..8).rev() {
            let nibble = ((offset >> (i * 4)) & 0xF) as usize;
            linux_write(1, &hex[nibble] as *const u8, 1);
        }
        print(b"  ");
        // Hex bytes
        for i in 0..16 {
            if i < count {
                linux_write(1, &hex[(buf[i] >> 4) as usize] as *const u8, 1);
                linux_write(1, &hex[(buf[i] & 0xF) as usize] as *const u8, 1);
            } else {
                print(b"  ");
            }
            print(b" ");
            if i == 7 {
                print(b" ");
            }
        }
        print(b" |");
        // ASCII
        for i in 0..count {
            if buf[i] >= 0x20 && buf[i] < 0x7F {
                linux_write(1, &buf[i] as *const u8, 1);
            } else {
                print(b".");
            }
        }
        print(b"|\n");
        offset += count as u64;
    }
    linux_close(fd as u64);
}

fn cmd_rm(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_unlink(path);
    if ret == 0 {
        print(b"removed\n");
    } else {
        print(b"rm: file not found\n");
    }
}

fn cmd_fork() {
    let child_fn = child_shell_main as *const () as u64;
    let child_pid = linux_clone(child_fn);
    if child_pid < 0 {
        print(b"fork: failed\n");
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

fn cmd_exec(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_execve(path);
    // If execve returns, it failed
    print(b"exec: failed (");
    print_u64((-ret) as u64);
    print(b")\n");
}

fn cmd_ps() {
    let mut path_buf = [0u8; 8];
    let path = null_terminate(b"/proc", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"ps: cannot open /proc\n");
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

fn cmd_uptime() {
    let mut path_buf = [0u8; 16];
    let path = null_terminate(b"/proc/uptime", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"uptime: cannot read\n");
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

fn cmd_kill(args: &[u8]) {
    match find_space(args) {
        Some(sp) => {
            let pid = parse_u64_simple(&args[..sp]);
            let sig = parse_u64_simple(trim(&args[sp + 1..]));
            let ret = linux_kill(pid, sig);
            if ret < 0 {
                print(b"kill: no such process\n");
            }
        }
        None => {
            // No signal specified, default to SIGKILL(9)
            let pid = parse_u64_simple(args);
            let ret = linux_kill(pid, 9);
            if ret < 0 {
                print(b"kill: no such process\n");
            }
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"PANIC in lucas-shell\n");
    linux_exit(1);
}
