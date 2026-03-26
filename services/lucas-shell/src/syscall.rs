// ---------------------------------------------------------------------------
// Linux syscall primitives (x86_64 ABI: rdi, rsi, rdx, r10, r8, r9)
// ---------------------------------------------------------------------------

#[inline(always)]
pub fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
pub fn syscall1(nr: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
pub fn syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
pub fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
pub fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3,
        in("r10") a4, in("r8") a5, in("r9") a6,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

// ---------------------------------------------------------------------------
// Linux syscall wrappers (one-liners atop primitives)
// ---------------------------------------------------------------------------

#[inline(always)] pub fn linux_write(fd: u64, buf: *const u8, len: usize) -> i64 { syscall3(1, fd, buf as u64, len as u64) }
#[inline(always)] pub fn linux_read(fd: u64, buf: *mut u8, len: usize) -> i64 { syscall3(0, fd, buf as u64, len as u64) }
#[inline(always)] pub fn linux_open(path: *const u8, flags: u64) -> i64 { syscall3(2, path as u64, flags, 0) }
#[inline(always)] pub fn linux_close(fd: u64) -> i64 { syscall1(3, fd) }
#[inline(always)] pub fn linux_stat(path: *const u8, buf: *mut u8) -> i64 { syscall2(4, path as u64, buf as u64) }
#[allow(dead_code)] #[inline(always)] pub fn linux_fstat(fd: u64, buf: *mut u8) -> i64 { syscall2(5, fd, buf as u64) }
#[allow(dead_code)] #[inline(always)] pub fn linux_lseek(fd: u64, off: i64, whence: u64) -> i64 { syscall3(8, fd, off as u64, whence) }
#[allow(dead_code)] #[inline(always)] pub fn linux_mmap(a: u64, l: u64, p: u64, f: u64, fd: u64, o: u64) -> i64 { syscall6(9, a, l, p, f, fd, o) }
#[allow(dead_code)] #[inline(always)] pub fn linux_brk(addr: u64) -> i64 { syscall1(12, addr) }
#[inline(always)] pub fn linux_getpid() -> i64 { syscall0(39) }
#[inline(always)] pub fn linux_clone(child_fn: u64) -> i64 { syscall2(56, child_fn, 0) }
#[inline(always)] pub fn linux_execve(path: *const u8, argv: *const u64, envp: *const u64) -> i64 { syscall3(59, path as u64, argv as u64, envp as u64) }
#[inline(always)] pub fn linux_waitpid(pid: u64) -> i64 { syscall2(61, pid, 0) }
#[inline(always)] pub fn linux_kill(pid: u64, sig: u64) -> i64 { syscall2(62, pid, sig) }
#[inline(always)] pub fn linux_getcwd(buf: *mut u8, size: u64) -> i64 { syscall2(79, buf as u64, size) }
#[inline(always)] pub fn linux_chdir(path: *const u8) -> i64 { syscall1(80, path as u64) }
#[inline(always)] pub fn linux_mkdir(path: *const u8, mode: u64) -> i64 { syscall2(83, path as u64, mode) }
#[inline(always)] pub fn linux_rmdir(path: *const u8) -> i64 { syscall1(84, path as u64) }
#[inline(always)] pub fn linux_unlink(path: *const u8) -> i64 { syscall1(87, path as u64) }
#[allow(dead_code)] #[inline(always)] pub fn linux_getppid() -> i64 { syscall0(110) }
#[inline(always)] pub fn linux_socket(dom: u64, typ: u64, proto: u64) -> i64 { syscall3(41, dom, typ, proto) }
#[inline(always)] pub fn linux_connect(fd: u64, addr: *const u8, len: u64) -> i64 { syscall3(42, fd, addr as u64, len) }
#[inline(always)] pub fn linux_sendto(fd: u64, buf: *const u8, len: u64, flags: u64) -> i64 { syscall6(44, fd, buf as u64, len, flags, 0, 0) }
#[inline(always)] pub fn linux_recvfrom(fd: u64, buf: *mut u8, len: u64, flags: u64) -> i64 { syscall6(45, fd, buf as u64, len, flags, 0, 0) }
// Custom sotOS syscalls (intercepted by LUCAS)
#[inline(always)] pub fn linux_dns_resolve(name: *const u8, len: usize) -> u64 { syscall2(200, name as u64, len as u64) as u64 }
#[inline(always)] pub fn linux_traceroute_hop(dst: u64, ttl: u64) -> u64 { syscall2(201, dst, ttl) as u64 }
#[inline(always)] pub fn linux_icmp_ping(dst: u64, seq: u64) -> u64 { syscall2(202, dst, seq) as u64 }

#[inline(always)]
pub fn linux_exit(status: u64) -> ! {
    unsafe {
        core::arch::asm!("syscall", in("rax") 60u64, in("rdi") status,
            options(nostack, noreturn));
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

pub fn print(s: &[u8]) {
    linux_write(1, s.as_ptr(), s.len());
}

pub fn print_u64(mut n: u64) {
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
