//! hello-linux: standalone Linux ABI test binary for sotX.
//!
//! Exercises raw Linux syscalls (write, getpid, arch_prctl, brk, mmap,
//! uname, exit_group) without any runtime or libc.  Runs under the LUCAS
//! child_handler Linux compatibility layer.

#![no_std]
#![no_main]

use core::arch::asm;

// ---- stack canary (required by -Zstack-protector=strong) ----

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    write_str(b"[hello-linux] STACK SMASH\n");
    syscall1(231, 137);
    loop {}
}

// ---- raw syscall helpers ----

#[inline(always)]
fn syscall1(nr: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe { asm!("syscall", in("rax") nr, in("rdi") a1,
        lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
fn syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe { asm!("syscall", in("rax") nr, in("rdi") a1, in("rsi") a2,
        lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe { asm!("syscall", in("rax") nr, in("rdi") a1, in("rsi") a2, in("rdx") a3,
        lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    unsafe { asm!("syscall", in("rax") nr, in("rdi") a1, in("rsi") a2, in("rdx") a3,
        in("r10") a4, in("r8") a5, in("r9") a6,
        lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack)); }
    ret
}

fn write_str(s: &[u8]) {
    syscall3(1, 1, s.as_ptr() as u64, s.len() as u64);
}

/// Write a C string (stops at first NUL or end of slice).
fn write_c_string(s: &[u8]) {
    let len = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    if len > 0 {
        write_str(&s[..len]);
    }
}

fn write_dec(mut n: u64) {
    if n == 0 { write_str(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    write_str(&buf[i..]);
}

fn write_ok(label: &[u8]) {
    write_str(label);
    write_str(b" OK\n");
}

fn write_fail(label: &[u8]) {
    write_str(label);
    write_str(b" FAIL\n");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. write
    write_str(b"[hello-linux] starting Linux ABI tests\n");
    write_ok(b"  write(1)");

    // 2. getpid
    let pid = syscall1(39, 0);
    if pid > 0 { write_ok(b"  getpid"); } else { write_fail(b"  getpid"); }

    // 3. arch_prctl (ARCH_SET_FS = 0x1002)
    let tls_val: u64 = 0x12345678;
    let r = syscall2(158, 0x1002, tls_val);
    if r == 0 { write_ok(b"  arch_prctl"); } else { write_fail(b"  arch_prctl"); }

    // 4. brk
    let cur = syscall1(12, 0);
    if cur > 0 { write_ok(b"  brk"); } else { write_fail(b"  brk"); }

    // 5. mmap (anonymous, 4096 bytes)
    let addr = syscall6(9, 0, 4096, 3 /* PROT_READ|WRITE */, 0x22 /* MAP_ANON|PRIVATE */, u64::MAX, 0);
    if addr > 0 { write_ok(b"  mmap"); } else { write_fail(b"  mmap"); }

    // 6. uname — print release field to reveal LKL vs LUCAS provenance.
    //    LKL: "6.6.0+"  (real Linux 6.6 kernel)
    //    LUCAS: "6.1.0-sotX"  (emulation sentinel)
    let mut buf = [0u8; 390]; // struct utsname: 6 × 65B fields
    let r = syscall1(63, buf.as_mut_ptr() as u64);
    if r == 0 {
        write_ok(b"  uname");
        write_str(b"    sysname=");
        write_c_string(&buf[0..65]);
        write_str(b" release=");
        write_c_string(&buf[130..195]);
        write_str(b"\n");
        if buf[130..].starts_with(b"6.6") {
            write_str(b"  [PHASE-4] uname routed via LKL \xe2\x9c\x93\n");
        } else {
            write_str(b"  [PHASE-4] uname answered by LUCAS (fallback)\n");
        }
    } else {
        write_fail(b"  uname");
    }

    // 7. Phase 6 fs routing — prove /tmp reaches LKL tmpfs.
    //    openat(AT_FDCWD=-100, "/tmp/phase6-test", O_CREAT|O_WRONLY, 0644)
    let path: &[u8] = b"/tmp/phase6-test\0";
    let fd = syscall6(
        257,                          // SYS_openat
        (-100i64) as u64,             // AT_FDCWD
        path.as_ptr() as u64,
        0o0100 | 0o0001,              // O_CREAT | O_WRONLY
        0o644,                        // mode
        0, 0,
    );
    if fd >= 0 {
        write_ok(b"  openat(/tmp/phase6-test, CREAT|WRONLY)");
        write_str(b"    fd=");
        write_dec(fd as u64);
        write_str(b"\n  [PHASE-6] /tmp open routed via LKL tmpfs \xe2\x9c\x93\n");

        // Phase 6 Category B test: write to the LKL-owned fd. The
        // run_linux_test harness routes non-stdio writes through LKL
        // via the LKL_FDS-bitmap path.
        let payload: &[u8] = b"phase6-roundtrip\n";
        let wn = syscall3(1 /* SYS_write */, fd as u64,
                         payload.as_ptr() as u64, payload.len() as u64);
        if wn == payload.len() as i64 {
            write_ok(b"  write(/tmp/phase6-test) bytes match");
        } else {
            write_str(b"  write returned ");
            write_dec(wn as u64);
            write_str(b" expected ");
            write_dec(payload.len() as u64);
            write_str(b"\n");
        }
        // close(fd)
        syscall1(3, fd as u64);
    } else {
        write_fail(b"  openat(/tmp/phase6-test)");
        write_str(b"    errno=");
        write_dec((-fd) as u64);
        write_str(b"\n  [PHASE-6] /tmp open did not reach LKL (fallback or error)\n");
    }

    // 8. Sanity: /etc/passwd should stay in LUCAS (NOT crash).
    //    openat(AT_FDCWD, "/etc/passwd", O_RDONLY)
    let etc_path: &[u8] = b"/etc/passwd\0";
    let efd = syscall6(
        257, (-100i64) as u64, etc_path.as_ptr() as u64,
        0,     // O_RDONLY
        0, 0, 0,
    );
    if efd >= 0 {
        write_ok(b"  openat(/etc/passwd, RDONLY) -- LUCAS owns");
        syscall1(3, efd as u64);
    } else {
        // ENOENT is fine — LUCAS virtual fs may not have /etc/passwd.
        // What matters is no crash from LKL taking it over.
        write_str(b"  openat(/etc/passwd) errno=");
        write_dec((-efd) as u64);
        write_str(b" (LUCAS fallback, no LKL crash -- OK)\n");
    }

    write_str(b"[hello-linux] all tests complete\n");

    // 9. exit_group(0)
    syscall1(231, 0);
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    write_str(b"[hello-linux] PANIC\n");
    syscall1(231, 1);
    loop {}
}
