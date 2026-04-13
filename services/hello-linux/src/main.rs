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

    // 6. uname
    let mut buf = [0u8; 390]; // struct utsname
    let r = syscall1(63, buf.as_mut_ptr() as u64);
    if r == 0 { write_ok(b"  uname"); } else { write_fail(b"  uname"); }

    write_str(b"[hello-linux] all tests complete\n");

    // 7. exit_group(0)
    syscall1(231, 0);
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    write_str(b"[hello-linux] PANIC\n");
    syscall1(231, 1);
    loop {}
}
