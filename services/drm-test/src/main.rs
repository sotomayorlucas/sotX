//! drm-test: DRM dumb buffer pipeline test for sotOS.

#![no_std]
#![no_main]

use core::arch::asm;

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000;

#[inline(always)]
fn syscall1(nr: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe { asm!("syscall", in("rax") nr, in("rdi") a1,
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

fn write_str(s: &[u8]) {
    syscall3(1, 1, s.as_ptr() as u64, s.len() as u64);
}

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    write_str(b"[drm-test] STACK SMASH\n");
    syscall1(231, 137);
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_str(b"[drm-test] DRM dumb buffer test stub\n");
    syscall1(231, 0);
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    write_str(b"[drm-test] PANIC\n");
    syscall1(231, 1);
    loop {}
}
