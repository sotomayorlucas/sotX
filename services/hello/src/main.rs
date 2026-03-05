#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if boot_info.is_valid() {
        print(b"HELLO: spawned from userspace! caps=");
        print_u64(boot_info.cap_count);
        print(b"\n");
    } else {
        print(b"HELLO: spawned from userspace! (no BootInfo)\n");
    }

    print(b"HELLO: exiting cleanly\n");
    sys::thread_exit();
}

fn print_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"HELLO: PANIC!\n");
    loop { sys::yield_now(); }
}
