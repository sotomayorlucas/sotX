#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    for &b in b"ELF!\n" {
        sotos_common::sys::debug_print(b);
    }
    sotos_common::sys::thread_exit();
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
