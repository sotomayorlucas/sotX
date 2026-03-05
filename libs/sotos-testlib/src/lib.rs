//! Test shared library for sotOS dynamic linking.
//!
//! Contains simple functions to verify dl_open/dl_sym/dl_close.

#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Simple addition function for testing dynamic symbol resolution.
#[no_mangle]
pub extern "C" fn add(a: u64, b: u64) -> u64 {
    a + b
}

/// Simple multiplication function.
#[no_mangle]
pub extern "C" fn mul(a: u64, b: u64) -> u64 {
    a * b
}
