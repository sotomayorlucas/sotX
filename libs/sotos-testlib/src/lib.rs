//! Test shared library for sotOS dynamic linking.
//!
//! Contains simple functions to verify dl_open/dl_sym/dl_close, plus a
//! `#[thread_local]` variable so the dynamic linker exercises the TLS
//! relocation path (R_X86_64_TPOFF64 / DTPOFF64 / DTPMOD64).

#![no_std]
#![feature(thread_local)]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Simple addition function for testing dynamic symbol resolution.
///
/// Uses wrapping arithmetic so the compiler does not emit overflow-check
/// panics that would pull in undefined external `core::panicking::*`
/// symbols (which would trigger unresolved-symbol relocations).
#[no_mangle]
pub extern "C" fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Simple multiplication function.
#[no_mangle]
pub extern "C" fn mul(a: u64, b: u64) -> u64 {
    a.wrapping_mul(b)
}

/// Thread-local counter, initial value 42.
///
/// Reading this from a different thread should yield a fresh 42; writing
/// to it from one thread must not be observable from another. Used by the
/// boot test to verify FS_BASE installation and TPOFF64 relocations.
#[thread_local]
#[no_mangle]
pub static mut TLS_COUNTER: i32 = 42;

/// Read `TLS_COUNTER` (forces the compiler to emit a TLS access and a
/// TPOFF64-style relocation in the resulting `.so`).
#[no_mangle]
pub extern "C" fn read_tls_counter() -> i32 {
    // Use raw pointer reads via core::ptr to keep the access opaque to
    // overflow / null-check codegen and avoid unresolved panic_const_*
    // imports in the resulting `.so`.
    unsafe { core::ptr::read(core::ptr::addr_of!(TLS_COUNTER)) }
}

/// Increment `TLS_COUNTER` and return the new value.
#[no_mangle]
pub extern "C" fn bump_tls_counter() -> i32 {
    unsafe {
        let p = core::ptr::addr_of_mut!(TLS_COUNTER);
        let v = core::ptr::read(p).wrapping_add(1);
        core::ptr::write(p, v);
        v
    }
}

/// Static jump table that produces R_X86_64_RELATIVE entries in `.rela.dyn`,
/// giving the relocation engine a non-trivial surface to chew on.
#[no_mangle]
pub static FN_TABLE: [extern "C" fn(u64, u64) -> u64; 2] = [add, mul];

/// Dispatch through `FN_TABLE`.
#[no_mangle]
pub extern "C" fn dispatch(idx: usize, a: u64, b: u64) -> u64 {
    let f = FN_TABLE[idx & 1];
    f(a, b)
}
