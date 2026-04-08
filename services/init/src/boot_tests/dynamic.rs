//! Dynamic linking test via sotos-ld (in-process dlopen/dlsym).
#![allow(unused_imports)]

use sotos_common::sys;
use crate::framebuffer::{print, print_u64, print_hex64};
use crate::exec::MAP_WRITABLE;

/// Base address for loading shared libraries.
const DL_LOAD_BASE: u64 = 0x6000000;
/// Buffer region for reading .so data from initrd.
const DL_BUF_BASE: u64 = 0x5200000;
/// Max .so size (128 KiB = 32 pages).
const DL_BUF_PAGES: u64 = 32;

pub(crate) fn test_dynamic_linking() {
    print(b"DLOPEN: loading libtest.so...\n");

    // Step 1: Map buffer pages for reading the .so.
    for i in 0..DL_BUF_PAGES {
        let frame_cap = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                print(b"DLOPEN: frame_alloc failed for buffer\n");
                return;
            }
        };
        if sys::map(DL_BUF_BASE + i * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"DLOPEN: map buffer page failed\n");
            return;
        }
    }

    // Step 2: Read .so from initrd.
    let name = b"libtest.so";
    let file_size = match sys::initrd_read(
        name.as_ptr() as u64,
        name.len() as u64,
        DL_BUF_BASE,
        DL_BUF_PAGES * 0x1000,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => {
            print(b"DLOPEN: initrd_read failed for libtest.so\n");
            for i in 0..DL_BUF_PAGES {
                let _ = sys::unmap_free(DL_BUF_BASE + i * 0x1000);
            }
            return;
        }
    };

    print(b"DLOPEN: libtest.so size = ");
    print_u64(file_size as u64);
    print(b" bytes\n");

    // Step 3: Load and relocate the shared library.
    let elf_data = unsafe { core::slice::from_raw_parts(DL_BUF_BASE as *const u8, file_size) };
    let handle = match sotos_ld::dl_open(elf_data, DL_LOAD_BASE) {
        Ok(h) => h,
        Err(e) => {
            print(b"DLOPEN: dl_open failed: ");
            print(e.as_bytes());
            print(b"\n");
            for i in 0..DL_BUF_PAGES {
                let _ = sys::unmap_free(DL_BUF_BASE + i * 0x1000);
            }
            return;
        }
    };

    print(b"DLOPEN: loaded at base 0x");
    print_hex64(handle.base);
    print(b"\n");

    // Step 4: Look up the "add" symbol.
    match sotos_ld::dl_sym(&handle, b"add") {
        Some(add_addr) => {
            print(b"DLSYM: add = 0x");
            print_hex64(add_addr);
            print(b"\n");

            // Call add(3, 4) — should return 7.
            let add_fn: extern "C" fn(u64, u64) -> u64 = unsafe {
                core::mem::transmute(add_addr)
            };
            let result = add_fn(3, 4);
            print(b"DLCALL: add(3, 4) = ");
            print_u64(result);
            print(b"\n");

            if result == 7 {
                print(b"DLTEST: PASS - dynamic linking works!\n");
            } else {
                print(b"DLTEST: FAIL - expected 7\n");
            }
        }
        None => {
            print(b"DLSYM: 'add' not found\n");
        }
    }

    // Step 5: Also test "mul" symbol.
    match sotos_ld::dl_sym(&handle, b"mul") {
        Some(mul_addr) => {
            let mul_fn: extern "C" fn(u64, u64) -> u64 = unsafe {
                core::mem::transmute(mul_addr)
            };
            let result = mul_fn(6, 7);
            print(b"DLCALL: mul(6, 7) = ");
            print_u64(result);
            print(b"\n");

            if result == 42 {
                print(b"DLTEST: mul PASS\n");
            } else {
                print(b"DLTEST: mul FAIL - expected 42\n");
            }
        }
        None => {
            print(b"DLSYM: 'mul' not found\n");
        }
    }

    // Step 6: Cleanup.
    sotos_ld::dl_close(&handle);
    for i in 0..DL_BUF_PAGES {
        let _ = sys::unmap_free(DL_BUF_BASE + i * 0x1000);
    }
}
