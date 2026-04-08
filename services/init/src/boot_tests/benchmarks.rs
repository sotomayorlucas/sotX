//! SPSC benchmarks, WASM SFI smoke test, and the shared `producer` thread entry.
#![allow(unused_imports)]

use sotos_common::sys;
use sotos_common::spsc;
use crate::framebuffer::{print, print_u64};
use crate::exec::rdtsc;

const RING_ADDR: u64 = 0xA00000;
const MSG_COUNT: u64 = 1000;

/// Producer entry point — runs in a separate thread, same address space.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn producer() -> ! {
    let ring = unsafe { spsc::SpscRing::from_ptr(RING_ADDR as *mut u8) };
    for i in 0..MSG_COUNT {
        spsc::send(ring, i);
    }
    sys::thread_exit();
}

/// Run SPSC benchmarks after the main test completes.
pub(crate) fn run_benchmarks(ring: &spsc::SpscRing) {
    // Latency: measure try_send + try_recv round-trip (single-threaded, no contention)
    const LAT_ITERS: u64 = 10000;

    // Warm up
    for i in 0..128 {
        spsc::try_send(ring, i);
    }
    for _ in 0..128 {
        spsc::try_recv(ring);
    }

    let start = rdtsc();
    for i in 0..LAT_ITERS {
        spsc::try_send(ring, i);
        spsc::try_recv(ring);
    }
    let end = rdtsc();
    let cycles_per_msg = (end - start) / LAT_ITERS;

    print(b"BENCH: spsc_rt=");
    print_u64(cycles_per_msg);
    print(b"cy/msg\n");

    // Throughput: stream 10K messages (single-threaded, no blocking)
    const TPUT_MSGS: u64 = 10000;
    let start = rdtsc();
    for i in 0..TPUT_MSGS {
        while !spsc::try_send(ring, i) {}
        while spsc::try_recv(ring).is_none() {}
    }
    let end = rdtsc();
    let tput_cy = (end - start) / TPUT_MSGS;

    print(b"BENCH: spsc_tput=");
    print_u64(tput_cy);
    print(b"cy/msg (10000 msgs)\n");
}

// ---------------------------------------------------------------------------
// WASM SFI test: hand-assembled module with add(a, b) function
// ---------------------------------------------------------------------------

/// Test the WASM interpreter with a minimal hand-assembled module.
/// The module exports a single function: add(i32, i32) -> i32
pub fn test_wasm() {
    use sotos_wasm::{Module, Runtime, Value};

    // Hand-assembled minimal .wasm binary:
    // (module
    //   (func $add (param i32) (param i32) (result i32)
    //     local.get 0
    //     local.get 1
    //     i32.add)
    //   (export "add" (func $add)))
    #[rustfmt::skip]
    let wasm_bytes: &[u8] = &[
        0x00, 0x61, 0x73, 0x6D, // magic: \0asm
        0x01, 0x00, 0x00, 0x00, // version: 1

        // Type section (1 type: (i32, i32) -> i32)
        0x01, 0x07, 0x01,       // section id=1, size=7, count=1
        0x60,                   // func type
        0x02, 0x7F, 0x7F,      // 2 params: i32, i32
        0x01, 0x7F,            // 1 result: i32

        // Function section (1 func, type index 0)
        0x03, 0x02, 0x01,       // section id=3, size=2, count=1
        0x00,                   // type index 0

        // Export section (export "add" as func 0)
        0x07, 0x07, 0x01,       // section id=7, size=7, count=1
        0x03,                   // name length=3
        0x61, 0x64, 0x64,      // "add"
        0x00,                   // export kind=func
        0x00,                   // func index=0

        // Code section (1 function body)
        0x0A, 0x09, 0x01,       // section id=10, size=9, count=1
        0x07,                   // body size=7
        0x00,                   // local decl count=0
        0x20, 0x00,            // local.get 0
        0x20, 0x01,            // local.get 1
        0x6A,                   // i32.add
        0x0B,                   // end
    ];

    print(b"WASM: parsing module (");
    print_u64(wasm_bytes.len() as u64);
    print(b" bytes)...\n");

    let module = match Module::parse(wasm_bytes) {
        Ok(m) => m,
        Err(e) => {
            print(b"WASM: parse FAILED: ");
            let msg = match e {
                sotos_wasm::ParseError::InvalidMagic => b"invalid magic" as &[u8],
                sotos_wasm::ParseError::InvalidVersion => b"invalid version",
                sotos_wasm::ParseError::InvalidSection => b"invalid section",
                sotos_wasm::ParseError::TooManyFunctions => b"too many functions",
                sotos_wasm::ParseError::TooManyTypes => b"too many types",
                sotos_wasm::ParseError::InvalidEncoding => b"invalid encoding",
                _ => b"unknown error",
            };
            print(msg);
            print(b"\n");
            return;
        }
    };

    print(b"WASM: module parsed, ");
    print_u64(module.func_count as u64);
    print(b" functions\n");

    let mut runtime = Runtime::new(&module);

    // Call add(3, 4) — should return 7
    let args = [Value::I32(3), Value::I32(4)];
    match runtime.call(&module, 0, &args) {
        Ok(Some(Value::I32(result))) => {
            print(b"WASM: add(3, 4) = ");
            print_u64(result as u64);
            print(b"\n");
            if result == 7 {
                print(b"WASM-TEST: PASS - SFI interpreter works!\n");
            } else {
                print(b"WASM-TEST: FAIL - expected 7\n");
            }
        }
        Ok(_other) => {
            print(b"WASM-TEST: FAIL - unexpected return type\n");
        }
        Err(_trap) => {
            print(b"WASM-TEST: FAIL - trap\n");
        }
    }

    // Call add(100, 200) — should return 300
    let args2 = [Value::I32(100), Value::I32(200)];
    match runtime.call(&module, 0, &args2) {
        Ok(Some(Value::I32(result))) => {
            print(b"WASM: add(100, 200) = ");
            print_u64(result as u64);
            if result == 300 {
                print(b" PASS\n");
            } else {
                print(b" FAIL\n");
            }
        }
        _ => { print(b"WASM: call 2 FAIL\n"); }
    }
}
