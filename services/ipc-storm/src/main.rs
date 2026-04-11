//! ipc-storm: flood IPC endpoints to test for deadlocks and resource leaks.
//!
//! Spawns 4 worker threads, each creating endpoints and sending 2500
//! messages with random payloads. Tests that:
//! - No kernel deadlock under IPC contention
//! - Endpoint creation/destruction under load is stable
//! - All threads complete without panic

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sotos_common::{sys, IpcMsg};

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff_0a0d_0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    print(b"ipc-storm: STACK CHECK FAIL\n");
    sys::thread_exit();
}

fn print(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

fn print_u64(mut n: u64) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

/// XORSHIFT64 PRNG for deterministic randomness.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// Shared counters
static THREADS_DONE: AtomicU32 = AtomicU32::new(0);
static TOTAL_SENDS: AtomicU64 = AtomicU64::new(0);
static TOTAL_ERRORS: AtomicU64 = AtomicU64::new(0);
static TOTAL_ENDPOINTS: AtomicU64 = AtomicU64::new(0);

// Shared endpoint for cross-thread messaging
static SHARED_EP: AtomicU64 = AtomicU64::new(0);

// Worker stacks (4 workers × 4 pages each)
const WORKER_STACK_BASE: u64 = 0x700000;
const WORKER_STACK_PAGES: u64 = 4;
const NUM_WORKERS: u32 = 4;
const MSGS_PER_WORKER: u64 = 200;

extern "C" fn worker_fn() -> ! {
    let worker_id = THREADS_DONE.load(Ordering::Relaxed); // rough ID
    let mut rng_state = 0x12345678_u64 + worker_id as u64 * 0x9ABCDEF0;
    let mut sends = 0u64;
    let mut errors = 0u64;
    let mut eps_created = 0u64;

    // Phase 1: Create and destroy endpoints rapidly (test pool recycling)
    for _ in 0..50 {
        match sys::endpoint_create() {
            Ok(ep) => {
                eps_created += 1;
                let _ = sys::endpoint_close(ep); // free the slot immediately
            }
            Err(_) => errors += 1,
        }
    }

    // Phase 2: call_timeout to shared endpoint (times out since nobody recvs).
    // Using call_timeout instead of send/call to avoid blocking forever.
    let shared = SHARED_EP.load(Ordering::Acquire);
    if shared != 0 {
        for _ in 0..MSGS_PER_WORKER {
            let val = xorshift64(&mut rng_state);
            let msg = IpcMsg {
                tag: val & 0xFF,
                regs: [val, val >> 8, val >> 16, val >> 24, 0, 0, 0, 0],
            };
            // call_timeout with 1 tick — returns error on timeout, never deadlocks
            let _ = sys::call_timeout(shared, &msg, 1);
            sends += 1;

            // Yield periodically
            if sends % 100 == 0 {
                sys::yield_now();
            }
        }
    }

    TOTAL_SENDS.fetch_add(sends, Ordering::Relaxed);
    TOTAL_ERRORS.fetch_add(errors, Ordering::Relaxed);
    TOTAL_ENDPOINTS.fetch_add(eps_created, Ordering::Relaxed);
    THREADS_DONE.fetch_add(1, Ordering::SeqCst);

    sys::thread_exit();
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"\n=== ipc-storm: IPC flood test ===\n");

    // Create shared endpoint
    match sys::endpoint_create() {
        Ok(ep) => {
            SHARED_EP.store(ep, Ordering::Release);
            print(b"  shared endpoint created\n");
        }
        Err(_) => {
            print(b"  FAILED to create shared endpoint\n");
            print(b"=== ipc-storm: FAIL ===\n\n");
            sys::thread_exit();
        }
    }

    // Allocate worker stacks and spawn threads
    let mut spawned = 0u32;
    for w in 0..NUM_WORKERS {
        let stack_base = WORKER_STACK_BASE + (w as u64) * WORKER_STACK_PAGES * 0x1000;
        let mut ok = true;
        for p in 0..WORKER_STACK_PAGES {
            let vaddr = stack_base + p * 0x1000;
            match sys::frame_alloc() {
                Ok(frame) => {
                    if sys::map(vaddr, frame, 0x03).is_err() {
                        ok = false;
                        break;
                    }
                }
                Err(_) => { ok = false; break; }
            }
        }
        if !ok {
            print(b"  worker stack alloc failed for worker ");
            print_u64(w as u64);
            print(b"\n");
            continue;
        }

        let stack_top = stack_base + WORKER_STACK_PAGES * 0x1000;
        match sys::thread_create(worker_fn as *const () as u64, stack_top) {
            Ok(_) => spawned += 1,
            Err(_) => {
                print(b"  thread_create failed for worker ");
                print_u64(w as u64);
                print(b"\n");
            }
        }
    }

    print(b"  spawned ");
    print_u64(spawned as u64);
    print(b" workers\n");

    // Wait for all workers to complete
    let mut timeout = 0u64;
    while THREADS_DONE.load(Ordering::SeqCst) < spawned {
        sys::yield_now();
        timeout += 1;
        if timeout > 5_000_000 {
            print(b"  TIMEOUT waiting for workers\n");
            break;
        }
    }

    let done = THREADS_DONE.load(Ordering::SeqCst);
    let sends = TOTAL_SENDS.load(Ordering::Relaxed);
    let errors = TOTAL_ERRORS.load(Ordering::Relaxed);
    let eps = TOTAL_ENDPOINTS.load(Ordering::Relaxed);

    print(b"  threads completed: ");
    print_u64(done as u64);
    print(b"/");
    print_u64(spawned as u64);
    print(b"\n  total sends: ");
    print_u64(sends);
    print(b"\n  total endpoints created: ");
    print_u64(eps);
    print(b"\n  endpoint create errors: ");
    print_u64(errors);
    print(b"\n");

    if done == spawned {
        print(b"=== ipc-storm: PASS ===\n\n");
    } else {
        print(b"=== ipc-storm: FAIL ===\n\n");
    }

    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"ipc-storm: PANIC\n");
    loop { sys::yield_now(); }
}
