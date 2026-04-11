//! smp-stress: cross-core contention test.
//!
//! Spawns threads that simultaneously:
//! - Allocate and map frames
//! - Create endpoints and send IPC
//! - Yield aggressively (stress work-stealing scheduler)
//! - Increment shared atomic counters
//!
//! Verifies that the Chase-Lev work-stealing deque doesn't lose work
//! and that spinlocks don't deadlock under cross-core contention.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sotos_common::sys;

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff_0a0d_0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    print(b"smp-stress: STACK CHECK FAIL\n");
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

const NUM_WORKERS: u32 = 4;
const ITERATIONS: u64 = 1000;
const WORKER_STACK_BASE: u64 = 0x700000;
const WORKER_STACK_PAGES: u64 = 4;

// Shared counters — each worker increments these from potentially different CPUs
static COUNTER_A: AtomicU64 = AtomicU64::new(0);
static COUNTER_B: AtomicU64 = AtomicU64::new(0);
static COUNTER_FRAMES: AtomicU64 = AtomicU64::new(0);
static COUNTER_YIELDS: AtomicU64 = AtomicU64::new(0);
static THREADS_DONE: AtomicU32 = AtomicU32::new(0);

extern "C" fn stress_worker() -> ! {
    let mut frames_allocd = 0u64;
    let mut yields = 0u64;

    for i in 0..ITERATIONS {
        // Phase 1: Atomic counter contention (tests cache line bouncing)
        COUNTER_A.fetch_add(1, Ordering::SeqCst);
        COUNTER_B.fetch_add(1, Ordering::Relaxed);

        // Phase 2: Frame allocation (tests frame allocator spinlock)
        if i % 10 == 0 {
            if let Ok(_frame) = sys::frame_alloc() {
                frames_allocd += 1;
            }
        }

        // Phase 3: Yield (triggers work-stealing scheduler path)
        if i % 5 == 0 {
            sys::yield_now();
            yields += 1;
        }

        // Phase 4: Endpoint create (tests cap table spinlock)
        if i % 50 == 0 {
            let _ = sys::endpoint_create();
        }
    }

    COUNTER_FRAMES.fetch_add(frames_allocd, Ordering::Relaxed);
    COUNTER_YIELDS.fetch_add(yields, Ordering::Relaxed);
    THREADS_DONE.fetch_add(1, Ordering::SeqCst);

    sys::thread_exit();
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"\n=== smp-stress: cross-core contention test ===\n");

    // Spawn workers
    let mut spawned = 0u32;
    for w in 0..NUM_WORKERS {
        let stack_base = WORKER_STACK_BASE + (w as u64) * WORKER_STACK_PAGES * 0x1000;
        let mut ok = true;
        for p in 0..WORKER_STACK_PAGES {
            let vaddr = stack_base + p * 0x1000;
            match sys::frame_alloc() {
                Ok(frame) => {
                    if sys::map(vaddr, frame, 0x03).is_err() {
                        ok = false; break;
                    }
                }
                Err(_) => { ok = false; break; }
            }
        }
        if !ok { continue; }

        let stack_top = stack_base + WORKER_STACK_PAGES * 0x1000;
        match sys::thread_create(stress_worker as *const () as u64, stack_top) {
            Ok(_) => spawned += 1,
            Err(_) => {}
        }
    }

    print(b"  spawned ");
    print_u64(spawned as u64);
    print(b" workers (");
    print_u64(ITERATIONS);
    print(b" iterations each)\n");

    // Wait for completion
    let mut timeout = 0u64;
    while THREADS_DONE.load(Ordering::SeqCst) < spawned {
        sys::yield_now();
        timeout += 1;
        if timeout > 10_000_000 {
            print(b"  TIMEOUT\n");
            break;
        }
    }

    let done = THREADS_DONE.load(Ordering::SeqCst);
    let ca = COUNTER_A.load(Ordering::SeqCst);
    let cb = COUNTER_B.load(Ordering::Relaxed);
    let frames = COUNTER_FRAMES.load(Ordering::Relaxed);
    let yields = COUNTER_YIELDS.load(Ordering::Relaxed);

    let expected = spawned as u64 * ITERATIONS;

    print(b"  threads done: ");
    print_u64(done as u64);
    print(b"/");
    print_u64(spawned as u64);
    print(b"\n  counter_a (SeqCst): ");
    print_u64(ca);
    print(b"/");
    print_u64(expected);
    print(b"\n  counter_b (Relaxed): ");
    print_u64(cb);
    print(b"/");
    print_u64(expected);
    print(b"\n  frames allocated: ");
    print_u64(frames);
    print(b"\n  yields: ");
    print_u64(yields);
    print(b"\n");

    // Verify: counter_a must equal expected (SeqCst guarantees no lost increments)
    let all_done = done == spawned;
    let counter_ok = ca == expected;

    if all_done && counter_ok {
        print(b"=== smp-stress: PASS ===\n\n");
    } else {
        if !all_done {
            print(b"  FAIL: not all threads completed\n");
        }
        if !counter_ok {
            print(b"  FAIL: counter_a mismatch (lost atomics)\n");
        }
        print(b"=== smp-stress: FAIL ===\n\n");
    }

    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"smp-stress: PANIC\n");
    loop { sys::yield_now(); }
}
