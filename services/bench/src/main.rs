//! sotOS Benchmark Suite
//!
//! Measures kernel primitive latencies via RDTSC and prints results to serial.
//! Benchmarks: IPC round-trip, frame alloc/free, thread create/exit, cap create/revoke.

#![no_std]
#![no_main]

use core::ptr::addr_of;
use sotos_common::sys;
use sotos_common::IpcMsg;

// ---------------------------------------------------------------------------
// Serial output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
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

// ---------------------------------------------------------------------------
// Shared state for benchmark threads
// ---------------------------------------------------------------------------

const STACK_SIZE: usize = 16384;

/// Stack for benchmark threads (16 KiB, 16-byte aligned).
static mut THREAD_STACK: [u8; STACK_SIZE] = [0u8; STACK_SIZE];

/// Endpoint capability shared between main and echo thread.
static mut ECHO_EP: u64 = 0;

/// Notification cap shared with benchmark threads.
static mut THREAD_NOTIFY_CAP: u64 = 0;

/// Number of IPC round-trips to perform.
const IPC_ITERS: u64 = 1000;

/// Get the stack top pointer (safe wrapper around static mut access).
fn thread_stack_top() -> u64 {
    unsafe {
        let base = addr_of!(THREAD_STACK) as *const u8;
        base.add(STACK_SIZE) as u64 & !0xF
    }
}

// ---------------------------------------------------------------------------
// IPC echo thread entry point
// ---------------------------------------------------------------------------

/// Entry point for the echo thread: receives a message and replies in a loop.
#[unsafe(no_mangle)]
extern "C" fn echo_thread_entry() -> ! {
    let ep = unsafe { core::ptr::read_volatile(addr_of!(ECHO_EP)) };
    for _ in 0..IPC_ITERS {
        if let Ok(msg) = sys::recv(ep) {
            let _ = sys::send(ep, &msg);
        }
    }
    sys::thread_exit();
}

/// Minimal thread: signal notification and exit.
#[unsafe(no_mangle)]
extern "C" fn bench_thread_fn() -> ! {
    let cap = unsafe { core::ptr::read_volatile(addr_of!(THREAD_NOTIFY_CAP)) };
    sys::notify_signal(cap);
    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_ipc() {
    print(b"IPC round-trip:    ");

    let ep = match sys::endpoint_create() {
        Ok(c) => c,
        Err(_) => {
            print(b"FAILED (endpoint_create)\n");
            return;
        }
    };
    unsafe { core::ptr::write_volatile(addr_of!(ECHO_EP) as *mut u64, ep); }

    let stack_top = thread_stack_top();

    let _thread = match sys::thread_create(
        echo_thread_entry as *const () as u64,
        stack_top,
    ) {
        Ok(t) => t,
        Err(_) => {
            print(b"FAILED (thread_create)\n");
            return;
        }
    };

    // Give the echo thread a chance to call recv.
    sys::yield_now();

    let msg = IpcMsg::empty();
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..IPC_ITERS {
        let t0 = sys::rdtsc();
        let _ = sys::call(ep, &msg);
        let t1 = sys::rdtsc();
        let dt = t1.wrapping_sub(t0);
        total += dt;
        if dt < min { min = dt; }
        if dt > max { max = dt; }
    }

    let avg = total / IPC_ITERS;
    print_u64(avg);
    print(b" cycles (min=");
    print_u64(min);
    print(b" avg=");
    print_u64(avg);
    print(b" max=");
    print_u64(max);
    print(b")\n");
}

fn bench_frame_alloc() {
    print(b"Frame alloc/free:  ");

    const COUNT: usize = 1000;
    let mut caps: [u64; COUNT] = [0; COUNT];

    let t0 = sys::rdtsc();

    for slot in caps.iter_mut() {
        match sys::frame_alloc() {
            Ok(c) => *slot = c,
            Err(_) => {
                print(b"FAILED (frame_alloc)\n");
                return;
            }
        }
    }

    for &cap in caps.iter() {
        let _ = sys::frame_free(cap);
    }

    let t1 = sys::rdtsc();
    let elapsed = t1.wrapping_sub(t0);

    // frames/sec = COUNT / (elapsed / tsc_freq).  Assume ~2 GHz TSC.
    // frames/sec = COUNT * 2_000_000_000 / elapsed
    // To avoid overflow: (COUNT * 2_000_000) / (elapsed / 1000)
    let elapsed_k = if elapsed > 1000 { elapsed / 1000 } else { 1 };
    let fps = (COUNT as u64 * 2_000_000) / elapsed_k;

    print_u64(fps);
    print(b" frames/sec (");
    print_u64(elapsed);
    print(b" cycles for ");
    print_u64(COUNT as u64);
    print(b" alloc+free)\n");
}

fn bench_thread_create() {
    print(b"Thread create:     ");

    const COUNT: usize = 100;

    let notify_cap = match sys::notify_create() {
        Ok(c) => c,
        Err(_) => {
            print(b"FAILED (notify_create)\n");
            return;
        }
    };
    unsafe { core::ptr::write_volatile(addr_of!(THREAD_NOTIFY_CAP) as *mut u64, notify_cap); }

    let mut total = 0u64;
    let stack_top = thread_stack_top();

    for _ in 0..COUNT {
        let t0 = sys::rdtsc();
        match sys::thread_create(bench_thread_fn as *const () as u64, stack_top) {
            Ok(_) => {}
            Err(_) => {
                print(b"FAILED (thread_create)\n");
                return;
            }
        }
        // Wait for thread to signal completion.
        sys::notify_wait(notify_cap);
        let t1 = sys::rdtsc();
        total += t1.wrapping_sub(t0);
    }

    let avg = total / COUNT as u64;
    print_u64(avg);
    print(b" cycles/thread (");
    print_u64(COUNT as u64);
    print(b" iterations)\n");
}

fn bench_cap_cycle() {
    print(b"Cap create/revoke: ");

    const COUNT: usize = 1000;

    // We need a source capability to grant from. Use a notification object.
    let source = match sys::notify_create() {
        Ok(c) => c,
        Err(_) => {
            print(b"FAILED (notify_create)\n");
            return;
        }
    };

    // Batch: create COUNT derived caps, then revoke them all.
    let mut caps: [u64; COUNT] = [0; COUNT];

    let t0 = sys::rdtsc();

    for slot in caps.iter_mut() {
        match sys::cap_grant(source, 0xFFFF_FFFF) {
            Ok(c) => *slot = c,
            Err(_) => {
                print(b"FAILED (cap_grant)\n");
                return;
            }
        }
    }

    for &cap in caps.iter() {
        let _ = sys::cap_revoke(cap);
    }

    let t1 = sys::rdtsc();
    let total = t1.wrapping_sub(t0);

    let per_cap = total / COUNT as u64;
    print_u64(per_cap);
    print(b" cycles/cap (");
    print_u64(COUNT as u64);
    print(b" grant+revoke)\n");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"\n=== sotOS Benchmark Suite ===\n");

    bench_ipc();
    bench_frame_alloc();
    bench_thread_create();
    bench_cap_cycle();

    print(b"=== Benchmark complete ===\n\n");
    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"BENCH: PANIC!\n");
    loop {
        sys::yield_now();
    }
}
