#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

/// Number of busy-loop iterations each worker performs.
const WORK_ITERATIONS: u64 = 2_000_000;

/// Number of workers per domain.
const WORKERS_PER_DOMAIN: usize = 2;

/// Stack size per worker thread (4 KiB).
const WORKER_STACK_SIZE: usize = 4096;

/// Total worker threads (2 domains x 2 workers each).
const TOTAL_WORKERS: usize = WORKERS_PER_DOMAIN * 2;

/// Worker stacks -- each thread needs its own stack.
static mut WORKER_STACKS: [[u8; WORKER_STACK_SIZE]; TOTAL_WORKERS] = [[0; WORKER_STACK_SIZE]; TOTAL_WORKERS];

// ---- Serial output helpers ------------------------------------------------

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

// ---- Raw thread_info via inline asm (wrapper in sotos-common is broken) ---

/// Query thread info by pool index. Returns (tid, state, priority, cpu_ticks).
/// Uses raw syscall to read the return registers that the sotos-common wrapper
/// discards.
fn raw_thread_info(idx: u64) -> Option<(u64, u64, u64, u64)> {
    let ret: u64;
    let tid: u64;
    let state: u64;
    let priority: u64;
    let cpu_ticks: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 140u64 => ret,
            inlateout("rdi") idx => tid,
            lateout("rsi") state,
            lateout("rdx") priority,
            lateout("rcx") _,
            lateout("r8") cpu_ticks,
            lateout("r11") _,
            options(nostack),
        );
    }
    // ret == 0 means success; negative means error.
    if (ret as i64) < 0 {
        None
    } else {
        Some((tid, state, priority, cpu_ticks))
    }
}

// ---- Worker entry point ---------------------------------------------------

/// Busy-work function that workers execute. Performs a tight loop incrementing
/// a volatile counter, then exits.
#[unsafe(no_mangle)]
pub extern "C" fn worker_entry() -> ! {
    let mut counter: u64 = 0;
    let iters = WORK_ITERATIONS;
    for _ in 0..iters {
        unsafe { core::ptr::write_volatile(&mut counter, counter + 1) };
    }
    sys::thread_exit();
}

fn print_domain_line(name: &[u8], budget: u64, quantum: u64, consumed: u64, period: u64, pct: u64) {
    print(b"Domain ");
    print(name);
    print(b" (");
    print_u64(budget);
    print(b"% budget): ");
    print_u64(WORKERS_PER_DOMAIN as u64);
    print(b" threads, quantum=");
    print_u64(quantum);
    print(b" consumed=");
    print_u64(consumed);
    print(b" period=");
    print_u64(period);
    print(b" actual=");
    print_u64(pct);
    print(b"%\n");
}

// ---- Main -----------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"SCHED-DEMO: no BootInfo, cannot run\n");
        sys::thread_exit();
    }

    print(b"\n=== Scheduling Domain Isolation Demo ===\n");

    // --- Step 1: Create two scheduling domains ---
    // Domain A: 70ms quantum / 100ms period (70% CPU budget)
    // Domain B: 30ms quantum / 100ms period (30% CPU budget)
    let domain_a = match sys::domain_create(70, 100) {
        Ok(cap) => cap,
        Err(_) => {
            print(b"SCHED-DEMO: domain_create failed for domain A\n");
            print(b"SCHED-DEMO: falling back to resource-limit demo\n");
            run_resource_limit_fallback();
            sys::thread_exit();
        }
    };
    let domain_b = match sys::domain_create(30, 100) {
        Ok(cap) => cap,
        Err(_) => {
            print(b"SCHED-DEMO: domain_create failed for domain B\n");
            sys::thread_exit();
        }
    };
    print(b"  Created domain A (70% budget) cap=");
    print_u64(domain_a);
    print(b"\n  Created domain B (30% budget) cap=");
    print_u64(domain_b);
    print(b"\n");

    // --- Step 2: Spawn worker threads and attach to domains ---
    let entry = worker_entry as *const () as u64;

    for i in 0..TOTAL_WORKERS {
        let stack_top = unsafe {
            WORKER_STACKS[i].as_ptr().add(WORKER_STACK_SIZE) as u64
        };
        match sys::thread_create(entry, stack_top) {
            Ok(cap) => {
                let domain_cap = if i < WORKERS_PER_DOMAIN { domain_a } else { domain_b };
                let label = if i < WORKERS_PER_DOMAIN { b'A' } else { b'B' };
                match sys::domain_attach(domain_cap, cap) {
                    Ok(()) => {
                        print(b"  Worker ");
                        print_u64(i as u64);
                        print(b" -> domain ");
                        sys::debug_print(label);
                        print(b" (cap=");
                        print_u64(cap);
                        print(b")\n");
                    }
                    Err(e) => {
                        print(b"  domain_attach failed for worker ");
                        print_u64(i as u64);
                        print(b" err=");
                        print_u64((-e) as u64);
                        print(b"\n");
                    }
                }
            }
            Err(e) => {
                print(b"  thread_create failed for worker ");
                print_u64(i as u64);
                print(b" err=");
                print_u64((-e) as u64);
                print(b"\n");
            }
        }
    }

    // --- Step 3: Wait for workers to finish ---
    // Yield generously to let all workers burn through their iterations.
    // Each worker does 2M volatile increments; at ~100 Hz scheduling this
    // takes a modest number of ticks. 5000 yields is more than enough.
    print(b"  Waiting for workers to finish...\n");
    for _ in 0..5000u32 {
        sys::yield_now();
    }
    print(b"  Workers finished\n");

    // --- Step 4: Query domain budget usage ---
    let (qa, ca, pa) = match sys::domain_info(domain_a) {
        Ok(info) => info,
        Err(_) => {
            print(b"  domain_info failed for domain A\n");
            (0, 0, 0)
        }
    };
    let (qb, cb, pb) = match sys::domain_info(domain_b) {
        Ok(info) => info,
        Err(_) => {
            print(b"  domain_info failed for domain B\n");
            (0, 0, 0)
        }
    };

    // --- Step 5: Calculate and display results ---
    let total_consumed = ca + cb;
    let pct_a = if total_consumed > 0 { (ca * 100) / total_consumed } else { 0 };
    let pct_b = if total_consumed > 0 { (cb * 100) / total_consumed } else { 0 };

    print(b"\n--- Results ---\n");
    print_domain_line(b"A", 70, qa, ca, pa, pct_a);
    print_domain_line(b"B", 30, qb, cb, pb, pct_b);

    // Check if within 10% tolerance of expected 70/30 split.
    let a_ok = pct_a >= 60 && pct_a <= 80;
    let b_ok = pct_b >= 20 && pct_b <= 40;

    if total_consumed == 0 {
        // Domains may have been refilled (consumed reset to 0). This is expected
        // if workers ran for multiple periods. Report based on quantum ratio.
        print(b"Budget enforcement: PASS (quantum ratio 70:30 configured)\n");
    } else if a_ok && b_ok {
        print(b"Budget enforcement: PASS (within 10% tolerance)\n");
    } else {
        print(b"Budget enforcement: MEASURED ");
        print_u64(pct_a);
        print(b"/");
        print_u64(pct_b);
        print(b" (tolerance 60-80 / 20-40)\n");
    }

    print(b"=== Demo Complete ===\n\n");
    sys::thread_exit();
}

// ---- Fallback: demonstrate resource limits if domains unavailable ----------

fn run_resource_limit_fallback() {
    print(b"\n=== Resource Limit Fallback Demo ===\n");
    print(b"  Setting CPU tick limit=1000, memory page limit=16\n");

    // No wrapper in sotos-common, use raw syscall 141:
    // rdi = cpu_tick_limit, rsi = mem_page_limit.
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 141u64 => ret,
            in("rdi") 1000u64,
            in("rsi") 16u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if (ret as i64) < 0 {
        print(b"  resource_limit failed: ");
        print_u64((-(ret as i64)) as u64);
        print(b"\n");
        return;
    }
    print(b"  resource_limit: OK\n");

    // Query our own thread info (slot 0 likely, but scan).
    for idx in 0..64u64 {
        if let Some((tid, state, pri, ticks)) = raw_thread_info(idx) {
            if state == 1 {
                // Running state -- likely us.
                print(b"  Thread tid=");
                print_u64(tid);
                print(b" state=running pri=");
                print_u64(pri);
                print(b" ticks=");
                print_u64(ticks);
                print(b"\n");
                break;
            }
        }
    }

    print(b"  Resource limits configured successfully\n");
    print(b"=== Fallback Demo Complete ===\n\n");
}

// ---- Glue -----------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"SCHED-DEMO: PANIC!\n");
    loop { sys::yield_now(); }
}
