use crate::kprintln;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

/// Prevent recursive panics.
static PANICKING: AtomicBool = AtomicBool::new(false);

/// NMI vector for halting other CPUs on panic.
const PANIC_NMI_VECTOR: u8 = 2;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Disable interrupts immediately to prevent further scheduling on this CPU.
    x86_64::instructions::interrupts::disable();

    // Prevent recursive panic (double fault during panic output).
    if PANICKING.swap(true, Ordering::SeqCst) {
        crate::arch::halt_loop();
    }

    let cpu_index = crate::arch::percpu::current_percpu().cpu_index;

    kprintln!("========================================");
    kprintln!("!!! KERNEL PANIC (CPU {}) !!!", cpu_index);
    kprintln!("========================================");
    kprintln!("{}", info);

    // Print current thread info.
    let percpu = crate::arch::percpu::current_percpu();
    let thread_idx = percpu.current_thread;
    if thread_idx != usize::MAX {
        if let Some(sched) = crate::sched::SCHEDULER.try_lock() {
            if let Some(t) = sched.threads.get_by_index(thread_idx as u32) {
                kprintln!(
                    "  thread: id={} pri={} user={} ticks={}",
                    t.id.0,
                    t.priority,
                    t.is_user,
                    t.cpu_ticks
                );
            }
        }
    }

    // Attempt basic stack trace via frame pointer chain.
    kprintln!("--- stack trace ---");
    let mut rbp: u64;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp);
    }
    for i in 0..16 {
        if rbp == 0 || rbp < 0x1000 || rbp % 8 != 0 {
            break;
        }
        // Frame: [rbp] = saved rbp, [rbp+8] = return address
        let ret_addr = unsafe { *((rbp + 8) as *const u64) };
        if ret_addr == 0 {
            break;
        }
        kprintln!("  #{}: 0x{:016x}", i, ret_addr);
        rbp = unsafe { *(rbp as *const u64) };
    }
    kprintln!("--- end trace ---");

    // Halt all other CPUs via NMI broadcast.
    crate::arch::x86_64::lapic::send_ipi_all_others(PANIC_NMI_VECTOR);

    kprintln!("System halted.");
    crate::arch::halt_loop()
}
