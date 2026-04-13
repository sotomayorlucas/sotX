//! sotX VMM (Virtual Memory Manager) Service Process
//!
//! Handles page faults for the init process and CoW-cloned child address
//! spaces by allocating frames and mapping them.
//!
//! Runs as a separate process with its own CR3.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

/// Root capability indices (must match kernel write_vmm_boot_info() order).
const CAP_NOTIFY: usize = 0;  // Notification (fault delivery)
const CAP_INIT_AS: usize = 1; // AddrSpace cap for init's CR3

/// WRITABLE flag for map_into syscall (bit 1).
const MAP_WRITABLE: u64 = 2;

// ── ρ_fiss frame pool (pre-allocated frames for fast CoW path) ──────
const POOL_SIZE: usize = 16;
static mut FRAME_POOL: [u64; POOL_SIZE] = [0; POOL_SIZE];
static mut FRAME_POOL_COUNT: usize = 0;

/// Take a frame from the pool, falling back to sys::frame_alloc().
fn pool_take() -> Result<u64, ()> {
    unsafe {
        if FRAME_POOL_COUNT > 0 {
            FRAME_POOL_COUNT -= 1;
            Ok(FRAME_POOL[FRAME_POOL_COUNT])
        } else {
            sys::frame_alloc().map_err(|_| ())
        }
    }
}

/// Refill the pool up to POOL_SIZE before blocking on notify_wait.
fn pool_refill() {
    unsafe {
        while FRAME_POOL_COUNT < POOL_SIZE {
            match sys::frame_alloc() {
                Ok(f) => {
                    FRAME_POOL[FRAME_POOL_COUNT] = f;
                    FRAME_POOL_COUNT += 1;
                }
                Err(_) => break,
            }
        }
    }
}

fn print(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

fn print_hex16(val: u64) {
    for i in (0..4).rev() {
        let nib = ((val >> (i * 4)) & 0xF) as u8;
        sys::debug_print(if nib < 10 { b'0' + nib } else { b'a' + nib - 10 });
    }
}

fn print_hex64(val: u64) {
    for i in (0..16).rev() {
        let nib = ((val >> (i * 4)) & 0xF) as u8;
        sys::debug_print(if nib < 10 { b'0' + nib } else { b'a' + nib - 10 });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"VMM: invalid BootInfo!\n");
        loop { sys::yield_now(); }
    }

    let notify_cap = boot_info.caps[CAP_NOTIFY];
    let init_as_cap = boot_info.caps[CAP_INIT_AS];

    // Register for page faults in init's address space.
    sys::fault_register_as(notify_cap, init_as_cap).unwrap_or_else(|_| {
        print(b"VMM: fault_register_as failed!\n");
        loop { sys::yield_now(); }
    });

    // Also register as global fallback handler (cr3=0) to catch faults
    // from CoW-cloned child address spaces created by fork.
    sys::fault_register(notify_cap).unwrap_or_else(|_| {
        print(b"VMM: global fault_register failed!\n");
        loop { sys::yield_now(); }
    });

    print(b"VMM: registered for init + global faults\n");

    // Track last fault per thread to detect infinite loops.
    // [tid % 16] -> (last_addr, repeat_count)
    let mut fault_track: [(u64, u32); 16] = [(0, 0); 16];
    let mut fault_count: u32 = 0;

    // Rate-limit noisy error messages (print first N, then go silent).
    let mut segv_logged: u32 = 0;
    let mut cow_fail_logged: u32 = 0;
    let mut map_fail_logged: u32 = 0;
    const MAX_ERR_LOG: u32 = 5;

    // Fault handling loop.
    loop {
        pool_refill(); // ρ_fiss: pre-allocate frames before blocking
        sys::notify_wait(notify_cap);
        loop {
            match sys::fault_recv() {
                Ok(fault) => {
                    let vaddr_raw = fault.addr & !0xFFF;
                    let code = fault.code;
                    let slot = (fault.tid as usize) % 16;

                    // Use the AS cap delivered with the fault.
                    // The kernel resolves cr3 → as_cap_id via register_cr3_cap().
                    // Fall back to init_as_cap if no specific cap was registered.
                    let target_as_cap = if fault.as_cap_id != 0 {
                        fault.as_cap_id
                    } else {
                        init_as_cap
                    };

                    fault_count += 1;
                    // Log only the first 5 faults
                    if fault_count <= 5 {
                        print(b"VF t=");
                        print_hex16(fault.tid as u64);
                        print(b" a=");
                        print_hex64(fault.addr);
                        print(b" c=");
                        print_hex16(code);
                        print(b" cap=");
                        print_hex16(fault.as_cap_id);
                        print(b" #");
                        print_hex16(fault_count as u64);
                        print(b"\n");
                    }

                    // Guard: kernel-space address — user tried to access HHDM/kernel memory.
                    // Leave thread suspended (can't deliver SIGSEGV without infinite fault loop).
                    if fault.addr >= 0xFFFF_8000_0000_0000 {
                        print(b"VMM: KERN-ADDR t=");
                        print_hex16(fault.tid as u64);
                        print(b"\n");
                        continue;
                    }

                    // Guard: NX violation (instruction fetch on NX page).
                    // Fix by making the page R+X (read-only executable).
                    // MUST strip WRITABLE — otherwise kernel W^X re-adds NX
                    // for address spaces without wx_relaxed.
                    if code & 0x11 == 0x11 {
                        // Pass flags=0 → kernel sets PRESENT|USER (R+X, no NX)
                        if sys::protect_in(target_as_cap, vaddr_raw, 0).is_ok() {
                            let _ = sys::thread_resume(fault.tid as u64);
                        } else {
                            let _ = sys::signal_inject(fault.tid as u64, 11);
                            let _ = sys::thread_resume(fault.tid as u64);
                        }
                        continue;
                    }

                    // Guard: Infinite loop detection (same address > 8 times).
                    // Inject SIGSEGV instead of leaving thread suspended.
                    if fault_track[slot].0 == vaddr_raw {
                        fault_track[slot].1 += 1;
                        if fault_track[slot].1 > 8 {
                            if segv_logged < MAX_ERR_LOG {
                                segv_logged += 1;
                                print(b"VMM: SEGV t=");
                                print_hex16(fault.tid as u64);
                                print(b" a=");
                                print_hex64(fault.addr);
                                print(b"\n");
                                if segv_logged == MAX_ERR_LOG {
                                    print(b"VMM: suppressing further SEGV messages\n");
                                }
                            }
                            let _ = sys::signal_inject(fault.tid as u64, 11); // SIGSEGV
                            let _ = sys::thread_resume(fault.tid as u64);
                            fault_track[slot].1 = 0;
                            continue;
                        }
                    } else {
                        fault_track[slot] = (vaddr_raw, 1);
                    }

                    // Check for CoW fault: write (bit 1) to present (bit 0) page.
                    if code & 0x03 == 0x03 {
                        // CoW fault: page is present but read-only due to clone_cow.
                        // 1. Allocate a new frame (from ρ_fiss pool or fallback)
                        let new_frame = match pool_take() {
                            Ok(f) => f,
                            Err(_) => {
                                if cow_fail_logged < MAX_ERR_LOG {
                                    cow_fail_logged += 1;
                                    print(b"VMM: OOM(CoW)\n");
                                    if cow_fail_logged == MAX_ERR_LOG {
                                        print(b"VMM: suppressing further OOM messages\n");
                                    }
                                }
                                let _ = sys::signal_inject(fault.tid as u64, 9);
                                let _ = sys::thread_resume(fault.tid as u64);
                                continue;
                            }
                        };
                        // 2. Copy 4KiB from the old frame to the new frame
                        //    (kernel copies via HHDM using SYS_FRAME_COPY)
                        if let Err(_) = sys::frame_copy(new_frame, target_as_cap, vaddr_raw) {
                            if cow_fail_logged < MAX_ERR_LOG {
                                cow_fail_logged += 1;
                                print(b"VMM: FC-FAIL t=");
                                print_hex16(fault.tid as u64);
                                print(b"\n");
                            }
                        }
                        // 3. Unmap old PTE
                        if sys::unmap_from(target_as_cap, vaddr_raw).is_err() {
                            if cow_fail_logged < MAX_ERR_LOG {
                                cow_fail_logged += 1;
                                print(b"VMM: UM-FAIL t=");
                                print_hex16(fault.tid as u64);
                                print(b"\n");
                            }
                        }
                        // 4. Map new frame as WRITABLE
                        if sys::map_into(target_as_cap, vaddr_raw, new_frame, MAP_WRITABLE).is_err() {
                            print(b"VMM: MI-FAIL t=");
                            print_hex16(fault.tid as u64);
                            print(b" a=");
                            print_hex64(vaddr_raw);
                            print(b"\n");
                            continue; // leave thread suspended
                        }
                        // 5. Resume thread
                        if sys::thread_resume(fault.tid as u64).is_err() {
                            print(b"VMM: RS-FAIL t=");
                            print_hex16(fault.tid as u64);
                            print(b"\n");
                        }

                        // 6. Speculative adjacent CoW resolution (ρ_fiss)
                        //    Pre-resolve neighboring pages that are likely also CoW,
                        //    avoiding future fault round-trips for sequential access.
                        for &adj in &[vaddr_raw.wrapping_add(0x1000), vaddr_raw.wrapping_sub(0x1000)] {
                            if adj == 0 || adj >= 0xFFFF_8000_0000_0000 { continue; }
                            match sys::pte_read(target_as_cap, adj) {
                                Ok((_, flags)) if flags & 0x03 == 0x01 => {
                                    // Present but not writable — likely CoW
                                    if let Ok(nf) = pool_take() {
                                        if sys::frame_copy(nf, target_as_cap, adj).is_ok()
                                            && sys::unmap_from(target_as_cap, adj).is_ok() {
                                            let _ = sys::map_into(target_as_cap, adj, nf, MAP_WRITABLE);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        continue;
                    }

                    // NULL page access: map a zeroed read-only page.
                    // Wine's loader reads from address 0 to probe for Windows PEB/TEB
                    // before signal handlers are installed. If we inject SIGSEGV here,
                    // the process dies (no handler). Instead, map a zero page read-only:
                    // reads succeed (return 0 → Wine skips Windows path), writes still
                    // fault (→ SIGSEGV once handlers are installed for exception dispatch).
                    if vaddr_raw == 0 {
                        let frame = match pool_take() {
                            Ok(f) => f,
                            Err(_) => { let _ = sys::thread_resume(fault.tid as u64); continue; }
                        };
                        let is_write = fault.code & 2 != 0;
                        if is_write {
                            // Write to NULL page → SIGSEGV (for Wine exception dispatch)
                            let _ = sys::signal_inject(fault.tid as u64, 11);
                            let _ = sys::thread_resume(fault.tid as u64);
                        } else {
                            // Read from NULL page → map zeroed read-only frame
                            let _ = sys::map_into(target_as_cap, 0, frame, 0); // RO, no write
                            let _ = sys::thread_resume(fault.tid as u64);
                        }
                        continue;
                    }

                    // Demand paging: page not present — allocate new frame (from pool).
                    let frame = match pool_take() {
                        Ok(f) => f,
                        Err(_) => {
                            print(b"VMM: OOM t=");
                            print_hex16(fault.tid as u64);
                            print(b"\n");
                            continue;
                        }
                    };
                    if sys::map_into(target_as_cap, vaddr_raw, frame, MAP_WRITABLE).is_err() {
                        if map_fail_logged < MAX_ERR_LOG {
                            map_fail_logged += 1;
                            print(b"VMM: SEGV t=");
                            print_hex16(fault.tid as u64);
                            print(b" a=");
                            print_hex64(fault.addr);
                            print(b"\n");
                            if map_fail_logged == MAX_ERR_LOG {
                                print(b"VMM: suppressing further map-fail messages\n");
                            }
                        }
                        let _ = sys::signal_inject(fault.tid as u64, 11);
                        let _ = sys::thread_resume(fault.tid as u64);
                        continue;
                    }
                    sys::thread_resume(fault.tid as u64).unwrap_or_else(|_| {
                        print(b"VMM: thread_resume failed!\n");
                        // Don't hang — just skip
                    });
                }
                Err(_) => break,
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"VMM PANIC\n");
    loop { sys::yield_now(); }
}
