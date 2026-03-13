//! sotOS VMM (Virtual Memory Manager) Service Process
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

    // Fault handling loop.
    loop {
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
                    // Log first 50 faults, then every 1000th
                    if fault_count <= 50 || fault_count % 1000 == 0 {
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

                    // Guard: Infinite loop detection (same address > 4 times).
                    if fault_track[slot].0 == vaddr_raw {
                        fault_track[slot].1 += 1;
                        if fault_track[slot].1 > 4 {
                            print(b"VMM: LOOP-KILL t=");
                            print_hex16(fault.tid as u64);
                            print(b" a=");
                            print_hex64(fault.addr);
                            print(b"\n");
                            continue; // leave thread suspended
                        }
                    } else {
                        fault_track[slot] = (vaddr_raw, 1);
                    }

                    // Check for CoW fault: write (bit 1) to present (bit 0) page.
                    if code & 0x03 == 0x03 {
                        // CoW fault: page is present but read-only due to clone_cow.
                        // 1. Allocate a new frame
                        let new_frame = match sys::frame_alloc() {
                            Ok(f) => f,
                            Err(_) => {
                                print(b"VMM: OOM(CoW)\n");
                                continue; // leave thread suspended
                            }
                        };
                        // 2. Copy 4KiB from the old frame to the new frame
                        //    (kernel copies via HHDM using SYS_FRAME_COPY)
                        if let Err(_) = sys::frame_copy(new_frame, target_as_cap, vaddr_raw) {
                            print(b"VMM: FC-FAIL t=");
                            print_hex16(fault.tid as u64);
                            print(b"\n");
                        }
                        // 3. Unmap old PTE
                        if sys::unmap_from(target_as_cap, vaddr_raw).is_err() {
                            print(b"VMM: UM-FAIL t=");
                            print_hex16(fault.tid as u64);
                            print(b"\n");
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
                        continue;
                    }

                    // Demand paging: page not present — allocate new frame.
                    let frame = match sys::frame_alloc() {
                        Ok(f) => f,
                        Err(_) => {
                            print(b"VMM: OOM t=");
                            print_hex16(fault.tid as u64);
                            print(b"\n");
                            continue;
                        }
                    };
                    if sys::map_into(target_as_cap, vaddr_raw, frame, MAP_WRITABLE).is_err() {
                        print(b"VMM: SEGV t=");
                        print_hex16(fault.tid as u64);
                        print(b" a=");
                        print_hex64(fault.addr);
                        print(b"\n");
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
