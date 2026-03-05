//! sotOS VMM (Virtual Memory Manager) Service Process
//!
//! Handles page faults for the init process by allocating frames and
//! mapping them into init's address space.
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

    print(b"VMM: registered for init faults\n");

    // Fault handling loop.
    loop {
        sys::notify_wait(notify_cap);
        loop {
            match sys::fault_recv() {
                Ok(fault) => {
                    let frame = sys::frame_alloc().unwrap_or_else(|_| {
                        print(b"VMM: frame_alloc failed!\n");
                        loop { sys::yield_now(); }
                    });
                    let vaddr = fault.addr & !0xFFF;
                    sys::map_into(init_as_cap, vaddr, frame, MAP_WRITABLE).unwrap_or_else(|_| {
                        print(b"VMM: map_into failed!\n");
                        loop { sys::yield_now(); }
                    });
                    sys::thread_resume(fault.tid as u64).unwrap_or_else(|_| {
                        print(b"VMM: thread_resume failed!\n");
                        loop { sys::yield_now(); }
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
