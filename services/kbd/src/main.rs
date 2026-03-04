#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

/// Root capability indices (must match kernel write_kbd_boot_info() order).
const CAP_KB_IRQ: usize = 0;      // IRQ 1 (keyboard)
const CAP_KB_PORT: usize = 1;     // I/O port 0x60 (keyboard data)
const CAP_KB_NOTIFY: usize = 2;   // Notification (KB IRQ delivery)

/// Keyboard ring buffer address (shared with init process).
const KB_RING_ADDR: u64 = 0x510000;

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"KBD: invalid BootInfo!\n");
        loop { sys::yield_now(); }
    }

    let irq_cap = boot_info.caps[CAP_KB_IRQ];
    let port_cap = boot_info.caps[CAP_KB_PORT];
    let notify_cap = boot_info.caps[CAP_KB_NOTIFY];

    sys::irq_register(irq_cap, notify_cap).unwrap_or_else(|_| {
        print(b"KBD: irq_register failed\n");
        loop { sys::yield_now(); }
    });

    // Init ring buffer: [write_idx: u32, read_idx: u32, data: [u8; 256]]
    unsafe {
        let ring = KB_RING_ADDR as *mut u32;
        core::ptr::write_volatile(ring, 0);          // write_idx = 0
        core::ptr::write_volatile(ring.add(1), 0);   // read_idx = 0
    }

    print(b"KB\n");

    loop {
        sys::notify_wait(notify_cap);
        let scancode = sys::port_in(port_cap, 0x60).unwrap_or(0);
        let _ = sys::irq_ack(irq_cap);

        unsafe {
            let ring = KB_RING_ADDR as *mut u32;
            let write_idx = core::ptr::read_volatile(ring);
            let idx = (write_idx & 0xFF) as usize;
            *((KB_RING_ADDR + 8 + idx as u64) as *mut u8) = scancode;
            core::ptr::write_volatile(ring, (write_idx.wrapping_add(1)) & 0xFF);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"KBD PANIC\n");
    loop { sys::yield_now(); }
}
