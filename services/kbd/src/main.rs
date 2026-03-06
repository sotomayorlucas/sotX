#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

/// Root capability indices (must match kernel write_kbd_boot_info() order).
const CAP_KB_IRQ: usize = 0;      // IRQ 1 (keyboard)
const CAP_KB_PORT: usize = 1;     // I/O port 0x60–0x64 (PS/2 data + command)
const CAP_KB_NOTIFY: usize = 2;   // Notification (KB+mouse IRQ delivery)
const CAP_MOUSE_IRQ: usize = 3;   // IRQ 12 (mouse)

use sotos_common::{KB_RING_ADDR, MOUSE_RING_ADDR};

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

/// Wait for PS/2 controller input buffer to be ready (bit 1 of 0x64 clear).
fn ps2_wait_write(port_cap: u64) {
    for _ in 0..10000 {
        let status = sys::port_in(port_cap, 0x64).unwrap_or(0xFF);
        if status & 0x02 == 0 { return; }
    }
}

/// Wait for PS/2 controller output buffer to have data (bit 0 of 0x64 set).
fn ps2_wait_read(port_cap: u64) -> bool {
    for _ in 0..10000 {
        let status = sys::port_in(port_cap, 0x64).unwrap_or(0);
        if status & 0x01 != 0 { return true; }
    }
    false
}

/// Send a command byte to the PS/2 controller (port 0x64).
fn ps2_cmd(port_cap: u64, cmd: u8) {
    ps2_wait_write(port_cap);
    let _ = sys::port_out(port_cap, 0x64, cmd);
}

/// Send a data byte to port 0x60.
fn ps2_data_out(port_cap: u64, data: u8) {
    ps2_wait_write(port_cap);
    let _ = sys::port_out(port_cap, 0x60, data);
}

/// Read a byte from port 0x60 (with timeout).
fn ps2_data_in(port_cap: u64) -> Option<u8> {
    if ps2_wait_read(port_cap) {
        sys::port_in(port_cap, 0x60).map(|v| v as u8).ok()
    } else {
        None
    }
}

/// Enable PS/2 mouse (auxiliary device).
fn enable_mouse(port_cap: u64) {
    // Enable auxiliary device.
    ps2_cmd(port_cap, 0xA8);

    // Read controller config byte.
    ps2_cmd(port_cap, 0x20);
    let config = ps2_data_in(port_cap).unwrap_or(0);

    // Set bit 1 (IRQ12 enable) and bit 5 clear (mouse clock enable).
    let new_config = (config | 0x02) & !0x20;
    ps2_cmd(port_cap, 0x60);
    ps2_data_out(port_cap, new_config);

    // Send "set defaults" to mouse.
    ps2_cmd(port_cap, 0xD4); // write to auxiliary device
    ps2_data_out(port_cap, 0xF6); // set defaults
    let _ = ps2_data_in(port_cap); // ACK

    // Enable data reporting.
    ps2_cmd(port_cap, 0xD4);
    ps2_data_out(port_cap, 0xF4); // enable
    let _ = ps2_data_in(port_cap); // ACK
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
    let mouse_irq_cap = boot_info.caps[CAP_MOUSE_IRQ];

    sys::irq_register(irq_cap, notify_cap).unwrap_or_else(|_| {
        print(b"KBD: irq_register failed\n");
        loop { sys::yield_now(); }
    });

    sys::irq_register(mouse_irq_cap, notify_cap).unwrap_or_else(|_| {
        print(b"KBD: mouse irq_register failed\n");
        loop { sys::yield_now(); }
    });

    // Init keyboard ring buffer: [write_idx: u32, read_idx: u32, data: [u8; 256]]
    unsafe {
        let ring = KB_RING_ADDR as *mut u32;
        core::ptr::write_volatile(ring, 0);
        core::ptr::write_volatile(ring.add(1), 0);
    }

    // Init mouse ring buffer: [write_idx: u32, read_idx: u32, packets: [(dx: i8, dy: i8, buttons: u8, _pad: u8); 64]]
    unsafe {
        let mring = MOUSE_RING_ADDR as *mut u32;
        core::ptr::write_volatile(mring, 0);
        core::ptr::write_volatile(mring.add(1), 0);
    }

    // Enable PS/2 mouse.
    enable_mouse(port_cap);

    print(b"KB+MOUSE\n");

    // Mouse packet state machine.
    let mut mouse_bytes: [u8; 3] = [0; 3];
    let mut mouse_idx: usize = 0;

    loop {
        sys::notify_wait(notify_cap);

        // Read all available bytes from PS/2 controller.
        loop {
            let status = sys::port_in(port_cap, 0x64).unwrap_or(0);
            if status & 0x01 == 0 { break; } // no data

            let data = sys::port_in(port_cap, 0x60).unwrap_or(0) as u8;

            if status & 0x20 != 0 {
                // Bit 5 set = mouse data (auxiliary).
                mouse_bytes[mouse_idx] = data;
                mouse_idx += 1;
                if mouse_idx >= 3 {
                    mouse_idx = 0;
                    // Validate: byte 0 bit 3 should be set.
                    if mouse_bytes[0] & 0x08 != 0 {
                        let buttons = mouse_bytes[0] & 0x07;
                        let dx = mouse_bytes[1] as i8;
                        let dy = mouse_bytes[2] as i8;
                        // Write to mouse ring.
                        unsafe {
                            let mring = MOUSE_RING_ADDR as *mut u32;
                            let write_idx = core::ptr::read_volatile(mring);
                            let idx = (write_idx & 63) as usize;
                            let base = MOUSE_RING_ADDR + 8 + (idx * 4) as u64;
                            *(base as *mut i8) = dx;
                            *((base + 1) as *mut i8) = dy;
                            *((base + 2) as *mut u8) = buttons;
                            *((base + 3) as *mut u8) = 0;
                            core::ptr::write_volatile(mring, (write_idx.wrapping_add(1)) & 63);
                        }
                    }
                }
            } else {
                // Keyboard data.
                unsafe {
                    let ring = KB_RING_ADDR as *mut u32;
                    let write_idx = core::ptr::read_volatile(ring);
                    let idx = (write_idx & 0xFF) as usize;
                    *((KB_RING_ADDR + 8 + idx as u64) as *mut u8) = data;
                    core::ptr::write_volatile(ring, (write_idx.wrapping_add(1)) & 0xFF);
                }
            }
        }

        let _ = sys::irq_ack(irq_cap);
        let _ = sys::irq_ack(mouse_irq_cap);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"KBD PANIC\n");
    loop { sys::yield_now(); }
}
