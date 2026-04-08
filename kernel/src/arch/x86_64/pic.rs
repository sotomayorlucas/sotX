//! 8259 PIC (Programmable Interrupt Controller) driver.
//!
//! Remaps IRQ 0-7 → vectors 32-39, IRQ 8-15 → vectors 40-47.

use super::io::{inb, outb};

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

const EOI: u8 = 0x20;

/// Vector offset for master PIC (IRQ 0-7).
pub const PIC1_OFFSET: u8 = 32;
/// Vector offset for slave PIC (IRQ 8-15).
pub const PIC2_OFFSET: u8 = 40;

/// Small I/O delay — read from an unused port.
#[inline]
unsafe fn io_wait() {
    // SAFETY: port 0x80 is the legacy POST diagnostic port — writing to it
    // is the canonical ~1us I/O delay and has no effect on any driver.
    unsafe { outb(0x80, 0) };
}

/// Initialize both 8259 PICs with ICW1-4 sequence and mask all IRQs.
pub fn init() {
    // SAFETY: the master/slave 8259 ports (0x20/0x21/0xA0/0xA1) are owned by
    // the PIC driver with no concurrent users during kernel init. The command
    // sequence below follows the 8259 ICW1-ICW4 initialization protocol exactly,
    // and port 0x80 is the POST diagnostic port used purely for I/O delay.
    unsafe {
        // Save current masks.
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        // ICW1: begin initialization sequence.
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: vector offsets.
        outb(PIC1_DATA, PIC1_OFFSET);
        io_wait();
        outb(PIC2_DATA, PIC2_OFFSET);
        io_wait();

        // ICW3: master has slave on IRQ2, slave cascade identity = 2.
        outb(PIC1_DATA, 0x04); // slave on IRQ2
        io_wait();
        outb(PIC2_DATA, 0x02); // cascade identity
        io_wait();

        // ICW4: 8086 mode.
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Mask all IRQs initially.
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);

        let _ = (mask1, mask2); // original masks intentionally discarded
    }
}

/// Unmask (enable) a specific IRQ line.
pub fn unmask(irq: u8) {
    // SAFETY: PIC1_DATA/PIC2_DATA (0x21/0xA1) are the IMR registers owned by
    // the PIC driver; the read-modify-write sequence is atomic w.r.t. other
    // IRQ sources on a single CPU and the driver is the sole writer.
    unsafe {
        if irq < 8 {
            let mask = inb(PIC1_DATA) & !(1 << irq);
            outb(PIC1_DATA, mask);
        } else {
            let mask = inb(PIC2_DATA) & !(1 << (irq - 8));
            outb(PIC2_DATA, mask);
            // Also unmask IRQ2 on master (cascade line).
            let master_mask = inb(PIC1_DATA) & !(1 << 2);
            outb(PIC1_DATA, master_mask);
        }
    }
}

/// Mask (disable) a specific IRQ line.
pub fn mask(irq: u8) {
    // SAFETY: same as `unmask` — PIC1_DATA/PIC2_DATA are the PIC IMR registers
    // owned exclusively by the PIC driver.
    unsafe {
        if irq < 8 {
            let val = inb(PIC1_DATA) | (1 << irq);
            outb(PIC1_DATA, val);
        } else {
            let val = inb(PIC2_DATA) | (1 << (irq - 8));
            outb(PIC2_DATA, val);
            // Do NOT re-mask IRQ2 (cascade) — other slave IRQs may still be active.
        }
    }
}

/// Send End-Of-Interrupt to the appropriate PIC(s).
pub fn send_eoi(irq: u8) {
    // SAFETY: writing 0x20 (EOI) to PIC1_CMD/PIC2_CMD (0x20/0xA0) is the
    // canonical end-of-interrupt sequence per the 8259 spec. Called from IRQ
    // handlers which are the sole users of these command ports.
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, EOI);
        }
        outb(PIC1_CMD, EOI);
    }
}
