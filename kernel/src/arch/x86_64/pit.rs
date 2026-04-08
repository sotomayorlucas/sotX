//! 8253/8254 PIT (Programmable Interval Timer) driver.
//!
//! Configures channel 0 as a rate generator at ~100 Hz.
//! Not currently used (LAPIC timer is used instead) but kept for fallback.

#![allow(dead_code)]

use super::io::outb;

const PIT_CH0: u16 = 0x40;
const PIT_CMD: u16 = 0x43;

const PIT_FREQUENCY: u32 = 1_193_182;
const TARGET_HZ: u32 = 100;

/// Initialize the PIT channel 0 at ~100 Hz (mode 2, rate generator).
pub fn init() {
    let divisor: u16 = (PIT_FREQUENCY / TARGET_HZ) as u16; // 11932 = 0x2E9C

    unsafe {
        // Channel 0, access lo/hi byte, mode 2 (rate generator), binary.
        outb(PIT_CMD, 0x34);
        outb(PIT_CH0, divisor as u8); // low byte
        outb(PIT_CH0, (divisor >> 8) as u8); // high byte
    }
}
