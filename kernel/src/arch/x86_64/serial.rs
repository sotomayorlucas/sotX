//! Minimal 16550 UART serial driver for early kernel output.
//! COM1 at I/O port 0x3F8.

use super::io::{inb, outb};
use core::fmt;
use spin::Mutex;

/// Lock protecting serial output from concurrent access on multiple CPUs.
static SERIAL_LOCK: Mutex<()> = Mutex::new(());

const COM1: u16 = 0x3F8;

/// Initialize COM1 serial port at 38400 baud.
pub fn init() {
    // SAFETY: COM1 I/O ports 0x3F8..0x3FF are owned by this serial driver;
    // no other code touches them. The write sequence below follows the 16550
    // UART init protocol and uses only constant port numbers.
    unsafe {
        outb(COM1 + 1, 0x00); // Disable all interrupts
        outb(COM1 + 3, 0x80); // Enable DLAB (set baud rate divisor)
        outb(COM1 + 0, 0x03); // Divisor low byte: 38400 baud
        outb(COM1 + 1, 0x00); // Divisor high byte
        outb(COM1 + 3, 0x03); // 8 bits, no parity, one stop bit
        outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }
}

/// Write a single byte to COM1, waiting for the transmit buffer.
pub fn write_byte(byte: u8) {
    // SAFETY: COM1+5 is the Line Status Register and COM1 is the Transmit
    // Holding Register; both are part of the serial driver's exclusive port
    // range. Reading the LSR has no side effects beyond the device.
    unsafe {
        // Wait for transmit holding register to be empty.
        while inb(COM1 + 5) & 0x20 == 0 {}
        outb(COM1, byte);
    }
}

/// Non-blocking read: returns Some(byte) if data available, None otherwise.
pub fn read_byte_nonblocking() -> Option<u8> {
    // SAFETY: COM1+5 (LSR) and COM1 (Receiver Buffer) are owned by this
    // serial driver. The LSR read is side-effect-free; RBR is only read when
    // DR=1, which is the documented way to consume a received byte.
    unsafe {
        // Check Line Status Register bit 0 (Data Ready).
        if inb(COM1 + 5) & 0x01 != 0 {
            Some(inb(COM1))
        } else {
            None
        }
    }
}

pub struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                write_byte(b'\r');
                super::fb_console::push_byte(b'\n');
            } else {
                super::fb_console::push_byte(byte);
            }
            write_byte(byte);
            // Mirror to the kernel framebuffer renderer. No-op once init
            // service takes over via `fb_text::hand_off_to_init()`.
            super::fb_text::putchar(byte);
        }
        Ok(())
    }
}

/// Internal print function used by the kprint!/kprintln! macros.
/// Protected by a spinlock for SMP safety.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    let _guard = SERIAL_LOCK.lock();
    SerialWriter.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ($crate::arch::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::kprint!("{}\n", format_args!($($arg)*)));
}

/// Debug-only print macro — gated on both the `verbose` compile-time feature
/// AND the runtime `boot_splash::VERBOSE` flag (off during splash).
#[macro_export]
macro_rules! kdebug {
    ($($arg:tt)*) => {
        #[cfg(feature = "verbose")]
        {
            if $crate::boot_splash::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
                $crate::kprintln!($($arg)*)
            }
        }
    };
}

/// Error macro — always prints in red regardless of verbose mode.
/// Format: `\x1b[31;1m[err]\x1b[0m message`
#[macro_export]
macro_rules! kerr {
    ($($arg:tt)*) => {
        $crate::kprint!("\x1b[31;1m[err]\x1b[0m ");
        $crate::kprintln!($($arg)*);
    };
}
