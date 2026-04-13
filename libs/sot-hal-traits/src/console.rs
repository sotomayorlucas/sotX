//! Console I/O abstraction.
//!
//! Provides a platform-portable interface for character-level console input
//! and output, used for early boot diagnostics and `kprintln!()`.

/// Console I/O trait -- implemented per platform.
///
/// On x86_64 in sotX, the console is COM1 (I/O port 0x3F8) using 8250 UART.
/// On AArch64, this would typically be a PL011 UART.
/// On RISC-V, this would use SBI console putchar/getchar.
pub trait Console {
    /// Write a single byte to the console.
    ///
    /// On x86_64, this writes to COM1 data register (port 0x3F8) after
    /// waiting for the transmit holding register to be empty.
    fn write_byte(&mut self, byte: u8);

    /// Read a single byte from the console, if available.
    ///
    /// Returns `None` if no data is ready. On x86_64, this checks the
    /// Line Status Register (port 0x3FD) bit 0 before reading.
    fn read_byte(&self) -> Option<u8>;

    /// Write a string to the console (default: byte-by-byte).
    fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.write_byte(b);
        }
    }

    /// Flush any buffered output. No-op by default.
    fn flush(&mut self) {}
}

/// Provider trait for obtaining a console instance.
///
/// Allows generic code to obtain a mutable reference to the platform console
/// without knowing the concrete type.
pub trait ConsoleProvider {
    /// The concrete console type.
    type C: Console;
    /// Return a mutable reference to the console.
    fn console(&mut self) -> &mut Self::C;
}
