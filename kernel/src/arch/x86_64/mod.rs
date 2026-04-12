pub mod ept;
pub mod fb_font;
pub mod fb_console;
pub mod gdt;
pub mod idt;
pub mod io;
pub mod ioapic;
pub mod lapic;
pub mod percpu;
pub mod pic;
pub mod pit;
pub mod serial;
pub mod syscall;
pub mod vmx;

/// Halt the CPU in a loop. Used after kernel initialization
/// and as the final stop for panics.
pub fn halt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
