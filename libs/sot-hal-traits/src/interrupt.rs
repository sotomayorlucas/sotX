//! Interrupt controller abstraction.
//!
//! Provides a platform-portable interface for masking, acknowledging, and
//! querying hardware interrupts.

/// Interrupt controller abstraction -- implemented per platform.
///
/// On x86_64 in sotOS, the interrupt controller is the Local APIC + I/O APIC.
/// On AArch64, this would map to the GIC (Generic Interrupt Controller).
/// On RISC-V, this would map to the PLIC (Platform-Level Interrupt Controller).
pub trait InterruptController {
    /// Mask (disable) the given IRQ line.
    ///
    /// On x86_64, this sets the mask bit in the I/O APIC redirection entry.
    fn mask(&mut self, irq: u32);

    /// Unmask (enable) the given IRQ line.
    ///
    /// On x86_64, this clears the mask bit in the I/O APIC redirection entry.
    fn unmask(&mut self, irq: u32);

    /// Send End-Of-Interrupt for the given IRQ.
    ///
    /// On x86_64, this writes to the LAPIC EOI register.
    /// On AArch64/GIC, this writes to GICC_EOIR.
    fn eoi(&mut self, irq: u32);

    /// Set the priority of the given IRQ.
    ///
    /// On x86_64 APIC, this maps to the interrupt vector number (higher = higher priority).
    /// On AArch64/GIC, this sets GICD_IPRIORITYR (lower value = higher priority).
    fn set_priority(&mut self, irq: u32, priority: u8);

    /// Return the highest-priority pending IRQ, if any.
    ///
    /// On x86_64, this reads the LAPIC ISR/IRR registers.
    /// On AArch64/GIC, this reads GICC_IAR.
    fn pending(&self) -> Option<u32>;

    /// Return the maximum IRQ number supported by this controller.
    fn max_irq(&self) -> u32;
}
