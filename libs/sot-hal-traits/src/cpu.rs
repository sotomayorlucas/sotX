//! CPU abstraction trait.
//!
//! Provides a platform-portable interface for core CPU operations such as
//! halting, interrupt control, timestamp reading, and SMP queries.

/// CPU operations trait -- implemented per architecture.
pub trait Cpu {
    /// Halt until next interrupt.
    ///
    /// On x86_64, this executes the `HLT` instruction.
    /// On AArch64, this would use `WFI` (Wait For Interrupt).
    fn halt(&self);

    /// Enable interrupts.
    ///
    /// On x86_64, this executes `STI`.
    /// On AArch64, this clears the DAIF interrupt mask bits.
    fn enable_interrupts(&self);

    /// Disable interrupts.
    ///
    /// On x86_64, this executes `CLI`.
    /// On AArch64, this sets the DAIF interrupt mask bits.
    fn disable_interrupts(&self);

    /// Read timestamp counter (or equivalent).
    ///
    /// On x86_64, this uses the `RDTSC` instruction (returns TSC value).
    /// On AArch64, this reads `CNTVCT_EL0`.
    /// On RISC-V, this reads the `cycle` CSR.
    fn read_tsc(&self) -> u64;

    /// Get current CPU ID.
    ///
    /// On x86_64, this reads the LAPIC ID register.
    /// On AArch64, this reads `MPIDR_EL1`.
    fn cpu_id(&self) -> u32;

    /// Memory barrier (full fence).
    ///
    /// On x86_64, this executes `MFENCE`.
    /// On AArch64, this executes `DSB SY`.
    /// On RISC-V, this executes `fence rw, rw`.
    fn memory_barrier(&self);

    /// Get number of CPUs (SMP).
    ///
    /// Returns the number of active processors as detected during boot.
    /// On x86_64 in sotX, this is determined from ACPI/MADT parsing.
    fn cpu_count(&self) -> u32;
}

/// x86_64 reference implementation (types only, actual impl in kernel).
///
/// The kernel provides the real implementation using inline assembly
/// for `HLT`, `STI`, `CLI`, `RDTSC`, `MFENCE`, and LAPIC register reads.
pub struct X86_64Cpu;

/// AArch64 stub for future portability.
///
/// Would use `WFI`, `WFE`, `CNTVCT_EL0`, `MPIDR_EL1`, `DSB SY`, etc.
pub struct AArch64Cpu;

/// RISC-V stub for future portability.
///
/// Would use `WFI`, CSR reads (`cycle`, `mhartid`), `fence` instructions.
pub struct RiscVCpu;
