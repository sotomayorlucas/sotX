//! Local APIC (LAPIC) driver.
//!
//! Provides per-CPU timer and interrupt acknowledgment via
//! memory-mapped LAPIC registers.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// LAPIC MMIO base virtual address (HHDM-adjusted).
static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Calibrated tick count for ~100Hz periodic timer.
static CALIBRATED_TICKS: AtomicU32 = AtomicU32::new(0);

/// LAPIC timer interrupt vector.
pub const TIMER_VECTOR: u8 = 48;

/// Reschedule IPI vector.
pub const RESCHEDULE_VECTOR: u8 = 49;

/// Spurious interrupt vector.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

// LAPIC register offsets (some used only in SMP paths)
#[allow(dead_code)]
const LAPIC_ID: u32 = 0x020;
const LAPIC_SVR: u32 = 0x0F0;
const LAPIC_EOI: u32 = 0x0B0;
#[allow(dead_code)]
const LAPIC_ICR_LO: u32 = 0x300;
#[allow(dead_code)]
const LAPIC_ICR_HI: u32 = 0x310;
const LAPIC_TIMER_LVT: u32 = 0x320;
const LAPIC_TIMER_INIT: u32 = 0x380;
const LAPIC_TIMER_CURRENT: u32 = 0x390;
const LAPIC_TIMER_DIV: u32 = 0x3E0;

/// MSR for APIC base address.
const IA32_APIC_BASE_MSR: u32 = 0x1B;

fn read_msr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn lapic_read(offset: u32) -> u32 {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

fn lapic_write(offset: u32, val: u32) {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u32, val) }
}

/// Initialize the LAPIC: read base from MSR, map MMIO page, enable via SVR.
pub fn init() {
    let apic_base_msr = read_msr(IA32_APIC_BASE_MSR);
    let apic_phys = apic_base_msr & 0xFFFF_F000;
    let hhdm = crate::mm::hhdm_offset();
    let apic_virt = apic_phys + hhdm;

    // The LAPIC MMIO region is not RAM, so Limine's HHDM may not map it.
    // Explicitly map it into the boot page tables (uncacheable MMIO).
    map_mmio_page(apic_phys, apic_virt);

    LAPIC_BASE.store(apic_virt, Ordering::Relaxed);

    // Enable LAPIC via Spurious Interrupt Vector Register
    let svr = lapic_read(LAPIC_SVR);
    lapic_write(LAPIC_SVR, svr | 0x100 | SPURIOUS_VECTOR as u32);
}

/// Map a single 4K MMIO page into the current (boot) page tables.
/// Uses PRESENT | WRITABLE | NO_CACHE | WRITE_THROUGH flags.
fn map_mmio_page(phys: u64, virt: u64) {
    use crate::mm::paging::{read_cr3, AddressSpace, PAGE_PRESENT, PAGE_WRITABLE};

    let cr3 = read_cr3();
    let aspace = AddressSpace::from_cr3(cr3);
    // PCD (bit 4) + PWT (bit 3) for uncacheable MMIO
    let flags = PAGE_PRESENT | PAGE_WRITABLE | (1 << 4) | (1 << 3);
    aspace.map_page(virt, phys, flags);
}

/// Read the LAPIC ID for this CPU.
#[allow(dead_code)]
pub fn id() -> u32 {
    (lapic_read(LAPIC_ID) >> 24) & 0xFF
}

/// Send End-Of-Interrupt to LAPIC.
pub fn eoi() {
    lapic_write(LAPIC_EOI, 0);
}

/// Calibrate the LAPIC timer against PIT channel 2.
/// Returns and stores the tick count for a ~10ms interval.
/// Only BSP needs to call this; APs reuse the result.
pub fn calibrate() -> u32 {
    use super::io::{inb, outb};

    // Set LAPIC timer divider to 16
    lapic_write(LAPIC_TIMER_DIV, 0x03); // divide by 16

    // PIT channel 2 one-shot for ~10ms (11932 ticks at 1.193182 MHz)
    let pit_count: u16 = 11932; // ~10ms

    unsafe {
        // Gate off speaker, use channel 2
        let gate = inb(0x61);
        outb(0x61, (gate & 0xFD) | 0x01); // gate on, speaker off

        // PIT channel 2, mode 0 (one-shot), lobyte/hibyte
        outb(0x43, 0xB0);
        outb(0x42, pit_count as u8);
        outb(0x42, (pit_count >> 8) as u8);

        // Start LAPIC timer at max count
        lapic_write(LAPIC_TIMER_INIT, 0xFFFF_FFFF);

        // Wait for PIT channel 2 to reach 0 (bit 5 of port 0x61 goes high)
        loop {
            let status = inb(0x61);
            if status & 0x20 != 0 {
                break;
            }
        }
    }

    // Read how many LAPIC ticks elapsed
    let elapsed = 0xFFFF_FFFFu32 - lapic_read(LAPIC_TIMER_CURRENT);

    // Stop LAPIC timer
    lapic_write(LAPIC_TIMER_INIT, 0);

    // Scale to 100 Hz (10ms * 10 = 100ms per tick... wait, we want 100 ticks/sec)
    // We measured ~10ms worth of ticks. For 100Hz we want 10ms intervals.
    // So elapsed is already the right count for 100Hz.
    let ticks = elapsed;

    CALIBRATED_TICKS.store(ticks, Ordering::Relaxed);

    crate::kdebug!("  lapic: calibrated {} ticks/10ms", ticks);
    ticks
}

/// Get the stored calibrated tick count.
pub fn calibrated_ticks() -> u32 {
    CALIBRATED_TICKS.load(Ordering::Relaxed)
}

/// Start the LAPIC timer in periodic mode at the calibrated rate.
pub fn start_timer(ticks: u32) {
    // Divider = 16
    lapic_write(LAPIC_TIMER_DIV, 0x03);
    // Periodic mode, vector = TIMER_VECTOR
    lapic_write(LAPIC_TIMER_LVT, 0x20000 | TIMER_VECTOR as u32);
    // Initial count
    lapic_write(LAPIC_TIMER_INIT, ticks);
}

/// Send an IPI to a specific LAPIC ID.
#[allow(dead_code)]
pub fn send_ipi(target_lapic_id: u32, vector: u8) {
    lapic_write(LAPIC_ICR_HI, target_lapic_id << 24);
    lapic_write(LAPIC_ICR_LO, vector as u32); // Fixed delivery, physical dest
}

/// Send IPI to all other CPUs (broadcast, exclude self).
#[allow(dead_code)]
pub fn send_ipi_all_others(vector: u8) {
    // Shorthand 11 = all excluding self, bits [19:18]
    lapic_write(LAPIC_ICR_LO, 0x000C_0000 | vector as u32);
}
