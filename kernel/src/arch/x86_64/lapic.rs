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

// LAPIC register offsets
#[allow(dead_code)] // LAPIC_ID only used by lapic::id(), itself unused.
const LAPIC_ID: u32 = 0x020;
const LAPIC_SVR: u32 = 0x0F0;
const LAPIC_EOI: u32 = 0x0B0;
const LAPIC_ICR_LO: u32 = 0x300;
const LAPIC_ICR_HI: u32 = 0x310;
const LAPIC_TIMER_LVT: u32 = 0x320;
const LAPIC_TIMER_INIT: u32 = 0x380;
const LAPIC_TIMER_CURRENT: u32 = 0x390;
const LAPIC_TIMER_DIV: u32 = 0x3E0;

/// MSR for APIC base address.
const IA32_APIC_BASE_MSR: u32 = 0x1B;

fn read_msr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdmsr` is only used here for IA32_APIC_BASE (0x1B), which is
    // present on every x86_64 CPU. The instruction only reads an MSR and
    // writes eax/edx — no memory access, no stack use.
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
    // SAFETY: `base` is the HHDM virtual address of the LAPIC MMIO page that
    // `init()` mapped as uncacheable; `offset` is a compile-time LAPIC
    // register offset (<0x400), so the address is inside the mapped MMIO page.
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

fn lapic_write(offset: u32, val: u32) {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    // SAFETY: `base` is the HHDM address of the LAPIC MMIO page mapped by
    // `init()`; `offset` is a compile-time LAPIC register offset inside the
    // mapped page. LAPIC registers are memory-mapped device state, never aliased
    // to regular RAM.
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

/// Plausible minimum LAPIC ticks per 10 ms. Below this we assume PIT
/// calibration was corrupted (e.g. by a hypervisor that virtualises the
/// PIT gate bit poorly) and fall back to a TSC-based estimate.
///
/// 10_000 ticks/10ms = 1 MHz LAPIC bus, the floor of any real x86_64 CPU.
const MIN_PLAUSIBLE_TICKS: u32 = 10_000;

/// Hardcoded fallback if both PIT and TSC calibration fail.
/// 100_000 ticks/10ms ≈ 10 MHz LAPIC bus — very conservative; the timer
/// will fire faster than 100 Hz on a real CPU but the kernel still ticks.
const FALLBACK_TICKS: u32 = 100_000;

/// Read TSC via `rdtsc`.
#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: rdtsc is unprivileged on every x86_64 and reads two registers.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Read TSC frequency from CPUID leaf 0x15 (Intel SDM Vol 2A 3.2 / 3.3).
///
/// Returns `Some(tsc_hz)` when:
///   - CPUID max basic leaf >= 0x15
///   - leaf 0x15: EAX (denominator) != 0, EBX (numerator) != 0, ECX
///     (crystal clock Hz) != 0
///
/// `tsc_hz = ECX * EBX / EAX`. On older parts (pre-Skylake) ECX is often 0
/// even when the ratio is reported, in which case we fall back to leaf
/// 0x16 (processor base frequency in MHz).
fn cpuid_tsc_hz() -> Option<u64> {
    // __cpuid is a safe core::arch wrapper that handles RBX save/restore
    // around the cpuid instruction. cpuid itself is unprivileged on x86_64.
    let max_leaf = core::arch::x86_64::__cpuid(0).eax;
    if max_leaf < 0x15 {
        return None;
    }
    let r15 = core::arch::x86_64::__cpuid(0x15);
    let denom = r15.eax;
    let num = r15.ebx;
    let crystal_hz = r15.ecx;
    if denom != 0 && num != 0 && crystal_hz != 0 {
        return Some((crystal_hz as u64) * (num as u64) / (denom as u64));
    }
    // Fallback: leaf 0x16 returns processor base frequency in MHz.
    if max_leaf >= 0x16 {
        let r16 = core::arch::x86_64::__cpuid(0x16);
        let base_mhz = r16.eax;
        if base_mhz != 0 {
            return Some((base_mhz as u64) * 1_000_000);
        }
    }
    None
}

/// Calibrate the LAPIC timer against PIT channel 2.
/// Returns and stores the tick count for a ~10ms interval.
/// Only BSP needs to call this; APs reuse the result.
///
/// **Fallback chain**: PIT → CPUID.15H/16H TSC → hardcoded floor.
/// On hypervisors that virtualise the PIT gate bit (port 0x61 bit 5)
/// inaccurately, the PIT loop can return 0 or a tiny value; we then
/// derive an estimate from CPUID-reported TSC frequency assuming the
/// LAPIC bus runs at TSC / 16 (typical Intel ratio with our DIV=16).
pub fn calibrate() -> u32 {
    use super::io::{inb, outb};

    // Set LAPIC timer divider to 16
    lapic_write(LAPIC_TIMER_DIV, 0x03); // divide by 16

    // PIT channel 2 one-shot for ~10ms (11932 ticks at 1.193182 MHz)
    let pit_count: u16 = 11932; // ~10ms

    let tsc_start = rdtsc();
    // SAFETY: PIT ports 0x42/0x43 and the PC/AT keyboard-controller port
    // 0x61 (used to gate PIT channel 2) are owned by the kernel during
    // calibration — no driver races here. The sequence configures channel 2
    // in mode 0 (one-shot) per the 8253/8254 spec.
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

        // Wait for PIT channel 2 to reach 0 (bit 5 of port 0x61 goes high).
        // Bound the spin so a broken hypervisor PIT cannot hang us forever.
        let mut spin = 0u64;
        const SPIN_LIMIT: u64 = 100_000_000;
        while spin < SPIN_LIMIT {
            let status = inb(0x61);
            if status & 0x20 != 0 {
                break;
            }
            spin += 1;
        }
    }
    let tsc_end = rdtsc();

    // Read how many LAPIC ticks elapsed
    let elapsed = 0xFFFF_FFFFu32 - lapic_read(LAPIC_TIMER_CURRENT);

    // Stop LAPIC timer
    lapic_write(LAPIC_TIMER_INIT, 0);

    // Primary: PIT-bracketed LAPIC count (matches all real hardware).
    let mut ticks = elapsed;
    let mut source = "pit";

    // Defensive fallback for hypervisors that botch the PIT gate.
    if ticks < MIN_PLAUSIBLE_TICKS {
        // Try TSC-based estimate. We measured tsc_delta ticks of TSC over
        // approximately 10 ms (from the PIT one-shot, even if the gate bit
        // was unreliable, the PIT loop took ~10 ms of wall time on most
        // emulators). Cross-reference against CPUID-reported TSC frequency.
        let tsc_delta = tsc_end.wrapping_sub(tsc_start);
        if let Some(tsc_hz) = cpuid_tsc_hz() {
            // LAPIC bus is conventionally TSC / 16 on Intel (DIV=16 on top
            // of that gives TSC / 256 per LAPIC tick). For 10 ms:
            //   ticks = tsc_hz / 256 / 100 = tsc_hz / 25600
            let estimate = (tsc_hz / 25_600) as u32;
            if estimate >= MIN_PLAUSIBLE_TICKS {
                ticks = estimate;
                source = "cpuid-tsc";
            } else {
                ticks = FALLBACK_TICKS;
                source = "fallback";
            }
        } else if tsc_delta > 0 {
            // No CPUID, but TSC moved. Assume tsc_delta ≈ 10 ms of TSC
            // ticks; LAPIC bus = TSC / 16 + DIV=16 → ticks = tsc_delta/256.
            let estimate = (tsc_delta / 256) as u32;
            if estimate >= MIN_PLAUSIBLE_TICKS {
                ticks = estimate;
                source = "tsc-delta";
            } else {
                ticks = FALLBACK_TICKS;
                source = "fallback";
            }
        } else {
            ticks = FALLBACK_TICKS;
            source = "fallback";
        }
        crate::kprintln!(
            "  lapic: PIT calibration suspicious ({} ticks); using {} → {} ticks/10ms",
            elapsed,
            source,
            ticks
        );
    }

    CALIBRATED_TICKS.store(ticks, Ordering::Relaxed);

    crate::kdebug!("  lapic: calibrated {} ticks/10ms ({})", ticks, source);
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
///
/// Live caller: `sched::reschedule_remote_cpu` uses this to wake idle CPUs
/// after enqueueing onto a remote per-CPU run queue.
pub fn send_ipi(target_lapic_id: u32, vector: u8) {
    lapic_write(LAPIC_ICR_HI, target_lapic_id << 24);
    lapic_write(LAPIC_ICR_LO, vector as u32); // Fixed delivery, physical dest
}

/// Send IPI to all other CPUs (broadcast, exclude self).
///
/// Live caller: `panic::panic_handler` uses this to broadcast a halt NMI
/// to remote CPUs after a kernel panic.
pub fn send_ipi_all_others(vector: u8) {
    // Shorthand 11 = all excluding self, bits [19:18]
    lapic_write(LAPIC_ICR_LO, 0x000C_0000 | vector as u32);
}
