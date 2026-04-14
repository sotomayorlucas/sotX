//! ACPI-based system shutdown with hardware fallbacks.
//!
//! Tries four mechanisms in order, falling through to the next on failure:
//!
//! 1. **QEMU debug-exit ports** (`0x604`, `0xB004`). Writing `0x2000` to
//!    either port causes QEMU to terminate cleanly with exit code 0. These
//!    ports are no-ops on real hardware (they're QEMU-only conventions).
//!
//! 2. **ACPI PM1a control register write**. The proper power-off mechanism on
//!    real hardware. `(SLP_TYPa << 10) | SLP_EN` written to the FADT's
//!    `PM1a_CNT_BLK` triggers a transition to S5 (soft-off). `SLP_TYPa` is
//!    encoded in the DSDT's `\_S5` AML object, which we can't parse without a
//!    full AML interpreter — so we try the common values `[5, 7, 0]` in
//!    sequence, which covers virtually all consumer hardware. If none works
//!    after a short pause, fall through.
//!
//! 3. **8042 keyboard controller reset** (`outb(0x64, 0xFE)`). This is a
//!    warm reboot, not a power-off, but on a laptop it's better than the
//!    machine staying on with a hung kernel.
//!
//! 4. **Triple fault** as a last resort. Loading a null IDT and executing
//!    `int3` triggers an unrecoverable exception that forces a CPU reset.
//!
//! On real HP Pavilion hardware some firmware requires the `\_PTS` (Prepare
//! To Sleep) AML method to run before PM1a write — that's an AML-interpreter
//! task and is left as future work. If the PM1a path doesn't work on a
//! given Pavilion, the 8042 reset still gets the laptop back to a defined
//! state instead of leaving it stuck.

use crate::arch::x86_64::io::{inb, outb, outw};

/// SLP_EN bit (bit 13) in PM1 control register — setting it commits the
/// new SLP_TYP value and starts the sleep transition.
const SLP_EN: u16 = 1 << 13;

/// Common SLP_TYPa values for S5 (soft-off). Real values come from the DSDT
/// `\_S5` AML object; we don't parse AML so we try the empirical favourites:
/// 5 covers ~95% of consumer hardware (Intel boards, QEMU, VirtualBox), 7
/// covers some AMD/server boards, 0 is the fallback some firmwares use.
const SLP_TYPA_CANDIDATES: &[u16] = &[5, 7, 0];

/// Power off the machine. Never returns. Tries every mechanism in sequence;
/// if all fail (very unlikely), spins in `hlt` so the system at least stops.
pub fn shutdown() -> ! {
    crate::kprintln!("shutdown: requested");

    // --- 1. QEMU debug exit ports (no-op on real HW) ---
    // 0x604 = ACPI shutdown port (modern QEMU, isa-debug-exit replacement)
    // 0xB004 = legacy QEMU shutdown port
    // SAFETY: these are well-known reserved I/O ports; on real HW they're
    // either unmapped (write ignored) or hit a chipset register that does
    // nothing. Either way no aliasing concern.
    unsafe {
        outw(0x604, 0x2000);
        outw(0xB004, 0x2000);
    }

    // --- 2. ACPI PM1a write ---
    if let Some(fadt) = crate::acpi::fadt() {
        let port = fadt.pm1a_cnt_blk as u16;
        if port != 0 {
            for &slp in SLP_TYPA_CANDIDATES {
                let val = (slp << 10) | SLP_EN;
                crate::kprintln!(
                    "shutdown: PM1a port={:#x} val={:#x} (SLP_TYPa={})",
                    port,
                    val,
                    slp
                );
                // SAFETY: PM1a_CNT_BLK is a 16-bit chipset register
                // documented in the ACPI spec; writing the SLP value with
                // SLP_EN is the spec-defined way to trigger S5 transition.
                unsafe { outw(port, val); }
                // Give the chipset a moment to act before we fall through.
                // ~10 ms of `pause` loop is enough for any sane firmware.
                for _ in 0..1_000_000 {
                    core::hint::spin_loop();
                }
            }
            // Try PM1b too if the firmware splits the controllers (rare).
            if fadt.pm1b_cnt_blk != 0 {
                let port_b = fadt.pm1b_cnt_blk as u16;
                for &slp in SLP_TYPA_CANDIDATES {
                    let val = (slp << 10) | SLP_EN;
                    // SAFETY: same as PM1a above.
                    unsafe { outw(port_b, val); }
                    for _ in 0..1_000_000 {
                        core::hint::spin_loop();
                    }
                }
            }
        }
    }

    crate::kprintln!("shutdown: ACPI path failed, trying 8042 reset");

    // --- 3. 8042 keyboard controller reset ---
    // Pulse the CPU reset line via the legacy 8042 controller.
    // SAFETY: 0x64 command port is a legacy chipset register; writing 0xFE
    // pulses the reset line. No memory effects.
    unsafe {
        // Drain the 8042 input buffer first (some chipsets ignore commands
        // while bit 1 of the status register is set).
        for _ in 0..1000 {
            if inb(0x64) & 0x02 == 0 {
                break;
            }
        }
        outb(0x64, 0xFE);
    }
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }

    crate::kprintln!("shutdown: 8042 reset failed, triple-faulting");

    // --- 4. Triple fault ---
    // Load a null IDT then trigger an exception. CPU has no handler so it
    // generates a #DF, then a triple fault, then resets.
    triple_fault();
}

/// Force a triple fault. Loads a zero-length IDT and raises `int3`. The CPU
/// can't dispatch the exception, escalates to #DF (no entry → escalation to
/// triple fault → reset). Never returns.
fn triple_fault() -> ! {
    #[repr(C, packed)]
    struct IdtPtr {
        limit: u16,
        base: u64,
    }
    let null_idt = IdtPtr { limit: 0, base: 0 };
    // SAFETY: lidt is a privileged instruction we're allowed to issue from
    // ring 0; the loaded null IDT plus int3 deliberately triggers a triple
    // fault, which is the desired effect (system reset).
    unsafe {
        core::arch::asm!(
            "lidt [{}]",
            "int3",
            in(reg) &null_idt,
            options(nostack, preserves_flags),
        );
    }
    // Should never reach here.
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}
