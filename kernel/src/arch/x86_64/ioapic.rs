//! Phase E — minimal IOAPIC driver.
//!
//! Each IOAPIC chip exposes its registers via two MMIO ports:
//!
//!   IOREGSEL  (offset 0x00)  — 8-bit register selector
//!   IOWIN     (offset 0x10)  — 32-bit data window
//!
//! Software writes the index of the desired register into IOREGSEL,
//! then reads/writes IOWIN to access it. The register set:
//!
//!   0x00       IOAPIC ID            — 8-bit APIC ID in bits 27..24
//!   0x01       IOAPIC VER           — bits 0..7 = version, bits 16..23 = max-redir-entry
//!   0x02       IOAPIC ARB           — arbitration ID (rarely used)
//!   0x10..0x3F Redirection table    — 24 entries × 64 bits, two 32-bit halves
//!
//! Each redirection table entry (RTE) is a 64-bit value:
//!
//!   bits 0..7   Vector (target IDT vector)
//!   bits 8..10  Delivery mode (0 = Fixed)
//!   bit  11     Destination mode (0 = physical, 1 = logical)
//!   bit  12     Delivery status (RO)
//!   bit  13     Polarity (0 = active high)
//!   bit  14     Remote IRR (RO)
//!   bit  15     Trigger mode (0 = edge, 1 = level)
//!   bit  16     Mask (1 = masked)
//!   bits 56..63 Destination (LAPIC ID in physical mode)
//!
//! Phase E only needs `set_redirection` (vector + LAPIC + mask) and
//! the `mask`/`unmask` toggles. The actual delivery happens in Phase F
//! once virtio devices migrate from PIC IRQ lines to MSI/IOAPIC GSIs.

use crate::acpi::{self, IoApicEntry};
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

const IOAPIC_REG_ID: u8 = 0x00;
const IOAPIC_REG_VER: u8 = 0x01;
const IOAPIC_REG_REDIR_BASE: u8 = 0x10;

const REDIR_MASKED: u64 = 1 << 16;

/// Maximum number of IOAPICs Phase E supports. Must match the value
/// in `kernel/src/acpi/mod.rs::MAX_IOAPICS`.
const MAX_IOAPICS: usize = 8;

/// One IOAPIC chip's runtime state.
#[derive(Debug, Clone, Copy)]
pub struct IoApic {
    /// HHDM-mapped virtual address of the IOAPIC's MMIO base.
    pub mmio_virt: usize,
    /// First GSI this IOAPIC handles.
    pub gsi_base: u32,
    /// Number of redirection entries (max-redir-entry + 1).
    pub redir_count: u8,
    /// IOAPIC's APIC ID, as reported by the firmware.
    pub apic_id: u8,
}

impl IoApic {
    /// Construct a runtime instance from an ACPI MADT entry. Maps
    /// the MMIO page UC into the kernel HHDM virtual address (the
    /// IOAPIC MMIO range is normally NOT in Limine's HHDM because
    /// it lives in the LAPIC/MMIO reserved zone), then reads back
    /// the version register to discover the redirection entry count.
    fn from_entry(entry: &IoApicEntry) -> Self {
        use crate::mm::paging::{
            boot_cr3, AddressSpace, PAGE_CACHE_DISABLE, PAGE_NO_EXECUTE, PAGE_PRESENT,
            PAGE_WRITABLE, PAGE_WRITE_THROUGH,
        };
        let hhdm = crate::mm::hhdm_offset();
        let phys = entry.mmio_phys as u64 & !0xFFF;
        let virt = phys + hhdm;
        // Install a UC writable kernel mapping for the IOAPIC's
        // MMIO page. UC = PCD | PWT (cache disable + write through).
        let space = AddressSpace::from_cr3(boot_cr3());
        space.map_page(
            virt,
            phys,
            PAGE_PRESENT
                | PAGE_WRITABLE
                | PAGE_NO_EXECUTE
                | PAGE_CACHE_DISABLE
                | PAGE_WRITE_THROUGH,
        );
        let mmio_virt = virt as usize;
        let mut io = Self {
            mmio_virt,
            gsi_base: entry.gsi_base,
            redir_count: 0,
            apic_id: entry.id,
        };
        let ver = io.read_reg(IOAPIC_REG_VER);
        let max_entry = ((ver >> 16) & 0xFF) as u8;
        io.redir_count = max_entry + 1;
        io
    }

    /// Read a 32-bit IOAPIC register through the IOREGSEL/IOWIN
    /// register pair.
    fn read_reg(&self, reg: u8) -> u32 {
        // SAFETY: `mmio_virt` was taken from a Limine-provided ACPI
        // entry; the firmware guarantees the IOAPIC MMIO range is
        // mapped UC and reads have no side effects beyond the
        // register access itself.
        unsafe {
            write_volatile(self.mmio_virt as *mut u32, reg as u32);
            read_volatile((self.mmio_virt + 0x10) as *const u32)
        }
    }

    /// Write a 32-bit IOAPIC register.
    fn write_reg(&self, reg: u8, value: u32) {
        // SAFETY: same as `read_reg`.
        unsafe {
            write_volatile(self.mmio_virt as *mut u32, reg as u32);
            write_volatile((self.mmio_virt + 0x10) as *mut u32, value);
        }
    }

    /// Read the IOAPIC ID register. Useful as a smoke test that the
    /// MMIO mapping works (the value should match what ACPI reported).
    pub fn read_id(&self) -> u8 {
        ((self.read_reg(IOAPIC_REG_ID) >> 24) & 0x0F) as u8
    }

    /// Read the version register's low byte.
    pub fn read_version(&self) -> u8 {
        (self.read_reg(IOAPIC_REG_VER) & 0xFF) as u8
    }

    /// Install a redirection table entry routing `gsi` to `vector`
    /// on `dest_lapic_id`. The entry is created in masked state by
    /// default — call `unmask` after the device is ready to receive.
    ///
    /// `gsi` is GLOBAL — the function returns silently if `gsi` is
    /// not in this IOAPIC's range.
    pub fn set_redirection(&self, gsi: u32, vector: u8, dest_lapic_id: u8, masked: bool) {
        if gsi < self.gsi_base || gsi >= self.gsi_base + self.redir_count as u32 {
            return;
        }
        let local = (gsi - self.gsi_base) as u8;
        let lo = vector as u32;
        let mut entry: u64 = lo as u64;
        if masked {
            entry |= REDIR_MASKED;
        }
        // Bits 56..63: destination LAPIC ID (physical mode).
        entry |= (dest_lapic_id as u64) << 56;
        let reg_lo = IOAPIC_REG_REDIR_BASE + local * 2;
        let reg_hi = reg_lo + 1;
        // Per Intel SDM, write the high half first to avoid a brief
        // window where the IOAPIC could deliver an interrupt with
        // the wrong destination.
        self.write_reg(reg_hi, (entry >> 32) as u32);
        self.write_reg(reg_lo, entry as u32);
    }

    /// Toggle the mask bit on a single GSI.
    #[allow(dead_code)]
    pub fn set_masked(&self, gsi: u32, masked: bool) {
        if gsi < self.gsi_base || gsi >= self.gsi_base + self.redir_count as u32 {
            return;
        }
        let local = (gsi - self.gsi_base) as u8;
        let reg_lo = IOAPIC_REG_REDIR_BASE + local * 2;
        let mut lo = self.read_reg(reg_lo);
        if masked {
            lo |= REDIR_MASKED as u32;
        } else {
            lo &= !(REDIR_MASKED as u32);
        }
        self.write_reg(reg_lo, lo);
    }
}

/// Global slot of discovered IOAPIC chips. Populated once at boot
/// from `init_all()`.
static IOAPICS: Mutex<[Option<IoApic>; MAX_IOAPICS]> = Mutex::new([None; MAX_IOAPICS]);

/// Walk the ACPI-discovered IOAPIC entries and bring up each chip.
/// Idempotent — calling twice has no effect because we initialise
/// the slots in place and a non-None slot is left untouched.
pub fn init_all() {
    let entries = acpi::ioapics();
    let mut slots = IOAPICS.lock();
    let mut count = 0;
    for slot in entries.iter() {
        if let Some(entry) = slot {
            if count >= MAX_IOAPICS {
                break;
            }
            if slots[count].is_some() {
                continue;
            }
            let io = IoApic::from_entry(entry);
            crate::kprintln!(
                "  ioapic: chip[{}] mmio={:#x} apic_id={} gsi_base={} entries={} ver={:#x}",
                count,
                io.mmio_virt,
                io.read_id(),
                io.gsi_base,
                io.redir_count,
                io.read_version()
            );
            slots[count] = Some(io);
            count += 1;
        }
    }
    if count == 0 {
        crate::kdebug!("  ioapic: no IOAPICs found in ACPI MADT");
    }
}

/// Look up the IOAPIC instance that owns a given GSI. Returns
/// `None` if no chip claims it.
#[allow(dead_code)]
pub fn for_gsi(gsi: u32) -> Option<IoApic> {
    let slots = IOAPICS.lock();
    for slot in slots.iter() {
        if let Some(io) = slot {
            if gsi >= io.gsi_base && gsi < io.gsi_base + io.redir_count as u32 {
                return Some(*io);
            }
        }
    }
    None
}

/// Number of IOAPICs currently registered.
#[allow(dead_code)]
pub fn count() -> usize {
    let slots = IOAPICS.lock();
    slots.iter().filter(|s| s.is_some()).count()
}
