//! Phase E — minimal ACPI parser.
//!
//! Walks the RSDP / RSDT / XSDT chain provided by Limine, finds the
//! MADT, and extracts the IOAPIC + Interrupt Source Override entries
//! needed by `arch::x86_64::ioapic`. Other ACPI tables (FADT, HPET,
//! MCFG, etc.) are intentionally ignored — Phase E only needs enough
//! to drive interrupt routing for Phase F's bzImage guest.
//!
//! ## What we extract
//!
//! 1. **IOAPIC entries** (MADT type 1) — physical MMIO base, GSI
//!    base, and APIC ID for every IOAPIC the firmware exposes.
//!    `arch::x86_64::ioapic::init_all()` consumes this list to
//!    construct one `IoApic` instance per chip.
//!
//! 2. **Interrupt Source Overrides** (MADT type 2) — legacy ISA IRQ
//!    → GSI mappings with polarity/trigger flags. Without these,
//!    legacy IRQ 0 (PIT) might actually be routed to GSI 2 (the
//!    common ICH/PIIX remap). We never directly use them in Phase E
//!    because we still go through the legacy 8259 PIC for those
//!    lines, but we record them so the IOAPIC driver can later
//!    install a redirection table entry for any legacy IRQ that
//!    Phase F decides to migrate.
//!
//! ## Limine RSDP protocol
//!
//! Limine v8 returns the RSDP at an HHDM virtual address — the
//! caller can dereference it directly without phys→virt fix-ups.
//! All tables it points at are similarly HHDM-mapped.

use core::mem::size_of;
use spin::Once;

/// Ensure the 4 KiB page containing `phys` is mapped at its HHDM
/// virtual address in the boot CR3. Idempotent — `AddressSpace::map_page`
/// silently overwrites an existing leaf with the same target frame
/// and flags. Used to make ACPI tables that Limine left out of the
/// HHDM (e.g. RSDP in BIOS ROM) reachable.
fn ensure_phys_page_mapped(phys: u64) {
    use crate::mm::paging::{
        boot_cr3, AddressSpace, PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_WRITABLE,
    };
    let aligned_phys = phys & !0xFFF;
    let virt = aligned_phys + crate::mm::hhdm_offset();
    let space = AddressSpace::from_cr3(boot_cr3());
    space.map_page(
        virt,
        aligned_phys,
        PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE,
    );
}

/// Map every 4 KiB page in `[phys .. phys + len)` at its HHDM
/// virtual address. The ACPI walker calls this before dereferencing
/// any table whose length it knows from the header.
fn ensure_phys_range_mapped(phys: u64, len: usize) {
    let start = phys & !0xFFF;
    let end = (phys + len as u64 + 0xFFF) & !0xFFF;
    let mut p = start;
    while p < end {
        ensure_phys_page_mapped(p);
        p += 4096;
    }
}

/// Maximum number of IOAPIC chips Phase E supports. Real systems
/// typically expose 1 (consumer) or 2-3 (server). This is a small
/// fixed cap so we don't need a heap-backed Vec.
pub const MAX_IOAPICS: usize = 8;

/// Maximum number of Interrupt Source Override entries the parser
/// records. The legacy ISA bus has 16 lines, each can have at most
/// one ISO; older firmware may also describe NMI/SMI overrides.
pub const MAX_ISO: usize = 24;

/// One IOAPIC discovered via the MADT.
#[derive(Debug, Clone, Copy)]
pub struct IoApicEntry {
    /// IOAPIC's APIC ID, as reported by the firmware. Note this is
    /// independent of the LAPIC IDs.
    pub id: u8,
    /// Physical MMIO base of the IOAPIC. The driver maps this UC.
    pub mmio_phys: u32,
    /// First GSI (Global System Interrupt) this IOAPIC handles.
    pub gsi_base: u32,
}

/// One Interrupt Source Override (legacy ISA IRQ → GSI mapping).
#[derive(Debug, Clone, Copy)]
pub struct IsoEntry {
    /// Bus number (always 0 = ISA in practice).
    pub bus: u8,
    /// Legacy IRQ line as the firmware expects software to think of
    /// it (e.g. 0 = PIT, 1 = keyboard, 4 = COM1, etc.).
    pub source: u8,
    /// Global System Interrupt the IRQ is actually wired to. Often
    /// equal to `source` but the PIT (0) is commonly remapped to GSI
    /// 2 by ICH/PIIX firmware.
    pub gsi: u32,
    /// MPS INTI flags: polarity (bits 1..0) + trigger mode (bits
    /// 3..2). 0/0 means "use bus default", which for ISA is
    /// active-high edge.
    pub flags: u16,
}

/// Parsed MADT contents.
struct MadtData {
    ioapics: [Option<IoApicEntry>; MAX_IOAPICS],
    ioapic_count: usize,
    isos: [Option<IsoEntry>; MAX_ISO],
    iso_count: usize,
    /// Physical address of the LAPIC MMIO range, as reported by the
    /// MADT header. Currently informational — `arch::x86_64::lapic`
    /// uses CPUID to discover the same value at boot.
    #[allow(dead_code)]
    lapic_phys: u32,
}

impl MadtData {
    const fn empty() -> Self {
        Self {
            ioapics: [None; MAX_IOAPICS],
            ioapic_count: 0,
            isos: [None; MAX_ISO],
            iso_count: 0,
            lapic_phys: 0,
        }
    }
}

/// Singleton populated once during boot. Subsequent reads are
/// lock-free; writes only happen inside `init()`.
static MADT: Once<MadtData> = Once::new();

// ---------------------------------------------------------------------------
// On-disk ACPI structures
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Rsdp1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Rsdp2 {
    v1: Rsdp1,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct AcpiHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MadtHeader {
    header: AcpiHeader,
    local_apic_address: u32,
    flags: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

const MADT_TYPE_IOAPIC: u8 = 1;
const MADT_TYPE_ISO: u8 = 2;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MadtIoApic {
    header: MadtEntryHeader,
    id: u8,
    reserved: u8,
    address: u32,
    gsi_base: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MadtIso {
    header: MadtEntryHeader,
    bus: u8,
    source: u8,
    gsi: u32,
    flags: u16,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the ACPI tables exposed by Limine. Idempotent: subsequent
/// calls are no-ops. Logs the discovered IOAPIC and ISO entries.
///
/// `rsdp_addr` is whatever Limine handed us — it can be either an
/// already-HHDM-mapped virtual address (newer base revision) or a
/// raw physical address (older base revision). The parser detects
/// which by looking at the high bits and converts both to a phys
/// address it can mark explicitly mapped via `ensure_phys_page_mapped`
/// before dereferencing. This is needed because Limine's HHDM only
/// covers RAM regions; the RSDP often lives in BIOS ROM (e.g.
/// `0xf52c0`) which is normally NOT in the HHDM and would otherwise
/// page-fault on the first access.
pub fn init(rsdp_addr: usize) {
    let hhdm = crate::mm::hhdm_offset();
    let rsdp_phys: u64 = if (rsdp_addr as u64) >= hhdm {
        rsdp_addr as u64 - hhdm
    } else {
        rsdp_addr as u64
    };
    MADT.call_once(|| parse(rsdp_phys).unwrap_or_else(MadtData::empty));
}

/// Iterate over all IOAPIC entries discovered in the MADT. Empty
/// slice if `init()` failed or wasn't called.
pub fn ioapics() -> &'static [Option<IoApicEntry>] {
    match MADT.get() {
        Some(m) => &m.ioapics[..m.ioapic_count],
        None => &[],
    }
}

/// Look up the GSI a legacy ISA IRQ is wired to. Returns `Some(gsi)`
/// if an ISO entry overrides the identity mapping; `None` if the
/// caller should assume `gsi == legacy_irq`.
#[allow(dead_code)]
pub fn iso_lookup(legacy_irq: u8) -> Option<u32> {
    let madt = MADT.get()?;
    for slot in &madt.isos[..madt.iso_count] {
        if let Some(iso) = slot {
            if iso.source == legacy_irq && iso.bus == 0 {
                return Some(iso.gsi);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Validate the bytes of an ACPI table sum to 0 modulo 256.
fn checksum_ok(ptr: *const u8, len: usize) -> bool {
    // SAFETY: caller has confirmed `ptr` points at a `len`-byte ACPI
    // table provided by Limine in HHDM-mapped memory.
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}

fn parse(rsdp_phys: u64) -> Option<MadtData> {
    if rsdp_phys == 0 {
        return None;
    }
    let hhdm = crate::mm::hhdm_offset();

    // Make sure the RSDP page is reachable through HHDM. Many
    // firmware revisions place the RSDP in BIOS ROM (around
    // `0xe0000..0xfffff`) which Limine excludes from HHDM, so a
    // direct deref would page-fault.
    ensure_phys_range_mapped(rsdp_phys, size_of::<Rsdp2>());
    let rsdp_virt = (rsdp_phys + hhdm) as usize;

    // SAFETY: page mapped above, structure laid out per ACPI spec.
    let rsdp1 = unsafe { *(rsdp_virt as *const Rsdp1) };
    if &rsdp1.signature != b"RSD PTR " {
        crate::kprintln!("  acpi: bad RSDP signature");
        return None;
    }
    if !checksum_ok(rsdp_virt as *const u8, size_of::<Rsdp1>()) {
        crate::kprintln!("  acpi: bad RSDP v1 checksum");
        return None;
    }

    // Pick XSDT (revision >= 2) over RSDT when both are available.
    let (sdt_phys, entry_size): (u64, usize) = if rsdp1.revision >= 2 {
        // SAFETY: revision >= 2 means the firmware provides Rsdp2.
        let rsdp2 = unsafe { *(rsdp_virt as *const Rsdp2) };
        let xsdt = { rsdp2.xsdt_address };
        if xsdt != 0 {
            (xsdt, 8)
        } else {
            (rsdp1.rsdt_address as u64, 4)
        }
    } else {
        (rsdp1.rsdt_address as u64, 4)
    };

    // Map the SDT header page first so we can read its length, then
    // re-map the full table.
    ensure_phys_page_mapped(sdt_phys);
    let sdt_virt = sdt_phys + hhdm;
    // SAFETY: page mapped above; AcpiHeader is 36 bytes which fits
    // in any aligned page.
    let sdt_header = unsafe { *(sdt_virt as *const AcpiHeader) };
    let sdt_total_len = sdt_header.length as usize;
    if sdt_total_len < size_of::<AcpiHeader>() {
        crate::kprintln!("  acpi: SDT length too small");
        return None;
    }
    ensure_phys_range_mapped(sdt_phys, sdt_total_len);

    let entries_ptr = (sdt_virt as usize + size_of::<AcpiHeader>()) as *const u8;
    let entries_len = sdt_total_len - size_of::<AcpiHeader>();
    let n_entries = entries_len / entry_size;

    // Walk the entry pointer array looking for the MADT (signature "APIC").
    let mut madt_phys: Option<u64> = None;
    for i in 0..n_entries {
        // SAFETY: in-bounds — `entries_len` was bounds-checked above.
        let entry_ptr_addr = unsafe { entries_ptr.add(i * entry_size) };
        let phys: u64 = if entry_size == 8 {
            unsafe { core::ptr::read_unaligned(entry_ptr_addr as *const u64) }
        } else {
            unsafe { core::ptr::read_unaligned(entry_ptr_addr as *const u32) as u64 }
        };
        // Each table entry points at another ACPI table whose header
        // is 36 bytes. Map the page so we can sniff the signature.
        ensure_phys_page_mapped(phys);
        let table_virt = phys + hhdm;
        // SAFETY: page mapped above; we only read the header.
        let header = unsafe { *(table_virt as *const AcpiHeader) };
        if &header.signature == b"APIC" {
            madt_phys = Some(phys);
            break;
        }
    }

    let madt_phys = madt_phys.or_else(|| {
        crate::kprintln!("  acpi: no MADT (APIC) entry in SDT");
        None
    })?;

    // Map the MADT's full extent before walking its variable-length
    // entry list.
    ensure_phys_page_mapped(madt_phys);
    let madt_virt = madt_phys + hhdm;
    // SAFETY: page mapped above.
    let madt_header = unsafe { *(madt_virt as *const MadtHeader) };
    let madt_len = { madt_header.header.length as usize };
    if madt_len < size_of::<MadtHeader>() {
        crate::kprintln!("  acpi: MADT length too small");
        return None;
    }
    ensure_phys_range_mapped(madt_phys, madt_len);
    if !checksum_ok(madt_virt as *const u8, madt_len) {
        crate::kprintln!("  acpi: bad MADT checksum");
        return None;
    }

    let mut data = MadtData::empty();
    let lapic_phys = madt_header.local_apic_address;
    data.lapic_phys = lapic_phys;

    // Walk the variable-length entry list following the MADT header.
    let entries_start = madt_virt as usize + size_of::<MadtHeader>();
    let entries_end = madt_virt as usize + madt_len;
    let mut cursor = entries_start;
    while cursor + size_of::<MadtEntryHeader>() <= entries_end {
        // SAFETY: bounds-checked above.
        let eh = unsafe { *(cursor as *const MadtEntryHeader) };
        if eh.length < size_of::<MadtEntryHeader>() as u8 {
            crate::kprintln!("  acpi: MADT entry length 0, aborting");
            break;
        }
        let entry_end = cursor + eh.length as usize;
        if entry_end > entries_end {
            crate::kprintln!("  acpi: MADT entry overruns table");
            break;
        }
        match eh.entry_type {
            MADT_TYPE_IOAPIC => {
                if eh.length as usize >= size_of::<MadtIoApic>()
                    && data.ioapic_count < MAX_IOAPICS
                {
                    // SAFETY: length-checked above.
                    let io = unsafe { *(cursor as *const MadtIoApic) };
                    let entry = IoApicEntry {
                        id: io.id,
                        mmio_phys: { io.address },
                        gsi_base: { io.gsi_base },
                    };
                    crate::kprintln!(
                        "  acpi: IOAPIC id={} mmio={:#x} gsi_base={}",
                        entry.id,
                        entry.mmio_phys,
                        entry.gsi_base
                    );
                    data.ioapics[data.ioapic_count] = Some(entry);
                    data.ioapic_count += 1;
                }
            }
            MADT_TYPE_ISO => {
                if eh.length as usize >= size_of::<MadtIso>() && data.iso_count < MAX_ISO {
                    // SAFETY: length-checked above.
                    let iso = unsafe { *(cursor as *const MadtIso) };
                    let entry = IsoEntry {
                        bus: iso.bus,
                        source: iso.source,
                        gsi: { iso.gsi },
                        flags: { iso.flags },
                    };
                    crate::kprintln!(
                        "  acpi: ISO bus={} source={} -> gsi={} flags={:#x}",
                        entry.bus,
                        entry.source,
                        entry.gsi,
                        entry.flags
                    );
                    data.isos[data.iso_count] = Some(entry);
                    data.iso_count += 1;
                }
            }
            _ => {
                // Other MADT entry types (LAPIC, NMI, x2APIC, etc.)
                // are skipped — Phase E only needs IOAPIC + ISO.
            }
        }
        cursor = entry_end;
    }

    crate::kprintln!(
        "  acpi: parsed MADT — {} IOAPIC(s), {} ISO(s)",
        data.ioapic_count,
        data.iso_count
    );
    Some(data)
}
