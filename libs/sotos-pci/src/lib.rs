//! sotos-pci — Userspace PCI bus enumeration library for sotX.
//!
//! Provides PCI configuration space access via the legacy *Mechanism #1*
//! I/O ports (`0xCF8` address, `0xCFC` data) defined in PCI Local Bus
//! Specification 3.0 §3.2.2.3.2. Used by every PCI driver in the project
//! (`sotos-virtio`, `sotos-nvme`, `sotos-xhci`, `sotos-ahci`) to
//! enumerate the bus, resolve BARs, and toggle command-register bits
//! before doing real I/O.
//!
//! # Key types
//! - [`PciBus`]: configuration space accessor backed by an `IoPort`
//!   capability covering ports `0xCF8`–`0xCFF`.
//! - [`PciAddr`]: bus/device/function tuple identifying one config space
//!   slot.
//! - [`PciDevice`]: a discovered device with vendor/device IDs, class
//!   triple, header type, and IRQ line.
//!
//! # Constraints
//! - `no_std`, no heap. [`PciBus::enumerate`] returns a stack array
//!   sized at the call site via a const generic.
//! - Single-bus only: enumeration walks bus 0 (devices 0..32, functions
//!   0..8 for multi-function headers).
//! - Requires an `IoPort` capability for `0xCF8..=0xCFF`; see
//!   [`PciBus::new`].
//!
//! # References
//! PCI Local Bus Specification 3.0 (config space layout, BAR encoding,
//! Command/Status register).

#![no_std]

use sotos_common::sys;

/// PCI configuration space *address* port (PCI 3.0 §3.2.2.3.2).
const PCI_CONFIG_ADDR: u64 = 0xCF8;
/// PCI configuration space *data* port (PCI 3.0 §3.2.2.3.2).
const PCI_CONFIG_DATA: u64 = 0xCFC;

/// Userspace handle to the PCI configuration space.
///
/// Wraps an `IoPort` capability for `0xCF8..=0xCFF` and exposes typed
/// reads/writes against the standard 256-byte config header. Cheap to
/// copy by value if needed; all state lives in the kernel-side cap.
pub struct PciBus {
    /// IoPort capability covering the config-space ports. Passed
    /// unchanged to every `port_in*` / `port_out*` syscall.
    cap: u64,
}

/// PCI bus / device / function address — identifies one of the 256
/// possible config-space slots on a single bus.
///
/// `bus` is the bus number (0..=255), `dev` the device slot (0..=31),
/// and `func` the function index inside a multi-function device
/// (0..=7). Encoded into the address dword written to `0xCF8`.
#[derive(Debug, Clone, Copy)]
pub struct PciAddr {
    /// Bus number (0..=255). Only bus 0 is currently enumerated.
    pub bus: u8,
    /// Device slot on the bus (0..=31).
    pub dev: u8,
    /// Function index inside a multi-function device (0..=7).
    pub func: u8,
}

/// A PCI device discovered during enumeration.
///
/// Holds the bare minimum from the type-0 config header that downstream
/// drivers need to bind to a device, program its BARs, and route its
/// interrupt. Populated by [`PciBus::enumerate`] and
/// [`PciBus::find_device`]; richer fields (BAR set, capability list)
/// are read on demand via the `PciBus` accessors.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    /// Bus/device/function address that originated this entry.
    pub addr: PciAddr,
    /// Vendor ID from config offset `0x00` (PCI 3.0 §6.2.1). `0xFFFF`
    /// is reserved for "no device" and is filtered out by enumeration.
    pub vendor_id: u16,
    /// Device ID from config offset `0x02`.
    pub device_id: u16,
    /// Base class code from config offset `0x0B` (e.g. `0x01` =
    /// mass storage, `0x02` = network controller, `0x0C` = serial bus).
    pub class: u8,
    /// Sub-class code from config offset `0x0A`.
    pub subclass: u8,
    /// Programming interface byte from config offset `0x09`.
    pub prog_if: u8,
    /// Header type from config offset `0x0E` with the multi-function
    /// bit (`0x80`) masked off — `0` for type-0 endpoints, `1` for
    /// PCI-to-PCI bridges.
    pub header_type: u8,
    /// Interrupt line (config offset `0x3C`) — the legacy 8259 IRQ
    /// the device is wired to. Meaningful only for legacy INTx routing.
    pub irq_line: u8,
}

impl PciBus {
    /// Wrap an existing `IoPort` capability covering `0xCF8..=0xCFF`
    /// into a `PciBus` accessor.
    ///
    /// The capability must be derived by the caller via the regular
    /// kernel cap-creation path; this constructor performs no
    /// validation. Cheap, infallible, and pure.
    pub fn new(pci_port_cap: u64) -> Self {
        Self { cap: pci_port_cap }
    }

    /// Read a 32-bit dword from PCI configuration space.
    ///
    /// Builds the Mechanism #1 address (enable bit + BDF + dword-aligned
    /// offset), writes it to `0xCF8`, then reads `0xCFC`. Returns
    /// `0xFFFFFFFF` (the spec's "no device" sentinel) if either port
    /// access is rejected by the kernel.
    ///
    /// `offset` is masked to a 4-byte boundary; sub-dword access must
    /// be done by the caller via shifts/masks.
    pub fn read32(&self, addr: PciAddr, offset: u8) -> u32 {
        let address: u32 = (1 << 31) // enable bit
            | ((addr.bus as u32) << 16)
            | ((addr.dev as u32) << 11)
            | ((addr.func as u32) << 8)
            | ((offset as u32) & 0xFC);
        let _ = sys::port_out32(self.cap, PCI_CONFIG_ADDR, address);
        sys::port_in32(self.cap, PCI_CONFIG_DATA).unwrap_or(0xFFFFFFFF)
    }

    /// Write a 32-bit dword to PCI configuration space at the given
    /// BDF + dword-aligned offset.
    ///
    /// Errors from the underlying `port_out32` syscall are silently
    /// dropped — driver code should verify side effects via a
    /// follow-up [`read32`](Self::read32) when correctness matters.
    pub fn write32(&self, addr: PciAddr, offset: u8, val: u32) {
        let address: u32 = (1 << 31)
            | ((addr.bus as u32) << 16)
            | ((addr.dev as u32) << 11)
            | ((addr.func as u32) << 8)
            | ((offset as u32) & 0xFC);
        let _ = sys::port_out32(self.cap, PCI_CONFIG_ADDR, address);
        let _ = sys::port_out32(self.cap, PCI_CONFIG_DATA, val);
    }

    /// Read the vendor and device IDs from offsets `0x00`/`0x02`.
    ///
    /// Returned as `(vendor, device)`. A vendor of `0xFFFF` indicates
    /// no device is present at the given BDF.
    pub fn vendor_device(&self, addr: PciAddr) -> (u16, u16) {
        let val = self.read32(addr, 0x00);
        let vendor = val as u16;
        let device = (val >> 16) as u16;
        (vendor, device)
    }

    /// Read the raw 32-bit BAR0 value from config offset `0x10`.
    ///
    /// Bit 0 distinguishes I/O (`1`) from memory (`0`); bits 2..1 of a
    /// memory BAR encode the type (32-bit, below-1MB, 64-bit). Use
    /// [`bar0_mmio`](Self::bar0_mmio) for the decoded MMIO base.
    pub fn bar0(&self, addr: PciAddr) -> u32 {
        self.read32(addr, 0x10)
    }

    /// Decode BAR0 as an MMIO base address.
    ///
    /// Returns `None` if BAR0 is an I/O port BAR (bit 0 set) or has an
    /// unrecognised type field. For 64-bit memory BARs (type `0b10`)
    /// the high 32 bits are read from BAR1 (offset `0x14`) and OR'd
    /// into the result. The low 4 bits (type/prefetch) are masked off.
    pub fn bar0_mmio(&self, addr: PciAddr) -> Option<u64> {
        let bar0 = self.read32(addr, 0x10);
        // Bit 0 = 0 means memory BAR
        if bar0 & 1 != 0 {
            return None; // I/O port BAR
        }
        let bar_type = (bar0 >> 1) & 3;
        let base_lo = (bar0 & !0xF) as u64;
        match bar_type {
            0 => Some(base_lo),        // 32-bit
            2 => {                      // 64-bit
                let bar1 = self.read32(addr, 0x14);
                Some(base_lo | ((bar1 as u64) << 32))
            }
            _ => None,
        }
    }

    /// Set the *Memory Space Enable* bit (bit 1) of the PCI Command
    /// register at offset `0x04`.
    ///
    /// Required before the device responds to MMIO accesses against
    /// any of its memory BARs. Read-modify-write so other command bits
    /// (e.g. bus master, INTx disable) are preserved.
    pub fn enable_memory_space(&self, addr: PciAddr) {
        let cmd = self.read32(addr, 0x04);
        self.write32(addr, 0x04, cmd | (1 << 1));
    }

    /// Read the legacy IRQ line from config offset `0x3C` byte 0.
    ///
    /// This is the 8259-style interrupt vector the device's INTx pin
    /// is wired to (per BIOS routing). MSI/MSI-X-only drivers can
    /// ignore the value.
    pub fn irq_line(&self, addr: PciAddr) -> u8 {
        self.read32(addr, 0x3C) as u8
    }

    /// Set the *Bus Master Enable* bit (bit 2) of the PCI Command
    /// register at offset `0x04`.
    ///
    /// Required before the device may issue DMA cycles. Read-modify-
    /// write so other command bits are preserved.
    pub fn enable_bus_master(&self, addr: PciAddr) {
        let cmd = self.read32(addr, 0x04);
        self.write32(addr, 0x04, cmd | (1 << 2));
    }

    /// Walk PCI bus 0 and return up to `N` discovered devices.
    ///
    /// For each of the 32 device slots: probe function 0; if the
    /// vendor ID is `0xFFFF` the slot is empty. Otherwise read the
    /// class triple and header type, and if the multi-function bit
    /// (`header_type & 0x80`) is set, probe functions 1..8 as well.
    ///
    /// Returns `(devices, count)` where `count <= N`. Devices beyond
    /// the `N`th are silently dropped — pick `N` large enough that
    /// truncation cannot happen on the boards you target. The result
    /// is a stack array, so `N` doubles as the on-stack footprint.
    pub fn enumerate<const N: usize>(&self) -> ([PciDevice; N], usize) {
        let mut devices = [PciDevice {
            addr: PciAddr { bus: 0, dev: 0, func: 0 },
            vendor_id: 0,
            device_id: 0,
            class: 0,
            subclass: 0,
            prog_if: 0,
            header_type: 0,
            irq_line: 0,
        }; N];
        let mut count = 0;

        for dev in 0..32u8 {
            let addr = PciAddr { bus: 0, dev, func: 0 };
            let (vendor, device) = self.vendor_device(addr);
            if vendor == 0xFFFF {
                continue;
            }

            let class_rev = self.read32(addr, 0x08);
            let header_val = self.read32(addr, 0x0C);
            let header_type = ((header_val >> 16) & 0xFF) as u8;

            if count < N {
                devices[count] = PciDevice {
                    addr,
                    vendor_id: vendor,
                    device_id: device,
                    class: (class_rev >> 24) as u8,
                    subclass: ((class_rev >> 16) & 0xFF) as u8,
                    prog_if: ((class_rev >> 8) & 0xFF) as u8,
                    header_type: header_type & 0x7F,
                    irq_line: self.irq_line(addr),
                };
                count += 1;
            }

            // Check multi-function device
            if header_type & 0x80 != 0 {
                for func in 1..8u8 {
                    let faddr = PciAddr { bus: 0, dev, func };
                    let (fv, fd) = self.vendor_device(faddr);
                    if fv == 0xFFFF {
                        continue;
                    }
                    let fc = self.read32(faddr, 0x08);
                    if count < N {
                        devices[count] = PciDevice {
                            addr: faddr,
                            vendor_id: fv,
                            device_id: fd,
                            class: (fc >> 24) as u8,
                            subclass: ((fc >> 16) & 0xFF) as u8,
                            prog_if: ((fc >> 8) & 0xFF) as u8,
                            header_type: 0,
                            irq_line: self.irq_line(faddr),
                        };
                        count += 1;
                    }
                }
            }
        }

        (devices, count)
    }

    /// Find the first device on bus 0 matching `(vendor, device)`.
    ///
    /// Internally enumerates into a 32-entry stack buffer and returns
    /// the first match, or `None` if absent. Callers needing more than
    /// 32 devices should call [`enumerate`](Self::enumerate) directly
    /// with a larger const generic.
    pub fn find_device(&self, vendor: u16, device: u16) -> Option<PciDevice> {
        let (devs, count) = self.enumerate::<32>();
        for i in 0..count {
            if devs[i].vendor_id == vendor && devs[i].device_id == device {
                return Some(devs[i]);
            }
        }
        None
    }
}
