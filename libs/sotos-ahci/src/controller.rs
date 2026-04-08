//! AHCI HBA controller initialization.

use crate::regs;
use crate::cmd::{CommandList, CommandTable};
use crate::fis::ReceivedFis;
use crate::port::{self, WaitFn};

/// Maximum number of ports we support simultaneously.
pub const MAX_PORTS: usize = 8;

/// Per-port DMA memory layout provided by the caller.
pub struct PortDma {
    /// Command List virtual address (1024-byte aligned).
    pub cl_virt: *mut u8,
    /// Command List physical address.
    pub cl_phys: u64,
    /// FIS Receive area virtual address (256-byte aligned).
    pub fb_virt: *mut u8,
    /// FIS Receive area physical address.
    pub fb_phys: u64,
    /// Command Table virtual address (128-byte aligned).
    pub ct_virt: *mut u8,
    /// Command Table physical address.
    pub ct_phys: u64,
    /// Data buffer virtual address (for IDENTIFY, etc.).
    pub data_virt: *mut u8,
    /// Data buffer physical address.
    pub data_phys: u64,
}

/// Information about an active SATA port.
#[derive(Clone, Copy)]
pub struct PortInfo {
    /// Port number (0-31).
    pub port_num: u8,
    /// Device is present and initialized.
    pub present: bool,
    /// Total sectors (from IDENTIFY DEVICE).
    pub total_sectors: u64,
    /// Sector size in bytes (usually 512).
    pub sector_size: u32,
    /// Model string (first 20 bytes of the model, ASCII, byte-swapped).
    pub model: [u8; 40],
    /// Serial number (first 10 bytes, ASCII, byte-swapped).
    pub serial: [u8; 20],
}

impl PortInfo {
    /// All-zeros placeholder (with `sector_size = 512`) used when
    /// pre-populating [`AhciController::ports`].
    pub const fn empty() -> Self {
        Self {
            port_num: 0,
            present: false,
            total_sectors: 0,
            sector_size: 512,
            model: [0; 40],
            serial: [0; 20],
        }
    }
}

/// AHCI controller state.
pub struct AhciController {
    /// HBA MMIO base address (BAR5, UC-mapped).
    pub hba_base: *mut u8,
    /// Number of command slots supported by the HBA.
    pub num_cmd_slots: u8,
    /// Ports Implemented bitmask.
    pub ports_impl: u32,
    /// Info about initialized ports.
    pub ports: [PortInfo; MAX_PORTS],
    /// Number of active ports.
    pub active_count: usize,
}

/// Result of controller initialization.
pub struct AhciInitResult {
    /// AHCI version major (from `VS` high word).
    pub version_major: u16,
    /// AHCI version minor (from `VS` low word).
    pub version_minor: u16,
    /// Number of SATA devices found.
    pub device_count: usize,
    /// Whether 64-bit addressing is supported.
    pub supports_64bit: bool,
}

impl AhciController {
    /// Initialize the AHCI controller and probe all ports.
    ///
    /// Performs the full initialization sequence:
    /// 1. Enable AHCI mode (GHC.AE).
    /// 2. Perform HBA reset if needed.
    /// 3. Read capabilities, enumerate ports.
    /// 4. For each SATA port: stop engine, set CLB/FB, start engine.
    /// 5. Issue IDENTIFY DEVICE on each detected SATA drive.
    ///
    /// - `hba_base`: HBA MMIO base (BAR5, UC-mapped).
    /// - `port_dma`: Array of DMA memory descriptors for each port to initialize.
    /// - `port_nums`: Array of port numbers to initialize (matching `port_dma`).
    /// - `count`: Number of ports in the arrays.
    /// - `wait`: Wait callback.
    ///
    /// # Safety
    /// `hba_base` and all DMA pointers must be valid.
    pub unsafe fn init(
        hba_base: *mut u8,
        port_dma: &[PortDma],
        port_nums: &[u8],
        count: usize,
        wait: WaitFn,
    ) -> Result<(Self, AhciInitResult), &'static str> {
        let hba_ro = hba_base as *const u8;

        // 1. Enable AHCI mode.
        let ghc = unsafe { regs::read32(hba_ro, regs::REG_GHC) };
        if ghc & regs::GHC_AE == 0 {
            unsafe { regs::write32(hba_base, regs::REG_GHC, ghc | regs::GHC_AE) };
        }

        // 2. Read version.
        let vs = unsafe { regs::read32(hba_ro, regs::REG_VS) };
        let ver_major = (vs >> 16) as u16;
        let ver_minor = (vs & 0xFFFF) as u16;

        // 3. Read capabilities.
        let cap = unsafe { regs::read32(hba_ro, regs::REG_CAP) };
        let num_cmd_slots = regs::cap_num_cmd_slots(cap);
        let supports_64bit = cap & regs::CAP_S64A != 0;
        let pi = unsafe { regs::read32(hba_ro, regs::REG_PI) };

        // Enable global interrupts.
        unsafe {
            regs::write32(hba_base, regs::REG_IS, 0xFFFFFFFF); // Clear pending
            let ghc = regs::read32(hba_ro, regs::REG_GHC);
            regs::write32(hba_base, regs::REG_GHC, ghc | regs::GHC_IE);
        }

        let mut ctrl = AhciController {
            hba_base,
            num_cmd_slots,
            ports_impl: pi,
            ports: [PortInfo::empty(); MAX_PORTS],
            active_count: 0,
        };

        // 4. Initialize each requested port.
        let n = if count > MAX_PORTS { MAX_PORTS } else { count };
        for i in 0..n {
            let port_num = port_nums[i];
            let dma = &port_dma[i];

            // Stop the command engine.
            unsafe { port::stop_cmd(hba_base, port_num, wait)? };

            // Zero-init CLB and FB.
            unsafe {
                core::ptr::write_bytes(dma.cl_virt, 0, core::mem::size_of::<CommandList>());
                core::ptr::write_bytes(dma.fb_virt, 0, core::mem::size_of::<ReceivedFis>());
                core::ptr::write_bytes(dma.ct_virt, 0, core::mem::size_of::<CommandTable>());
            }

            // Set CLB and FB addresses.
            unsafe {
                port::set_clb(hba_base, port_num, dma.cl_phys);
                port::set_fb(hba_base, port_num, dma.fb_phys);
            }

            // Clear pending interrupts and errors.
            unsafe {
                port::clear_serr(hba_base, port_num);
                port::clear_interrupts(hba_base, port_num);
            }

            // Set up Command Header 0 pointing to the Command Table.
            let cl = dma.cl_virt as *mut crate::cmd::CommandHeader;
            unsafe {
                let hdr = &mut *cl;
                hdr.ctba = dma.ct_phys as u32;
                hdr.ctbau = (dma.ct_phys >> 32) as u32;
            }

            // Start the command engine.
            unsafe { port::start_cmd(hba_base, port_num) };

            // 5. Try IDENTIFY DEVICE.
            let mut info = PortInfo::empty();
            info.port_num = port_num;

            if let Ok(()) = unsafe {
                Self::identify_device(hba_base, port_num, dma, wait)
            } {
                // Parse IDENTIFY response from data buffer.
                let data = dma.data_virt as *const u16;

                // Word 60-61: total addressable sectors (28-bit LBA).
                let lba28 = unsafe {
                    let lo = core::ptr::read_volatile(data.add(60)) as u64;
                    let hi = core::ptr::read_volatile(data.add(61)) as u64;
                    (hi << 16) | lo
                };

                // Word 100-103: total addressable sectors (48-bit LBA).
                let lba48 = unsafe {
                    let w100 = core::ptr::read_volatile(data.add(100)) as u64;
                    let w101 = core::ptr::read_volatile(data.add(101)) as u64;
                    let w102 = core::ptr::read_volatile(data.add(102)) as u64;
                    let w103 = core::ptr::read_volatile(data.add(103)) as u64;
                    (w103 << 48) | (w102 << 32) | (w101 << 16) | w100
                };

                info.total_sectors = if lba48 > 0 { lba48 } else { lba28 };
                info.sector_size = 512; // Default; could parse word 106 for 4K sectors.

                // Serial number: words 10-19 (20 bytes, byte-swapped).
                for w in 0..10 {
                    let val = unsafe { core::ptr::read_volatile(data.add(10 + w)) };
                    info.serial[w * 2] = (val >> 8) as u8;
                    info.serial[w * 2 + 1] = (val & 0xFF) as u8;
                }

                // Model: words 27-46 (40 bytes, byte-swapped).
                for w in 0..20 {
                    let val = unsafe { core::ptr::read_volatile(data.add(27 + w)) };
                    info.model[w * 2] = (val >> 8) as u8;
                    info.model[w * 2 + 1] = (val & 0xFF) as u8;
                }

                info.present = true;
            }

            ctrl.ports[ctrl.active_count] = info;
            ctrl.active_count += 1;
        }

        let device_count = ctrl.ports[..ctrl.active_count]
            .iter()
            .filter(|p| p.present)
            .count();

        let result = AhciInitResult {
            version_major: ver_major,
            version_minor: ver_minor,
            device_count,
            supports_64bit,
        };

        Ok((ctrl, result))
    }

    /// Issue IDENTIFY DEVICE on a port using command slot 0.
    ///
    /// # Safety
    /// Port must be initialized with CLB, FB, and CT. Engine must be running.
    unsafe fn identify_device(
        hba_base: *mut u8,
        port_num: u8,
        dma: &PortDma,
        wait: WaitFn,
    ) -> Result<(), &'static str> {
        // Wait for port to not be busy.
        unsafe { port::wait_busy(hba_base as *const u8, port_num, wait)? };

        // Set up Command Header 0 for a PIO-in command (IDENTIFY).
        let cl = dma.cl_virt as *mut crate::cmd::CommandHeader;
        unsafe {
            let hdr = &mut *cl;
            // CFL = 5 DWORDs, Read (W=0), PRDTL = 1, Clear BSY on ok.
            hdr.flags_cfl_prdtl = crate::cmd::CFL_H2D
                | crate::cmd::CH_FLAG_CLEAR_BSY
                | (1u32 << 16); // PRDTL = 1
            hdr.prdbc = 0;
            hdr.ctba = dma.ct_phys as u32;
            hdr.ctbau = (dma.ct_phys >> 32) as u32;
        }

        // Set up Command Table: FIS + PRDT.
        let ct = dma.ct_virt as *mut crate::cmd::CommandTable;
        unsafe {
            // Zero the table.
            core::ptr::write_bytes(ct as *mut u8, 0, core::mem::size_of::<crate::cmd::CommandTable>());
            let table = &mut *ct;

            // Write IDENTIFY FIS.
            let fis = crate::fis::FisRegH2D::identify();
            table.set_cfis(&fis);

            // Set PRDT[0]: 512 bytes at data_phys, IOC.
            table.prdt[0] = crate::cmd::PrdtEntry::new(dma.data_phys, 512, true);
        }

        // Zero the data buffer.
        unsafe { core::ptr::write_bytes(dma.data_virt, 0, 512) };

        // Clear port interrupt status.
        unsafe { port::clear_interrupts(hba_base, port_num) };

        // Issue command slot 0.
        unsafe { port::issue_command(hba_base, port_num, 0) };

        // Wait for completion.
        unsafe { port::wait_command(hba_base, port_num, 0, wait) }
    }

    /// Find a port info entry by port number.
    pub fn port_info(&self, port_num: u8) -> Option<&PortInfo> {
        self.ports[..self.active_count]
            .iter()
            .find(|p| p.port_num == port_num && p.present)
    }
}
