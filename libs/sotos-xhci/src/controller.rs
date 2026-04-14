//! xHCI controller initialization and command submission.

use crate::regs;
use crate::trb::{self, Trb, TrbRing, EventRing, ErstEntry};

/// DMA memory layout provided by the service process.
///
/// The driver is allocation-free: the wrapping userspace service
/// hands in every physical page the controller will touch (DCBAA,
/// command/event rings, ERST, scratchpad, the first device's context
/// and EP0 transfer ring, plus one scratch data buffer).
pub struct XhciDma {
    /// Device Context Base Address Array virtual address (4 KiB, page-aligned).
    pub dcbaa_virt: *mut u8,
    /// Device Context Base Address Array physical address.
    pub dcbaa_phys: u64,
    /// Command Ring virtual base (4 KiB, 64-byte aligned).
    pub cmd_ring_virt: *mut u8,
    /// Command Ring physical base (programmed into `CRCR`).
    pub cmd_ring_phys: u64,
    /// Event Ring segment virtual base (4 KiB).
    pub evt_ring_virt: *mut u8,
    /// Event Ring segment physical base.
    pub evt_ring_phys: u64,
    /// Event Ring Segment Table virtual base (single-entry here).
    pub erst_virt: *mut u8,
    /// Event Ring Segment Table physical base (programmed into `ERSTBA`).
    pub erst_phys: u64,
    /// Scratchpad Buffer Array virtual base.
    pub scratch_arr_virt: *mut u8,
    /// Scratchpad Buffer Array physical base (first DCBAA slot).
    pub scratch_arr_phys: u64,
    /// Physical addresses of up to 16 scratchpad buffers.
    pub scratch_buf_phys: [u64; 16],
    /// Input Context virtual base (64-byte aligned, used during Address Device).
    pub input_ctx_virt: *mut u8,
    /// Input Context physical base.
    pub input_ctx_phys: u64,
    /// Device Context virtual base for the first tracked device.
    pub device_ctx_virt: *mut u8,
    /// Device Context physical base for the first tracked device.
    pub device_ctx_phys: u64,
    /// EP0 Transfer Ring virtual base for the first tracked device.
    pub ep0_ring_virt: *mut u8,
    /// EP0 Transfer Ring physical base.
    pub ep0_ring_phys: u64,
    /// Scratch data buffer for `GET_DESCRIPTOR` / control responses.
    pub data_buf_virt: *mut u8,
    /// Scratch data buffer physical address.
    pub data_buf_phys: u64,
}

/// Wait callback — called while polling hardware state changes so
/// the driver can yield back to the service event loop.
pub type WaitFn = fn();

/// Result of controller initialization.
pub struct XhciInitResult {
    /// HCIVERSION major byte (e.g. `0x01` for xHCI 1.x).
    pub version_major: u8,
    /// HCIVERSION minor byte (e.g. `0x20` for xHCI 1.2).
    pub version_minor: u8,
    /// Maximum device slots supported by the host controller (`HCSPARAMS1`).
    pub max_slots: u8,
    /// Number of root-hub ports reported by the controller.
    pub max_ports: u8,
}

/// Maximum number of concurrently tracked USB devices.
pub const MAX_DEVICES: usize = 16;

/// USB device state tracked by the controller.
#[derive(Clone, Copy)]
pub struct UsbDevice {
    /// xHCI slot ID (1-based, assigned by Enable Slot).
    pub slot_id: u8,
    /// Root hub port this device is attached to (1-based).
    pub port: u8,
    /// Port speed (1=FS, 2=LS, 3=HS, 4=SS).
    pub speed: u8,
    /// Whether this device is configured (SET_CONFIGURATION done).
    pub configured: bool,
    /// USB device class (from device descriptor).
    pub device_class: u8,
    /// Whether this device is a hub.
    pub is_hub: bool,
    /// Number of hub ports (if is_hub).
    pub hub_ports: u8,
    /// Physical address of the device context.
    pub ctx_phys: u64,
    /// Physical address of the EP0 transfer ring.
    pub ep0_ring_phys: u64,
    /// Virtual address of the EP0 transfer ring.
    pub ep0_ring_virt: *mut u8,
}

impl UsbDevice {
    /// All-zeros placeholder used to pre-populate the `devices` array.
    /// `const` so it can be used in static initialisers.
    pub const fn empty() -> Self {
        UsbDevice {
            slot_id: 0,
            port: 0,
            speed: 0,
            configured: false,
            device_class: 0,
            is_hub: false,
            hub_ports: 0,
            ctx_phys: 0,
            ep0_ring_phys: 0,
            ep0_ring_virt: core::ptr::null_mut(),
        }
    }

    /// A slot is considered active once `Enable Slot` has assigned it a
    /// non-zero slot ID.
    pub fn is_active(&self) -> bool {
        self.slot_id != 0
    }
}

/// BIOS → OS handoff for the USB Legacy Support extended capability.
///
/// Walks the xECP linked list at `(HCCPARAMS1.xECP * 4)` looking for
/// cap ID `XECP_ID_USBLEGSUP` (0x01). When found, sets `HC OS Owned`,
/// polls until `HC BIOS Owned` clears (with a generous timeout — some
/// firmwares run several SMI handlers before releasing ownership), and
/// disables every SMI source in USBLEGCTLSTS so the kernel doesn't
/// re-enter SMM on every doorbell.
///
/// On real Intel PCH chipsets, **without this handoff every doorbell
/// write silently traps to SMM and the controller never advances**.
/// QEMU's `qemu-xhci` doesn't implement the extended cap list so this
/// becomes a no-op (xECP=0). On both platforms the function returns
/// without error so callers can call it unconditionally.
///
/// # Safety
/// `mmio_base` must point to a valid UC-mapped xHCI BAR0 region; the
/// extended capability list is contained within BAR0.
unsafe fn legacy_handoff(mmio_base: *mut u8, hcc1: u32, wait: WaitFn) {
    let xecp = regs::hcc1_xecp(hcc1);
    if xecp == 0 {
        return; // No extended capabilities advertised.
    }

    let mut offset = (xecp as usize) * 4;
    // Hard cap on the walk so a bogus firmware loop doesn't spin us
    // forever. 64 capabilities is well past anything real hardware ships.
    for _ in 0..64 {
        let cap = regs::read32(mmio_base as *const u8, offset);
        let cap_id = cap & 0xFF;
        let next = (cap >> 8) & 0xFF;

        if cap_id == regs::XECP_ID_USBLEGSUP {
            // Request ownership: set HC_OS_OWNED, leaving HC_BIOS_OWNED for
            // BIOS to clear when it has finished tearing down its handler.
            regs::write32(mmio_base, offset + regs::USBLEGSUP_OFFSET,
                cap | regs::USBLEGSUP_OS_OWNED);

            // Poll for BIOS to release. 1M iterations × ~1µs MMIO read on
            // real HW = ~1s budget; on QEMU it's faster but still bounded.
            // BIOS handlers commonly take 100-500ms so allow margin.
            for i in 0..1_000_000_u32 {
                let v = regs::read32(mmio_base as *const u8,
                    offset + regs::USBLEGSUP_OFFSET);
                if v & regs::USBLEGSUP_BIOS_OWNED == 0 {
                    break;
                }
                if (i & 0xFF) == 0 {
                    wait();
                }
            }

            // Final state: even if BIOS missed the deadline (some quirky
            // firmwares never release), force-clear BIOS_OWNED. Per spec
            // this is allowed once OS_OWNED has been set — the OS is now
            // authoritative.
            let v = regs::read32(mmio_base as *const u8,
                offset + regs::USBLEGSUP_OFFSET);
            regs::write32(mmio_base, offset + regs::USBLEGSUP_OFFSET,
                (v | regs::USBLEGSUP_OS_OWNED) & !regs::USBLEGSUP_BIOS_OWNED);

            // Disable every SMI source: write 0 to the enable bits and
            // 1s to the RW1C status bits in USBLEGCTLSTS so we leave a
            // clean slate. Without this, BIOS may keep generating SMIs
            // on port events / OS ownership changes that trap into SMM
            // mid-driver-init.
            regs::write32(mmio_base, offset + regs::USBLEGCTLSTS_OFFSET,
                regs::USBLEGCTLSTS_SMI_ENABLES);
            return;
        }

        if next == 0 {
            return; // End of list, no USBLEGSUP found.
        }
        offset += (next as usize) * 4;
    }
}

/// One entry returned by [`walk_supported_protocols`]. Describes a
/// contiguous range of xHCI root-hub ports that belong to one USB
/// protocol major revision (2 = USB2.x, 3 = USB3.x).
#[derive(Clone, Copy, Debug)]
pub struct SupportedProtocol {
    /// Major revision (`2` or `3`).
    pub major: u8,
    /// Minor revision within the major (e.g. `0` for 2.0, `10` for 2.10).
    pub minor: u8,
    /// 1-based first root-hub port in this range.
    pub port_offset: u8,
    /// Number of ports in this range.
    pub port_count: u8,
}

/// Walk the xECP list for Supported Protocol capabilities (cap ID 0x02)
/// and return up to `out.len()` entries. Returns the number of entries
/// written. No-op when xECP is zero.
///
/// # Safety
/// `mmio_base` must point to a valid UC-mapped xHCI BAR0 region. The
/// library never itself prints; callers are responsible for logging
/// the returned info through whatever channel they have available
/// (kernel has kprintln!, userspace drivers have `sys::debug_print`).
pub unsafe fn walk_supported_protocols(
    mmio_base: *mut u8,
    hcc1: u32,
    out: &mut [SupportedProtocol],
) -> usize {
    let xecp = regs::hcc1_xecp(hcc1);
    if xecp == 0 {
        return 0;
    }
    let mut offset = (xecp as usize) * 4;
    let mut found = 0usize;
    for _ in 0..64 {
        let cap = regs::read32(mmio_base as *const u8, offset);
        let cap_id = cap & 0xFF;
        let next = (cap >> 8) & 0xFF;

        if cap_id == regs::XECP_ID_SUPPORTED_PROTOCOL && found < out.len() {
            let minor_rev = ((cap >> 16) & 0xFF) as u8;
            let major_rev = ((cap >> 24) & 0xFF) as u8;
            // Dword 2 at +8: port offset (bits 0..7), port count (bits 8..15).
            let w2 = regs::read32(mmio_base as *const u8, offset + 8);
            out[found] = SupportedProtocol {
                major: major_rev,
                minor: minor_rev,
                port_offset: (w2 & 0xFF) as u8,
                port_count: ((w2 >> 8) & 0xFF) as u8,
            };
            found += 1;
        }

        if next == 0 {
            break;
        }
        offset += (next as usize) * 4;
    }
    found
}

/// xHCI host-controller driver state.
///
/// Caches the MMIO sub-base pointers (operational, doorbell, runtime)
/// derived from the capability-header length byte, owns the command
/// and event rings, and tracks every `UsbDevice` the driver has
/// successfully addressed. Single instance per controller.
pub struct XhciController {
    mmio_base: *mut u8,
    op_base: *mut u8,
    db_base: *mut u8,
    rt_base: *mut u8,
    cmd_ring: TrbRing,
    evt_ring: EventRing,
    /// Number of root-hub ports (`HCSPARAMS1.MaxPorts`).
    pub max_ports: u8,
    /// Maximum device slots supported (`HCSPARAMS1.MaxSlots`).
    pub max_slots: u8,
    /// Array of tracked USB devices (index 0..15).
    pub devices: [Option<UsbDevice>; MAX_DEVICES],
}

impl XhciController {
    /// Initialize the xHCI controller. Follows the 10-step sequence from the spec.
    ///
    /// # Safety
    /// `mmio_base` must point to a valid UC-mapped xHCI BAR0 region.
    pub unsafe fn init(
        mmio_base: *mut u8,
        dma: &XhciDma,
        wait: WaitFn,
    ) -> Result<(Self, XhciInitResult), &'static str> {
        // 1. Read CAPLENGTH, HCIVERSION, DBOFF, RTSOFF.
        let caplength = regs::read8(mmio_base as *const u8, regs::CAP_CAPLENGTH) as usize;
        // HCIVERSION is at offset 2 within a 32-bit register at offset 0.
        let cap0 = regs::read32(mmio_base as *const u8, 0x00);
        let hciversion = (cap0 >> 16) as u16;
        let dboff = regs::read32(mmio_base as *const u8, regs::CAP_DBOFF) as usize;
        let rtsoff = regs::read32(mmio_base as *const u8, regs::CAP_RTSOFF) as usize;

        let op_base = mmio_base.add(caplength);
        let db_base = mmio_base.add(dboff);
        let rt_base = mmio_base.add(rtsoff);

        let version_major = (hciversion >> 8) as u8;
        let version_minor = (hciversion & 0xFF) as u8;

        // 2. Read HCSPARAMS1 → max_slots, max_ports; HCSPARAMS2 → max_scratchpad.
        let hcs1 = regs::read32(mmio_base as *const u8, regs::CAP_HCSPARAMS1);
        let hcs2 = regs::read32(mmio_base as *const u8, regs::CAP_HCSPARAMS2);
        let hcc1 = regs::read32(mmio_base as *const u8, regs::CAP_HCCPARAMS1);
        let max_slots = regs::hcs1_max_slots(hcs1);
        let max_ports = regs::hcs1_max_ports(hcs1);
        let max_scratch = regs::hcs2_max_scratchpad(hcs2);

        // 2.5. BIOS → OS legacy handoff. Critical on Intel PCH xHCI: BIOS
        // holds USB ownership via SMM and silently swallows our writes
        // until we explicitly claim it. QEMU's qemu-xhci has no extended
        // capabilities so this is a no-op there.
        legacy_handoff(mmio_base, hcc1, wait);

        // 3. Halt: clear USBCMD.RS, wait for USBSTS.HCH=1.
        // TCG fix (run-full deadlock U1): cap loop + yield only every 256 iters.
        // Each MMIO read costs ~1000 host cycles on TCG; the old per-iter
        // wait() generated 100K context switches that round-robin-starved init.
        let cmd = regs::read32(op_base as *const u8, regs::OP_USBCMD);
        regs::write32(op_base, regs::OP_USBCMD, cmd & !regs::CMD_RS);
        for i in 0..100_000_u32 {
            let sts = regs::read32(op_base as *const u8, regs::OP_USBSTS);
            if sts & regs::STS_HCH != 0 {
                break;
            }
            if (i & 0xFF) == 0 {
                wait();
            }
        }

        // 4. Reset: set HCRST, wait for HCRST=0 AND CNR=0.
        // TCG fix (run-full deadlock U1): cap from 1M -> 100K, yield every 256 iters.
        regs::write32(op_base, regs::OP_USBCMD, regs::CMD_HCRST);
        for i in 0..100_000_u32 {
            let cmd_val = regs::read32(op_base as *const u8, regs::OP_USBCMD);
            let sts = regs::read32(op_base as *const u8, regs::OP_USBSTS);
            if (cmd_val & regs::CMD_HCRST == 0) && (sts & regs::STS_CNR == 0) {
                break;
            }
            if (i & 0xFF) == 0 {
                wait();
            }
        }
        // Verify reset completed.
        let sts = regs::read32(op_base as *const u8, regs::OP_USBSTS);
        if sts & regs::STS_CNR != 0 {
            return Err("xhci: controller not ready after reset");
        }

        // 5. Set CONFIG.MaxSlotsEn = max_slots.
        regs::write32(op_base, regs::OP_CONFIG, max_slots as u32);

        // 6. Set DCBAAP. Wire scratchpad buffers if needed.
        let dcbaa = dma.dcbaa_virt as *mut u64;
        // Zero the DCBAA (256 entries * 8 bytes = 2048, fits in 1 page).
        core::ptr::write_bytes(dcbaa, 0, 512); // 512 u64s = 4096 bytes

        if max_scratch > 0 {
            // DCBAA[0] points to the scratchpad buffer array.
            let scratch_arr = dma.scratch_arr_virt as *mut u64;
            let count = core::cmp::min(max_scratch as usize, 16);
            for i in 0..count {
                core::ptr::write_volatile(scratch_arr.add(i), dma.scratch_buf_phys[i]);
            }
            core::ptr::write_volatile(dcbaa, dma.scratch_arr_phys);
        }

        regs::write64(op_base, regs::OP_DCBAAP, dma.dcbaa_phys);

        // 7. Init Command Ring, set CRCR = phys | RCS.
        let cmd_ring = TrbRing::init(dma.cmd_ring_virt, dma.cmd_ring_phys);
        regs::write64(op_base, regs::OP_CRCR, dma.cmd_ring_phys | regs::CRCR_RCS);

        // 8. Init Event Ring + ERST, configure Interrupter 0.
        let evt_ring = EventRing::init(dma.evt_ring_virt, dma.evt_ring_phys);

        // Write ERST entry (1 segment).
        let erst = dma.erst_virt as *mut ErstEntry;
        core::ptr::write_volatile(erst, ErstEntry::new(dma.evt_ring_phys, trb::RING_SIZE as u32));

        let ir0_base = rt_base.add(regs::RT_IR0_BASE);
        // ERSTSZ = 1.
        regs::write32(ir0_base, regs::IR_ERSTSZ, 1);
        // ERDP = event ring physical base.
        regs::write64(ir0_base, regs::IR_ERDP, dma.evt_ring_phys);
        // ERSTBA = ERST physical address (must be written AFTER ERSTSZ).
        regs::write64(ir0_base, regs::IR_ERSTBA, dma.erst_phys);

        // 9. Enable interrupts: IMAN.IE=1, USBCMD.INTE=1.
        let iman = regs::read32(ir0_base as *const u8, regs::IR_IMAN);
        regs::write32(ir0_base, regs::IR_IMAN, iman | regs::IMAN_IE);

        let usbcmd = regs::read32(op_base as *const u8, regs::OP_USBCMD);
        regs::write32(op_base, regs::OP_USBCMD, usbcmd | regs::CMD_INTE);

        // 10. Run: set USBCMD.RS=1, wait for USBSTS.HCH=0.
        // TCG fix (run-full deadlock U1): yield every 256 iters.
        let usbcmd = regs::read32(op_base as *const u8, regs::OP_USBCMD);
        regs::write32(op_base, regs::OP_USBCMD, usbcmd | regs::CMD_RS);
        for i in 0..100_000_u32 {
            let sts_val = regs::read32(op_base as *const u8, regs::OP_USBSTS);
            if sts_val & regs::STS_HCH == 0 {
                break;
            }
            if (i & 0xFF) == 0 {
                wait();
            }
        }
        let sts_final = regs::read32(op_base as *const u8, regs::OP_USBSTS);
        if sts_final & regs::STS_HCH != 0 {
            return Err("xhci: controller failed to start (HCH still set)");
        }

        let ctrl = XhciController {
            mmio_base,
            op_base,
            db_base,
            rt_base,
            cmd_ring,
            evt_ring,
            max_ports,
            max_slots,
            devices: [None; MAX_DEVICES],
        };

        Ok((ctrl, XhciInitResult {
            version_major,
            version_minor,
            max_slots,
            max_ports,
        }))
    }

    /// Return Supported Protocol capabilities by re-reading the xECP list
    /// through this controller's cached MMIO base. Fills up to `out.len()`
    /// entries and returns the count written. Useful for userspace services
    /// that want to print USB2/USB3 port mapping after `init()` succeeds.
    pub fn supported_protocols(&self, out: &mut [SupportedProtocol]) -> usize {
        unsafe {
            let hcc1 = regs::read32(self.mmio_base as *const u8, regs::CAP_HCCPARAMS1);
            walk_supported_protocols(self.mmio_base, hcc1, out)
        }
    }

    /// Ring the command doorbell (doorbell register 0).
    pub unsafe fn ring_cmd_doorbell(&self) {
        regs::write32(self.db_base, 0, 0);
    }

    /// Ring an endpoint doorbell for the given slot and endpoint ID.
    pub unsafe fn ring_ep_doorbell(&self, slot: u8, ep_id: u8) {
        let offset = (slot as usize) * 4;
        regs::write32(self.db_base, offset, ep_id as u32);
    }

    /// Submit a command TRB and wait for a Command Completion Event.
    /// Skips non-command events (e.g. Port Status Change) that may be pending.
    ///
    /// TCG fix (run-full deadlock U1): cap from 10M -> 100K, yield every 256.
    /// Each MMIO read costs ~1000 host cycles on TCG; the old 10M iter loop
    /// took ~10s per command and starved init's main thread for ~13 minutes
    /// across 8 USB enumeration commands.
    pub unsafe fn submit_command(&mut self, trb: Trb, wait: WaitFn) -> Result<Trb, &'static str> {
        self.cmd_ring.enqueue(trb);
        self.ring_cmd_doorbell();

        // Poll event ring for completion, skipping non-command events.
        for i in 0..100_000_u32 {
            if let Some(evt) = self.evt_ring.poll() {
                self.evt_ring.advance();
                self.update_erdp();

                if evt.trb_type() == trb::TRB_CMD_COMPLETE {
                    return Ok(evt);
                }
                // Non-command event (e.g. Port Status Change) — skip and keep polling.
                continue;
            }
            if (i & 0xFF) == 0 {
                wait();
            }
        }
        Err("xhci: command timeout")
    }

    /// Drain all pending events from the event ring.
    /// Returns the number of events processed.
    pub unsafe fn drain_events(&mut self) -> usize {
        let mut count = 0;
        loop {
            match self.evt_ring.poll() {
                Some(_evt) => {
                    self.evt_ring.advance();
                    count += 1;
                }
                None => break,
            }
        }
        if count > 0 {
            self.update_erdp();
        }
        count
    }

    /// Update the ERDP register with the current dequeue pointer.
    unsafe fn update_erdp(&self) {
        let ir0_base = self.rt_base.add(regs::RT_IR0_BASE);
        // Write dequeue pointer, clear EHB bit (bit 3).
        let erdp_val = self.evt_ring.dequeue_phys() & !regs::ERDP_EHB;
        regs::write64(ir0_base, regs::IR_ERDP, erdp_val);
    }

    /// Read PORTSC for a 1-based port number.
    pub unsafe fn portsc(&self, port: u8) -> u32 {
        regs::read32(self.op_base as *const u8, regs::portsc_offset(port))
    }

    /// Write PORTSC for a 1-based port number.
    pub unsafe fn write_portsc(&self, port: u8, val: u32) {
        regs::write32(self.op_base, regs::portsc_offset(port), val);
    }

    /// Get the MMIO base pointer.
    pub fn mmio_base(&self) -> *mut u8 {
        self.mmio_base
    }

    /// Get the operational registers base pointer.
    pub fn op_base(&self) -> *mut u8 {
        self.op_base
    }

    /// Set DCBAA entry for a slot (1-based slot_id).
    pub unsafe fn set_dcbaa_entry(&self, dma: &XhciDma, slot_id: u8, ctx_phys: u64) {
        let dcbaa = dma.dcbaa_virt as *mut u64;
        core::ptr::write_volatile(dcbaa.add(slot_id as usize), ctx_phys);
    }

    /// Perform a control transfer with IN data stage on EP0.
    /// Enqueues Setup + Data + Status TRBs, rings doorbell, waits for Transfer Event.
    pub unsafe fn control_transfer_in(
        &mut self,
        slot_id: u8,
        ep0_ring: &mut TrbRing,
        setup_packet: u64,
        buf_phys: u64,
        length: u16,
        wait: WaitFn,
    ) -> Result<Trb, &'static str> {
        ep0_ring.enqueue(trb::trb_setup_stage(setup_packet, 3)); // TRT=3 (IN)
        ep0_ring.enqueue(trb::trb_data_stage(buf_phys, length, true));
        ep0_ring.enqueue(trb::trb_status_stage(false)); // Status OUT for IN data
        self.ring_ep_doorbell(slot_id, 1); // DCI 1 = EP0
        self.wait_transfer_event(wait)
    }

    /// Perform a control transfer with no data stage on EP0.
    pub unsafe fn control_transfer_no_data(
        &mut self,
        slot_id: u8,
        ep0_ring: &mut TrbRing,
        setup_packet: u64,
        wait: WaitFn,
    ) -> Result<Trb, &'static str> {
        ep0_ring.enqueue(trb::trb_setup_stage(setup_packet, 0)); // TRT=0 (No Data)
        ep0_ring.enqueue(trb::trb_status_stage(true)); // Status IN for no-data
        self.ring_ep_doorbell(slot_id, 1); // DCI 1 = EP0
        self.wait_transfer_event(wait)
    }

    /// Wait for a Transfer Event on the event ring.
    /// Skips Command Completion and Port Status events.
    ///
    /// TCG fix (run-full deadlock U1): cap from 10M -> 100K, yield every 256.
    pub unsafe fn wait_transfer_event(&mut self, wait: WaitFn) -> Result<Trb, &'static str> {
        for i in 0..100_000_u32 {
            if let Some(evt) = self.evt_ring.poll() {
                self.evt_ring.advance();
                self.update_erdp();

                if evt.trb_type() == trb::TRB_XFER_EVENT {
                    return Ok(evt);
                }
                // Skip non-transfer events.
                continue;
            }
            if (i & 0xFF) == 0 {
                wait();
            }
        }
        Err("xhci: transfer event timeout")
    }

    /// Poll for a single event (non-blocking). Returns None if no event pending.
    pub unsafe fn poll_event(&mut self) -> Option<Trb> {
        if let Some(evt) = self.evt_ring.poll() {
            self.evt_ring.advance();
            self.update_erdp();
            Some(evt)
        } else {
            None
        }
    }

    // ---------------------------------------------------------------
    // Multi-device management
    // ---------------------------------------------------------------

    /// Enumerate all connected ports, returning a bitmask of ports with devices.
    /// Does NOT perform reset or address assignment — use `init_device_on_port()`
    /// for each connected port to complete device setup.
    pub unsafe fn enumerate_ports(&self) -> u32 {
        let mut mask: u32 = 0;
        for p in 1..=self.max_ports {
            let portsc = self.portsc(p);
            if portsc & regs::PORTSC_CCS != 0 {
                mask |= 1 << p;
            }
        }
        mask
    }

    /// Allocate a device slot by submitting an Enable Slot command.
    /// Returns the allocated slot_id (1-based) on success.
    pub unsafe fn allocate_slot(&mut self, wait: WaitFn) -> Result<u8, &'static str> {
        let evt = self.submit_command(trb::cmd_enable_slot(), wait)?;
        let cc = evt.completion_code();
        if cc != trb::CC_SUCCESS {
            return Err("xhci: enable slot failed");
        }
        Ok(evt.slot_id())
    }

    /// Register a device in the internal tracking table.
    /// Returns the index into `devices[]` where it was stored.
    pub fn register_device(&mut self, dev: UsbDevice) -> Option<usize> {
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(dev);
                return Some(i);
            }
        }
        None
    }

    /// Remove a device from the tracking table by slot_id.
    /// Returns the removed device, if found.
    pub fn remove_device(&mut self, slot_id: u8) -> Option<UsbDevice> {
        for slot in self.devices.iter_mut() {
            if let Some(dev) = slot {
                if dev.slot_id == slot_id {
                    return slot.take();
                }
            }
        }
        None
    }

    /// Find a tracked device by slot_id.
    pub fn find_device(&self, slot_id: u8) -> Option<&UsbDevice> {
        for slot in &self.devices {
            if let Some(dev) = slot {
                if dev.slot_id == slot_id {
                    return Some(dev);
                }
            }
        }
        None
    }

    /// Find a tracked device by port number.
    pub fn find_device_on_port(&self, port: u8) -> Option<&UsbDevice> {
        for slot in &self.devices {
            if let Some(dev) = slot {
                if dev.port == port {
                    return Some(dev);
                }
            }
        }
        None
    }

    /// Get the number of currently tracked devices.
    pub fn device_count(&self) -> usize {
        self.devices.iter().filter(|s| s.is_some()).count()
    }

    // ---------------------------------------------------------------
    // Hot-plug handling
    // ---------------------------------------------------------------

    /// Handle a Port Status Change event.
    ///
    /// Detects connect and disconnect events:
    /// - **Connect**: Sets CSC, CCS=1 — caller should call `handle_port_connect()`
    /// - **Disconnect**: Sets CSC, CCS=0 — releases slot, cleans up device
    ///
    /// Returns the port number and whether a device was connected (true) or
    /// disconnected (false).
    pub unsafe fn handle_port_change(&mut self, port: u8) -> Option<(u8, bool)> {
        let portsc = self.portsc(port);

        // Clear the Connect Status Change bit (RW1C).
        if portsc & regs::PORTSC_CSC != 0 {
            let val = (portsc & !regs::PORTSC_RW1C_MASK) | regs::PORTSC_CSC;
            self.write_portsc(port, val);

            let connected = portsc & regs::PORTSC_CCS != 0;
            if !connected {
                // Device disconnected — clean up.
                self.handle_port_disconnect(port);
            }
            return Some((port, connected));
        }

        // Clear Port Reset Change if set.
        if portsc & regs::PORTSC_PRC != 0 {
            let val = (portsc & !regs::PORTSC_RW1C_MASK) | regs::PORTSC_PRC;
            self.write_portsc(port, val);
        }

        None
    }

    /// Handle device disconnection on a port.
    /// Releases the slot and removes the device from tracking.
    fn handle_port_disconnect(&mut self, port: u8) {
        // Find and remove the device on this port.
        let mut slot_id = 0u8;
        for slot in self.devices.iter_mut() {
            if let Some(dev) = slot {
                if dev.port == port {
                    slot_id = dev.slot_id;
                    *slot = None;
                    break;
                }
            }
        }
        // Note: The xHCI spec says the HC automatically disables the slot
        // when the port is disconnected. The host software should issue a
        // Disable Slot command, but for simplicity we just remove tracking.
        let _ = slot_id; // slot_id could be used for Disable Slot command
    }

    /// Process all pending Port Status Change events from the event ring.
    /// Returns a list of (port, connected) pairs for ports that changed state.
    pub unsafe fn process_port_events(&mut self) -> [(u8, bool); 16] {
        let mut results = [(0u8, false); 16];
        let mut count = 0;

        loop {
            match self.evt_ring.poll() {
                Some(evt) => {
                    self.evt_ring.advance();

                    if evt.trb_type() == trb::TRB_PORT_STATUS {
                        // Port ID is in bits 31:24 of the parameter (lower 32 bits).
                        let port_id = ((evt.param >> 24) & 0xFF) as u8;
                        if port_id > 0 && port_id <= self.max_ports {
                            if let Some(result) = self.handle_port_change(port_id) {
                                if count < 16 {
                                    results[count] = result;
                                    count += 1;
                                }
                            }
                        }
                    }
                    // Skip non-port-status events.
                }
                None => break,
            }
        }
        if count > 0 {
            self.update_erdp();
        }
        results
    }
}
