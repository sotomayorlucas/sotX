//! sotOS xHCI USB Host Controller Service Process
//!
//! Drives an xHCI USB 3.x controller via MMIO (BAR0 pre-mapped by kernel).
//! Implements HID boot protocol keyboard support — converts USB HID reports
//! to PS/2 scancodes and writes them to the shared KB ring buffer.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::KB_RING_ADDR;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};
use sotos_pci::PciBus;
use sotos_xhci::controller::{XhciController, XhciDma};
use sotos_xhci::{trb, port, usb, hid, regs};

const CAP_PCI: usize = 0;
const CAP_IRQ: usize = 1;
const CAP_NOTIFY: usize = 2;

const PCI_CLASS_SERIAL: u8 = 0x0C;
const PCI_SUBCLASS_USB: u8 = 0x03;
const PCI_PROGIF_XHCI: u8 = 0x30;

// Address space layout.
const MMIO_BASE: u64 = 0xC00000;
const DCBAA_VADDR: u64 = 0xD00000;
const CMD_RING_VADDR: u64 = 0xD01000;
const EVT_RING_VADDR: u64 = 0xD02000;
const ERST_VADDR: u64 = 0xD03000;
const SCRATCH_ARR_VADDR: u64 = 0xD04000;
const SCRATCH_BUF_BASE: u64 = 0xD05000;
const INPUT_CTX_VADDR: u64 = 0xD20000;
const DEVICE_CTX_VADDR: u64 = 0xD21000;
const EP0_RING_VADDR: u64 = 0xD22000;
const INT_RING_VADDR: u64 = 0xD23000;  // Interrupt IN transfer ring
const DATA_BUF_VADDR: u64 = 0xD30000;  // Data buffer page 0 (descriptors / control xfers)
const INT_BUF_VADDR: u64 = 0xD31000;   // Interrupt IN data buffer (HID reports)

const SCRATCH_BUF_PAGES: usize = 16;
// KB_RING_ADDR imported from sotos_common

fn print(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

fn print_u64(mut n: u64) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

fn print_u32(n: u32) { print_u64(n as u64); }

fn print_hex32(val: u32) {
    let hex = b"0123456789abcdef";
    print(b"0x");
    for i in (0..8).rev() {
        sys::debug_print(hex[((val >> (i * 4)) & 0xF) as usize]);
    }
}

fn xhci_wait() {
    sys::yield_now();
}

fn alloc_and_map(vaddr: u64, flags: u64) -> u64 {
    let frame_cap = sys::frame_alloc().expect("xhci: frame_alloc failed");
    let phys = sys::frame_phys(frame_cap).expect("xhci: frame_phys failed");
    sys::map(vaddr, frame_cap, flags).expect("xhci: map failed");
    unsafe { core::ptr::write_bytes(vaddr as *mut u8, 0, 4096); }
    phys
}

/// Write a PS/2 scancode byte to the shared KB ring buffer.
unsafe fn kb_ring_write(scancode: u8) {
    let ring = KB_RING_ADDR as *mut u32;
    let write_idx = core::ptr::read_volatile(ring);
    let idx = (write_idx & 0xFF) as usize;
    *((KB_RING_ADDR + 8 + idx as u64) as *mut u8) = scancode;
    core::ptr::write_volatile(ring, (write_idx.wrapping_add(1)) & 0xFF);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    print(b"xhci: starting xHCI USB service\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if boot_info.magic != sotos_common::BOOT_INFO_MAGIC {
        print(b"xhci: bad BootInfo magic\n");
        loop { sys::yield_now(); }
    }

    let pci_cap = boot_info.caps[CAP_PCI];
    let irq_cap = boot_info.caps[CAP_IRQ];
    let notify_cap = boot_info.caps[CAP_NOTIFY];

    sys::irq_register(irq_cap, notify_cap).expect("xhci: irq_register failed");

    let pci = PciBus::new(pci_cap);
    let (devs, count) = pci.enumerate::<32>();
    let mut xhci_dev = None;
    for i in 0..count {
        if devs[i].class == PCI_CLASS_SERIAL
            && devs[i].subclass == PCI_SUBCLASS_USB
            && devs[i].prog_if == PCI_PROGIF_XHCI
        {
            xhci_dev = Some(devs[i]);
            break;
        }
    }

    let dev = match xhci_dev {
        Some(d) => d,
        None => {
            print(b"xhci: no xHCI device found\n");
            loop { sys::yield_now(); }
        }
    };

    print(b"xhci: found xHCI at PCI ");
    print_u32(dev.addr.bus as u32);
    sys::debug_print(b':');
    print_u32(dev.addr.dev as u32);
    sys::debug_print(b'.');
    print_u32(dev.addr.func as u32);
    sys::debug_print(b'\n');

    pci.enable_bus_master(dev.addr);
    pci.enable_memory_space(dev.addr);

    // Allocate DMA pages.
    let map_flags: u64 = 0x7;
    let dcbaa_phys = alloc_and_map(DCBAA_VADDR, map_flags);
    let cmd_ring_phys = alloc_and_map(CMD_RING_VADDR, map_flags);
    let evt_ring_phys = alloc_and_map(EVT_RING_VADDR, map_flags);
    let erst_phys = alloc_and_map(ERST_VADDR, map_flags);
    let scratch_arr_phys = alloc_and_map(SCRATCH_ARR_VADDR, map_flags);
    let mut scratch_buf_phys = [0u64; 16];
    for i in 0..SCRATCH_BUF_PAGES {
        scratch_buf_phys[i] = alloc_and_map(SCRATCH_BUF_BASE + (i as u64) * 0x1000, map_flags);
    }
    let input_ctx_phys = alloc_and_map(INPUT_CTX_VADDR, map_flags);
    let device_ctx_phys = alloc_and_map(DEVICE_CTX_VADDR, map_flags);
    let ep0_ring_phys = alloc_and_map(EP0_RING_VADDR, map_flags);
    let int_ring_phys = alloc_and_map(INT_RING_VADDR, map_flags);
    let data_buf_phys = alloc_and_map(DATA_BUF_VADDR, map_flags);
    let int_buf_phys = alloc_and_map(INT_BUF_VADDR, map_flags);

    let dma = XhciDma {
        dcbaa_virt: DCBAA_VADDR as *mut u8,
        dcbaa_phys,
        cmd_ring_virt: CMD_RING_VADDR as *mut u8,
        cmd_ring_phys,
        evt_ring_virt: EVT_RING_VADDR as *mut u8,
        evt_ring_phys,
        erst_virt: ERST_VADDR as *mut u8,
        erst_phys,
        scratch_arr_virt: SCRATCH_ARR_VADDR as *mut u8,
        scratch_arr_phys,
        scratch_buf_phys,
        input_ctx_virt: INPUT_CTX_VADDR as *mut u8,
        input_ctx_phys,
        device_ctx_virt: DEVICE_CTX_VADDR as *mut u8,
        device_ctx_phys,
        ep0_ring_virt: EP0_RING_VADDR as *mut u8,
        ep0_ring_phys,
        data_buf_virt: DATA_BUF_VADDR as *mut u8,
        data_buf_phys,
    };

    // Initialize controller.
    let (mut ctrl, info) = match unsafe { XhciController::init(MMIO_BASE as *mut u8, &dma, xhci_wait) } {
        Ok(r) => r,
        Err(msg) => {
            print(b"xhci: init failed: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
            loop { sys::yield_now(); }
        }
    };

    print(b"xhci: controller v");
    print_u32(info.version_major as u32);
    sys::debug_print(b'.');
    print_u32(info.version_minor as u32);
    print(b" max_slots=");
    print_u32(info.max_slots as u32);
    print(b" max_ports=");
    print_u32(info.max_ports as u32);
    sys::debug_print(b'\n');

    // --- No Op self-test ---
    let noop = trb::cmd_no_op();
    match unsafe { ctrl.submit_command(noop, xhci_wait) } {
        Ok(evt) if evt.completion_code() == trb::CC_SUCCESS => {
            print(b"xhci: No Op VERIFIED\n");
        }
        Ok(evt) => {
            print(b"xhci: No Op code=");
            print_u32(evt.completion_code() as u32);
            sys::debug_print(b'\n');
        }
        Err(msg) => {
            print(b"xhci: No Op failed: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
        }
    }

    // --- Find connected port ---
    let connected = unsafe { port::connected_ports(&ctrl) };
    let mut first_port: u8 = 0;
    for p in 1..=ctrl.max_ports {
        if connected & (1 << p) != 0 {
            first_port = p;
            break;
        }
    }
    if first_port == 0 {
        print(b"xhci: no connected ports\n");
        loop { sys::yield_now(); }
    }

    // Read port speed.
    let portsc = unsafe { ctrl.portsc(first_port) };
    let speed = regs::portsc_speed(portsc);
    print(b"xhci: port ");
    print_u32(first_port as u32);
    print(b" speed=");
    print_u32(speed as u32);
    sys::debug_print(b'\n');

    // --- Port reset ---
    unsafe { port::reset_port(&ctrl, first_port); }
    if !unsafe { port::wait_port_reset(&ctrl, first_port, xhci_wait) } {
        print(b"xhci: port reset timeout\n");
        loop { sys::yield_now(); }
    }
    // Re-read speed after reset (may change).
    let portsc = unsafe { ctrl.portsc(first_port) };
    let speed = regs::portsc_speed(portsc);

    // --- Enable Slot ---
    let slot_id = match unsafe { ctrl.submit_command(trb::cmd_enable_slot(), xhci_wait) } {
        Ok(evt) if evt.completion_code() == trb::CC_SUCCESS && evt.slot_id() > 0 => {
            let sid = evt.slot_id();
            print(b"xhci: slot ");
            print_u32(sid as u32);
            print(b" enabled\n");
            sid
        }
        _ => {
            print(b"xhci: Enable Slot failed\n");
            loop { sys::yield_now(); }
        }
    };

    // --- Address Device ---
    unsafe { ctrl.set_dcbaa_entry(&dma, slot_id, device_ctx_phys); }
    let mut ep0_ring = unsafe { trb::TrbRing::init(EP0_RING_VADDR as *mut u8, ep0_ring_phys) };

    unsafe {
        core::ptr::write_bytes(INPUT_CTX_VADDR as *mut u8, 0, 4096);
        port::build_input_context(INPUT_CTX_VADDR as *mut u8, first_port, ep0_ring_phys, speed);
    }

    let addr_cmd = trb::cmd_address_device(input_ctx_phys, slot_id, false);
    match unsafe { ctrl.submit_command(addr_cmd, xhci_wait) } {
        Ok(evt) if evt.completion_code() == trb::CC_SUCCESS => {
            print(b"xhci: device addressed\n");
        }
        Ok(evt) => {
            print(b"xhci: Address Device failed, code=");
            print_u32(evt.completion_code() as u32);
            sys::debug_print(b'\n');
            loop { sys::yield_now(); }
        }
        Err(msg) => {
            print(b"xhci: Address Device error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
            loop { sys::yield_now(); }
        }
    }

    // --- GET_DESCRIPTOR(Device) ---
    let setup = usb::get_device_descriptor();
    match unsafe { ctrl.control_transfer_in(slot_id, &mut ep0_ring, setup, data_buf_phys, 18, xhci_wait) } {
        Ok(evt) if evt.completion_code() == trb::CC_SUCCESS => {
            print(b"xhci: device descriptor ok\n");
        }
        Ok(evt) => {
            print(b"xhci: GET_DESCRIPTOR(dev) code=");
            print_u32(evt.completion_code() as u32);
            sys::debug_print(b'\n');
        }
        Err(msg) => {
            print(b"xhci: GET_DESCRIPTOR(dev) error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
        }
    }

    // --- GET_DESCRIPTOR(Configuration) — first 9 bytes to get wTotalLength ---
    let setup = usb::get_config_descriptor(64);
    match unsafe { ctrl.control_transfer_in(slot_id, &mut ep0_ring, setup, data_buf_phys, 64, xhci_wait) } {
        Ok(evt) if evt.completion_code() == trb::CC_SUCCESS || evt.completion_code() == 13 => {
            // code 13 = Short Packet — that's OK for descriptors
            print(b"xhci: config descriptor ok\n");
        }
        Ok(evt) => {
            print(b"xhci: GET_DESCRIPTOR(cfg) code=");
            print_u32(evt.completion_code() as u32);
            sys::debug_print(b'\n');
        }
        Err(msg) => {
            print(b"xhci: GET_DESCRIPTOR(cfg) error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
        }
    }

    // Parse config descriptor to find HID keyboard.
    let cfg_buf = unsafe { core::slice::from_raw_parts(DATA_BUF_VADDR as *const u8, 64) };
    let hid_info = match usb::parse_config_for_hid_kbd(cfg_buf) {
        Some(info) => {
            print(b"xhci: HID kbd found: iface=");
            print_u32(info.interface_num as u32);
            print(b" ep=");
            print_hex32(info.ep_addr as u32);
            print(b" maxpkt=");
            print_u32(info.max_packet as u32);
            print(b" interval=");
            print_u32(info.interval as u32);
            sys::debug_print(b'\n');
            info
        }
        None => {
            print(b"xhci: no HID keyboard in config descriptor\n");
            loop { sys::yield_now(); }
        }
    };

    let ep_dci = usb::ep_addr_to_dci(hid_info.ep_addr);
    let xhci_interval = usb::convert_interval(hid_info.interval, speed);

    // --- Configure Endpoint ---
    // Initialize the interrupt IN transfer ring.
    let mut int_ring = unsafe { trb::TrbRing::init(INT_RING_VADDR as *mut u8, int_ring_phys) };

    // Build Configure Endpoint input context.
    unsafe {
        core::ptr::write_bytes(INPUT_CTX_VADDR as *mut u8, 0, 4096);
        port::build_configure_ep_input(
            INPUT_CTX_VADDR as *mut u8,
            ep_dci,
            int_ring_phys,
            hid_info.max_packet,
            xhci_interval,
            speed,
        );
    }

    let cfg_cmd = trb::cmd_configure_endpoint(input_ctx_phys, slot_id);
    match unsafe { ctrl.submit_command(cfg_cmd, xhci_wait) } {
        Ok(evt) if evt.completion_code() == trb::CC_SUCCESS => {
            print(b"xhci: endpoint configured (DCI=");
            print_u32(ep_dci as u32);
            print(b")\n");
        }
        Ok(evt) => {
            print(b"xhci: Configure Endpoint code=");
            print_u32(evt.completion_code() as u32);
            sys::debug_print(b'\n');
            loop { sys::yield_now(); }
        }
        Err(msg) => {
            print(b"xhci: Configure Endpoint error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
            loop { sys::yield_now(); }
        }
    }

    // --- SET_CONFIGURATION ---
    let setup = usb::set_configuration(hid_info.config_value);
    match unsafe { ctrl.control_transfer_no_data(slot_id, &mut ep0_ring, setup, xhci_wait) } {
        Ok(_) => print(b"xhci: SET_CONFIGURATION ok\n"),
        Err(msg) => {
            print(b"xhci: SET_CONFIGURATION error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
        }
    }

    // --- SET_PROTOCOL (boot protocol = 0) ---
    let setup = usb::set_protocol(0, hid_info.interface_num as u16);
    match unsafe { ctrl.control_transfer_no_data(slot_id, &mut ep0_ring, setup, xhci_wait) } {
        Ok(_) => print(b"xhci: SET_PROTOCOL(boot) ok\n"),
        Err(msg) => {
            print(b"xhci: SET_PROTOCOL error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
        }
    }

    // --- SET_IDLE(0) ---
    let setup = usb::set_idle(hid_info.interface_num as u16);
    match unsafe { ctrl.control_transfer_no_data(slot_id, &mut ep0_ring, setup, xhci_wait) } {
        Ok(_) => print(b"xhci: SET_IDLE ok\n"),
        Err(msg) => {
            // SET_IDLE may be stalled by some devices — not fatal.
            print(b"xhci: SET_IDLE: ");
            print(msg.as_bytes());
            print(b" (non-fatal)\n");
        }
    }

    // --- Post initial interrupt IN transfers ---
    // Post several Normal TRBs to keep the HC busy.
    let report_size = core::cmp::min(hid_info.max_packet, 8) as u16;
    for i in 0..4u64 {
        let buf = int_buf_phys + i * 64; // use different 64-byte offsets within the page
        unsafe { int_ring.enqueue(trb::trb_normal(buf, report_size)); }
    }
    // Ring the interrupt endpoint doorbell.
    unsafe { ctrl.ring_ep_doorbell(slot_id, ep_dci); }

    print(b"xhci: HID keyboard ready, entering event loop\n");

    // --- Event loop ---
    let mut prev_report = hid::BootReport::empty();
    let mut pending_trbs: u32 = 4;

    loop {
        sys::notify_wait(notify_cap);

        // Drain all events.
        loop {
            let evt = unsafe { ctrl.poll_event() };
            let evt = match evt {
                Some(e) => e,
                None => break,
            };

            if evt.trb_type() == trb::TRB_XFER_EVENT && evt.endpoint_id() == ep_dci {
                if evt.completion_code() == trb::CC_SUCCESS || evt.completion_code() == 13 {
                    // Determine which buffer this TRB pointed to.
                    // TRB param = physical address of the original TRB.
                    // We use a rotating buffer within the interrupt buffer page.
                    // For simplicity, always read from the base of int_buf.
                    // The HC writes the report into the buffer specified in the Normal TRB.
                    // Our TRBs point to int_buf_phys + (idx * 64).
                    // The TRB pointer in param tells us which TRB completed.
                    // Calculate which buffer offset this corresponds to.
                    let buf_idx = if pending_trbs > 0 { pending_trbs - 1 } else { 0 };
                    let _ = buf_idx; // We just read the rotating buffer
                    // Since we post TRBs with increasing offsets (0, 64, 128, 192),
                    // we can figure out the buffer from the TRB pointer.
                    // But for simplicity, we track pending_trbs as a counter.
                    // Each completed TRB means one report is available.
                    // The report is at the buffer address we gave to the TRB.
                    // Since the TRB param (in Transfer Event) = phys addr of the TRB itself,
                    // not the data buffer... we need another approach.
                    //
                    // Simplest: just use a single rotating index.
                    // We posted TRBs 0..3 with buffers at offsets 0, 64, 128, 192.
                    // After processing, re-post one more.
                    pending_trbs = pending_trbs.saturating_sub(1);

                    // Read the most recently written report from the first buffer slot.
                    // Since QEMU processes TRBs in order, the first one completes first.
                    // We use a simple rotating read pointer.
                    let read_offset = (3 - pending_trbs) as u64 * 64;
                    let report_buf = unsafe {
                        core::slice::from_raw_parts(
                            (INT_BUF_VADDR + read_offset) as *const u8,
                            8,
                        )
                    };
                    let curr_report = hid::BootReport::from_bytes(report_buf);

                    // Convert HID report to PS/2 scancodes.
                    hid::process_report(&prev_report, &curr_report, &mut |scancode| {
                        unsafe { kb_ring_write(scancode); }
                    });

                    prev_report = curr_report;

                    // Re-post a Normal TRB for the next report.
                    let next_buf = int_buf_phys + ((3 - pending_trbs) as u64 % 4) * 64;
                    unsafe { int_ring.enqueue(trb::trb_normal(next_buf, report_size)); }
                    unsafe { ctrl.ring_ep_doorbell(slot_id, ep_dci); }
                    pending_trbs += 1;
                }
            }
            // Ignore other event types (port status, etc.)
        }

        let _ = sys::irq_ack(irq_cap);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"xhci: PANIC: ");
    if let Some(msg) = info.message().as_str() {
        print(msg.as_bytes());
    }
    sys::debug_print(b'\n');
    loop { sys::yield_now(); }
}
