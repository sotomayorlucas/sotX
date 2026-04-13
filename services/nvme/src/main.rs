//! sotX NVMe Service Process
//!
//! Runs as a separate process with its own address space.
//! Drives an NVMe SSD via MMIO (BAR0 pre-mapped by kernel at 0xC00000).

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR, IpcMsg};
use sotos_pci::PciBus;
use sotos_nvme::controller::{NvmeController, DmaPages};

/// Root capability indices (must match kernel write_nvme_boot_info() order).
const CAP_PCI: usize = 0; // I/O port 0xCF8-0xCFF (PCI config)

/// NVMe class code.
const PCI_CLASS_STORAGE: u8 = 0x01;
/// NVMe subclass.
const PCI_SUBCLASS_NVME: u8 = 0x08;

// --- Address space layout (pre-mapped by kernel) ---
const MMIO_BASE: u64 = 0xC00000;      // BAR0 MMIO (16 pages, UC)
const ADMIN_SQ_VADDR: u64 = 0xD00000; // Admin SQ (1 page)
const ADMIN_CQ_VADDR: u64 = 0xD01000; // Admin CQ (1 page)
const IO_SQ_VADDR: u64 = 0xD02000;    // I/O SQ (1 page)
const IO_CQ_VADDR: u64 = 0xD03000;    // I/O CQ (1 page)
const IDENTIFY_VADDR: u64 = 0xD04000; // Identify buffer (1 page)
const DMA_BUF_VADDR: u64 = 0xD10000;  // DMA data buffer (16 pages = 64KB)

/// Number of DMA data buffer pages (64 KiB).
const DMA_DATA_PAGES: u64 = 16;

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

/// Yield-based wait function (avoids TCG spin deadlock).
fn nvme_wait() {
    sys::yield_now();
}

/// Allocate a page, get its physical address, and map it at `vaddr`.
/// Returns the physical address.
fn alloc_and_map(vaddr: u64, flags: u64) -> u64 {
    let frame_cap = sys::frame_alloc().expect("nvme: frame_alloc failed");
    let phys = sys::frame_phys(frame_cap).expect("nvme: frame_phys failed");
    sys::map(vaddr, frame_cap, flags).expect("nvme: map failed");
    // Zero the page.
    unsafe { core::ptr::write_bytes(vaddr as *mut u8, 0, 4096); }
    phys
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    print(b"nvme: starting NVMe service\n");

    // Read BootInfo.
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if boot_info.magic != sotos_common::BOOT_INFO_MAGIC {
        print(b"nvme: bad BootInfo magic\n");
        loop { sys::yield_now(); }
    }

    let pci_cap = boot_info.caps[CAP_PCI];
    let pci = PciBus::new(pci_cap);

    // Find NVMe device (class 0x01, subclass 0x08).
    let (devs, count) = pci.enumerate::<32>();
    let mut nvme_dev = None;
    for i in 0..count {
        if devs[i].class == PCI_CLASS_STORAGE && devs[i].subclass == PCI_SUBCLASS_NVME {
            nvme_dev = Some(devs[i]);
            break;
        }
    }

    let dev = match nvme_dev {
        Some(d) => d,
        None => {
            print(b"nvme: no NVMe device found on PCI bus\n");
            loop { sys::yield_now(); }
        }
    };

    print(b"nvme: found NVMe at PCI ");
    print_u32(dev.addr.bus as u32);
    sys::debug_print(b':');
    print_u32(dev.addr.dev as u32);
    sys::debug_print(b'.');
    print_u32(dev.addr.func as u32);
    print(b" vendor=");
    print_hex32(dev.vendor_id as u32);
    print(b" device=");
    print_hex32(dev.device_id as u32);
    print(b" irq=");
    print_u32(dev.irq_line as u32);
    sys::debug_print(b'\n');

    // Enable bus mastering + memory space access.
    pci.enable_bus_master(dev.addr);
    pci.enable_memory_space(dev.addr);

    // Allocate DMA pages for queues + identify buffer.
    // MAP flags: present + writable + user (0x7).
    let map_flags: u64 = 0x7;
    let admin_sq_phys = alloc_and_map(ADMIN_SQ_VADDR, map_flags);
    let admin_cq_phys = alloc_and_map(ADMIN_CQ_VADDR, map_flags);
    let io_sq_phys = alloc_and_map(IO_SQ_VADDR, map_flags);
    let io_cq_phys = alloc_and_map(IO_CQ_VADDR, map_flags);
    let identify_phys = alloc_and_map(IDENTIFY_VADDR, map_flags);

    // Allocate DMA data buffer pages.
    let mut dma_buf_phys: [u64; 16] = [0; 16];
    for i in 0..DMA_DATA_PAGES as usize {
        dma_buf_phys[i] = alloc_and_map(DMA_BUF_VADDR + (i as u64) * 0x1000, map_flags);
    }

    print(b"nvme: DMA pages allocated\n");

    // MMIO base is pre-mapped at 0xC00000 by kernel (UC flags).
    let mmio_base = MMIO_BASE as *mut u8;

    let dma = DmaPages {
        admin_sq_virt: ADMIN_SQ_VADDR as *mut u8,
        admin_sq_phys,
        admin_cq_virt: ADMIN_CQ_VADDR as *mut u8,
        admin_cq_phys,
        io_sq_virt: IO_SQ_VADDR as *mut u8,
        io_sq_phys,
        io_cq_virt: IO_CQ_VADDR as *mut u8,
        io_cq_phys,
        identify_virt: IDENTIFY_VADDR as *mut u8,
        identify_phys,
    };

    // Initialize controller.
    let (mut ctrl, info) = match unsafe { NvmeController::init(mmio_base, &dma, nvme_wait) } {
        Ok(r) => r,
        Err(msg) => {
            print(b"nvme: init failed: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
            loop { sys::yield_now(); }
        }
    };

    print(b"nvme: controller v");
    print_u32(info.version_major as u32);
    sys::debug_print(b'.');
    print_u32(info.version_minor as u32);
    print(b" ns_size=");
    print_u64(info.ns_size);
    print(b" lba_size=");
    print_u32(info.lba_size);
    sys::debug_print(b'\n');

    // --- Self-test: read sector 0, check for marker ---
    print(b"nvme: reading sector 0...\n");
    match ctrl.read_sectors(0, 1, dma_buf_phys[0], nvme_wait) {
        Ok(()) => {
            let buf = unsafe { core::slice::from_raw_parts(DMA_BUF_VADDR as *const u8, 512) };
            let marker = b"NVME DISK TEST";
            let mut found = true;
            for i in 0..marker.len() {
                if buf[i] != marker[i] {
                    found = false;
                    break;
                }
            }
            if found {
                print(b"nvme: sector 0 marker VERIFIED: \"NVME DISK TEST\"\n");
            } else {
                print(b"nvme: sector 0 read ok, but no marker (first 16 bytes: ");
                for i in 0..16 {
                    let hex = b"0123456789abcdef";
                    sys::debug_print(hex[(buf[i] >> 4) as usize]);
                    sys::debug_print(hex[(buf[i] & 0xF) as usize]);
                    sys::debug_print(b' ');
                }
                print(b")\n");
            }
        }
        Err(msg) => {
            print(b"nvme: read sector 0 failed: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
        }
    }

    // --- Self-test: write sector 1 and read back ---
    print(b"nvme: write/read test on sector 1...\n");
    {
        // Write a test pattern to sector 1.
        let write_buf = unsafe { core::slice::from_raw_parts_mut(DMA_BUF_VADDR as *mut u8, 512) };
        for i in 0..512 {
            write_buf[i] = (i & 0xFF) as u8;
        }
        // Overwrite first bytes with our marker.
        let test_marker = b"NVME WRITE TEST";
        write_buf[..test_marker.len()].copy_from_slice(test_marker);

        match ctrl.write_sectors(1, 1, dma_buf_phys[0], nvme_wait) {
            Ok(()) => {
                print(b"nvme: sector 1 write ok\n");
            }
            Err(msg) => {
                print(b"nvme: write sector 1 failed: ");
                print(msg.as_bytes());
                sys::debug_print(b'\n');
            }
        }

        // Clear buffer and read back.
        for i in 0..512 { write_buf[i] = 0; }

        match ctrl.read_sectors(1, 1, dma_buf_phys[0], nvme_wait) {
            Ok(()) => {
                let buf = unsafe { core::slice::from_raw_parts(DMA_BUF_VADDR as *const u8, 512) };
                let test_marker = b"NVME WRITE TEST";
                let mut ok = true;
                for i in 0..test_marker.len() {
                    if buf[i] != test_marker[i] {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    print(b"nvme: sector 1 round-trip VERIFIED\n");
                } else {
                    print(b"nvme: sector 1 read-back MISMATCH\n");
                }
            }
            Err(msg) => {
                print(b"nvme: read sector 1 failed: ");
                print(msg.as_bytes());
                sys::debug_print(b'\n');
            }
        }
    }

    print(b"nvme: self-test complete\n");

    // --- Register as IPC service ---
    let ep_cap = match sys::endpoint_create() {
        Ok(cap) => cap,
        Err(_) => {
            print(b"nvme: endpoint_create failed\n");
            loop { sys::yield_now(); }
        }
    };

    let svc_name = b"nvme";
    match sys::svc_register(svc_name.as_ptr() as u64, svc_name.len() as u64, ep_cap) {
        Ok(()) => print(b"nvme: registered as 'nvme' service\n"),
        Err(_) => print(b"nvme: svc_register failed\n"),
    }

    // IPC service loop: handle block I/O requests.
    // Protocol:
    //   tag=1 (READ):  regs[0]=lba, regs[1]=count → regs[0]=status, data at shared page
    //   tag=2 (WRITE): regs[0]=lba, regs[1]=count, data at shared page → regs[0]=status
    //   tag=3 (INFO):  → regs[0]=ns_size_lo, regs[1]=ns_size_hi, regs[2]=lba_size
    const IPC_READ: u64 = 1;
    const IPC_WRITE: u64 = 2;
    const IPC_INFO: u64 = 3;

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let mut reply = IpcMsg::empty();

        match msg.tag {
            IPC_READ => {
                let lba = msg.regs[0];
                let count = msg.regs[1] as u16;
                let count = if count == 0 { 1 } else { count.min(8) }; // max 8 sectors
                let result = ctrl.read_sectors(lba, count, dma_buf_phys[0], nvme_wait);
                reply.tag = 0;
                reply.regs[0] = if result.is_ok() { 0 } else { 1 };
            }
            IPC_WRITE => {
                let lba = msg.regs[0];
                let count = msg.regs[1] as u16;
                let count = if count == 0 { 1 } else { count.min(8) };
                let result = ctrl.write_sectors(lba, count, dma_buf_phys[0], nvme_wait);
                reply.tag = 0;
                reply.regs[0] = if result.is_ok() { 0 } else { 1 };
            }
            IPC_INFO => {
                reply.tag = 0;
                reply.regs[0] = ctrl.ns_size & 0xFFFFFFFF;
                reply.regs[1] = ctrl.ns_size >> 32;
                reply.regs[2] = ctrl.lba_size as u64;
            }
            _ => {
                reply.tag = u64::MAX;
            }
        }

        let _ = sys::send(ep_cap, &reply);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"nvme: PANIC: ");
    if let Some(msg) = info.message().as_str() {
        print(msg.as_bytes());
    }
    sys::debug_print(b'\n');
    loop { sys::yield_now(); }
}
