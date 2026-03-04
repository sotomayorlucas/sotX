//! Virtio-BLK device driver (legacy transport v0.9.5).
//!
//! Talks to the device via BAR0 I/O ports. Uses a single virtqueue
//! (queue 0) for all block requests.

use sotos_common::sys;
use sotos_pci::{PciBus, PciDevice};
use crate::virtqueue::Virtqueue;

/// Legacy virtio register offsets (I/O port).
const VIRTIO_DEVICE_FEATURES: u64 = 0x00;
const VIRTIO_GUEST_FEATURES: u64 = 0x04;
const VIRTIO_QUEUE_ADDRESS: u64 = 0x08;
const VIRTIO_QUEUE_SIZE: u64 = 0x0C;
const VIRTIO_QUEUE_SELECT: u64 = 0x0E;
const VIRTIO_QUEUE_NOTIFY: u64 = 0x10;
const VIRTIO_DEVICE_STATUS: u64 = 0x12;
const VIRTIO_ISR_STATUS: u64 = 0x13;
const VIRTIO_BLK_CAPACITY: u64 = 0x14; // u64 at offset 0x14 (device-specific config)

/// Device status bits.
const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;

/// Virtio-blk request types.
const VIRTIO_BLK_T_IN: u32 = 0;  // Read
const VIRTIO_BLK_T_OUT: u32 = 1; // Write

/// Virtio-blk request header (16 bytes).
#[repr(C)]
struct VirtioBlkReqHeader {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

/// Virtual address layout for driver memory.
const VQ_VADDR: u64 = 0xC00000;     // Virtqueue pages (up to 3 pages for queue_size=256)
const HDR_VADDR: u64 = 0xC03000;    // Request header page
const STATUS_VADDR: u64 = 0xC04000; // Status byte page
const DATA_VADDR: u64 = 0xC05000;   // Data buffer page

/// Virtio-BLK device driver.
pub struct VirtioBlk {
    /// I/O port cap for BAR0.
    bar_cap: u64,
    /// BAR0 base I/O port.
    bar_base: u64,
    /// IRQ cap for ACK.
    irq_cap: u64,
    /// Notification cap for IRQ wait.
    notify_cap: u64,
    /// The virtqueue.
    vq: Virtqueue,
    /// Physical addresses for DMA.
    hdr_phys: u64,
    status_phys: u64,
    data_phys: u64,
    /// Disk capacity in sectors.
    pub capacity: u64,
}

fn dbg(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

fn dbg_hex(mut val: u64) {
    let hex = b"0123456789ABCDEF";
    dbg(b"0x");
    if val == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while val > 0 {
        buf[i] = hex[(val & 0xF) as usize];
        val >>= 4;
        i += 1;
    }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

fn dbg_u64(mut n: u64) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

impl VirtioBlk {
    /// Initialize the virtio-blk device.
    ///
    /// Performs full legacy device init: reset → ack → driver → features →
    /// virtqueue setup → driver_ok.
    pub fn init(pci_dev: &PciDevice, pci_bus: &PciBus) -> Result<Self, &'static str> {
        // 1. Read BAR0 (I/O port space).
        let bar0_raw = pci_bus.bar0(pci_dev.addr);
        if bar0_raw & 1 == 0 {
            return Err("BAR0 is MMIO, expected I/O port");
        }
        let bar_base = (bar0_raw & 0xFFFFFFFC) as u64;
        dbg(b"  BLK: bar_base="); dbg_hex(bar_base); dbg(b"\n");

        // 2. Enable bus mastering.
        pci_bus.enable_bus_master(pci_dev.addr);

        // 3. Create I/O port cap for BAR0 range (32 ports covers all legacy registers + config).
        let bar_cap = sys::ioport_create(bar_base as u16, 32)
            .map_err(|_| "ioport_create failed")?;

        // 4. Create IRQ cap + notification for interrupt-driven completion.
        let irq_cap = sys::irq_create(pci_dev.irq_line as u64)
            .map_err(|_| "irq_create failed")?;
        let notify_cap = sys::notify_create()
            .map_err(|_| "notify_create failed")?;
        sys::irq_register(irq_cap, notify_cap)
            .map_err(|_| "irq_register failed")?;

        // 5. Reset device.
        let _ = sys::port_out(bar_cap, bar_base + VIRTIO_DEVICE_STATUS, 0);

        // 6. Set ACKNOWLEDGE.
        let _ = sys::port_out(bar_cap, bar_base + VIRTIO_DEVICE_STATUS, STATUS_ACK);

        // 7. Set DRIVER.
        let _ = sys::port_out(bar_cap, bar_base + VIRTIO_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);

        // 8. Read device features.
        let _features = sys::port_in32(bar_cap, bar_base + VIRTIO_DEVICE_FEATURES).unwrap_or(0);

        // 9. Set guest features = 0 (no features requested).
        let _ = sys::port_out32(bar_cap, bar_base + VIRTIO_GUEST_FEATURES, 0);

        // 10. Select queue 0.
        let _ = sys::port_out16(bar_cap, bar_base + VIRTIO_QUEUE_SELECT, 0);

        // 11. Read queue size.
        let queue_size = sys::port_in16(bar_cap, bar_base + VIRTIO_QUEUE_SIZE).unwrap_or(0);
        dbg(b"  BLK: queue_size="); dbg_u64(queue_size as u64); dbg(b"\n");
        if queue_size == 0 {
            return Err("virtqueue size is 0");
        }

        // 12. Allocate contiguous physical pages for the virtqueue.
        let vq_bytes = Virtqueue::byte_size(queue_size);
        let vq_pages = (vq_bytes + 4095) / 4096;
        let vq_mem_cap = sys::frame_alloc_contiguous(vq_pages as u64)
            .map_err(|_| "frame_alloc_contiguous for vq failed")?;
        let vq_phys = sys::frame_phys(vq_mem_cap)
            .map_err(|_| "frame_phys for vq failed")?;
        dbg(b"  BLK: vq_phys="); dbg_hex(vq_phys); dbg(b"\n");

        // Map virtqueue pages.
        for i in 0..vq_pages {
            sys::map_offset(VQ_VADDR + (i as u64) * 4096, vq_mem_cap, (i as u64) * 4096, 2)
                .map_err(|_| "map_offset for vq failed")?;
        }

        // 13. Initialize the virtqueue data structure (zeroes all pages via volatile writes + mfence).
        let vq = Virtqueue::new(VQ_VADDR, vq_phys, queue_size);

        // 14. Write queue address (PFN) to device.
        let _ = sys::port_out32(bar_cap, bar_base + VIRTIO_QUEUE_ADDRESS, vq.phys_pfn());

        // 15. Allocate and map DMA pages: header, status, data.
        let hdr_cap = sys::frame_alloc().map_err(|_| "frame_alloc hdr")?;
        let hdr_phys = sys::frame_phys(hdr_cap).map_err(|_| "frame_phys hdr")?;
        sys::map(HDR_VADDR, hdr_cap, 2).map_err(|_| "map hdr")?;

        let status_cap = sys::frame_alloc().map_err(|_| "frame_alloc status")?;
        let status_phys = sys::frame_phys(status_cap).map_err(|_| "frame_phys status")?;
        sys::map(STATUS_VADDR, status_cap, 2).map_err(|_| "map status")?;

        let data_cap = sys::frame_alloc().map_err(|_| "frame_alloc data")?;
        let data_phys = sys::frame_phys(data_cap).map_err(|_| "frame_phys data")?;
        sys::map(DATA_VADDR, data_cap, 2).map_err(|_| "map data")?;

        // 16. Set DRIVER_OK.
        let _ = sys::port_out(bar_cap, bar_base + VIRTIO_DEVICE_STATUS,
                              STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);

        // 17. Read capacity from device config.
        let cap_lo = sys::port_in32(bar_cap, bar_base + VIRTIO_BLK_CAPACITY).unwrap_or(0) as u64;
        let cap_hi = sys::port_in32(bar_cap, bar_base + VIRTIO_BLK_CAPACITY + 4).unwrap_or(0) as u64;
        let capacity = (cap_hi << 32) | cap_lo;

        Ok(VirtioBlk {
            bar_cap,
            bar_base,
            irq_cap,
            notify_cap,
            vq,
            hdr_phys,
            status_phys,
            data_phys,
            capacity,
        })
    }

    /// Read a 512-byte sector into the data buffer at DATA_VADDR.
    pub fn read_sector(&mut self, sector: u64) -> Result<(), &'static str> {
        // Write request header (volatile — DMA shared memory).
        let hdr = HDR_VADDR as *mut VirtioBlkReqHeader;
        unsafe {
            core::ptr::write_volatile(&raw mut (*hdr).req_type, VIRTIO_BLK_T_IN);
            core::ptr::write_volatile(&raw mut (*hdr).reserved, 0);
            core::ptr::write_volatile(&raw mut (*hdr).sector, sector);
        }

        // Clear status byte.
        unsafe { core::ptr::write_volatile(STATUS_VADDR as *mut u8, 0xFF); }

        // Allocate 3 descriptors: header(RO) → data(WO) → status(WO).
        let d0 = self.vq.alloc_desc().ok_or("no desc for header")?;
        let d1 = self.vq.alloc_desc().ok_or("no desc for data")?;
        let d2 = self.vq.alloc_desc().ok_or("no desc for status")?;

        self.vq.set_buf_ro(d0, self.hdr_phys, 16);
        self.vq.set_buf_wo(d1, self.data_phys, 512);
        self.vq.set_buf_wo(d2, self.status_phys, 1);

        self.vq.chain(d0, d1);
        self.vq.chain(d1, d2);

        // Submit and notify device.
        self.vq.submit(d0);
        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
        let _ = sys::port_out16(self.bar_cap, self.bar_base + VIRTIO_QUEUE_NOTIFY, 0);

        // Wait for completion.
        self.wait_completion()?;

        // Free descriptor chain.
        self.vq.free_chain(d0);

        // Check status byte.
        let status = unsafe { core::ptr::read_volatile(STATUS_VADDR as *const u8) };
        if status != 0 {
            return Err("read_sector: device returned error status");
        }

        Ok(())
    }

    /// Write a 512-byte sector from the data buffer at DATA_VADDR.
    pub fn write_sector(&mut self, sector: u64) -> Result<(), &'static str> {
        // Write request header.
        let hdr = HDR_VADDR as *mut VirtioBlkReqHeader;
        unsafe {
            core::ptr::write_volatile(&raw mut (*hdr).req_type, VIRTIO_BLK_T_OUT);
            core::ptr::write_volatile(&raw mut (*hdr).reserved, 0);
            core::ptr::write_volatile(&raw mut (*hdr).sector, sector);
        }

        // Clear status byte.
        unsafe { core::ptr::write_volatile(STATUS_VADDR as *mut u8, 0xFF); }

        // Allocate 3 descriptors: header(RO) → data(RO) → status(WO).
        let d0 = self.vq.alloc_desc().ok_or("no desc for header")?;
        let d1 = self.vq.alloc_desc().ok_or("no desc for data")?;
        let d2 = self.vq.alloc_desc().ok_or("no desc for status")?;

        self.vq.set_buf_ro(d0, self.hdr_phys, 16);
        self.vq.set_buf_ro(d1, self.data_phys, 512);
        self.vq.set_buf_wo(d2, self.status_phys, 1);

        self.vq.chain(d0, d1);
        self.vq.chain(d1, d2);

        // Submit and notify device.
        self.vq.submit(d0);
        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
        let _ = sys::port_out16(self.bar_cap, self.bar_base + VIRTIO_QUEUE_NOTIFY, 0);

        // Wait for completion.
        self.wait_completion()?;

        // Free descriptor chain.
        self.vq.free_chain(d0);

        // Check status byte.
        let status = unsafe { core::ptr::read_volatile(STATUS_VADDR as *const u8) };
        if status != 0 {
            return Err("write_sector: device returned error status");
        }

        Ok(())
    }

    /// Return a pointer to the data buffer (for reading sector data).
    pub fn data_ptr(&self) -> *const u8 {
        DATA_VADDR as *const u8
    }

    /// Return a mutable pointer to the data buffer (for writing sector data).
    pub fn data_ptr_mut(&self) -> *mut u8 {
        DATA_VADDR as *mut u8
    }

    /// Wait for the virtqueue to return a used entry.
    /// Uses notify_wait (blocking) to yield CPU to QEMU's I/O loop in TCG mode.
    fn wait_completion(&mut self) -> Result<(), &'static str> {
        for _ in 0..1000 {
            // Block until IRQ fires. In TCG, this yields the vCPU to QEMU's event loop.
            sys::notify_wait(self.notify_cap);
            // Read ISR to acknowledge the interrupt (clears ISR + deasserts PCI IRQ).
            let _ = sys::port_in(self.bar_cap, self.bar_base + VIRTIO_ISR_STATUS);
            let _ = sys::irq_ack(self.irq_cap);
            if self.vq.poll_used().is_some() {
                return Ok(());
            }
        }
        Err("wait_completion: timeout")
    }
}
