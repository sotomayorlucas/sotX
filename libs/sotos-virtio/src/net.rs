//! Virtio-NET device driver (legacy transport v0.9.5).
//!
//! Two virtqueues: queue 0 = RX, queue 1 = TX.
//! Each packet is prefixed with a VirtioNetHdr (10 bytes, legacy).

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
/// MAC address is at device-specific config offset 0x14 (6 bytes).
const VIRTIO_NET_MAC: u64 = 0x14;

/// Device status bits.
const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;

/// Number of pre-posted RX buffers.
const RX_BUFS: usize = 16;

/// Virtio-net header (legacy, 10 bytes, prepended to every packet).
#[repr(C)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

const NET_HDR_SIZE: usize = core::mem::size_of::<VirtioNetHdr>(); // 10

/// Virtual address layout for net driver memory (net process AS, 0xC00000+ free).
const RX_VQ_VADDR: u64 = 0xC00000;   // RX virtqueue (3 pages)
const TX_VQ_VADDR: u64 = 0xC03000;   // TX virtqueue (3 pages)
const RX_BUF_VADDR: u64 = 0xC06000;  // RX buffer pool (16 pages, one per buf)
const TX_BUF_VADDR: u64 = 0xC16000;  // TX header+data page (1 page)

/// Virtio-NET device driver.
pub struct VirtioNet {
    bar_cap: u64,
    bar_base: u64,
    irq_cap: u64,
    notify_cap: u64,
    rx_vq: Virtqueue,
    tx_vq: Virtqueue,
    mac: [u8; 6],
    /// Physical addresses for each RX buffer page.
    rx_buf_phys: [u64; RX_BUFS],
    /// Physical address of the TX buffer page.
    tx_buf_phys: u64,
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

impl VirtioNet {
    /// Initialize the virtio-net device.
    pub fn init(pci_dev: &PciDevice, pci_bus: &PciBus) -> Result<Self, &'static str> {
        // 1. Read BAR0 (I/O port space).
        let bar0_raw = pci_bus.bar0(pci_dev.addr);
        if bar0_raw & 1 == 0 {
            return Err("BAR0 is MMIO, expected I/O port");
        }
        let bar_base = (bar0_raw & 0xFFFFFFFC) as u64;
        dbg(b"  NET: bar_base="); dbg_hex(bar_base); dbg(b"\n");

        // 2. Enable bus mastering.
        pci_bus.enable_bus_master(pci_dev.addr);

        // 3. Create I/O port cap for BAR0 range.
        let bar_cap = sys::ioport_create(bar_base as u16, 32)
            .map_err(|_| "ioport_create failed")?;

        // 4. Create IRQ cap + notification.
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

        // 10. Setup queue 0 (RX).
        let _ = sys::port_out16(bar_cap, bar_base + VIRTIO_QUEUE_SELECT, 0);
        let rx_qs = sys::port_in16(bar_cap, bar_base + VIRTIO_QUEUE_SIZE).unwrap_or(0);
        dbg(b"  NET: rx_queue_size="); dbg_u64(rx_qs as u64); dbg(b"\n");
        if rx_qs == 0 { return Err("RX queue size is 0"); }

        let rx_vq_bytes = Virtqueue::byte_size(rx_qs);
        let rx_vq_pages = (rx_vq_bytes + 4095) / 4096;
        let rx_vq_mem = sys::frame_alloc_contiguous(rx_vq_pages as u64)
            .map_err(|_| "frame_alloc_contiguous for rx vq")?;
        let rx_vq_phys = sys::frame_phys(rx_vq_mem)
            .map_err(|_| "frame_phys for rx vq")?;
        for i in 0..rx_vq_pages {
            sys::map_offset(RX_VQ_VADDR + (i as u64) * 4096, rx_vq_mem, (i as u64) * 4096, 2)
                .map_err(|_| "map_offset rx vq")?;
        }
        let rx_vq = Virtqueue::new(RX_VQ_VADDR, rx_vq_phys, rx_qs);
        let _ = sys::port_out32(bar_cap, bar_base + VIRTIO_QUEUE_ADDRESS, rx_vq.phys_pfn());

        // 11. Setup queue 1 (TX).
        let _ = sys::port_out16(bar_cap, bar_base + VIRTIO_QUEUE_SELECT, 1);
        let tx_qs = sys::port_in16(bar_cap, bar_base + VIRTIO_QUEUE_SIZE).unwrap_or(0);
        dbg(b"  NET: tx_queue_size="); dbg_u64(tx_qs as u64); dbg(b"\n");
        if tx_qs == 0 { return Err("TX queue size is 0"); }

        let tx_vq_bytes = Virtqueue::byte_size(tx_qs);
        let tx_vq_pages = (tx_vq_bytes + 4095) / 4096;
        let tx_vq_mem = sys::frame_alloc_contiguous(tx_vq_pages as u64)
            .map_err(|_| "frame_alloc_contiguous for tx vq")?;
        let tx_vq_phys = sys::frame_phys(tx_vq_mem)
            .map_err(|_| "frame_phys for tx vq")?;
        for i in 0..tx_vq_pages {
            sys::map_offset(TX_VQ_VADDR + (i as u64) * 4096, tx_vq_mem, (i as u64) * 4096, 2)
                .map_err(|_| "map_offset tx vq")?;
        }
        let tx_vq = Virtqueue::new(TX_VQ_VADDR, tx_vq_phys, tx_qs);
        let _ = sys::port_out32(bar_cap, bar_base + VIRTIO_QUEUE_ADDRESS, tx_vq.phys_pfn());

        // 12. Allocate RX buffer pool (16 pages).
        let mut rx_buf_phys = [0u64; RX_BUFS];
        for i in 0..RX_BUFS {
            let cap = sys::frame_alloc().map_err(|_| "frame_alloc rx buf")?;
            let phys = sys::frame_phys(cap).map_err(|_| "frame_phys rx buf")?;
            sys::map(RX_BUF_VADDR + (i as u64) * 4096, cap, 2)
                .map_err(|_| "map rx buf")?;
            rx_buf_phys[i] = phys;
        }

        // 13. Allocate TX buffer page.
        let tx_cap = sys::frame_alloc().map_err(|_| "frame_alloc tx buf")?;
        let tx_buf_phys = sys::frame_phys(tx_cap).map_err(|_| "frame_phys tx buf")?;
        sys::map(TX_BUF_VADDR, tx_cap, 2).map_err(|_| "map tx buf")?;

        // 14. Set DRIVER_OK.
        let _ = sys::port_out(bar_cap, bar_base + VIRTIO_DEVICE_STATUS,
                              STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);

        // 15. Read MAC from config (6 bytes at offset 0x14).
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = sys::port_in(bar_cap, bar_base + VIRTIO_NET_MAC + i as u64).unwrap_or(0);
        }

        let mut net = VirtioNet {
            bar_cap,
            bar_base,
            irq_cap,
            notify_cap,
            rx_vq,
            tx_vq,
            mac,
            rx_buf_phys,
            tx_buf_phys,
        };

        // 16. Pre-post all RX buffers.
        for i in 0..RX_BUFS {
            net.post_rx_buf(i);
        }
        // Notify device that RX buffers are available.
        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
        let _ = sys::port_out16(bar_cap, bar_base + VIRTIO_QUEUE_NOTIFY, 0);

        Ok(net)
    }

    /// Get the device MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Transmit an Ethernet frame.
    /// `frame` is the raw Ethernet frame (dst + src + ethertype + payload).
    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() + NET_HDR_SIZE > 4096 {
            return Err("frame too large");
        }

        // Write VirtioNetHdr (all zeros = no offload) + frame data to TX buffer.
        let tx_ptr = TX_BUF_VADDR as *mut u8;
        unsafe {
            // Zero the header.
            for i in 0..NET_HDR_SIZE {
                core::ptr::write_volatile(tx_ptr.add(i), 0);
            }
            // Copy frame data after header.
            for i in 0..frame.len() {
                core::ptr::write_volatile(tx_ptr.add(NET_HDR_SIZE + i), frame[i]);
            }
        }

        let total_len = NET_HDR_SIZE + frame.len();

        // Single descriptor: device-readable (entire hdr+frame).
        let d0 = self.tx_vq.alloc_desc().ok_or("no TX desc")?;
        self.tx_vq.set_buf_ro(d0, self.tx_buf_phys, total_len as u32);
        self.tx_vq.submit(d0);

        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
        let _ = sys::port_out16(self.bar_cap, self.bar_base + VIRTIO_QUEUE_NOTIFY, 1);

        // Wait for TX completion.
        self.wait_tx_completion()?;
        self.tx_vq.free_desc(d0);

        Ok(())
    }

    /// Poll the RX queue for a received packet.
    /// Returns `Some((buf_index, total_bytes_written))` if a packet is available.
    /// The total includes the VirtioNetHdr.
    pub fn poll_rx(&mut self) -> Option<(usize, usize)> {
        if let Some((id, len)) = self.rx_vq.poll_used() {
            Some((id as usize, len as usize))
        } else {
            None
        }
    }

    /// Get a pointer to the received frame data (after VirtioNetHdr) for buffer `idx`.
    pub fn rx_buf(&self, idx: usize) -> *const u8 {
        (RX_BUF_VADDR + (idx as u64) * 4096 + NET_HDR_SIZE as u64) as *const u8
    }

    /// Re-post an RX buffer after processing.
    /// `idx` is the descriptor ID returned by `poll_rx`.
    pub fn rx_done(&mut self, idx: usize) {
        // Free the old descriptor before allocating a new one.
        self.rx_vq.free_desc(idx as u16);
        self.post_rx_buf(idx);
        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
        let _ = sys::port_out16(self.bar_cap, self.bar_base + VIRTIO_QUEUE_NOTIFY, 0);
    }

    /// Acknowledge a pending interrupt (read ISR + ack IRQ).
    pub fn ack_irq(&mut self) {
        let _ = sys::port_in(self.bar_cap, self.bar_base + VIRTIO_ISR_STATUS);
        let _ = sys::irq_ack(self.irq_cap);
    }

    /// Wait for the notification (IRQ delivery).
    pub fn wait_irq(&self) {
        sys::notify_wait(self.notify_cap);
    }

    /// Post a single RX buffer to the RX virtqueue.
    fn post_rx_buf(&mut self, idx: usize) {
        let d = self.rx_vq.alloc_desc().expect("no RX desc");
        // Device writes entire page: VirtioNetHdr + frame data.
        self.rx_vq.set_buf_wo(d, self.rx_buf_phys[idx], 4096);
        self.rx_vq.submit(d);
    }

    /// Wait for TX completion via IRQ.
    fn wait_tx_completion(&mut self) -> Result<(), &'static str> {
        for _ in 0..1000 {
            sys::notify_wait(self.notify_cap);
            let _ = sys::port_in(self.bar_cap, self.bar_base + VIRTIO_ISR_STATUS);
            let _ = sys::irq_ack(self.irq_cap);
            if self.tx_vq.poll_used().is_some() {
                return Ok(());
            }
        }
        Err("TX completion timeout")
    }
}
