//! sotOS xHCI USB Host Controller Service Process
//!
//! Drives an xHCI USB 3.x controller via MMIO (BAR0 pre-mapped by kernel).
//! Implements HID boot protocol keyboard support — converts USB HID reports
//! to PS/2 scancodes and writes them to the shared KB ring buffer.
//!
//! Architecture (U4 defer-to-worker fix):
//! The main thread performs minimum boot-critical setup (PCI, DMA, controller
//! reset, No-Op verification) then SPAWNS a dedicated worker thread that owns
//! the USB enumeration sequence (~8 blocking control transfers on TCG). While
//! the worker enumerates, the main thread drops into an IPC poll loop — it
//! registers the service under the name "xhci" and responds to any incoming
//! call with ENXIO until `XHCI_ENUM_READY` flips. This way the boot cannot
//! stall waiting for xhci to come up; any other service that does
//! `svc_lookup("xhci")` gets a prompt answer even during enumeration.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sotos_common::sys;
use sotos_common::KB_RING_ADDR;
use sotos_common::{BootInfo, BOOT_INFO_ADDR, IpcMsg};
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

// Worker thread stack. The main xhci thread uses the process stack at
// PROCESS_STACK_BASE (0x900000) allocated by the kernel loader. The worker
// needs its own independent stack, which we allocate at a VA that does not
// collide with MMIO (0xC00000), DMA (0xD00000..), or the shared KB ring
// (0x510000). 16 KiB / 4 pages is enough headroom for the enumeration's
// nested control-transfer call chain.
const WORKER_STACK_BASE: u64 = 0xA00000;
const WORKER_STACK_PAGES: u64 = 4;
const WORKER_STACK_TOP: u64 = WORKER_STACK_BASE + WORKER_STACK_PAGES * 0x1000;

// IPC "not ready yet" reply code. Any consumer that calls svc_lookup("xhci")
// and then IPC-calls the endpoint before enumeration is complete gets this.
// -6 = ENXIO in the Linux-compatible numbering used throughout the tree.
const ERR_NOT_READY: i64 = -6;

// ---------------------------------------------------------------------------
// Worker handoff state (main thread → enumeration worker)
// ---------------------------------------------------------------------------

/// Flipped to `true` by the worker after the USB enumeration sequence
/// (Enable Slot, Address Device, GET_DESCRIPTOR, Configure Endpoint,
/// SET_CONFIGURATION, SET_PROTOCOL, SET_IDLE, initial interrupt TRBs)
/// has completed. Consumers can poll this to know when it is safe to
/// interact with the xhci service.
pub static XHCI_ENUM_READY: AtomicBool = AtomicBool::new(false);

/// Shared context handed from the main thread to the enumeration worker.
///
/// SAFETY: single-writer/single-reader handoff — the main thread fully
/// populates every field and sets `WORKER_CTX_READY` before spawning the
/// worker, and the worker reads the values only after its first instruction
/// observes `WORKER_CTX_READY == true`. After handoff, the main thread never
/// touches the controller again; the worker owns it for the lifetime of the
/// process. This pattern sidesteps the lack of an `arg` parameter on
/// `sys::thread_create(rip, rsp)` without introducing a lock.
struct WorkerCtx {
    /// Fully-initialized XhciController (ownership transferred to worker).
    ctrl: UnsafeCell<MaybeUninit<XhciController>>,
    /// DMA descriptor table — Copy, so the worker can read it directly.
    dma: UnsafeCell<MaybeUninit<XhciDma>>,
    /// IRQ acknowledgement cap passed from BootInfo.
    irq_cap: AtomicU64,
    /// IRQ notification cap (worker blocks on this in the event loop).
    notify_cap: AtomicU64,
    /// Physical address of the interrupt-IN data buffer (HID reports).
    int_buf_phys: AtomicU64,
    /// Physical address of the interrupt-IN transfer ring.
    int_ring_phys: AtomicU64,
    /// Physical address of the input context (for Address Device / Configure EP).
    input_ctx_phys: AtomicU64,
    /// Physical address of the device context.
    device_ctx_phys: AtomicU64,
    /// Physical address of the EP0 transfer ring.
    ep0_ring_phys: AtomicU64,
    /// Physical address of the scratch data buffer for descriptors.
    data_buf_phys: AtomicU64,
}

// SAFETY: This is a single-AS userspace process. Thread creation within the
// same address space (`sys::thread_create`) preserves data visibility for
// statics; the protocol is enforced by `WORKER_CTX_READY` below.
unsafe impl Sync for WorkerCtx {}

static WORKER_CTX: WorkerCtx = WorkerCtx {
    ctrl: UnsafeCell::new(MaybeUninit::uninit()),
    dma: UnsafeCell::new(MaybeUninit::uninit()),
    irq_cap: AtomicU64::new(0),
    notify_cap: AtomicU64::new(0),
    int_buf_phys: AtomicU64::new(0),
    int_ring_phys: AtomicU64::new(0),
    input_ctx_phys: AtomicU64::new(0),
    device_ctx_phys: AtomicU64::new(0),
    ep0_ring_phys: AtomicU64::new(0),
    data_buf_phys: AtomicU64::new(0),
};

/// Synchronization flag ensuring the worker thread reads WORKER_CTX only
/// after the main thread finishes writing every field. Uses SeqCst for
/// a full happens-before ordering between the stores on the main thread
/// and the load on the worker.
static WORKER_CTX_READY: AtomicBool = AtomicBool::new(false);

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

    // ---------------------------------------------------------------
    // Publish the fully-initialized controller into the worker context
    // and spawn the enumeration worker thread.
    //
    // Everything from here down — port scan, reset, Enable Slot,
    // Address Device, GET_DESCRIPTOR, Configure Endpoint,
    // SET_CONFIGURATION, SET_PROTOCOL, SET_IDLE, initial interrupt
    // TRBs and the subsequent HID event loop — happens in the worker
    // so the main thread can promptly register its IPC service and
    // stop blocking any consumer that wants to talk to xhci.
    //
    // SAFETY: the main thread transfers ownership of `ctrl` and `dma`
    // into WORKER_CTX and never touches them again. Every field is
    // stored before WORKER_CTX_READY is set (SeqCst), and the worker
    // only reads the fields after observing WORKER_CTX_READY == true.
    // ---------------------------------------------------------------
    unsafe {
        (*WORKER_CTX.ctrl.get()).write(ctrl);
        (*WORKER_CTX.dma.get()).write(dma);
    }
    WORKER_CTX.irq_cap.store(irq_cap, Ordering::Relaxed);
    WORKER_CTX.notify_cap.store(notify_cap, Ordering::Relaxed);
    WORKER_CTX.int_buf_phys.store(int_buf_phys, Ordering::Relaxed);
    WORKER_CTX.int_ring_phys.store(int_ring_phys, Ordering::Relaxed);
    WORKER_CTX.input_ctx_phys.store(input_ctx_phys, Ordering::Relaxed);
    WORKER_CTX.device_ctx_phys.store(device_ctx_phys, Ordering::Relaxed);
    WORKER_CTX.ep0_ring_phys.store(ep0_ring_phys, Ordering::Relaxed);
    WORKER_CTX.data_buf_phys.store(data_buf_phys, Ordering::Relaxed);
    WORKER_CTX_READY.store(true, Ordering::SeqCst);

    // Allocate and map the worker stack (4 pages = 16 KiB). Reuses the
    // local `alloc_and_map` helper so the stack pages are zeroed and mapped
    // writable with the same flags as every other DMA page above.
    for i in 0..WORKER_STACK_PAGES {
        let _ = alloc_and_map(WORKER_STACK_BASE + i * 0x1000, map_flags);
    }

    // Spawn the enumeration worker thread in the same address space.
    // `sys::thread_create(rip, rsp)` starts it at `usb_enumerate_worker`
    // with its own RSP — WORKER_CTX is read via statics on first entry.
    match sys::thread_create(
        usb_enumerate_worker as *const () as u64,
        WORKER_STACK_TOP,
    ) {
        Ok(_) => print(b"xhci: enumeration deferred to worker thread\n"),
        Err(_) => {
            print(b"xhci: FATAL worker thread_create failed, running enum inline\n");
            // Fallback: call worker entry on this thread. This matches the
            // pre-U4 behavior. We diverge (never return), so main-thread IPC
            // registration is skipped in this degraded mode.
            usb_enumerate_worker();
        }
    }

    // ---------------------------------------------------------------
    // Main thread: IPC service loop.
    //
    // Create an endpoint, register under "xhci", and answer calls.
    // While enumeration is in progress we return ERR_NOT_READY (ENXIO)
    // so consumers see a prompt reply rather than blocking. Once the
    // worker sets XHCI_ENUM_READY, the same loop answers with success.
    // ---------------------------------------------------------------
    let ep_cap = match sys::endpoint_create() {
        Ok(c) => c,
        Err(_) => {
            print(b"xhci: endpoint_create failed, parking main thread\n");
            loop { sys::yield_now(); }
        }
    };

    let name = b"xhci";
    match sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep_cap) {
        Ok(()) => print(b"xhci: registered as 'xhci' service\n"),
        Err(_) => print(b"xhci: svc_register failed (non-fatal)\n"),
    }

    ipc_main_loop(ep_cap);
}

// ---------------------------------------------------------------------------
// Main-thread IPC loop
// ---------------------------------------------------------------------------

/// Serve IPC calls on the xhci endpoint forever. Answers with ERR_NOT_READY
/// until the worker flips XHCI_ENUM_READY, and with success (0) after.
///
/// The minimal ABI today is "ping" — any caller learns whether the
/// controller has finished enumeration and therefore whether HID keyboard
/// reports are flowing into the shared KB ring. Future commands can be
/// dispatched by inspecting `msg.tag` without touching the worker.
fn ipc_main_loop(ep_cap: u64) -> ! {
    loop {
        // The incoming message is ignored today — the minimal ABI is "ping"
        // to discover enumeration status. Future commands can dispatch on
        // `_msg.tag` without touching the worker.
        if sys::recv(ep_cap).is_err() {
            sys::yield_now();
            continue;
        }

        let ready = XHCI_ENUM_READY.load(Ordering::Acquire);
        let reply_code: i64 = if ready { 0 } else { ERR_NOT_READY };

        // reply.tag carries the status code (0 = ready, ERR_NOT_READY otherwise)
        // and reply.regs[0] mirrors it as a boolean ready bit. regs[1..7]
        // are reserved for future command responses.
        let reply = IpcMsg {
            tag: reply_code as u64,
            regs: [ready as u64, 0, 0, 0, 0, 0, 0, 0],
        };
        let _ = sys::send(ep_cap, &reply);
    }
}

// ---------------------------------------------------------------------------
// USB enumeration worker thread (runs everything after XhciController::init)
// ---------------------------------------------------------------------------

/// Real USB enumeration worker. Runs the full post-init sequence
/// (port scan/reset, Enable Slot, Address Device, descriptors, Configure
/// Endpoint, SET_CONFIGURATION, SET_PROTOCOL, SET_IDLE, initial interrupt
/// TRBs) and then drops into the HID keyboard event loop forever.
///
/// Takes no explicit argument — reads its context from `WORKER_CTX`, which
/// the main thread fully populates before spawn. Emits the exact same boot
/// log messages as the pre-U4 inline enumeration so external log watchers
/// (and the test harness) keep seeing familiar output.
extern "C" fn usb_enumerate_worker() -> ! {
    // Wait for the main thread's setup to become visible. In practice this
    // is already true because main sets the flag before calling thread_create,
    // but the acquire load establishes happens-before regardless of
    // scheduler order.
    while !WORKER_CTX_READY.load(Ordering::Acquire) {
        sys::yield_now();
    }

    // SAFETY: WORKER_CTX_READY is true and the main thread has surrendered
    // ownership of ctrl/dma to this worker. We are the only reader.
    let ctrl: &mut XhciController = unsafe { (*WORKER_CTX.ctrl.get()).assume_init_mut() };
    let dma: &XhciDma = unsafe { (*WORKER_CTX.dma.get()).assume_init_ref() };
    let irq_cap = WORKER_CTX.irq_cap.load(Ordering::Relaxed);
    let notify_cap = WORKER_CTX.notify_cap.load(Ordering::Relaxed);
    let int_buf_phys = WORKER_CTX.int_buf_phys.load(Ordering::Relaxed);
    let int_ring_phys = WORKER_CTX.int_ring_phys.load(Ordering::Relaxed);
    let input_ctx_phys = WORKER_CTX.input_ctx_phys.load(Ordering::Relaxed);
    let device_ctx_phys = WORKER_CTX.device_ctx_phys.load(Ordering::Relaxed);
    let ep0_ring_phys = WORKER_CTX.ep0_ring_phys.load(Ordering::Relaxed);
    let data_buf_phys = WORKER_CTX.data_buf_phys.load(Ordering::Relaxed);

    // --- Find connected port ---
    let connected = unsafe { port::connected_ports(ctrl) };
    let mut first_port: u8 = 0;
    for p in 1..=ctrl.max_ports {
        if connected & (1 << p) != 0 {
            first_port = p;
            break;
        }
    }
    if first_port == 0 {
        print(b"xhci: no connected ports, parking worker on notify_wait\n");
        // Still mark enum ready so IPC consumers don't wait forever — the
        // controller is up, there's simply nothing plugged in. The main
        // thread's IPC loop can distinguish via a future "has_device" bit.
        XHCI_ENUM_READY.store(true, Ordering::SeqCst);
        // TCG fix (run-full deadlock U2): sleep on notify instead of
        // busy-yielding so the kernel scheduler doesn't round-robin.
        loop { sys::notify_wait(notify_cap); }
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
    unsafe { port::reset_port(ctrl, first_port); }
    if !unsafe { port::wait_port_reset(ctrl, first_port, xhci_wait) } {
        print(b"xhci: port reset timeout\n");
        XHCI_ENUM_READY.store(true, Ordering::SeqCst);
        loop { sys::notify_wait(notify_cap); }
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
            XHCI_ENUM_READY.store(true, Ordering::SeqCst);
            loop { sys::notify_wait(notify_cap); }
        }
    };

    // --- Address Device ---
    unsafe { ctrl.set_dcbaa_entry(dma, slot_id, device_ctx_phys); }
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
            XHCI_ENUM_READY.store(true, Ordering::SeqCst);
            loop { sys::notify_wait(notify_cap); }
        }
        Err(msg) => {
            print(b"xhci: Address Device error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
            XHCI_ENUM_READY.store(true, Ordering::SeqCst);
            loop { sys::notify_wait(notify_cap); }
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

    // --- GET_DESCRIPTOR(Configuration) — first 64 bytes to get wTotalLength ---
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
    // Check for mass storage device
    if let Some(ms_info) = usb::parse_config_for_mass_storage(cfg_buf) {
        print(b"xhci: USB Mass Storage found: iface=");
        print_u32(ms_info.interface_num as u32);
        print(b" ep_in=");
        print_hex32(ms_info.ep_bulk_in as u32);
        print(b" ep_out=");
        print_hex32(ms_info.ep_bulk_out as u32);
        print(b" maxpkt=");
        print_u32(ms_info.max_packet_in as u32);
        sys::debug_print(b'\n');
        // Future: setup bulk endpoints, SCSI INQUIRY, expose block device via IPC.
        print(b"xhci: mass storage detected (bulk transfer not yet implemented)\n");
    }

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
            XHCI_ENUM_READY.store(true, Ordering::SeqCst);
            loop { sys::notify_wait(notify_cap); }
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
            XHCI_ENUM_READY.store(true, Ordering::SeqCst);
            loop { sys::notify_wait(notify_cap); }
        }
        Err(msg) => {
            print(b"xhci: Configure Endpoint error: ");
            print(msg.as_bytes());
            sys::debug_print(b'\n');
            XHCI_ENUM_READY.store(true, Ordering::SeqCst);
            loop { sys::notify_wait(notify_cap); }
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
        let buf = int_buf_phys + i * 64; // 64-byte slots within the interrupt buffer page
        unsafe { int_ring.enqueue(trb::trb_normal(buf, report_size)); }
    }
    // Ring the interrupt endpoint doorbell.
    unsafe { ctrl.ring_ep_doorbell(slot_id, ep_dci); }

    print(b"xhci: HID keyboard ready, entering event loop\n");
    XHCI_ENUM_READY.store(true, Ordering::SeqCst);

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

            if evt.trb_type() == trb::TRB_XFER_EVENT && evt.endpoint_id() == ep_dci
                && (evt.completion_code() == trb::CC_SUCCESS || evt.completion_code() == 13)
            {
                // Each completed TRB means one report is available. We
                // use a simple rotating read pointer over the 4 x 64-byte
                // slots we posted into the interrupt buffer page.
                pending_trbs = pending_trbs.saturating_sub(1);
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
