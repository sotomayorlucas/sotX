//! sotOS Microkernel
//!
//! A formally-verifiable microkernel implementing five primitives:
//! - Thread scheduling (preemptive with delegation)
//! - IRQ virtualization to userspace
//! - IPC (register-based + shared memory channels)
//! - Capability management (creation, delegation, revocation)
//! - Physical frame allocation (no virtual memory — that's userspace)

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod arch;
mod cap;
mod elf;
mod fault;
mod initrd;
mod ipc;
mod irq;
mod mm;
mod panic;
mod pool;
mod sched;
mod syscall;
mod user_init;

use limine::BaseRevision;
use limine::request::{HhdmRequest, MemoryMapRequest, ModuleRequest, RequestsEndMarker, RequestsStartMarker};

#[used]
#[link_section = ".requests_start_marker"]
static _REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".requests_end_marker"]
static _REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

/// Limine base revision — ensures bootloader compatibility.
#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();

/// Request the Higher Half Direct Map offset.
/// All physical memory is identity-mapped at this offset.
#[used]
#[link_section = ".requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

/// Request the physical memory map from the bootloader.
#[used]
#[link_section = ".requests"]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

/// Request modules loaded by the bootloader (initramfs).
#[used]
#[link_section = ".requests"]
static MODULE_REQUEST: ModuleRequest = ModuleRequest::new();

/// Kernel entry point — called by the Limine bootloader.
#[no_mangle]
extern "C" fn kmain() -> ! {
    // Serial MUST be first — we need debug output before anything else.
    arch::serial::init();
    kprintln!("sotOS v0.1.0 — microkernel booting...");

    if !BASE_REVISION.is_supported() {
        kprintln!("FATAL: Limine base revision not supported");
        arch::halt_loop();
    }

    // CPU structures.
    arch::gdt::init();
    kprintln!("[ok] GDT");

    arch::idt::init();
    kprintln!("[ok] IDT");

    // Physical frame allocator from bootloader memory map.
    let mmap_response = MEMORY_MAP_REQUEST
        .get_response()
        .expect("bootloader: no memory map");
    let hhdm_response = HHDM_REQUEST
        .get_response()
        .expect("bootloader: no HHDM");

    mm::init(mmap_response, hhdm_response.offset());
    kprintln!("[ok] Frame allocator");

    // Slab allocator (kernel heap).
    mm::slab::init();
    kprintln!("[ok] Slab allocator");

    // Smoke test: prove alloc works.
    {
        let mut v = alloc::vec::Vec::new();
        v.push(1u64);
        v.push(2);
        v.push(3);
        assert_eq!(v.iter().sum::<u64>(), 6);
        kprintln!("[ok] Heap (Vec test)");
    }

    // Save boot CR3 before any address space changes.
    mm::paging::init_boot_cr3();

    // Capability system.
    cap::init();
    kprintln!("[ok] Capabilities");

    // Scheduler.
    sched::init();
    kprintln!("[ok] Scheduler");

    // SYSCALL/SYSRET MSRs.
    arch::syscall::init();
    kprintln!("[ok] SYSCALL/SYSRET");

    // Hardware interrupts.
    arch::pic::init();
    kprintln!("[ok] PIC");

    arch::pit::init();
    kprintln!("[ok] PIT");

    // Spawn init process (first userspace code).
    let user_cr3 = spawn_init_process();
    kprintln!("[ok] Init process");

    // Load ELF from initramfs (if present).
    load_initrd(user_cr3);
    kprintln!("[ok] Initrd");

    // Enable timer IRQ and interrupts.
    arch::pic::unmask(0);
    x86_64::instructions::interrupts::enable();
    kprintln!("Kernel ready — entering idle loop");

    // Idle loop (thread 0). Timer interrupts cause preemptive switching.
    loop {
        x86_64::instructions::hlt();
    }
}

/// Create the user address space and spawn two threads for IPC testing.
///
/// - Sender at 0x400000: prints "INIT\n", sends IPC message, prints "OK\n"
/// - Receiver at 0x401000: receives IPC message, prints "IPC!\n"
/// - Both share one address space and one IPC endpoint (ep 0).
/// - Receiver spawned first so it blocks on Recv before sender runs.
fn spawn_init_process() -> u64 {
    use mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let addr_space = AddressSpace::new_user();
    let hhdm = mm::hhdm_offset();
    let cr3 = addr_space.cr3();

    // --- Copy sender code to 0x400000 ---
    let sender_code = user_init::init_code();
    let sender_frame = mm::alloc_frame().expect("no frame for sender code");
    let sender_phys = sender_frame.addr();
    unsafe {
        core::ptr::write_bytes((sender_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            sender_code.as_ptr(),
            (sender_phys + hhdm) as *mut u8,
            sender_code.len(),
        );
    }
    let sender_addr: u64 = 0x400000;
    addr_space.map_page(sender_addr, sender_phys, PAGE_PRESENT | PAGE_USER);

    // --- Copy receiver code to 0x401000 ---
    let recv_code = user_init::recv_code();
    let recv_frame = mm::alloc_frame().expect("no frame for receiver code");
    let recv_phys = recv_frame.addr();
    unsafe {
        core::ptr::write_bytes((recv_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            recv_code.as_ptr(),
            (recv_phys + hhdm) as *mut u8,
            recv_code.len(),
        );
    }
    let recv_addr: u64 = 0x401000;
    addr_space.map_page(recv_addr, recv_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate sender stack at 0x800000 ---
    let stack1_frame = mm::alloc_frame().expect("no frame for sender stack");
    let stack1_phys = stack1_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack1_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack1_base: u64 = 0x800000;
    addr_space.map_page(stack1_base, stack1_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack1_top = stack1_base + 0x1000;

    // --- Allocate receiver stack at 0x802000 ---
    let stack2_frame = mm::alloc_frame().expect("no frame for receiver stack");
    let stack2_phys = stack2_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack2_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack2_base: u64 = 0x802000;
    addr_space.map_page(stack2_base, stack2_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack2_top = stack2_base + 0x1000;

    // --- Create IPC endpoint 0 and its root capability ---
    let ep = ipc::endpoint::create().expect("failed to create endpoint");
    let ep_cap = cap::insert(cap::CapObject::Endpoint { id: ep.0 }, cap::Rights::ALL, None)
        .expect("failed to create endpoint cap");
    kprintln!("  ipc: endpoint {} created (cap {})", ep.0, ep_cap.index());

    kprintln!(
        "  init: receiver @ {:#x}, sender @ {:#x}, cr3 = {:#x}",
        recv_addr, sender_addr, cr3
    );

    // --- Copy keyboard driver code to 0x402000 ---
    let kb_code = user_init::kb_code();
    let kb_frame = mm::alloc_frame().expect("no frame for kb code");
    let kb_phys = kb_frame.addr();
    unsafe {
        core::ptr::write_bytes((kb_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            kb_code.as_ptr(),
            (kb_phys + hhdm) as *mut u8,
            kb_code.len(),
        );
    }
    let kb_addr: u64 = 0x402000;
    addr_space.map_page(kb_addr, kb_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate keyboard driver stack at 0x804000 ---
    let stack3_frame = mm::alloc_frame().expect("no frame for kb stack");
    let stack3_phys = stack3_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack3_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack3_base: u64 = 0x804000;
    addr_space.map_page(stack3_base, stack3_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack3_top = stack3_base + 0x1000;

    // --- Copy async producer code to 0x403000 ---
    let tx_code = user_init::async_tx_code();
    let tx_frame = mm::alloc_frame().expect("no frame for async tx code");
    let tx_phys = tx_frame.addr();
    unsafe {
        core::ptr::write_bytes((tx_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            tx_code.as_ptr(),
            (tx_phys + hhdm) as *mut u8,
            tx_code.len(),
        );
    }
    let tx_addr: u64 = 0x403000;
    addr_space.map_page(tx_addr, tx_phys, PAGE_PRESENT | PAGE_USER);

    // --- Copy async consumer code to 0x404000 ---
    let rx_code = user_init::async_rx_code();
    let rx_frame = mm::alloc_frame().expect("no frame for async rx code");
    let rx_phys = rx_frame.addr();
    unsafe {
        core::ptr::write_bytes((rx_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            rx_code.as_ptr(),
            (rx_phys + hhdm) as *mut u8,
            rx_code.len(),
        );
    }
    let rx_addr: u64 = 0x404000;
    addr_space.map_page(rx_addr, rx_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate async producer stack at 0x806000 ---
    let stack4_frame = mm::alloc_frame().expect("no frame for async tx stack");
    let stack4_phys = stack4_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack4_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack4_base: u64 = 0x806000;
    addr_space.map_page(stack4_base, stack4_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack4_top = stack4_base + 0x1000;

    // --- Allocate async consumer stack at 0x808000 ---
    let stack5_frame = mm::alloc_frame().expect("no frame for async rx stack");
    let stack5_phys = stack5_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack5_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack5_base: u64 = 0x808000;
    addr_space.map_page(stack5_base, stack5_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack5_top = stack5_base + 0x1000;

    // --- Copy child thread code to 0x405000 ---
    let child_code = user_init::child_code();
    let child_frame = mm::alloc_frame().expect("no frame for child code");
    let child_phys = child_frame.addr();
    unsafe {
        core::ptr::write_bytes((child_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            child_code.as_ptr(),
            (child_phys + hhdm) as *mut u8,
            child_code.len(),
        );
    }
    let child_addr: u64 = 0x405000;
    addr_space.map_page(child_addr, child_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate child thread stack at 0x80A000 ---
    let stack6_frame = mm::alloc_frame().expect("no frame for child stack");
    let stack6_phys = stack6_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack6_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack6_base: u64 = 0x80A000;
    addr_space.map_page(stack6_base, stack6_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    // Stack top = 0x80B000 (used by SYS_THREAD_CREATE from sender)

    // --- Create async channel 0 and its root capability ---
    let ch = ipc::channel::create().expect("failed to create channel");
    let ch_cap = cap::insert(cap::CapObject::Channel { id: ch.0 }, cap::Rights::ALL, None)
        .expect("failed to create channel cap");
    kprintln!("  ipc: channel {} created (cap {})", ch.0, ch_cap.index());

    // --- Create root capability for IRQ 1 (keyboard) ---
    let irq_cap = cap::insert(cap::CapObject::Irq { line: 1 }, cap::Rights::ALL, None)
        .expect("failed to create irq cap");
    kprintln!("  irq: keyboard cap {}", irq_cap.index());

    // --- Create root capability for I/O port 0x60 (keyboard data) ---
    let port_cap = cap::insert(cap::CapObject::IoPort { base: 0x60, count: 1 }, cap::Rights::ALL, None)
        .expect("failed to create ioport cap");
    kprintln!("  ioport: 0x60 cap {}", port_cap.index());

    // --- Create notification 0 and its root capability (cap 4) — SHM ---
    let notify = ipc::notify::create().expect("failed to create notification");
    let notify_cap = cap::insert(cap::CapObject::Notification { id: notify.0 }, cap::Rights::ALL, None)
        .expect("failed to create notification cap");
    kprintln!("  ipc: notification {} created (cap {})", notify.0, notify_cap.index());

    // --- Create notification 1 (cap 5) — keyboard IRQ ---
    let kb_notify = ipc::notify::create().expect("failed to create kb notification");
    let kb_notify_cap = cap::insert(cap::CapObject::Notification { id: kb_notify.0 }, cap::Rights::ALL, None)
        .expect("failed to create kb notification cap");
    kprintln!("  ipc: notification {} created (cap {}) — keyboard IRQ", kb_notify.0, kb_notify_cap.index());

    // --- Create IRQ 4 capability (cap 6) — COM1 ---
    let serial_irq_cap = cap::insert(cap::CapObject::Irq { line: 4 }, cap::Rights::ALL, None)
        .expect("failed to create serial irq cap");
    kprintln!("  irq: COM1 (IRQ 4) cap {}", serial_irq_cap.index());

    // --- Create I/O port range 0x3F8..0x3FF capability (cap 7) — COM1 ports ---
    let serial_port_cap = cap::insert(cap::CapObject::IoPort { base: 0x3F8, count: 8 }, cap::Rights::ALL, None)
        .expect("failed to create serial ioport cap");
    kprintln!("  ioport: 0x3F8-0x3FF cap {}", serial_port_cap.index());

    // --- Create notification 2 (cap 8) — serial IRQ ---
    let serial_notify = ipc::notify::create().expect("failed to create serial notification");
    let serial_notify_cap = cap::insert(cap::CapObject::Notification { id: serial_notify.0 }, cap::Rights::ALL, None)
        .expect("failed to create serial notification cap");
    kprintln!("  ipc: notification {} created (cap {}) — serial IRQ", serial_notify.0, serial_notify_cap.index());

    // --- Allocate shared page at 0x500000 (zero-copy IPC data) ---
    let shm_frame = mm::alloc_frame().expect("no frame for shared page");
    let shm_phys = shm_frame.addr();
    unsafe {
        core::ptr::write_bytes((shm_phys + hhdm) as *mut u8, 0, 4096);
    }
    let shm_addr: u64 = 0x500000;
    addr_space.map_page(shm_addr, shm_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);

    // --- Copy shm producer code to 0x406000 ---
    let shm_tx_code = user_init::shm_tx_code();
    let shm_tx_frame = mm::alloc_frame().expect("no frame for shm tx code");
    let shm_tx_phys = shm_tx_frame.addr();
    unsafe {
        core::ptr::write_bytes((shm_tx_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            shm_tx_code.as_ptr(),
            (shm_tx_phys + hhdm) as *mut u8,
            shm_tx_code.len(),
        );
    }
    let shm_tx_addr: u64 = 0x406000;
    addr_space.map_page(shm_tx_addr, shm_tx_phys, PAGE_PRESENT | PAGE_USER);

    // --- Copy shm consumer code to 0x407000 ---
    let shm_rx_code = user_init::shm_rx_code();
    let shm_rx_frame = mm::alloc_frame().expect("no frame for shm rx code");
    let shm_rx_phys = shm_rx_frame.addr();
    unsafe {
        core::ptr::write_bytes((shm_rx_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            shm_rx_code.as_ptr(),
            (shm_rx_phys + hhdm) as *mut u8,
            shm_rx_code.len(),
        );
    }
    let shm_rx_addr: u64 = 0x407000;
    addr_space.map_page(shm_rx_addr, shm_rx_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate shm producer stack at 0x80C000 ---
    let stack7_frame = mm::alloc_frame().expect("no frame for shm tx stack");
    let stack7_phys = stack7_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack7_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack7_base: u64 = 0x80C000;
    addr_space.map_page(stack7_base, stack7_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack7_top = stack7_base + 0x1000;

    // --- Allocate shm consumer stack at 0x80E000 ---
    let stack8_frame = mm::alloc_frame().expect("no frame for shm rx stack");
    let stack8_phys = stack8_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack8_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack8_base: u64 = 0x80E000;
    addr_space.map_page(stack8_base, stack8_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack8_top = stack8_base + 0x1000;

    // --- Copy serial driver code to 0x408000 ---
    let serial_code = user_init::serial_code();
    let serial_frame = mm::alloc_frame().expect("no frame for serial code");
    let serial_phys = serial_frame.addr();
    unsafe {
        core::ptr::write_bytes((serial_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            serial_code.as_ptr(),
            (serial_phys + hhdm) as *mut u8,
            serial_code.len(),
        );
    }
    let serial_addr: u64 = 0x408000;
    addr_space.map_page(serial_addr, serial_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate serial driver stack at 0x810000 ---
    let stack9_frame = mm::alloc_frame().expect("no frame for serial stack");
    let stack9_phys = stack9_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack9_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack9_base: u64 = 0x810000;
    addr_space.map_page(stack9_base, stack9_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack9_top = stack9_base + 0x1000;

    // --- Create notification 3 (cap 9) — fault delivery for VMM ---
    let fault_notify = ipc::notify::create().expect("failed to create fault notification");
    let fault_notify_cap = cap::insert(cap::CapObject::Notification { id: fault_notify.0 }, cap::Rights::ALL, None)
        .expect("failed to create fault notification cap");
    kprintln!("  ipc: notification {} created (cap {}) — fault delivery", fault_notify.0, fault_notify_cap.index());

    // --- Copy VMM server code to 0x409000 ---
    let vmm_code = user_init::vmm_code();
    let vmm_frame = mm::alloc_frame().expect("no frame for vmm code");
    let vmm_phys = vmm_frame.addr();
    unsafe {
        core::ptr::write_bytes((vmm_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            vmm_code.as_ptr(),
            (vmm_phys + hhdm) as *mut u8,
            vmm_code.len(),
        );
    }
    let vmm_addr: u64 = 0x409000;
    addr_space.map_page(vmm_addr, vmm_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate VMM stack at 0x812000 ---
    let stack10_frame = mm::alloc_frame().expect("no frame for vmm stack");
    let stack10_phys = stack10_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack10_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack10_base: u64 = 0x812000;
    addr_space.map_page(stack10_base, stack10_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack10_top = stack10_base + 0x1000;

    // --- Copy fault test code to 0x40A000 ---
    let ft_code = user_init::fault_test_code();
    let ft_frame = mm::alloc_frame().expect("no frame for fault test code");
    let ft_phys = ft_frame.addr();
    unsafe {
        core::ptr::write_bytes((ft_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            ft_code.as_ptr(),
            (ft_phys + hhdm) as *mut u8,
            ft_code.len(),
        );
    }
    let ft_addr: u64 = 0x40A000;
    addr_space.map_page(ft_addr, ft_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate fault test stack at 0x814000 ---
    let stack11_frame = mm::alloc_frame().expect("no frame for fault test stack");
    let stack11_phys = stack11_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack11_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack11_base: u64 = 0x814000;
    addr_space.map_page(stack11_base, stack11_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack11_top = stack11_base + 0x1000;

    // Spawn order:
    //   1. Sync receiver — blocks on Recv(ep 0)
    //   2. Sync sender — runs, rendezvous with receiver
    //   3. Keyboard driver — registers IRQ 1, blocks on NOTIFY_WAIT
    //   4. Async consumer — blocks on empty channel
    //   5. Async producer — sends 5 messages, consumer wakes
    //   6. SHM consumer — blocks on NOTIFY_WAIT (notification 0)
    //   7. SHM producer — writes data to 0x500000, signals notification
    //   8. Serial driver — sets up COM1 receive IRQ, blocks on NOTIFY_WAIT
    //   9. VMM server — registers for faults, blocks on NOTIFY_WAIT
    //  10. Fault test — touches 0x600000, faults, VMM handles, resumes
    sched::spawn_user(recv_addr, stack2_top, cr3);
    sched::spawn_user(sender_addr, stack1_top, cr3);
    sched::spawn_user(kb_addr, stack3_top, cr3);
    sched::spawn_user(rx_addr, stack5_top, cr3);
    sched::spawn_user(tx_addr, stack4_top, cr3);
    sched::spawn_user(shm_rx_addr, stack8_top, cr3);
    sched::spawn_user(shm_tx_addr, stack7_top, cr3);
    sched::spawn_user(serial_addr, stack9_top, cr3);
    sched::spawn_user(vmm_addr, stack10_top, cr3);
    sched::spawn_user(ft_addr, stack11_top, cr3);

    cr3
}

/// Load an ELF binary from the initramfs module (if present).
///
/// The bootloader delivers the initramfs as a module. We parse the CPIO
/// archive to find "init", load the ELF segments, allocate a stack, and
/// spawn a user thread. The new thread shares the existing user address
/// space (same CR3).
fn load_initrd(cr3: u64) {
    use mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let response = match MODULE_REQUEST.get_response() {
        Some(r) => r,
        None => return, // No modules loaded — initrd is optional
    };

    let modules = response.modules();
    if modules.is_empty() {
        return;
    }

    let module = modules[0];
    let module_data = unsafe {
        core::slice::from_raw_parts(module.addr(), module.size() as usize)
    };
    kprintln!("  initrd: {} bytes", module.size());

    // Find the "init" entry in the CPIO archive.
    let elf_data = match initrd::find(module_data, "init") {
        Some(d) => d,
        None => {
            kprintln!("  initrd: 'init' not found in archive");
            return;
        }
    };
    kprintln!("  initrd: found 'init' ({} bytes)", elf_data.len());

    // Load ELF segments into the user address space.
    let addr_space = AddressSpace::from_cr3(cr3);
    let entry = match elf::load(elf_data, &addr_space) {
        Ok(e) => e,
        Err(msg) => {
            kprintln!("  initrd: ELF load failed: {}", msg);
            return;
        }
    };
    kprintln!("  initrd: entry = {:#x}", entry);

    // Allocate a user stack at 0x900000.
    let stack_frame = mm::alloc_frame().expect("no frame for ELF stack");
    let stack_phys = stack_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack_phys + mm::hhdm_offset()) as *mut u8, 0, 4096);
    }
    let stack_base: u64 = 0x900000;
    addr_space.map_page(stack_base, stack_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack_top = stack_base + 0x1000;

    sched::spawn_user(entry, stack_top, cr3);
}
