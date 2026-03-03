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
mod sync;
mod syscall;
mod user_init;

use core::sync::atomic::{AtomicU32, Ordering};
use limine::BaseRevision;
use limine::request::{HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RequestsEndMarker, RequestsStartMarker};

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

/// Request SMP info from the bootloader (AP processor list).
#[used]
#[link_section = ".requests"]
static MP_REQUEST: MpRequest = MpRequest::new();

/// Counter for APs that have finished initialization.
static APS_READY: AtomicU32 = AtomicU32::new(0);

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

    // Per-CPU data (GS base). Must be after slab init (heap-allocated).
    let bsp_percpu = arch::percpu::init_bsp();
    kprintln!("[ok] PerCpu (BSP)");

    // Per-CPU GDT + TSS (replaces early-boot static GDT).
    arch::gdt::init_percpu(bsp_percpu);
    kprintln!("[ok] Per-CPU GDT+TSS (BSP)");

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

    // LAPIC: per-CPU timer (replaces PIT for preemption).
    arch::lapic::init();
    kprintln!("[ok] LAPIC");

    let lapic_ticks = arch::lapic::calibrate();
    kprintln!("[ok] LAPIC calibrated ({} ticks/10ms)", lapic_ticks);

    // Spawn init process (first userspace code).
    let user_cr3 = spawn_init_process();
    kprintln!("[ok] Init process");

    // Load ELF from initramfs (if present).
    load_initrd(user_cr3);
    kprintln!("[ok] Initrd");

    // Mask PIT IRQ (no longer needed — using LAPIC timer).
    arch::pic::mask(0);

    // Boot Application Processors (before enabling interrupts on BSP).
    boot_aps();

    // Start BSP LAPIC timer (~100 Hz periodic).
    arch::lapic::start_timer(lapic_ticks);

    // Enable interrupts.
    x86_64::instructions::interrupts::enable();
    kprintln!("Kernel ready — entering idle loop");

    // Idle loop (thread 0). Timer interrupts cause preemptive switching.
    loop {
        x86_64::instructions::hlt();
    }
}

// ---------------------------------------------------------------------------
// SMP: Application Processor boot
// ---------------------------------------------------------------------------

/// Boot all Application Processors via the Limine MP protocol.
fn boot_aps() {
    let response = match MP_REQUEST.get_response() {
        Some(r) => r,
        None => {
            kprintln!("  smp: no MP response (single CPU)");
            return;
        }
    };

    let bsp_lapic_id = response.bsp_lapic_id();
    let cpus = response.cpus();

    // Update BSP percpu with correct LAPIC ID from ACPI.
    let bsp_percpu = arch::percpu::current_percpu();
    bsp_percpu.lapic_id = bsp_lapic_id;

    let ap_count = cpus.iter().filter(|c| c.lapic_id != bsp_lapic_id).count();
    if ap_count == 0 {
        kprintln!("  smp: BSP only (LAPIC ID {})", bsp_lapic_id);
        return;
    }
    kprintln!("  smp: {} CPUs detected, booting {} APs...", cpus.len(), ap_count);

    let mut cpu_index: u32 = 1; // BSP is 0
    for cpu in cpus.iter() {
        if cpu.lapic_id == bsp_lapic_id {
            continue; // Skip BSP
        }

        // Allocate PerCpu for this AP.
        let percpu = arch::percpu::alloc_ap(cpu_index, cpu.lapic_id);

        // Create an idle thread for this AP.
        let idle_idx = sched::create_idle_thread();
        percpu.idle_thread = idle_idx;
        percpu.current_thread = idle_idx;

        // Store PerCpu pointer in the extra field for the AP to pick up.
        let percpu_addr = percpu as *mut _ as u64;
        cpu.extra.store(percpu_addr, Ordering::Release);

        // Launch the AP.
        cpu.goto_address.write(ap_entry);

        cpu_index += 1;
    }

    // Spin-wait for all APs to signal ready.
    while APS_READY.load(Ordering::Acquire) < ap_count as u32 {
        core::hint::spin_loop();
    }
    kprintln!("  smp: all {} APs online", ap_count);
}

/// Entry point for Application Processors, called by Limine after goto_address.write().
unsafe extern "C" fn ap_entry(cpu: &limine::mp::Cpu) -> ! {
    // Read PerCpu pointer from extra field.
    let percpu_addr = cpu.extra.load(Ordering::Acquire);
    let percpu = unsafe { &mut *(percpu_addr as *mut arch::percpu::PerCpu) };

    // Set GS base for this CPU.
    arch::percpu::write_gs_base(percpu_addr);

    // Load the shared IDT.
    arch::idt::load();

    // Allocate per-CPU GDT + TSS.
    arch::gdt::init_percpu(percpu);

    // Program SYSCALL/SYSRET MSRs (per-CPU).
    arch::syscall::init();

    // Initialize LAPIC (reads APIC base MSR, maps MMIO if needed, enables).
    arch::lapic::init();

    // Start LAPIC timer with BSP-calibrated tick count.
    let ticks = arch::lapic::calibrated_ticks();
    arch::lapic::start_timer(ticks);

    // Signal BSP that this AP is ready.
    APS_READY.fetch_add(1, Ordering::Release);

    kprintln!("  CPU {} online (LAPIC {})", percpu.cpu_index, percpu.lapic_id);

    // Enable interrupts and enter idle HLT loop.
    x86_64::instructions::interrupts::enable();
    loop {
        x86_64::instructions::hlt();
    }
}

// ---------------------------------------------------------------------------
// Init process layout — all virtual addresses used by assembly blob threads.
// ---------------------------------------------------------------------------

mod init_layout {
    // Code pages (RX)
    pub const SENDER_CODE:    u64 = 0x400000;
    pub const RECV_CODE:      u64 = 0x401000;
    pub const KB_CODE:        u64 = 0x402000;
    pub const ASYNC_TX_CODE:  u64 = 0x403000;
    pub const ASYNC_RX_CODE:  u64 = 0x404000;
    pub const CHILD_CODE:     u64 = 0x405000;
    pub const SHM_TX_CODE:    u64 = 0x406000;
    pub const SHM_RX_CODE:    u64 = 0x407000;
    pub const SERIAL_CODE:    u64 = 0x408000;
    pub const VMM_CODE:       u64 = 0x409000;
    pub const FAULT_TEST_CODE:u64 = 0x40A000;

    // Stack pages (RW)
    pub const SENDER_STACK:   u64 = 0x800000;
    pub const RECV_STACK:     u64 = 0x802000;
    pub const KB_STACK:       u64 = 0x804000;
    pub const ASYNC_TX_STACK: u64 = 0x806000;
    pub const ASYNC_RX_STACK: u64 = 0x808000;
    pub const CHILD_STACK:    u64 = 0x80A000;
    pub const SHM_TX_STACK:   u64 = 0x80C000;
    pub const SHM_RX_STACK:   u64 = 0x80E000;
    pub const SERIAL_STACK:   u64 = 0x810000;
    pub const VMM_STACK:      u64 = 0x812000;
    pub const FAULT_TEST_STACK: u64 = 0x814000;

    // Shared memory
    pub const SHARED_PAGE:    u64 = 0x500000;
}

/// Allocate a frame, zero it, copy code bytes, map as RX at `vaddr`.
fn map_code_page(
    addr_space: &mm::paging::AddressSpace,
    code: &[u8],
    vaddr: u64,
    hhdm: u64,
) {
    use mm::paging::{PAGE_PRESENT, PAGE_USER};

    let frame = mm::alloc_frame().expect("no frame for code page");
    let phys = frame.addr();
    unsafe {
        core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(code.as_ptr(), (phys + hhdm) as *mut u8, code.len());
    }
    addr_space.map_page(vaddr, phys, PAGE_PRESENT | PAGE_USER);
}

/// Allocate a frame, zero it, map as RW at `vaddr`. Returns stack top (vaddr + 0x1000).
fn map_stack_page(
    addr_space: &mm::paging::AddressSpace,
    vaddr: u64,
    hhdm: u64,
) -> u64 {
    use mm::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let frame = mm::alloc_frame().expect("no frame for stack page");
    let phys = frame.addr();
    unsafe {
        core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
    }
    addr_space.map_page(vaddr, phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    vaddr + 0x1000
}

/// Map all 11 code blobs into the user address space.
fn map_all_blobs(addr_space: &mm::paging::AddressSpace, hhdm: u64) {
    use init_layout::*;

    map_code_page(addr_space, user_init::init_code(),       SENDER_CODE, hhdm);
    map_code_page(addr_space, user_init::recv_code(),       RECV_CODE, hhdm);
    map_code_page(addr_space, user_init::kb_code(),         KB_CODE, hhdm);
    map_code_page(addr_space, user_init::async_tx_code(),   ASYNC_TX_CODE, hhdm);
    map_code_page(addr_space, user_init::async_rx_code(),   ASYNC_RX_CODE, hhdm);
    map_code_page(addr_space, user_init::child_code(),      CHILD_CODE, hhdm);
    map_code_page(addr_space, user_init::shm_tx_code(),     SHM_TX_CODE, hhdm);
    map_code_page(addr_space, user_init::shm_rx_code(),     SHM_RX_CODE, hhdm);
    map_code_page(addr_space, user_init::serial_code(),     SERIAL_CODE, hhdm);
    map_code_page(addr_space, user_init::vmm_code(),        VMM_CODE, hhdm);
    map_code_page(addr_space, user_init::fault_test_code(), FAULT_TEST_CODE, hhdm);
}

/// Allocate all 11 stacks + shared memory page. Returns stack tops as array.
fn map_all_stacks(addr_space: &mm::paging::AddressSpace, hhdm: u64) -> [u64; 11] {
    use init_layout::*;
    use mm::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    // Shared memory page (RW, not a stack)
    let shm_frame = mm::alloc_frame().expect("no frame for shared page");
    let shm_phys = shm_frame.addr();
    unsafe { core::ptr::write_bytes((shm_phys + hhdm) as *mut u8, 0, 4096); }
    addr_space.map_page(SHARED_PAGE, shm_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);

    [
        map_stack_page(addr_space, SENDER_STACK, hhdm),
        map_stack_page(addr_space, RECV_STACK, hhdm),
        map_stack_page(addr_space, KB_STACK, hhdm),
        map_stack_page(addr_space, ASYNC_TX_STACK, hhdm),
        map_stack_page(addr_space, ASYNC_RX_STACK, hhdm),
        map_stack_page(addr_space, CHILD_STACK, hhdm),
        map_stack_page(addr_space, SHM_TX_STACK, hhdm),
        map_stack_page(addr_space, SHM_RX_STACK, hhdm),
        map_stack_page(addr_space, SERIAL_STACK, hhdm),
        map_stack_page(addr_space, VMM_STACK, hhdm),
        map_stack_page(addr_space, FAULT_TEST_STACK, hhdm),
    ]
}

/// Create all root capabilities for init (endpoint, channel, notifications, IRQs, I/O ports).
fn create_init_caps() {
    // Endpoint
    let ep = ipc::endpoint::create().expect("failed to create endpoint");
    let ep_cap = cap::insert(cap::CapObject::Endpoint { id: ep.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create endpoint cap");
    kprintln!("  cap {}: endpoint", ep_cap.raw());

    // Async channel
    let ch = ipc::channel::create().expect("failed to create channel");
    let ch_cap = cap::insert(cap::CapObject::Channel { id: ch.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create channel cap");
    kprintln!("  cap {}: channel", ch_cap.raw());

    // IRQ 1 (keyboard)
    let irq_cap = cap::insert(cap::CapObject::Irq { line: 1 }, cap::Rights::ALL, None)
        .expect("failed to create irq cap");
    kprintln!("  cap {}: IRQ 1 (keyboard)", irq_cap.raw());

    // I/O port 0x60 (keyboard data)
    let port_cap = cap::insert(cap::CapObject::IoPort { base: 0x60, count: 1 }, cap::Rights::ALL, None)
        .expect("failed to create ioport cap");
    kprintln!("  cap {}: port 0x60", port_cap.raw());

    // Notification 0 — SHM
    let n0 = ipc::notify::create().expect("failed to create notification");
    let n0_cap = cap::insert(cap::CapObject::Notification { id: n0.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create notification cap");
    kprintln!("  cap {}: notification (SHM)", n0_cap.raw());

    // Notification 1 — keyboard IRQ
    let n1 = ipc::notify::create().expect("failed to create notification");
    let n1_cap = cap::insert(cap::CapObject::Notification { id: n1.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create notification cap");
    kprintln!("  cap {}: notification (KB IRQ)", n1_cap.raw());

    // IRQ 4 (COM1)
    let sirq_cap = cap::insert(cap::CapObject::Irq { line: 4 }, cap::Rights::ALL, None)
        .expect("failed to create serial irq cap");
    kprintln!("  cap {}: IRQ 4 (COM1)", sirq_cap.raw());

    // I/O port range 0x3F8-0x3FF (COM1)
    let sport_cap = cap::insert(cap::CapObject::IoPort { base: 0x3F8, count: 8 }, cap::Rights::ALL, None)
        .expect("failed to create serial ioport cap");
    kprintln!("  cap {}: port 0x3F8-0x3FF", sport_cap.raw());

    // Notification 2 — serial IRQ
    let n2 = ipc::notify::create().expect("failed to create notification");
    let n2_cap = cap::insert(cap::CapObject::Notification { id: n2.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create notification cap");
    kprintln!("  cap {}: notification (serial IRQ)", n2_cap.raw());

    // Notification 3 — fault delivery (VMM)
    let n3 = ipc::notify::create().expect("failed to create notification");
    let n3_cap = cap::insert(cap::CapObject::Notification { id: n3.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create notification cap");
    kprintln!("  cap {}: notification (VMM faults)", n3_cap.raw());
}

/// Create the user address space, map code+stacks, create caps, spawn all threads.
fn spawn_init_process() -> u64 {
    use init_layout::*;

    let addr_space = mm::paging::AddressSpace::new_user();
    let hhdm = mm::hhdm_offset();
    let cr3 = addr_space.cr3();

    // 1. Map all code blobs
    map_all_blobs(&addr_space, hhdm);

    // 2. Map all stacks + shared page
    let stacks = map_all_stacks(&addr_space, hhdm);
    // stacks: [sender, recv, kb, async_tx, async_rx, child, shm_tx, shm_rx, serial, vmm, fault_test]

    // 3. Create root capabilities
    create_init_caps();

    kprintln!("  init: cr3 = {:#x}", cr3);

    // 4. Spawn all threads in dependency order
    //   recv blocks on ep → sender rendezvous → kb → async_rx → async_tx
    //   → shm_rx → shm_tx → serial → vmm → fault_test
    let recv_tid = sched::spawn_user(RECV_CODE,       stacks[1], cr3);  // recv
    let sender_tid = sched::spawn_user(SENDER_CODE,     stacks[0], cr3);  // sender
    sched::spawn_user(KB_CODE,         stacks[2], cr3);  // keyboard
    sched::spawn_user(ASYNC_RX_CODE,   stacks[4], cr3);  // async consumer
    sched::spawn_user(ASYNC_TX_CODE,   stacks[3], cr3);  // async producer
    sched::spawn_user(SHM_RX_CODE,     stacks[7], cr3);  // shm consumer
    sched::spawn_user(SHM_TX_CODE,     stacks[6], cr3);  // shm producer
    sched::spawn_user(SERIAL_CODE,     stacks[8], cr3);  // serial driver
    sched::spawn_user(VMM_CODE,        stacks[9], cr3);  // VMM server
    sched::spawn_user(FAULT_TEST_CODE, stacks[10], cr3); // fault test

    // 5. Create a test scheduling domain: quantum=5, period=20 (25% CPU share).
    //    Attach sender + receiver threads to demonstrate budget enforcement.
    if let Some(dom_handle) = sched::create_domain(5, 20) {
        let _ = sched::attach_to_domain(dom_handle, sender_tid);
        let _ = sched::attach_to_domain(dom_handle, recv_tid);
        kprintln!("  init: domain test — sender+recv attached (25% CPU budget)");
    }

    cr3
}

/// Load an ELF binary from the initramfs module (if present).
///
/// The bootloader delivers the initramfs as a module. We parse the CPIO
/// archive to find "init", load the ELF segments, allocate a stack, write
/// BootInfo, and spawn a user thread. The new thread shares the existing
/// user address space (same CR3).
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

    // Write BootInfo page at 0xB00000 (read-only for userspace).
    write_boot_info(cr3, &addr_space);

    sched::spawn_user(entry, stack_top, cr3);
}

/// Write a BootInfo struct to 0xB00000 with all root capabilities granted to init.
fn write_boot_info(
    _cr3: u64,
    addr_space: &mm::paging::AddressSpace,
) {
    use mm::paging::{PAGE_PRESENT, PAGE_USER};
    use sotos_common::{BOOT_INFO_ADDR, BOOT_INFO_MAGIC, BootInfo};

    let hhdm = mm::hhdm_offset();
    let frame = mm::alloc_frame().expect("no frame for BootInfo");
    let phys = frame.addr();
    unsafe {
        core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
    }

    // Map read-only into user address space (PAGE_PRESENT | PAGE_USER, no WRITABLE).
    addr_space.map_page(BOOT_INFO_ADDR, phys, PAGE_PRESENT | PAGE_USER);

    // Collect all existing capability IDs (caps 0..N created during spawn_init_process).
    // We know caps 0-9 were created. Query the cap table for them.
    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;

    let mut count = 0u64;
    for i in 0..sotos_common::BOOT_INFO_MAX_CAPS as u32 {
        if cap::lookup(cap::CapId::new(i)).is_some() {
            if (count as usize) < sotos_common::BOOT_INFO_MAX_CAPS {
                info.caps[count as usize] = i as u64;
                count += 1;
            }
        }
    }
    info.cap_count = count;

    // Write the struct via HHDM.
    unsafe {
        let ptr = (phys + hhdm) as *mut BootInfo;
        core::ptr::write(ptr, info);
    }

    kprintln!("  bootinfo: {} caps at {:#x}", count, BOOT_INFO_ADDR);
}
