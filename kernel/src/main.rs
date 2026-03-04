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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use limine::BaseRevision;
use limine::request::{FramebufferRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RequestsEndMarker, RequestsStartMarker};

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

/// Request a framebuffer from the bootloader.
#[used]
#[link_section = ".requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

/// Counter for APs that have finished initialization.
static APS_READY: AtomicU32 = AtomicU32::new(0);

/// Guest (LUCAS shell) ELF entry point, set by load_initrd().
static GUEST_ENTRY: AtomicU64 = AtomicU64::new(0);

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

/// Virtual address for keyboard scancode ring buffer (shared between KB driver + LUCAS handler).
const KB_RING_PAGE: u64 = 0x510000;

/// Create root capabilities for init (keyboard caps removed — they go to kbd process).
///
/// Cap 0: Notification (VMM page faults)
/// Cap 1: I/O port 0xCF8-0xCFF (PCI config)
fn create_init_caps() {
    // Cap 0: Notification — fault delivery (VMM)
    let n_vmm = ipc::notify::create().expect("failed to create notification");
    let n_vmm_cap = cap::insert(cap::CapObject::Notification { id: n_vmm.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create notification cap");
    kprintln!("  cap {}: notification (VMM faults)", n_vmm_cap.raw());

    // Cap 1: PCI config space ports 0xCF8-0xCFF (8 bytes: address + data)
    let pci_cap = cap::insert(cap::CapObject::IoPort { base: 0xCF8, count: 8 }, cap::Rights::ALL, None)
        .expect("failed to create PCI ioport cap");
    kprintln!("  cap {}: port 0xCF8-0xCFF (PCI config)", pci_cap.raw());
}

/// Create the user address space, map KB ring page, create caps.
/// No assembly blobs or blob threads — VMM and KB driver are Rust
/// functions in the init binary, spawned by init itself.
fn spawn_init_process() -> u64 {
    use mm::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let addr_space = mm::paging::AddressSpace::new_user();
    let hhdm = mm::hhdm_offset();
    let cr3 = addr_space.cr3();

    // Map KB ring buffer page at 0x510000 (shared between KB driver + LUCAS handler).
    let kb_ring_frame = mm::alloc_frame().expect("no frame for KB ring");
    let kb_ring_phys = kb_ring_frame.addr();
    unsafe { core::ptr::write_bytes((kb_ring_phys + hhdm) as *mut u8, 0, 4096); }
    addr_space.map_page(KB_RING_PAGE, kb_ring_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);

    // Create root capabilities.
    create_init_caps();

    kprintln!("  init: cr3 = {:#x}", cr3);

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

    // Find and load "shell" binary (LUCAS guest) if present.
    if let Some(shell_data) = initrd::find(module_data, "shell") {
        kprintln!("  initrd: found 'shell' ({} bytes)", shell_data.len());
        match elf::load(shell_data, &addr_space) {
            Ok(shell_entry) => {
                kprintln!("  initrd: shell entry = {:#x}", shell_entry);
                GUEST_ENTRY.store(shell_entry, Ordering::Release);
            }
            Err(msg) => {
                kprintln!("  initrd: shell ELF load failed: {}", msg);
            }
        }
    }

    // Allocate a user stack at 0x900000 (4 pages = 16 KiB).
    let stack_base: u64 = 0x900000;
    let stack_pages: u64 = 4;
    for i in 0..stack_pages {
        let sf = mm::alloc_frame().expect("no frame for ELF stack");
        let sp = sf.addr();
        unsafe {
            core::ptr::write_bytes((sp + mm::hhdm_offset()) as *mut u8, 0, 4096);
        }
        addr_space.map_page(stack_base + i * 0x1000, sp, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }
    let stack_top = stack_base + stack_pages * 0x1000;

    // Write BootInfo page at 0xB00000 (read-only for userspace).
    write_boot_info(cr3, &addr_space);

    sched::spawn_user(entry, stack_top, cr3);

    // --- Load "kbd" as a separate process (if present in initrd) ---
    if let Some(kbd_data) = initrd::find(module_data, "kbd") {
        kprintln!("  initrd: found 'kbd' ({} bytes)", kbd_data.len());
        load_kbd_process(kbd_data, cr3);
    }
}

/// Write a BootInfo struct to 0xB00000 with all root capabilities granted to init.
fn write_boot_info(
    _cr3: u64,
    addr_space: &mm::paging::AddressSpace,
) {
    use mm::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE, PAGE_CACHE_DISABLE, PAGE_WRITE_THROUGH};
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
    info.guest_entry = GUEST_ENTRY.load(Ordering::Acquire);

    // Map framebuffer into user address space if available.
    if let Some(fb_response) = FRAMEBUFFER_REQUEST.get_response() {
        if let Some(fb) = fb_response.framebuffers().next() {
            let fb_virt = fb.addr() as u64;
            let fb_phys = fb_virt - hhdm;
            let width = fb.width() as u32;
            let height = fb.height() as u32;
            let pitch = fb.pitch() as u32;
            let bpp = fb.bpp() as u32;
            let fb_size = (pitch as u64) * (height as u64);
            let fb_pages = (fb_size + 0xFFF) / 0x1000;
            let fb_user_base: u64 = 0x4000000;

            for i in 0..fb_pages {
                addr_space.map_page(
                    fb_user_base + i * 0x1000,
                    fb_phys + i * 0x1000,
                    PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER
                        | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH,
                );
            }

            info.fb_addr = fb_user_base;
            info.fb_width = width;
            info.fb_height = height;
            info.fb_pitch = pitch;
            info.fb_bpp = bpp;
            kprintln!("  fb: {}x{} bpp={} phys=0x{:x} ({} pages)", width, height, bpp, fb_phys, fb_pages);
        }
    }

    // Write the struct via HHDM.
    unsafe {
        let ptr = (phys + hhdm) as *mut BootInfo;
        core::ptr::write(ptr, info);
    }

    kprintln!("  bootinfo: {} caps at {:#x}", count, BOOT_INFO_ADDR);
}

/// Load the keyboard driver as a fully pre-mapped separate process.
///
/// Creates a new address space, loads the ELF, maps stack, shared KB ring page,
/// creates kbd-specific capabilities, and spawns the thread.
fn load_kbd_process(kbd_data: &[u8], init_cr3: u64) {
    use mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let kbd_as = AddressSpace::new_user();
    let kbd_cr3 = kbd_as.cr3();

    // Load ELF segments into the kbd address space.
    let kbd_entry = match elf::load(kbd_data, &kbd_as) {
        Ok(e) => e,
        Err(msg) => {
            kprintln!("  kbd: ELF load failed: {}", msg);
            return;
        }
    };
    kprintln!("  kbd: entry = {:#x}", kbd_entry);

    let hhdm = mm::hhdm_offset();

    // Stack for kbd (4 pages at 0x900000 in kbd's AS).
    let stack_base: u64 = 0x900000;
    let stack_pages: u64 = 4;
    for i in 0..stack_pages {
        let sf = mm::alloc_frame().expect("no frame for kbd stack");
        unsafe { core::ptr::write_bytes((sf.addr() + hhdm) as *mut u8, 0, 4096); }
        kbd_as.map_page(stack_base + i * 0x1000, sf.addr(),
            PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }
    let stack_top = stack_base + stack_pages * 0x1000;

    // Map shared KB ring page into kbd's AS at 0x510000.
    // Find the physical address of init's 0x510000 (already mapped).
    let init_as = AddressSpace::from_cr3(init_cr3);
    let kb_ring_phys = init_as.lookup_phys(KB_RING_PAGE)
        .expect("init's KB ring page not mapped");
    kbd_as.map_page(KB_RING_PAGE, kb_ring_phys,
        PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);

    // Create kbd capabilities and write BootInfo.
    write_kbd_boot_info(kbd_cr3, &kbd_as);

    sched::spawn_user(kbd_entry, stack_top, kbd_cr3);
    kprintln!("  kbd: separate process, cr3={:#x}", kbd_cr3);
}

/// Write BootInfo for the keyboard driver process.
///
/// Creates fresh capabilities for kbd:
///   Cap 0: IRQ 1 (keyboard)
///   Cap 1: I/O port 0x60 (keyboard data)
///   Cap 2: Notification (KB IRQ delivery)
fn write_kbd_boot_info(
    _kbd_cr3: u64,
    kbd_as: &mm::paging::AddressSpace,
) {
    use mm::paging::{PAGE_PRESENT, PAGE_USER};
    use sotos_common::{BOOT_INFO_ADDR, BOOT_INFO_MAGIC, BootInfo};

    let hhdm = mm::hhdm_offset();
    let frame = mm::alloc_frame().expect("no frame for kbd BootInfo");
    let phys = frame.addr();
    unsafe {
        core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
    }

    // Map read-only into kbd address space.
    kbd_as.map_page(BOOT_INFO_ADDR, phys, PAGE_PRESENT | PAGE_USER);

    // Create kbd-specific capabilities.
    let irq_cap = cap::insert(cap::CapObject::Irq { line: 1 }, cap::Rights::ALL, None)
        .expect("failed to create kbd irq cap");
    kprintln!("  kbd cap {}: IRQ 1 (keyboard)", irq_cap.raw());

    let port_cap = cap::insert(cap::CapObject::IoPort { base: 0x60, count: 1 }, cap::Rights::ALL, None)
        .expect("failed to create kbd ioport cap");
    kprintln!("  kbd cap {}: port 0x60", port_cap.raw());

    let n_kb = ipc::notify::create().expect("failed to create kbd notification");
    let n_kb_cap = cap::insert(cap::CapObject::Notification { id: n_kb.0.raw() }, cap::Rights::ALL, None)
        .expect("failed to create kbd notification cap");
    kprintln!("  kbd cap {}: notification (KB IRQ)", n_kb_cap.raw());

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 3;
    info.caps[0] = irq_cap.raw() as u64;
    info.caps[1] = port_cap.raw() as u64;
    info.caps[2] = n_kb_cap.raw() as u64;

    unsafe {
        let ptr = (phys + hhdm) as *mut BootInfo;
        core::ptr::write(ptr, info);
    }

    kprintln!("  kbd bootinfo: 3 caps at {:#x}", BOOT_INFO_ADDR);
}
