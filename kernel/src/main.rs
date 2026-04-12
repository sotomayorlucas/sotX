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
// Many subsystems (EFI shim, chacha RNG, fast-IPC scaffolding, demand-paging,
// CHERI/NUMA/GPU placeholders, migrate/snapshot, W^X enforcer, BSD user
// table, etc.) are landed ahead of their wiring. Their symbols are
// intentionally unused today but must stay in-tree so the cleanup PR cost
// doesn't spike when they come online. Targeted allows — no blanket
// `allow(warnings)`.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
// Style-only clippy lints that fire widely on kernel code where the
// "more idiomatic" rewrite costs readability or requires per-CPU
// arrays to be iterator-sourced. Each is opt-in and targeted, not a
// blanket `allow(warnings)` or `allow(clippy::all)`.
//
// * needless_range_loop — many `for i in 0..MAX_CPUS` loops index into
//   per-CPU static arrays where the index itself is meaningful.
// * manual_div_ceil — `.div_ceil()` is nightly-unstable on const fns
//   in older toolchains; existing `(x + N - 1) / N` is the audited form.
// * declare_interior_mutable_const — `const INIT: TicketMutex<_>` is
//   the standard pattern for `static [Mutex; N]` array initialization
//   and is correct here (each array slot gets its own instance).
// * manual_is_multiple_of — `x % N == 0` is clearer than the proposed
//   nightly `.is_multiple_of(N)` for alignment math in the kernel.
// * manual_find / manual_flatten / manual_contains — rewriting tight
//   hot loops over fixed-size arrays into iterator chains obscures the
//   fast-path without changing the generated code.
// * manual_checked_ops — explicit `if denom > 0` is intentional and
//   kept for symmetry with the watchdog/stats counters.
// * unnecessary_cast — cross-ABI register loads where the cast
//   documents the user/kernel boundary width.
// * unnecessary_map_or — `map_or(false, ...)` reads clearer than
//   `is_some_and` in places that pair with `Option::map`.
// * if_same_then_else, collapsible_if, collapsible_match — kept
//   expanded for branch-specific kprintln! tracing.
// * wrong_self_convention — kernel FFI structs mirror hardware layout.
// * fn_to_numeric_cast — trampolines deliberately expose function
//   addresses as raw u64 for IDT/LAPIC setup.
// * identity_op, doc_lazy_continuation, vec_init_then_push,
//   question_mark — very small one-off occurrences where the existing
//   form matches surrounding code.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_find)]
#![allow(clippy::manual_flatten)]
#![allow(clippy::manual_contains)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::fn_to_numeric_cast)]
#![allow(clippy::identity_op)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::question_mark)]

extern crate alloc;

mod acpi;
mod arch;
pub mod boot_splash;
mod boot_uefi;
mod cap;
pub mod dbg_diag;
mod elf;
mod fault;
mod initrd;
mod ipc;
mod irq;
mod karl;
mod migrate;
mod mm;
mod panic;
mod pool;
mod sched;
mod shm;
mod sot;
mod svc_registry;
mod sync;
mod syscall;
pub mod trace;
mod user;
mod vm;
pub mod watchdog;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------
// Stack canary support — __stack_chk_guard / __stack_chk_fail
// ---------------------------------------------------------------
// When `-Z stack-protector=strong` is enabled, LLVM inserts a canary
// check in function prologues/epilogues reading from __stack_chk_guard.
// On mismatch, __stack_chk_fail is called.

/// The stack canary value. Initialized with RDTSC entropy in kmain().
#[used]
#[no_mangle]
pub static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000; // sentinel until real init

/// Called when a stack buffer overflow is detected.
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    // Use raw serial output — don't trust anything on the stack.
    unsafe {
        let msg = b"!!! STACK SMASH DETECTED (kernel) !!!\n";
        for &b in msg {
            x86_64::instructions::port::Port::<u8>::new(0x3F8).write(b);
        }
    }
    x86_64::instructions::interrupts::disable();
    arch::halt_loop()
}

use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RequestsEndMarker,
    RequestsStartMarker, RsdpRequest,
};
use limine::BaseRevision;

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

/// Request the ACPI RSDP virtual address from Limine. Used by the
/// Phase E ACPI parser to discover IOAPIC + ISO entries.
#[used]
#[link_section = ".requests"]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

/// Counter for APs that have finished initialization.
static APS_READY: AtomicU32 = AtomicU32::new(0);

/// Guest (LUCAS shell) ELF entry point, set by load_initrd().
static GUEST_ENTRY: AtomicU64 = AtomicU64::new(0);

/// Enable SSE/SSE2 by clearing CR0.EM, setting CR0.MP, and setting
/// CR4.OSFXSR + CR4.OSXMMEXCPT. Required for userspace code (e.g. musl)
/// that uses SSE instructions like movaps/movups.
fn enable_sse() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    unsafe {
        // CR0: clear EM (emulation), set MP (monitor coprocessor)
        let mut cr0 = Cr0::read();
        cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
        cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
        Cr0::write(cr0);
        // CR4: enable FXSAVE/FXRSTOR and SIMD exceptions
        let mut cr4 = Cr4::read();
        cr4.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        Cr4::write(cr4);
    }
}

/// Kernel entry point — called by the Limine bootloader.
#[no_mangle]
extern "C" fn kmain() -> ! {
    // Serial MUST be first — we need debug output before anything else.
    arch::serial::init();

    // Suppress verbose output during splash (kinfo!/kdebug! become no-ops).
    // Errors still print via kerror!/kerr!.
    boot_splash::VERBOSE.store(false, Ordering::Release);

    // Show centered Tokyo Night boot splash with empty progress bar.
    boot_splash::show();

    // KARL-style per-boot ID seed -- derived from RDTSC + a fixed
    // mixer. Read by tx, sched, and other id pools so that visible
    // identifiers drift across reboots.
    karl::init();

    if !BASE_REVISION.is_supported() {
        kerr!("FATAL: Limine base revision not supported");
        arch::halt_loop();
    }

    // ---------------------------------------------------------------
    // Stage 0: CPU + memory
    // ---------------------------------------------------------------
    boot_splash::set_progress(0, "CPU + memory");

    // CPU structures.
    arch::gdt::init();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] GDT");

    // Enable SSE/SSE2 so userspace can use SIMD instructions (musl requires it).
    enable_sse();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] SSE");

    arch::idt::init();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] IDT");

    // Physical frame allocator from bootloader memory map.
    let mmap_response = MEMORY_MAP_REQUEST
        .get_response()
        .expect("bootloader: no memory map");
    let hhdm_response = HHDM_REQUEST.get_response().expect("bootloader: no HHDM");

    mm::init(mmap_response, hhdm_response.offset());
    kinfo!(sotos_common::trace::cat::MM, "[ok] Frame allocator");

    // Slab allocator (kernel heap).
    mm::slab::init();
    kinfo!(sotos_common::trace::cat::MM, "[ok] Slab allocator");

    // Per-CPU data (GS base). Must be after slab init (heap-allocated).
    let bsp_percpu = arch::percpu::init_bsp();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] PerCpu (BSP)");

    // Per-CPU GDT + TSS (replaces early-boot static GDT).
    arch::gdt::init_percpu(bsp_percpu);
    kinfo!(
        sotos_common::trace::cat::PROCESS,
        "[ok] Per-CPU GDT+TSS (BSP)"
    );

    // Smoke test: prove alloc works.
    {
        let mut v = alloc::vec::Vec::new();
        v.push(1u64);
        v.push(2);
        v.push(3);
        assert_eq!(v.iter().sum::<u64>(), 6);
        kinfo!(sotos_common::trace::cat::MM, "[ok] Heap (Vec test)");
    }

    // Save boot CR3 before any address space changes.
    mm::paging::init_boot_cr3();

    // ---------------------------------------------------------------
    // Stage 1: Scheduler + IPC
    // ---------------------------------------------------------------
    boot_splash::set_progress(1, "Scheduler + IPC");

    // Capability system.
    cap::init();
    // Tier 5 KARL: seed the channel/notification/endpoint pools so
    // their visible IDs drift across reboots, just like cap IDs.
    ipc::channel::init();
    ipc::notify::init();
    ipc::endpoint::init();
    kinfo!(sotos_common::trace::cat::IPC, "[ok] Capabilities");

    // Scheduler.
    sched::init();
    kinfo!(sotos_common::trace::cat::SCHED, "[ok] Scheduler");

    // SYSCALL/SYSRET MSRs.
    arch::syscall::init();
    kinfo!(sotos_common::trace::cat::SYSCALL, "[ok] SYSCALL/SYSRET");

    // ---------------------------------------------------------------
    // Stage 2: Capabilities
    // ---------------------------------------------------------------
    boot_splash::set_progress(2, "Capabilities");

    // Hardware interrupts.
    arch::pic::init();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] PIC");

    // LAPIC: per-CPU timer (replaces PIT for preemption).
    arch::lapic::init();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] LAPIC");

    let lapic_ticks = arch::lapic::calibrate();
    kinfo!(
        sotos_common::trace::cat::PROCESS,
        "[ok] LAPIC calibrated ({} ticks/10ms)",
        lapic_ticks
    );

    // ---------------------------------------------------------------
    // Stage 3: Drivers
    // ---------------------------------------------------------------
    boot_splash::set_progress(3, "Drivers");

    // Phase E — ACPI parser + IOAPIC discovery + MSI vector allocator.
    if let Some(rsdp) = RSDP_REQUEST.get_response() {
        acpi::init(rsdp.address());
    } else {
        kdebug!("  acpi: limine did not provide an RSDP — skipping");
    }
    arch::ioapic::init_all();
    irq::init_msi();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] ACPI + IOAPIC + MSI");

    // Phase E — MSI delivery acceptance test.
    {
        use core::sync::atomic::Ordering;
        let lapic_id = arch::percpu::current_percpu().lapic_id;
        let before = arch::idt::MSI_TEST_COUNTER.load(Ordering::Acquire);
        arch::lapic::send_ipi(lapic_id, irq::MSI_TEST_VECTOR);
        // Sti window so the LAPIC delivers the queued vector.
        unsafe { core::arch::asm!("sti", "nop", "cli", options(nomem, nostack)); }
        let after = arch::idt::MSI_TEST_COUNTER.load(Ordering::Acquire);
        if after == before + 1 {
            kdebug!(
                "  msi-test: self-IPI (vector {}) delivered, counter {} -> {} — PASS",
                irq::MSI_TEST_VECTOR,
                before,
                after
            );
        } else {
            kerr!(
                "msi-test: self-IPI delivery failed; counter {} -> {} (expected +1)",
                before,
                after
            );
        }
    }

    // VMX capability detection (Phase B.0 — read-only).
    arch::vmx::print_capabilities();

    // VMX bringup on the BSP (Phase B.1 + B.2).
    arch::vmx::init_bsp();

    // Phase C: VM subsystem driven by userspace via SYS_VM_* syscalls.
    vm::init();

    // ---------------------------------------------------------------
    // Stage 4: Userspace
    // ---------------------------------------------------------------
    boot_splash::set_progress(4, "Userspace");

    // Spawn init process (first userspace code).
    let user_cr3 = spawn_init_process();
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] Init process");

    // Load ELF from initramfs (if present).
    load_initrd(user_cr3);
    kinfo!(sotos_common::trace::cat::PROCESS, "[ok] Initrd");

    // Mask PIT IRQ (no longer needed — using LAPIC timer).
    arch::pic::mask(0);

    // Boot Application Processors (before enabling interrupts on BSP).
    boot_aps();

    // Start BSP LAPIC timer (~100 Hz periodic).
    arch::lapic::start_timer(lapic_ticks);

    // ---------------------------------------------------------------
    // Boot complete — finalize splash and enter idle loop
    // ---------------------------------------------------------------
    boot_splash::set_progress(5, "ready");
    boot_splash::finish();

    // Re-enable verbose output now that splash is done.
    boot_splash::VERBOSE.store(true, Ordering::Release);

    // Enable interrupts.
    x86_64::instructions::interrupts::enable();

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
            kdebug!("  smp: no MP response (single CPU)");
            return;
        }
    };

    let bsp_lapic_id = response.bsp_lapic_id();
    let cpus = response.cpus();

    // Update BSP percpu with correct LAPIC ID from ACPI.
    let bsp_percpu = arch::percpu::current_percpu();
    bsp_percpu.lapic_id = bsp_lapic_id;
    // R1: register BSP's logical-index → LAPIC-ID mapping so reschedule
    // IPIs targeting CPU 0 from another CPU resolve to the right APIC.
    sched::register_cpu_lapic_id(0, bsp_lapic_id);

    let ap_count = cpus.iter().filter(|c| c.lapic_id != bsp_lapic_id).count();
    if ap_count == 0 {
        kdebug!("  smp: BSP only (LAPIC ID {})", bsp_lapic_id);
        return;
    }
    kdebug!(
        "  smp: {} CPUs detected, booting {} APs...",
        cpus.len(),
        ap_count
    );

    let mut cpu_index: u32 = 1; // BSP is 0
    for cpu in cpus.iter() {
        if cpu.lapic_id == bsp_lapic_id {
            continue; // Skip BSP
        }

        // Allocate PerCpu for this AP.
        let percpu = arch::percpu::alloc_ap(cpu_index, cpu.lapic_id);

        // R1: register the AP's logical-index → LAPIC-ID mapping. Must
        // happen before the AP is launched so any reschedule IPI from
        // the BSP to this CPU resolves to the correct APIC.
        sched::register_cpu_lapic_id(cpu_index as usize, cpu.lapic_id);

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

    // Spin-wait for all APs to signal ready, with TSC-based timeout.
    let tsc_start = {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        ((hi as u64) << 32) | (lo as u64)
    };
    const TSC_TIMEOUT: u64 = 500_000_000; // ~250ms at 2 GHz
    loop {
        if APS_READY.load(Ordering::Acquire) >= ap_count as u32 {
            break;
        }
        let tsc_now = {
            let lo: u32;
            let hi: u32;
            unsafe {
                core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
            }
            ((hi as u64) << 32) | (lo as u64)
        };
        if tsc_now.wrapping_sub(tsc_start) > TSC_TIMEOUT {
            let ready = APS_READY.load(Ordering::Acquire);
            kdebug!("  smp: TIMEOUT — {}/{} APs responded", ready, ap_count);
            break;
        }
        core::hint::spin_loop();
    }
    let online = APS_READY.load(Ordering::Acquire);
    kdebug!(
        "  smp: {} CPUs online ({} BSP + {} APs)",
        online + 1,
        1,
        online
    );
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

    // Enable SSE/SSE2 for this CPU.
    enable_sse();

    // Program SYSCALL/SYSRET MSRs (per-CPU).
    arch::syscall::init();

    // Initialize LAPIC (reads APIC base MSR, maps MMIO if needed, enables).
    arch::lapic::init();

    // Start LAPIC timer with BSP-calibrated tick count.
    let ticks = arch::lapic::calibrated_ticks();
    arch::lapic::start_timer(ticks);

    // Signal BSP that this AP is ready.
    APS_READY.fetch_add(1, Ordering::Release);

    kdebug!(
        "  CPU {} online (LAPIC {})",
        percpu.cpu_index,
        percpu.lapic_id
    );

    // Enable interrupts and enter idle HLT loop.
    x86_64::instructions::interrupts::enable();
    loop {
        x86_64::instructions::hlt();
    }
}

use sotos_common::{ASLR_JITTER_PAGES, BAR0_VIRT_BASE, FB_USER_BASE, PROCESS_STACK_BASE};
use sotos_common::{
    CONSOLE_RING_ADDR as CONSOLE_RING_PAGE, KB_RING_ADDR as KB_RING_PAGE,
    MOUSE_RING_ADDR as MOUSE_RING_PAGE,
};

// ---------------------------------------------------------------------------
// Process loading helpers — shared by all load_*_process() functions
// ---------------------------------------------------------------------------

const PCI_CONFIG_PORT: u16 = 0xCF8;
const PCI_DATA_PORT: u16 = 0xCFC;

/// Allocate a user stack with ASLR jitter and a guard page.
/// Returns `stack_top` (the initial RSP value for the new thread).
fn allocate_user_stack(addr_space: &mm::paging::AddressSpace, stack_pages: u64, name: &str) -> u64 {
    use mm::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};
    let hhdm = mm::hhdm_offset();

    let stack_rand = (mm::random_u64() % ASLR_JITTER_PAGES) * 0x1000;
    let stack_base = PROCESS_STACK_BASE + stack_rand;

    // Guard page: present but not user-accessible — triggers fault on overflow.
    let guard_frame =
        mm::alloc_frame().unwrap_or_else(|| panic!("no frame for {} stack guard", name));
    addr_space.map_page(stack_base - 0x1000, guard_frame.addr(), PAGE_PRESENT);

    for i in 0..stack_pages {
        let sf = mm::alloc_frame().unwrap_or_else(|| panic!("no frame for {} stack", name));
        unsafe {
            core::ptr::write_bytes((sf.addr() + hhdm) as *mut u8, 0, 4096);
        }
        addr_space.map_page(
            stack_base + i * 0x1000,
            sf.addr(),
            PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER,
        );
    }

    let stack_top = stack_base + stack_pages * 0x1000;
    kdebug!(
        "  {}: stack = {:#x}..{:#x} (ASLR offset {:#x})",
        name,
        stack_base,
        stack_top,
        stack_rand
    );
    stack_top
}

/// Allocate a zeroed BootInfo page and map it read-only into the given address space.
/// Returns the physical address of the page (write BootInfo struct via HHDM).
fn alloc_bootinfo_page(addr_space: &mm::paging::AddressSpace, name: &str) -> u64 {
    use mm::paging::{PAGE_PRESENT, PAGE_USER};
    use sotos_common::BOOT_INFO_ADDR;
    let hhdm = mm::hhdm_offset();

    let frame = mm::alloc_frame().unwrap_or_else(|| panic!("no frame for {} BootInfo", name));
    let phys = frame.addr();
    unsafe {
        core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
    }
    addr_space.map_page(BOOT_INFO_ADDR, phys, PAGE_PRESENT | PAGE_USER);
    phys
}

/// Write a BootInfo struct to a pre-allocated physical page.
fn write_bootinfo(phys: u64, info: &sotos_common::BootInfo) {
    let hhdm = mm::hhdm_offset();
    unsafe {
        let ptr = (phys + hhdm) as *mut sotos_common::BootInfo;
        core::ptr::write(ptr, *info);
    }
}

/// Load an ELF binary into an address space, returning the entry point.
/// Returns None on failure (logs the error).
fn load_elf_into(data: &[u8], addr_space: &mm::paging::AddressSpace, name: &str) -> Option<u64> {
    match elf::load(data, addr_space) {
        Ok(entry) => {
            kdebug!("  {}: entry = {:#x}", name, entry);
            Some(entry)
        }
        Err(msg) => {
            kdebug!("  {}: ELF load failed: {}", name, msg);
            None
        }
    }
}

/// Map framebuffer into a user address space and fill BootInfo fb fields.
fn map_framebuffer(addr_space: &mm::paging::AddressSpace, info: &mut sotos_common::BootInfo) {
    use mm::paging::{
        PAGE_CACHE_DISABLE, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE, PAGE_WRITE_THROUGH,
    };
    let hhdm = mm::hhdm_offset();

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

            for i in 0..fb_pages {
                addr_space.map_page(
                    FB_USER_BASE + i * 0x1000,
                    fb_phys + i * 0x1000,
                    PAGE_PRESENT
                        | PAGE_WRITABLE
                        | PAGE_USER
                        | PAGE_CACHE_DISABLE
                        | PAGE_WRITE_THROUGH,
                );
            }

            info.fb_addr = FB_USER_BASE;
            info.fb_width = width;
            info.fb_height = height;
            info.fb_pitch = pitch;
            info.fb_bpp = bpp;
            kdebug!(
                "  fb: {}x{} bpp={} phys=0x{:x} ({} pages)",
                width,
                height,
                bpp,
                fb_phys,
                fb_pages
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Generic service process loader (WU-03)
// ---------------------------------------------------------------------------

/// A loaded but not-yet-spawned service process.
struct LoadedProcess {
    addr_space: mm::paging::AddressSpace,
    cr3: u64,
    entry: u64,
    stack_top: u64,
}

/// Specification for loading a service process.
struct ProcessSpec<'a> {
    name: &'a str,
    data: &'a [u8],
    stack_pages: u64,
}

/// Create a new address space, load an ELF, and allocate a stack.
/// Returns None if ELF loading fails.
fn load_service(spec: &ProcessSpec) -> Option<LoadedProcess> {
    let addr_space = mm::paging::AddressSpace::new_user();
    let cr3 = addr_space.cr3();
    let entry = load_elf_into(spec.data, &addr_space, spec.name)?;
    let stack_top = allocate_user_stack(&addr_space, spec.stack_pages, spec.name);
    Some(LoadedProcess {
        addr_space,
        cr3,
        entry,
        stack_top,
    })
}

impl LoadedProcess {
    /// Map a shared ring page from init's address space into this process.
    fn map_shared_ring(&self, init_cr3: u64, ring_addr: u64) {
        use mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};
        let init_as = AddressSpace::from_cr3(init_cr3);
        let phys = init_as
            .lookup_phys(ring_addr)
            .unwrap_or_else(|| panic!("ring page {:#x} not mapped in init", ring_addr));
        self.addr_space
            .map_page(ring_addr, phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }

    /// Spawn the process thread.
    fn spawn(&self) {
        sched::spawn_user(self.entry, self.stack_top, self.cr3);
    }
}

/// Pre-map device BAR0 MMIO pages (uncacheable) at BAR0_VIRT_BASE.
fn map_bar0_mmio(addr_space: &mm::paging::AddressSpace, bar0_phys: u64, pages: u64, name: &str) {
    use mm::paging::{
        PAGE_CACHE_DISABLE, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE, PAGE_WRITE_THROUGH,
    };
    for i in 0..pages {
        addr_space.map_page(
            BAR0_VIRT_BASE + i * 0x1000,
            bar0_phys + i * 0x1000,
            PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH,
        );
    }
    kdebug!(
        "  {}: BAR0 {:#x} mapped at {:#x} ({}p, UC)",
        name,
        bar0_phys,
        BAR0_VIRT_BASE,
        pages
    );
}

/// Scan PCI bus 0 for a device matching the given class/subclass (and optional prog_if).
/// Returns (BAR0 physical address, IRQ line) if found.
/// Enables bus mastering + memory space in the PCI command register.
fn scan_pci_for_device(
    class: u8,
    subclass: u8,
    prog_if: Option<u8>,
    name: &str,
) -> Option<(u64, u8)> {
    use x86_64::instructions::port::Port;

    let mut addr_port = Port::<u32>::new(PCI_CONFIG_PORT);
    let mut data_port = Port::<u32>::new(PCI_DATA_PORT);

    for dev in 0..32u8 {
        let address: u32 = (1 << 31) | ((dev as u32) << 11);

        // Read vendor/device (offset 0x00).
        unsafe {
            addr_port.write(address);
        }
        let vendor_device = unsafe { data_port.read() };
        if (vendor_device & 0xFFFF) == 0xFFFF {
            continue;
        }

        // Read class/subclass/prog_if (offset 0x08).
        unsafe {
            addr_port.write(address | 0x08);
        }
        let class_rev = unsafe { data_port.read() };
        let dev_class = (class_rev >> 24) as u8;
        let dev_subclass = ((class_rev >> 16) & 0xFF) as u8;
        let dev_prog_if = ((class_rev >> 8) & 0xFF) as u8;

        if dev_class != class || dev_subclass != subclass {
            continue;
        }
        if let Some(required_pi) = prog_if {
            if dev_prog_if != required_pi {
                continue;
            }
        }

        // Device found. Read BAR0 (offset 0x10).
        unsafe {
            addr_port.write(address | 0x10);
        }
        let bar0 = unsafe { data_port.read() };
        if bar0 & 1 != 0 {
            continue; // I/O port BAR, skip
        }
        let bar_type = (bar0 >> 1) & 3;
        let base_lo = (bar0 & !0xF) as u64;
        let bar0_phys = if bar_type == 2 {
            // 64-bit BAR: read BAR1 (offset 0x14).
            unsafe {
                addr_port.write(address | 0x14);
            }
            let bar1 = unsafe { data_port.read() };
            base_lo | ((bar1 as u64) << 32)
        } else {
            base_lo
        };

        // Read IRQ line (offset 0x3C).
        unsafe {
            addr_port.write(address | 0x3C);
        }
        let irq_reg = unsafe { data_port.read() };
        let irq_line = (irq_reg & 0xFF) as u8;

        // Enable bus mastering (bit 2) + memory space (bit 1).
        unsafe {
            addr_port.write(address | 0x04);
        }
        let cmd = unsafe { data_port.read() };
        unsafe {
            addr_port.write(address | 0x04);
        }
        unsafe {
            data_port.write(cmd | (1 << 1) | (1 << 2));
        }

        kdebug!(
            "  {}: PCI dev={} BAR0={:#x} IRQ={}",
            name,
            dev,
            bar0_phys,
            irq_line
        );
        return Some((bar0_phys, irq_line));
    }
    None
}

/// Create a PCI config I/O port capability (0xCF8-0xCFF).
fn create_pci_cap(name: &str) -> cap::CapId {
    let pci_cap = cap::insert(
        cap::CapObject::IoPort {
            base: PCI_CONFIG_PORT,
            count: 8,
        },
        cap::Rights::ALL,
        None,
    )
    .unwrap_or_else(|| panic!("failed to create {} PCI ioport cap", name));
    kdebug!(
        "  {} cap {}: port 0xCF8-0xCFF (PCI config)",
        name,
        pci_cap.raw()
    );
    pci_cap
}

/// Create root capabilities for init (VMM and keyboard caps removed — they go to separate processes).
///
/// Cap 0: I/O port 0xCF8-0xCFF (PCI config)
fn create_init_caps() {
    create_pci_cap("init");
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
    unsafe {
        core::ptr::write_bytes((kb_ring_phys + hhdm) as *mut u8, 0, 4096);
    }
    addr_space.map_page(
        KB_RING_PAGE,
        kb_ring_phys,
        PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER,
    );

    // Map mouse ring buffer page at 0x520000 (shared between mouse driver + desktop).
    let mouse_ring_frame = mm::alloc_frame().expect("no frame for mouse ring");
    let mouse_ring_phys = mouse_ring_frame.addr();
    unsafe {
        core::ptr::write_bytes((mouse_ring_phys + hhdm) as *mut u8, 0, 4096);
    }
    addr_space.map_page(
        MOUSE_RING_PAGE,
        mouse_ring_phys,
        PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER,
    );

    // Map console ring buffer page at CONSOLE_RING_ADDR (kernel writes, init reads).
    let console_ring_frame = mm::alloc_frame().expect("no frame for console ring");
    let console_ring_phys = console_ring_frame.addr();
    unsafe {
        core::ptr::write_bytes((console_ring_phys + hhdm) as *mut u8, 0, 4096);
    }
    addr_space.map_page(
        CONSOLE_RING_PAGE,
        console_ring_phys,
        PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER,
    );
    // Tell the kernel fb_console module the physical address so kprintln! can
    // push bytes into the ring from this point onwards.
    arch::x86_64::fb_console::init(console_ring_phys + hhdm);

    // Create root capabilities.
    create_init_caps();

    kdebug!("  init: cr3 = {:#x}", cr3);

    cr3
}

/// Load an ELF binary from the initramfs module (if present).
///
/// The bootloader delivers the initramfs as a module. We parse the CPIO
/// archive to find "init", load the ELF segments, allocate a stack, write
/// BootInfo, and spawn a user thread. The new thread shares the existing
/// user address space (same CR3).
fn load_initrd(cr3: u64) {
    use mm::paging::AddressSpace;

    let response = match MODULE_REQUEST.get_response() {
        Some(r) => r,
        None => return, // No modules loaded — initrd is optional
    };

    let modules = response.modules();
    if modules.is_empty() {
        return;
    }

    let module = modules[0];
    let module_data = unsafe { core::slice::from_raw_parts(module.addr(), module.size() as usize) };
    kdebug!("  initrd: {} bytes", module.size());

    // Save initrd location for userspace InitrdRead syscall.
    let hhdm = mm::hhdm_offset();
    let initrd_phys = module.addr() as u64 - hhdm;
    initrd::set_initrd(initrd_phys, module.size());

    // Single-pass CPIO scan for all service binaries (matroid optimization).
    let names = [
        "init",
        "shell",
        "vmm",
        "kbd",
        "net",
        "nvme",
        "xhci",
        "compositor",
        "hello-gui",
        "bzImage",
        "guest-initramfs",
        "sotos-term",
    ];
    let found = initrd::find_all(module_data, &names);
    // Indices: 0=init, 1=shell, 2=vmm, 3=kbd, 4=net, 5=nvme, 6=xhci,
    //          7=compositor, 8=hello-gui, 9=bzImage, 10=guest-initramfs,
    //          11=sotos-term

    // Phase F.4 — stash the bzImage slice's physical pointer + length
    // in a kernel global so the VM subsystem (`vm::run_payload_on_vm`)
    // can grab it without re-scanning the CPIO archive.
    if let Some(bz) = found[9] {
        crate::vm::set_bzimage(bz);
        kdebug!("  initrd: found 'bzImage' ({} bytes)", bz.len());
        match crate::vm::bzimage::BzImage::parse(bz) {
            Ok(parsed) => parsed.dump(),
            Err(e) => kprintln!("  bzImage: parse failed: {:?}", e),
        }
    }
    // Phase F.6.3 — stash the guest initramfs (cpio.gz).
    if let Some(rd) = found[10] {
        crate::vm::set_guest_initramfs(rd);
        kdebug!("  initrd: found 'guest-initramfs' ({} bytes)", rd.len());
    }

    let elf_data = match found[0] {
        Some(d) => d,
        None => {
            kdebug!("  initrd: 'init' not found in archive");
            return;
        }
    };
    kdebug!("  initrd: found 'init' ({} bytes)", elf_data.len());

    // Load ELF segments into the user address space.
    let addr_space = AddressSpace::from_cr3(cr3);
    let entry = match elf::load(elf_data, &addr_space) {
        Ok(e) => e,
        Err(msg) => {
            kdebug!("  initrd: ELF load failed: {}", msg);
            return;
        }
    };
    kdebug!("  initrd: entry = {:#x}", entry);

    // Find and load "shell" binary (LUCAS guest) if present.
    kprintln!("  initrd: shell lookup = {}", if found[1].is_some() { "FOUND" } else { "MISSING" });
    if let Some(shell_data) = found[1] {
        kdebug!("  initrd: found 'shell' ({} bytes)", shell_data.len());
        match elf::load(shell_data, &addr_space) {
            Ok(shell_entry) => {
                kdebug!("  initrd: shell entry = {:#x}", shell_entry);
                GUEST_ENTRY.store(shell_entry, Ordering::Release);
            }
            Err(msg) => {
                kdebug!("  initrd: shell ELF load failed: {}", msg);
            }
        }
    }

    // Tier 5: Ed25519 verify (ed25519-compact) plus SHA-512 burns ~8KB
    // of stack, on top of init's existing usage. 16 pages (64 KB) gives
    // headroom; 4 pages overflowed into the BootInfo page.
    let stack_top = allocate_user_stack(&addr_space, 16, "init");

    // Create an AddrSpace cap for init's own AS (for CoW fork cloning).
    let init_as_cap = cap::insert(cap::CapObject::AddrSpace { cr3 }, cap::Rights::ALL, None)
        .expect("failed to create init self-AS cap");
    kdebug!("  init self-AS cap: {} (cr3={:#x})", init_as_cap.raw(), cr3);

    // Write BootInfo page at 0xB00000 (read-only for userspace).
    write_boot_info(cr3, &addr_space, stack_top, init_as_cap.raw() as u64);

    // --- Load "vmm" BEFORE spawning init --- (PARALLEL-SPAWN-SAFE: independent)
    // VMM must be in the run queue first so it registers for faults
    // before init can page-fault.
    if let Some(vmm_data) = found[2] {
        kdebug!("  initrd: found 'vmm' ({} bytes)", vmm_data.len());
        load_vmm_process(vmm_data, cr3);
    }

    sched::spawn_user(entry, stack_top, cr3);

    // --- PARALLEL-SPAWN-SAFE: kbd, net, nvme, xhci, compositor are independent ---
    if let Some(kbd_data) = found[3] {
        kdebug!("  initrd: found 'kbd' ({} bytes)", kbd_data.len());
        load_kbd_process(kbd_data, cr3);
    }
    if let Some(net_data) = found[4] {
        kdebug!("  initrd: found 'net' ({} bytes)", net_data.len());
        load_net_process(net_data);
    }
    if let Some(nvme_data) = found[5] {
        kdebug!("  initrd: found 'nvme' ({} bytes)", nvme_data.len());
        load_nvme_process(nvme_data);
    }
    if let Some(xhci_data) = found[6] {
        kdebug!("  initrd: found 'xhci' ({} bytes)", xhci_data.len());
        load_xhci_process(xhci_data, cr3);
    }
    if let Some(comp_data) = found[7] {
        kdebug!("  initrd: found 'compositor' ({} bytes)", comp_data.len());
        load_compositor_process(comp_data, cr3);
    }
    if let Some(gui_data) = found[8] {
        kdebug!("  initrd: found 'hello-gui' ({} bytes)", gui_data.len());
        load_hello_gui_process(gui_data);
    }
    if let Some(term_data) = found[11] {
        kdebug!("  initrd: found 'sotos-term' ({} bytes)", term_data.len());
        load_sotos_term_process(term_data);
    }
}

/// Write a BootInfo struct to 0xB00000 with all root capabilities granted to init.
fn write_boot_info(
    _cr3: u64,
    addr_space: &mm::paging::AddressSpace,
    stack_top: u64,
    self_as_cap: u64,
) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let hhdm = mm::hhdm_offset();
    let phys = alloc_bootinfo_page(addr_space, "init");

    // Collect all existing capability IDs (caps 0..N created during spawn_init_process).
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
    map_framebuffer(addr_space, &mut info);

    info.stack_top = stack_top;
    info.self_as_cap = self_as_cap;

    write_bootinfo(phys, &info);
    kdebug!("  bootinfo: {} caps at {:#x}", count, BOOT_INFO_ADDR);
}

/// Load the VMM as a separate process. Must be spawned BEFORE init.
fn load_vmm_process(vmm_data: &[u8], init_cr3: u64) {
    let proc = match load_service(&ProcessSpec {
        name: "vmm",
        data: vmm_data,
        stack_pages: 4,
    }) {
        Some(p) => p,
        None => return,
    };
    write_vmm_boot_info(&proc.addr_space, init_cr3);
    proc.spawn();
    kdebug!("  vmm: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for the VMM process.
///
/// Creates fresh capabilities for VMM:
///   Cap 0: Notification (fault delivery)
///   Cap 1: AddrSpace (init's CR3) — for fault_register_as + map_into
fn write_vmm_boot_info(vmm_as: &mm::paging::AddressSpace, init_cr3: u64) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(vmm_as, "vmm");

    // Cap 0: VMM notification (fault delivery).
    let n_vmm = ipc::notify::create().expect("failed to create vmm notification");
    let n_vmm_cap = cap::insert(
        cap::CapObject::Notification { id: n_vmm.0.raw() },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create vmm notification cap");
    kdebug!(
        "  vmm cap {}: notification (fault delivery)",
        n_vmm_cap.raw()
    );

    // Cap 1: AddrSpace for init's CR3 (allows fault_register_as + map_into).
    let init_as_cap = cap::insert(
        cap::CapObject::AddrSpace { cr3: init_cr3 },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create init AS cap");
    kdebug!(
        "  vmm cap {}: addr_space (init cr3={:#x})",
        init_as_cap.raw(),
        init_cr3
    );

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 2;
    info.caps[0] = n_vmm_cap.raw() as u64;
    info.caps[1] = init_as_cap.raw() as u64;

    write_bootinfo(phys, &info);
    kdebug!("  vmm bootinfo: 2 caps at {:#x}", BOOT_INFO_ADDR);
}

/// Load the keyboard driver as a separate process.
fn load_kbd_process(kbd_data: &[u8], init_cr3: u64) {
    let proc = match load_service(&ProcessSpec {
        name: "kbd",
        data: kbd_data,
        stack_pages: 4,
    }) {
        Some(p) => p,
        None => return,
    };
    proc.map_shared_ring(init_cr3, KB_RING_PAGE);
    proc.map_shared_ring(init_cr3, MOUSE_RING_PAGE);
    write_kbd_boot_info(proc.cr3, &proc.addr_space);
    proc.spawn();
    kdebug!("  kbd: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for the keyboard driver process.
///
/// Creates fresh capabilities for kbd:
///   Cap 0: IRQ 1 (keyboard)
///   Cap 1: I/O port 0x60–0x64 (PS/2 data + command)
///   Cap 2: Notification (KB+mouse IRQ delivery)
///   Cap 3: IRQ 12 (mouse)
fn write_kbd_boot_info(_kbd_cr3: u64, kbd_as: &mm::paging::AddressSpace) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(kbd_as, "kbd");

    // Create kbd-specific capabilities.
    let irq_cap = cap::insert(cap::CapObject::Irq { line: 1 }, cap::Rights::ALL, None)
        .expect("failed to create kbd irq cap");
    kdebug!("  kbd cap {}: IRQ 1 (keyboard)", irq_cap.raw());

    let port_cap = cap::insert(
        cap::CapObject::IoPort {
            base: 0x60,
            count: 5,
        },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create kbd ioport cap");
    kdebug!("  kbd cap {}: port 0x60-0x64", port_cap.raw());

    let n_kb = ipc::notify::create().expect("failed to create kbd notification");
    let n_kb_cap = cap::insert(
        cap::CapObject::Notification { id: n_kb.0.raw() },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create kbd notification cap");
    kdebug!("  kbd cap {}: notification (KB+mouse IRQ)", n_kb_cap.raw());

    let mouse_irq_cap = cap::insert(cap::CapObject::Irq { line: 12 }, cap::Rights::ALL, None)
        .expect("failed to create mouse irq cap");
    kdebug!("  kbd cap {}: IRQ 12 (mouse)", mouse_irq_cap.raw());

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 4;
    info.caps[0] = irq_cap.raw() as u64;
    info.caps[1] = port_cap.raw() as u64;
    info.caps[2] = n_kb_cap.raw() as u64;
    info.caps[3] = mouse_irq_cap.raw() as u64;

    write_bootinfo(phys, &info);

    kdebug!("  kbd bootinfo: 4 caps at {:#x}", BOOT_INFO_ADDR);
}

/// Load the network driver as a separate process (16-page stack for DHCP+smoltcp).
fn load_net_process(net_data: &[u8]) {
    let proc = match load_service(&ProcessSpec {
        name: "net",
        data: net_data,
        stack_pages: 16,
    }) {
        Some(p) => p,
        None => return,
    };
    write_net_boot_info(proc.cr3, &proc.addr_space);
    proc.spawn();
    kdebug!("  net: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for the network driver process.
///
/// Creates fresh capabilities for net:
///   Cap 0: I/O port 0xCF8-0xCFF (PCI config)
fn write_net_boot_info(_net_cr3: u64, net_as: &mm::paging::AddressSpace) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(net_as, "net");
    let pci_cap = create_pci_cap("net");

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 1;
    info.caps[0] = pci_cap.raw() as u64;

    write_bootinfo(phys, &info);
    kdebug!("  net bootinfo: 1 cap at {:#x}", BOOT_INFO_ADDR);
}

// ---------------------------------------------------------------------------
// NVMe SSD driver process
// ---------------------------------------------------------------------------

// NVMe: class=0x01 (Mass Storage), subclass=0x08 (NVM), any prog_if
fn scan_pci_for_nvme() -> Option<(u64, u8)> {
    scan_pci_for_device(0x01, 0x08, None, "nvme")
}

/// Load the NVMe driver as a separate process.
fn load_nvme_process(nvme_data: &[u8]) {
    let (bar0_phys, _irq_line) = match scan_pci_for_nvme() {
        Some(r) => r,
        None => {
            kdebug!("  nvme: no NVMe controller found on PCI bus — skipping");
            return;
        }
    };
    let proc = match load_service(&ProcessSpec {
        name: "nvme",
        data: nvme_data,
        stack_pages: 4,
    }) {
        Some(p) => p,
        None => return,
    };
    map_bar0_mmio(&proc.addr_space, bar0_phys, 16, "nvme");
    write_nvme_boot_info(&proc.addr_space);
    proc.spawn();
    kdebug!("  nvme: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for the NVMe driver process.
///
/// Creates fresh capabilities:
///   Cap 0: I/O port 0xCF8-0xCFF (PCI config)
fn write_nvme_boot_info(nvme_as: &mm::paging::AddressSpace) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(nvme_as, "nvme");
    let pci_cap = create_pci_cap("nvme");

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 1;
    info.caps[0] = pci_cap.raw() as u64;

    write_bootinfo(phys, &info);
    kdebug!("  nvme bootinfo: 1 cap at {:#x}", BOOT_INFO_ADDR);
}

// ---------------------------------------------------------------------------
// xHCI USB Host Controller driver process
// ---------------------------------------------------------------------------

// xHCI: class=0x0C (Serial Bus), subclass=0x03 (USB), prog_if=0x30 (xHCI)
fn scan_pci_for_xhci() -> Option<(u64, u8)> {
    scan_pci_for_device(0x0C, 0x03, Some(0x30), "xhci")
}

/// Load the xHCI driver as a separate process.
fn load_xhci_process(xhci_data: &[u8], init_cr3: u64) {
    let (bar0_phys, irq_line) = match scan_pci_for_xhci() {
        Some(r) => r,
        None => {
            kdebug!("  xhci: no xHCI controller found on PCI bus — skipping");
            return;
        }
    };
    let proc = match load_service(&ProcessSpec {
        name: "xhci",
        data: xhci_data,
        stack_pages: 4,
    }) {
        Some(p) => p,
        None => return,
    };
    map_bar0_mmio(&proc.addr_space, bar0_phys, 32, "xhci");
    proc.map_shared_ring(init_cr3, KB_RING_PAGE);
    write_xhci_boot_info(&proc.addr_space, irq_line);
    proc.spawn();
    kdebug!("  xhci: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for the xHCI driver process.
///
/// Creates fresh capabilities:
///   Cap 0: I/O port 0xCF8-0xCFF (PCI config)
///   Cap 1: IRQ (xHCI interrupt line)
///   Cap 2: Notification (IRQ delivery)
fn write_xhci_boot_info(xhci_as: &mm::paging::AddressSpace, irq_line: u8) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(xhci_as, "xhci");
    let pci_cap = create_pci_cap("xhci");

    let irq_cap = cap::insert(
        cap::CapObject::Irq {
            line: irq_line as u32,
        },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create xhci IRQ cap");
    kdebug!("  xhci cap {}: IRQ {}", irq_cap.raw(), irq_line);

    let n_xhci = ipc::notify::create().expect("failed to create xhci notification");
    let n_xhci_cap = cap::insert(
        cap::CapObject::Notification { id: n_xhci.0.raw() },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create xhci notification cap");
    kdebug!(
        "  xhci cap {}: notification (IRQ delivery)",
        n_xhci_cap.raw()
    );

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 3;
    info.caps[0] = pci_cap.raw() as u64;
    info.caps[1] = irq_cap.raw() as u64;
    info.caps[2] = n_xhci_cap.raw() as u64;

    write_bootinfo(phys, &info);
    kdebug!("  xhci bootinfo: 3 caps at {:#x}", BOOT_INFO_ADDR);
}

// ---------------------------------------------------------------------------
// Wayland Compositor process
// ---------------------------------------------------------------------------

/// Load the Wayland compositor as a separate process.
fn load_compositor_process(comp_data: &[u8], init_cr3: u64) {
    let proc = match load_service(&ProcessSpec {
        name: "compositor",
        data: comp_data,
        stack_pages: 4,
    }) {
        Some(p) => p,
        None => return,
    };
    proc.map_shared_ring(init_cr3, KB_RING_PAGE);
    proc.map_shared_ring(init_cr3, MOUSE_RING_PAGE);
    write_compositor_boot_info(&proc.addr_space);
    proc.spawn();
    kdebug!("  compositor: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for the compositor process.
///
/// Cap 0: IPC endpoint (for client connections).
/// Cap 1: AddrSpace (compositor's own CR3) -- for shm_map into self.
/// Also maps framebuffer if available.
fn write_compositor_boot_info(comp_as: &mm::paging::AddressSpace) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(comp_as, "compositor");

    let ep = ipc::endpoint::create().expect("failed to create compositor endpoint");
    let ep_cap = cap::insert(
        cap::CapObject::Endpoint { id: ep.0.raw() },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create compositor endpoint cap");
    kdebug!(
        "  compositor cap {}: endpoint (client connections)",
        ep_cap.raw()
    );

    // Cap 1: AddrSpace for compositor's own CR3 (needed for shm_map into self).
    let comp_as_cap = cap::insert(
        cap::CapObject::AddrSpace { cr3: comp_as.cr3() },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create compositor AS cap");
    kdebug!(
        "  compositor cap {}: addr_space (self, cr3={:#x})",
        comp_as_cap.raw(),
        comp_as.cr3()
    );

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 2;
    info.caps[0] = ep_cap.raw() as u64;
    info.caps[1] = comp_as_cap.raw() as u64;
    info.self_as_cap = comp_as_cap.raw() as u64;

    map_framebuffer(comp_as, &mut info);

    write_bootinfo(phys, &info);
    kdebug!("  compositor bootinfo: 2 caps at {:#x}", BOOT_INFO_ADDR);
}

/// Load the hello-gui Wayland test client as a separate process.
fn load_hello_gui_process(gui_data: &[u8]) {
    let proc = match load_service(&ProcessSpec {
        name: "hello-gui",
        data: gui_data,
        stack_pages: 4,
    }) {
        Some(p) => p,
        None => return,
    };
    write_hello_gui_boot_info(&proc.addr_space);
    proc.spawn();
    kdebug!("  hello-gui: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for hello-gui process.
///
/// Cap 0: AddrSpace (hello-gui's own CR3) -- for shm_map into self.
/// No IPC endpoint needed (it looks up the compositor via svc_lookup).
fn write_hello_gui_boot_info(gui_as: &mm::paging::AddressSpace) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(gui_as, "hello-gui");

    // Cap 0: AddrSpace for hello-gui's own CR3 (needed for shm_map).
    let gui_as_cap = cap::insert(
        cap::CapObject::AddrSpace { cr3: gui_as.cr3() },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create hello-gui AS cap");
    kdebug!(
        "  hello-gui cap {}: addr_space (self, cr3={:#x})",
        gui_as_cap.raw(),
        gui_as.cr3()
    );

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 1;
    info.caps[0] = gui_as_cap.raw() as u64;
    info.self_as_cap = gui_as_cap.raw() as u64;

    write_bootinfo(phys, &info);
    kdebug!("  hello-gui bootinfo: 1 cap at {:#x}", BOOT_INFO_ADDR);
}

/// Load the sotos-term Wayland terminal emulator as a separate process.
///
/// sotos-term needs its own AS cap for `shm_map`, so like hello-gui it is
/// loaded by the kernel rather than spawned by init.
fn load_sotos_term_process(term_data: &[u8]) {
    let proc = match load_service(&ProcessSpec {
        name: "sotos-term",
        data: term_data,
        stack_pages: 4,
    }) {
        Some(p) => p,
        None => return,
    };
    write_sotos_term_boot_info(&proc.addr_space);
    proc.spawn();
    kdebug!("  sotos-term: separate process, cr3={:#x}", proc.cr3);
}

/// Write BootInfo for sotos-term process.
///
/// Cap 0: AddrSpace (sotos-term's own CR3) -- for shm_map into self.
fn write_sotos_term_boot_info(term_as: &mm::paging::AddressSpace) {
    use sotos_common::{BootInfo, BOOT_INFO_ADDR, BOOT_INFO_MAGIC};

    let phys = alloc_bootinfo_page(term_as, "sotos-term");

    let term_as_cap = cap::insert(
        cap::CapObject::AddrSpace { cr3: term_as.cr3() },
        cap::Rights::ALL,
        None,
    )
    .expect("failed to create sotos-term AS cap");
    kdebug!(
        "  sotos-term cap {}: addr_space (self, cr3={:#x})",
        term_as_cap.raw(),
        term_as.cr3()
    );

    let mut info = BootInfo::empty();
    info.magic = BOOT_INFO_MAGIC;
    info.cap_count = 1;
    info.caps[0] = term_as_cap.raw() as u64;
    info.self_as_cap = term_as_cap.raw() as u64;

    write_bootinfo(phys, &info);
    kdebug!("  sotos-term bootinfo: 1 cap at {:#x}", BOOT_INFO_ADDR);
}
