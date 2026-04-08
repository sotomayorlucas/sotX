//! Global Descriptor Table setup.
//!
//! GDT layout for SYSRET compatibility:
//!   0x00 — Null
//!   0x08 — Kernel Code 64 (DPL=0)
//!   0x10 — Kernel Data    (DPL=0)
//!   0x18 — User Data      (DPL=3)
//!   0x20 — User Code 64   (DPL=3)
//!   0x28 — TSS            (16-byte descriptor)
//!
//! SYSRET requires User Data immediately before User Code.
//!
//! Two initialization paths:
//! - `init()`: early boot (before heap). Uses static Lazy GDT+TSS.
//! - `init_percpu()`: after heap init. Heap-allocates per-CPU GDT+TSS.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use super::percpu::PerCpu;

// ---------------------------------------------------------------------------
// Selector constants (including RPL bits)
// ---------------------------------------------------------------------------

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
/// User data selector — 0x18 | RPL 3.
pub const USER_DS: u16 = 0x1B;
/// User code selector — 0x20 | RPL 3.
pub const USER_CS: u16 = 0x23;

// ---------------------------------------------------------------------------
// IST / Double-fault stack (static, for early boot only)
// ---------------------------------------------------------------------------

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const PAGE_FAULT_IST_INDEX: u16 = 1;
pub const GP_FAULT_IST_INDEX: u16 = 2;
pub const MISC_FAULT_IST_INDEX: u16 = 3;

/// Double-fault stack size per CPU (20 KiB).
const DF_STACK_SIZE: usize = 4096 * 5;

#[repr(align(16))]
#[allow(dead_code)]
struct DoubleFaultStack([u8; DF_STACK_SIZE]);
static DOUBLE_FAULT_STACK: DoubleFaultStack = DoubleFaultStack([0; DF_STACK_SIZE]);
static PAGE_FAULT_STACK: DoubleFaultStack = DoubleFaultStack([0; DF_STACK_SIZE]);
static GP_FAULT_STACK: DoubleFaultStack = DoubleFaultStack([0; DF_STACK_SIZE]);

// ---------------------------------------------------------------------------
// TSS — static for early boot, replaced by per-CPU heap TSS later
// ---------------------------------------------------------------------------

#[repr(align(16))]
struct TssStorage(UnsafeCell<TaskStateSegment>);
unsafe impl Sync for TssStorage {}

static TSS_STORAGE: TssStorage = TssStorage(UnsafeCell::new(TaskStateSegment::new()));

fn tss() -> &'static TaskStateSegment {
    // SAFETY: `TSS_STORAGE` is a `static` `UnsafeCell<TaskStateSegment>`
    // initialized at compile time with `TaskStateSegment::new()`. We only
    // hand out shared references here; the only mutation of the cell happens
    // inside the GDT `Lazy` initializer, which runs exactly once before any
    // caller of `tss()`, so no aliasing `&mut` can coexist.
    unsafe { &*TSS_STORAGE.0.get() }
}

// ---------------------------------------------------------------------------
// Early-boot GDT (Lazy, before heap is available)
// ---------------------------------------------------------------------------

struct Selectors {
    code: SegmentSelector,
    data: SegmentSelector,
    #[allow(dead_code)]
    user_data: SegmentSelector,
    #[allow(dead_code)]
    user_code: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    // Set up the double-fault IST entry before the GDT captures a reference
    // to the TSS. (Lazy init runs exactly once, before GDT.0.load().)
    // SAFETY: `Lazy::new` runs this closure exactly once, strictly before any
    // other code can observe the GDT, so we hold the only mutable access to
    // `TSS_STORAGE`'s UnsafeCell. The static stack arrays we take `VirtAddr`s
    // of are valid for `'static`.
    unsafe {
        (*TSS_STORAGE.0.get()).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(&DOUBLE_FAULT_STACK);
            let stack_size = core::mem::size_of::<DoubleFaultStack>() as u64;
            stack_start + stack_size
        };
        (*TSS_STORAGE.0.get()).interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(&PAGE_FAULT_STACK);
            let stack_size = core::mem::size_of::<DoubleFaultStack>() as u64;
            stack_start + stack_size
        };
        (*TSS_STORAGE.0.get()).interrupt_stack_table[GP_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(&GP_FAULT_STACK);
            let stack_size = core::mem::size_of::<DoubleFaultStack>() as u64;
            stack_start + stack_size
        };
        // Reuse GP stack for misc faults in early boot (they all panic immediately)
        (*TSS_STORAGE.0.get()).interrupt_stack_table[MISC_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(&GP_FAULT_STACK);
            let stack_size = core::mem::size_of::<DoubleFaultStack>() as u64;
            stack_start + stack_size
        };
    }

    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment()); // 0x08
    let data = gdt.append(Descriptor::kernel_data_segment()); // 0x10
    let user_data = gdt.append(Descriptor::user_data_segment()); // 0x18
    let user_code = gdt.append(Descriptor::user_code_segment()); // 0x20
    let tss = gdt.append(Descriptor::tss_segment(tss())); // 0x28

    (
        gdt,
        Selectors {
            code,
            data,
            user_data,
            user_code,
            tss,
        },
    )
});

/// Early-boot GDT init (before heap). Uses static Lazy GDT + TSS.
pub fn init() {
    GDT.0.load();
    // SAFETY: `GDT.0.load()` on the preceding line installed the GDT, so the
    // selectors in `GDT.1` are present and valid for the current CPU; loading
    // matching segment registers and the TSS selector is always allowed
    // immediately after the GDT is made active.
    unsafe {
        CS::set_reg(GDT.1.code);
        SS::set_reg(GDT.1.data);
        DS::set_reg(GDT.1.data);
        ES::set_reg(GDT.1.data);
        load_tss(GDT.1.tss);
    }
}

// ---------------------------------------------------------------------------
// Per-CPU GDT + TSS (heap-allocated, for SMP)
// ---------------------------------------------------------------------------

/// Initialize a per-CPU GDT and TSS for the given CPU.
///
/// Heap-allocates a TSS and GDT, sets up the double-fault IST,
/// and loads the new GDT+TSS, replacing the early-boot static GDT.
/// The old Lazy GDT is still referenced by static but no longer loaded.
pub fn init_percpu(percpu: &mut PerCpu) {
    // Allocate TSS
    let mut tss = Box::new(TaskStateSegment::new());

    // Allocate double-fault IST stack via frame allocator (too large for slab).
    let df_frames = DF_STACK_SIZE / 4096;
    let df_base =
        crate::mm::alloc_contiguous(df_frames).expect("out of frames for double-fault stack");
    let df_virt = df_base.addr() + crate::mm::hhdm_offset();
    let df_stack_top = VirtAddr::new(df_virt + DF_STACK_SIZE as u64);
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = df_stack_top;

    // Allocate page-fault IST stack.
    let pf_base =
        crate::mm::alloc_contiguous(df_frames).expect("out of frames for page-fault IST stack");
    let pf_virt = pf_base.addr() + crate::mm::hhdm_offset();
    let pf_stack_top = VirtAddr::new(pf_virt + DF_STACK_SIZE as u64);
    tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = pf_stack_top;

    // Allocate GP-fault IST stack.
    let gp_base =
        crate::mm::alloc_contiguous(df_frames).expect("out of frames for GP-fault IST stack");
    let gp_virt = gp_base.addr() + crate::mm::hhdm_offset();
    let gp_stack_top = VirtAddr::new(gp_virt + DF_STACK_SIZE as u64);
    tss.interrupt_stack_table[GP_FAULT_IST_INDEX as usize] = gp_stack_top;

    // Allocate misc-fault IST stack (shared for #DE, #UD, #NM, #TS, #NP, #SS, #AC).
    let misc_base =
        crate::mm::alloc_contiguous(df_frames).expect("out of frames for misc-fault IST stack");
    let misc_virt = misc_base.addr() + crate::mm::hhdm_offset();
    let misc_stack_top = VirtAddr::new(misc_virt + DF_STACK_SIZE as u64);
    tss.interrupt_stack_table[MISC_FAULT_IST_INDEX as usize] = misc_stack_top;

    let tss = Box::leak(tss);
    percpu.tss = tss as *mut TaskStateSegment;

    // Allocate GDT with identical segment layout
    let mut gdt = Box::new(GlobalDescriptorTable::new());
    let code = gdt.append(Descriptor::kernel_code_segment()); // 0x08
    let data = gdt.append(Descriptor::kernel_data_segment()); // 0x10
    let _user_data = gdt.append(Descriptor::user_data_segment()); // 0x18
    let _user_code = gdt.append(Descriptor::user_code_segment()); // 0x20
    let tss_sel = gdt.append(Descriptor::tss_segment(tss)); // 0x28

    let gdt = Box::leak(gdt);
    gdt.load();

    // SAFETY: the per-CPU GDT was just loaded on the line above, so all
    // selectors computed by `gdt.append(...)` are present in the new GDT; the
    // TSS referenced by `tss_sel` was leaked onto the heap and lives for
    // `'static`. Reloading segment registers and the TSS selector is safe
    // immediately after installing a new GDT.
    unsafe {
        CS::set_reg(code);
        SS::set_reg(data);
        DS::set_reg(data);
        ES::set_reg(data);
        load_tss(tss_sel);
    }
}
