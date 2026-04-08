//! Per-CPU data accessed via the GS segment base.
//!
//! Each CPU has a heap-allocated `PerCpu` struct. The GS base MSR
//! (IA32_GS_BASE, 0xC0000101) is set to point at this struct so that
//! assembly code can access per-CPU fields at fixed offsets (e.g. `gs:[8]`
//! for `kernel_stack_top`).
//!
//! SWAPGS is used at every user/kernel boundary: SYSCALL entry/exit,
//! interrupt handlers, and exception handlers. In kernel mode GS points
//! to PerCpu; in user mode GS holds the application's value (e.g. Wine TEB).

use alloc::boxed::Box;
use x86_64::structures::tss::TaskStateSegment;

/// Assembly-accessible offset constants.
#[allow(dead_code)]
pub const PERCPU_KSTACK: usize = 8;
#[allow(dead_code)]
pub const PERCPU_URSP: usize = 16;

/// MSR number for IA32_GS_BASE.
const IA32_GS_BASE: u32 = 0xC000_0101;

/// MSR number for IA32_KERNEL_GS_BASE (swapped by SWAPGS instruction).
/// In kernel mode (after swapgs at entry): GS_BASE = percpu, KERNEL_GS_BASE = user value.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

#[repr(C)]
pub struct PerCpu {
    /// offset 0: self pointer for `gs:[0]` validation
    pub self_ptr: u64,
    /// offset 8: kernel stack top (replaces KERNEL_STACK_TOP)
    pub kernel_stack_top: u64,
    /// offset 16: user RSP save area (replaces USER_RSP_SAVE)
    pub user_rsp_save: u64,
    /// offset 24: index of the currently running thread (usize::MAX = none)
    pub current_thread: usize,
    /// offset 32: CPU index (0 = BSP)
    pub cpu_index: u32,
    /// offset 36: LAPIC ID
    pub lapic_id: u32,
    /// offset 40: idle thread pool index
    pub idle_thread: usize,
    /// offset 48: post-switch re-enqueue target
    pub switch_old_idx: usize,
    /// offset 56: whether the old thread needs re-enqueue after switch
    pub switch_needs_enqueue: bool,
    // Padding
    _pad: [u8; 5],
    /// offset 62: bitmask of held lock levels (for debug lock ordering)
    pub held_locks: u16,
    /// offset 64: pointer to this CPU's TSS (not accessed from asm)
    pub tss: *mut TaskStateSegment,
}

unsafe impl Send for PerCpu {}
unsafe impl Sync for PerCpu {}

impl PerCpu {
    fn new(cpu_index: u32, lapic_id: u32) -> Self {
        Self {
            self_ptr: 0, // filled in after allocation
            kernel_stack_top: 0,
            user_rsp_save: 0,
            current_thread: usize::MAX,
            cpu_index,
            lapic_id,
            idle_thread: usize::MAX,
            switch_old_idx: usize::MAX,
            switch_needs_enqueue: false,
            _pad: [0; 5],
            held_locks: 0,
            tss: core::ptr::null_mut(),
        }
    }

    /// Returns true if this is the Bootstrap Processor.
    pub fn is_bsp(&self) -> bool {
        self.cpu_index == 0
    }
}

/// Initialize PerCpu for the BSP (CPU 0). Must be called after slab init.
pub fn init_bsp() -> &'static mut PerCpu {
    let percpu = Box::new(PerCpu::new(0, 0));
    let percpu = Box::leak(percpu);
    let addr = percpu as *mut PerCpu as u64;
    percpu.self_ptr = addr;

    // Set IA32_GS_BASE to point at PerCpu
    write_gs_base(addr);

    // Signal to slab allocator that percpu is ready for CPU index lookups.
    crate::mm::slab::mark_percpu_ready();

    crate::kdebug!("  percpu: BSP gs_base = {:#x}", addr);
    percpu
}

/// Allocate PerCpu for an AP. Does NOT set GS base (AP does that itself).
pub fn alloc_ap(cpu_index: u32, lapic_id: u32) -> &'static mut PerCpu {
    let percpu = Box::new(PerCpu::new(cpu_index, lapic_id));
    let percpu = Box::leak(percpu);
    let addr = percpu as *mut PerCpu as u64;
    percpu.self_ptr = addr;
    percpu
}

/// Read the current CPU's PerCpu struct via `gs:[0]`.
///
/// # Safety
/// GS base must have been initialized (init_bsp or AP entry).
#[inline]
pub fn current_percpu() -> &'static mut PerCpu {
    let ptr: u64;
    // SAFETY: per the fn docs, the caller has ensured GS_BASE points at a
    // valid leaked `PerCpu` whose `self_ptr` field (at offset 0) stores the
    // struct's own virtual address. The resulting `&mut PerCpu` is then a
    // unique-per-CPU reference to a stable heap allocation.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) ptr,
            options(nomem, nostack, preserves_flags),
        );
        &mut *(ptr as *mut PerCpu)
    }
}

/// Write the IA32_GS_BASE MSR.
pub fn write_gs_base(addr: u64) {
    // SAFETY: IA32_GS_BASE (0xC0000101) exists on all x86_64 CPUs. Callers
    // pass the address of a leaked `PerCpu` struct, which remains live for
    // the lifetime of the kernel; this function is only invoked from BSP/AP
    // boot paths before any code reads gs:xx.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_GS_BASE,
            in("eax") addr as u32,
            in("edx") (addr >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Write the IA32_KERNEL_GS_BASE MSR.
/// In kernel mode (after swapgs), this holds the user's GS value.
/// Used to restore a thread's user GS_BASE on context switch.
pub fn write_kernel_gs_base(addr: u64) {
    // SAFETY: IA32_KERNEL_GS_BASE (0xC0000102) is defined on all x86_64 CPUs.
    // Writing it only changes the value that a later SWAPGS will load into
    // GS_BASE; it cannot affect currently-executing kernel code.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_KERNEL_GS_BASE,
            in("eax") addr as u32,
            in("edx") (addr >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}
