//! SYSCALL/SYSRET setup and entry/exit assembly.
//!
//! Programs the four MSRs (EFER, STAR, LSTAR, FMASK) and provides
//! the syscall_entry trampoline that saves/restores user state.
//!
//! Per-CPU state (kernel stack, user RSP save) is accessed via GS base
//! rather than RIP-relative globals, making this SMP-safe.

use super::gdt;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::SegmentSelector;
use x86_64::VirtAddr;

// ---------------------------------------------------------------------------
// Trap frame — matches the push/pop order in syscall_entry
// ---------------------------------------------------------------------------

/// Saved register state pushed by syscall_entry.
#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub rax: u64, // syscall number / return value
    pub rbx: u64,
    pub rcx: u64, // user RIP (saved by CPU on SYSCALL)
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64, // arg0
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64, // user RFLAGS (saved by CPU on SYSCALL)
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

// ---------------------------------------------------------------------------
// SYSCALL entry/exit assembly — GS-relative per-CPU access
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    // CPU did: RCX = user RIP, R11 = user RFLAGS, CS/SS = kernel
    // IF=0 (FMASK cleared it). GS base = user's GS.

    // Swap user GS ↔ kernel GS (percpu) so we can access percpu via gs:xx
    "    swapgs",

    // Save user RSP to percpu.user_rsp_save (offset 16), load kernel stack
    "    mov gs:[16], rsp",       // percpu.user_rsp_save
    "    mov rsp, gs:[8]",        // percpu.kernel_stack_top

    // Push trap frame (matches TrapFrame struct, low-to-high)
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11", // user RFLAGS
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi", // arg0
    "    push rsi",
    "    push rdx",
    "    push rcx", // user RIP
    "    push rbx",
    "    push rax", // syscall number

    // Call Rust dispatcher: syscall_dispatch(&mut TrapFrame)
    "    mov rdi, rsp",
    "    call syscall_dispatch",

    // Pop trap frame
    "    pop rax",
    "    pop rbx",
    "    pop rcx",
    "    pop rdx",
    "    pop rsi",
    "    pop rdi",
    "    pop rbp",
    "    pop r8",
    "    pop r9",
    "    pop r10",
    "    pop r11",
    "    pop r12",
    "    pop r13",
    "    pop r14",
    "    pop r15",

    // Restore user RSP and return to Ring 3
    "    mov rsp, gs:[16]",       // percpu.user_rsp_save
    // Swap kernel GS ↔ user GS before returning to user mode
    "    swapgs",
    "    sysretq",
);

// ---------------------------------------------------------------------------
// MSR initialization
// ---------------------------------------------------------------------------

extern "C" {
    fn syscall_entry();
}

/// Program SYSCALL/SYSRET MSRs. Call once during boot, after GDT init.
/// On SMP, each CPU must call this (MSRs are per-CPU).
pub fn init() {
    // Enable SYSCALL/SYSRET in EFER.
    unsafe {
        Efer::update(|flags| {
            *flags |= EferFlags::SYSTEM_CALL_EXTENSIONS;
        });
    }

    // STAR: segment selectors for SYSCALL (kernel) and SYSRET (user).
    Star::write(
        SegmentSelector(gdt::USER_CS),  // cs_sysret  = 0x23
        SegmentSelector(gdt::USER_DS),  // ss_sysret  = 0x1B
        SegmentSelector(gdt::KERNEL_CS), // cs_syscall = 0x08
        SegmentSelector(gdt::KERNEL_DS), // ss_syscall = 0x10
    )
    .expect("STAR segment selector validation failed");

    // LSTAR: RIP target for SYSCALL.
    LStar::write(VirtAddr::new(syscall_entry as *const () as u64));

    // FMASK: clear IF on SYSCALL entry (disable interrupts).
    SFMask::write(RFlags::INTERRUPT_FLAG);
}
