//! Interrupt Descriptor Table setup.
//!
//! Registers CPU exception handlers, hardware IRQ handlers (PIC),
//! and LAPIC timer/spurious handlers.

use crate::kprintln;
use spin::Lazy;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use super::gdt::DOUBLE_FAULT_IST_INDEX;
use super::lapic;
use super::pic;

/// PIT timer interrupt vector (IRQ0 after PIC remap). Kept for PIC fallback.
pub const PIT_TIMER_VECTOR: u8 = 32;

/// LAPIC timer interrupt vector.
pub const LAPIC_TIMER_VECTOR: u8 = lapic::TIMER_VECTOR; // 48

/// Reschedule IPI vector.
pub const RESCHEDULE_VECTOR: u8 = lapic::RESCHEDULE_VECTOR; // 49

/// LAPIC spurious interrupt vector.
pub const SPURIOUS_VECTOR: u8 = lapic::SPURIOUS_VECTOR; // 0xFF

/// Generate an IRQ handler for a hardware IRQ line (1-15).
/// PIC IRQs are routed to BSP only. If an AP somehow receives one
/// (spurious), just EOI the LAPIC and return.
macro_rules! irq_handler {
    ($name:ident, $irq:expr) => {
        extern "x86-interrupt" fn $name(frame: InterruptStackFrame) {
            // If interrupted from user mode, swap GS so percpu is accessible.
            let from_user = frame.code_segment.0 & 3 != 0;
            if from_user {
                unsafe {
                    core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
                }
            }
            if !super::percpu::current_percpu().is_bsp() {
                lapic::eoi();
                if from_user {
                    unsafe {
                        core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
                    }
                }
                return;
            }
            pic::send_eoi($irq);
            pic::mask($irq);
            crate::irq::notify($irq);
            if from_user {
                unsafe {
                    core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
                }
            }
        }
    };
}

irq_handler!(irq1_handler, 1);
irq_handler!(irq2_handler, 2);
irq_handler!(irq3_handler, 3);
irq_handler!(irq4_handler, 4);
irq_handler!(irq5_handler, 5);
irq_handler!(irq6_handler, 6);
irq_handler!(irq7_handler, 7);
irq_handler!(irq8_handler, 8);
irq_handler!(irq9_handler, 9);
irq_handler!(irq10_handler, 10);
irq_handler!(irq11_handler, 11);
irq_handler!(irq12_handler, 12);
irq_handler!(irq13_handler, 13);
irq_handler!(irq14_handler, 14);
irq_handler!(irq15_handler, 15);

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    idt.breakpoint.set_handler_fn(breakpoint_handler);

    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }

    // #GP does NOT use IST — same rationale as #PF: user-mode faults use per-thread
    // kernel stack (TSS RSP0). IST causes stack corruption when multiple threads fault.
    // Uses raw handler address for custom assembly that saves all 15 GPRs.
    unsafe {
        idt.general_protection_fault
            .set_handler_addr(x86_64::VirtAddr::new(
                general_protection_handler_asm as *const () as u64,
            ));
    }
    // #PF does NOT use IST — user-mode faults use the per-thread kernel stack
    // (TSS RSP0), which is safe for context switching away faulted threads.
    // Using IST causes corruption when multiple threads fault before the first
    // returns through the IST stack (e.g., CoW fork marks all PTEs read-only).
    // Uses raw handler address (like LAPIC timer) because our custom assembly
    // entry saves all 15 GPRs for Wine's ucontext — not x86-interrupt ABI.
    unsafe {
        idt.page_fault.set_handler_addr(x86_64::VirtAddr::new(
            page_fault_handler_asm as *const () as u64,
        ));
    }

    // #DE and #UD: no IST, custom assembly handlers for signal delivery with real GPRs.
    // No error code pushed by CPU → assembly pushes dummy 0 to normalize layout.
    unsafe {
        idt.divide_error.set_handler_addr(x86_64::VirtAddr::new(
            divide_error_handler_asm as *const () as u64,
        ));
    }
    unsafe {
        idt.invalid_opcode.set_handler_addr(x86_64::VirtAddr::new(
            invalid_opcode_handler_asm as *const () as u64,
        ));
    }
    unsafe {
        idt.device_not_available
            .set_handler_fn(device_not_available_handler)
            .set_stack_index(super::gdt::MISC_FAULT_IST_INDEX);
    }
    unsafe {
        idt.invalid_tss
            .set_handler_fn(invalid_tss_handler)
            .set_stack_index(super::gdt::MISC_FAULT_IST_INDEX);
    }
    unsafe {
        idt.segment_not_present
            .set_handler_fn(segment_not_present_handler)
            .set_stack_index(super::gdt::MISC_FAULT_IST_INDEX);
    }
    unsafe {
        idt.stack_segment_fault
            .set_handler_fn(stack_segment_fault_handler)
            .set_stack_index(super::gdt::MISC_FAULT_IST_INDEX);
    }
    unsafe {
        idt.alignment_check
            .set_handler_fn(alignment_check_handler)
            .set_stack_index(super::gdt::MISC_FAULT_IST_INDEX);
    }

    // PIT timer (vector 32) — still registered for fallback / early boot
    idt[PIT_TIMER_VECTOR].set_handler_fn(pit_timer_handler);

    // Hardware IRQ handlers for IRQ 1-15 (vectors 33-47).
    idt[33].set_handler_fn(irq1_handler);
    idt[34].set_handler_fn(irq2_handler);
    idt[35].set_handler_fn(irq3_handler);
    idt[36].set_handler_fn(irq4_handler);
    idt[37].set_handler_fn(irq5_handler);
    idt[38].set_handler_fn(irq6_handler);
    idt[39].set_handler_fn(irq7_handler);
    idt[40].set_handler_fn(irq8_handler);
    idt[41].set_handler_fn(irq9_handler);
    idt[42].set_handler_fn(irq10_handler);
    idt[43].set_handler_fn(irq11_handler);
    idt[44].set_handler_fn(irq12_handler);
    idt[45].set_handler_fn(irq13_handler);
    idt[46].set_handler_fn(irq14_handler);
    idt[47].set_handler_fn(irq15_handler);

    // LAPIC timer (vector 48) — custom assembly handler for async signal delivery.
    // Uses raw handler address instead of set_handler_fn because we need full
    // GPR access (x86-interrupt ABI doesn't expose general-purpose registers).
    unsafe {
        idt[LAPIC_TIMER_VECTOR].set_handler_addr(x86_64::VirtAddr::new(
            lapic_timer_handler_asm as *const () as u64,
        ));
    }

    // Reschedule IPI (vector 49)
    idt[RESCHEDULE_VECTOR].set_handler_fn(reschedule_ipi_handler);

    // LAPIC spurious interrupt (vector 0xFF)
    idt[SPURIOUS_VECTOR].set_handler_fn(spurious_handler);

    idt
});

/// Initialize the IDT (first call forces Lazy init and loads IDTR).
pub fn init() {
    IDT.load();
}

/// Reload the IDTR on the current CPU (for APs sharing the same IDT).
pub fn load() {
    IDT.load();
}

// ---------------------------------------------------------------------------
// Exception handlers
// ---------------------------------------------------------------------------

extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    kprintln!("EXCEPTION: breakpoint\n{:#?}", frame);
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, _code: u64) -> ! {
    // If #DF arrived while in user mode (rare but possible), fix GS.
    if frame.code_segment.0 & 3 != 0 {
        unsafe {
            core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
        }
    }
    let cr2 = Cr2::read_raw();
    let cr3 = crate::mm::paging::read_cr3();
    let percpu = crate::arch::x86_64::percpu::current_percpu();
    let kstack = percpu.kernel_stack_top;
    let tss = unsafe { &*percpu.tss };
    let tss_rsp0 = tss.privilege_stack_table[0].as_u64();
    let ist0 = tss.interrupt_stack_table[0].as_u64();
    let ist1 = tss.interrupt_stack_table[1].as_u64();
    let ist2 = tss.interrupt_stack_table[2].as_u64();
    panic!("EXCEPTION: double fault cr2={:#x} cr3={:#x} rsp0={:#x} ist0={:#x} ist1={:#x} ist2={:#x}\n{:#?}",
        cr2, cr3, tss_rsp0, ist0, ist1, ist2, frame);
}

// ---------------------------------------------------------------------------
// Shared fault signal delivery helper — used by #GP, #UD, #DE handlers.
// Saves real GPRs, sets kernel signal, redirects to trampoline via iretq.
// Returns true if signal was delivered (iframe RIP redirected to trampoline),
// false if no trampoline → caller should kill thread.
// ---------------------------------------------------------------------------

/// Deliver a fault-generated signal to the current user thread.
/// `gprs`: pointer to 15 saved GPRs [rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15]
/// `iframe`: pointer to [error_code, rip, cs, rflags, rsp, ss]
/// `signal`: Linux signal number (11=SIGSEGV, 4=SIGILL, 8=SIGFPE)
/// `fault_addr`: address to store in fault_info (faulting RIP for #GP/#UD/#DE)
/// `fault_code`: error code to store in fault_info
#[inline(never)]
fn deliver_fault_signal(
    gprs: *mut u64,
    iframe: *mut u64,
    signal: u64,
    fault_addr: u64,
    fault_code: u64,
) -> bool {
    let rip = unsafe { *iframe.add(1) };
    let rsp = unsafe { *iframe.add(4) };
    let rflags = unsafe { *iframe.add(3) };

    let percpu = super::percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX {
        return false;
    }

    let tramp = crate::sched::get_signal_trampoline_by_idx(idx as u32);
    if tramp == 0 {
        return false;
    }

    // Save real GPRs from assembly frame
    let mut real_gprs = [0u64; 15];
    unsafe {
        for i in 0..15 {
            real_gprs[i] = *gprs.add(i);
        }
    }

    // Force-save new faulting context (overwrite any previous undelivered signal)
    if let Some(tid) = crate::sched::current_tid() {
        crate::sched::clear_signal_ctx(tid);
    }
    crate::sched::save_signal_context_current(&real_gprs, rip, rsp, rflags);
    crate::sched::set_kernel_signal_current(signal);
    crate::sched::set_fault_info_current(fault_addr, fault_code);

    // Direct redirect: overwrite RIP in interrupt frame → iret goes to trampoline
    unsafe {
        *iframe.add(1) = tramp;
    }
    true
}

// ---------------------------------------------------------------------------
// #GP handler — assembly entry saves all 15 GPRs for user-mode faults.
// #GP has error code on stack → identical layout to #PF.
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".global general_protection_handler_asm",
    "general_protection_handler_asm:",
    // Check if from user mode: CS at rsp+16 (after error code at rsp+0)
    "    test qword ptr [rsp + 16], 3",
    "    jz 2f",
    // === User-mode #GP ===
    "    swapgs",
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11",
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",
    "    push rbx",
    "    push rax",
    "    mov rdi, rsp",
    "    lea rsi, [rsp + 120]",
    "    call gp_fault_user_handler",
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
    "    add rsp, 8", // pop error code
    "    swapgs",
    "    iretq",
    // === Kernel-mode #GP: panic ===
    "2:",
    "    call gp_fault_kernel_handler",
    "    ud2",
);

/// Rust handler for user-mode #GP. Called from assembly with all GPRs saved.
#[no_mangle]
extern "C" fn gp_fault_user_handler(gprs: *mut u64, iframe: *mut u64) {
    let error_code = unsafe { *iframe };
    let rip = unsafe { *iframe.add(1) };
    let rsp = unsafe { *iframe.add(4) };

    {
        use core::sync::atomic::{AtomicU32, Ordering};
        static GP_COUNT: AtomicU32 = AtomicU32::new(0);
        let n = GP_COUNT.fetch_add(1, Ordering::Relaxed);
        if n < 10 {
            let rax = unsafe { *gprs };
            let rcx = unsafe { *gprs.add(2) };
            let rdx = unsafe { *gprs.add(3) };
            kprintln!(
                "#GP(user) #{} rip={:#x} rsp={:#x} code={:#x} rax={:#x} rcx={:#x} rdx={:#x}",
                n,
                rip,
                rsp,
                error_code,
                rax,
                rcx,
                rdx
            );
        }
    }

    // Deliver SIGSEGV (signal 11) with real GPRs
    if deliver_fault_signal(gprs, iframe, 11, rip, error_code) {
        return;
    }

    // No trampoline — kill thread
    if let Some(tid) = crate::sched::current_tid() {
        crate::sched::set_pending_signal(tid, 11);
    }
    crate::sched::exit_current(); // diverges
}

/// Kernel-mode #GP handler — panics.
#[no_mangle]
extern "C" fn gp_fault_kernel_handler() {
    panic!("EXCEPTION: #GP general protection fault (kernel)");
}

// ---------------------------------------------------------------------------
// #UD handler — assembly entry. No error code → push dummy 0.
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".global invalid_opcode_handler_asm",
    "invalid_opcode_handler_asm:",
    // No error code pushed by CPU. Check CS at rsp+8 (no error code offset).
    "    test qword ptr [rsp + 8], 3",
    "    jz 2f",
    // === User-mode #UD ===
    "    swapgs",
    "    push 0", // dummy error code to normalize layout
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11",
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",
    "    push rbx",
    "    push rax",
    "    mov rdi, rsp",
    "    lea rsi, [rsp + 120]", // 15*8=120 → iframe starts at [error_code, rip, ...]
    "    call ud_fault_user_handler",
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
    "    add rsp, 8", // pop dummy error code
    "    swapgs",
    "    iretq",
    // === Kernel-mode #UD: panic ===
    "2:",
    "    call ud_fault_kernel_handler",
    "    ud2",
);

/// Rust handler for user-mode #UD.
#[no_mangle]
extern "C" fn ud_fault_user_handler(gprs: *mut u64, iframe: *mut u64) {
    let rip = unsafe { *iframe.add(1) };
    let tid = crate::sched::current_tid().map(|t| t.0).unwrap_or(0);
    kprintln!("#UD tid={} rip={:#x} (user)", tid, rip);

    // Dump 16 bytes at faulting RIP for diagnosis
    let ptr = rip as *const u8;
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = unsafe { core::ptr::read_volatile(ptr.add(i)) };
    }
    kprintln!("#UD bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);

    // Deliver SIGILL (signal 4) with real GPRs
    if deliver_fault_signal(gprs, iframe, 4, rip, 0) {
        return;
    }

    // No trampoline — kill thread
    crate::sched::exit_current();
}

/// Kernel-mode #UD handler — panics.
#[no_mangle]
extern "C" fn ud_fault_kernel_handler() {
    panic!("EXCEPTION: #UD invalid opcode (kernel)");
}

// ---------------------------------------------------------------------------
// #DE handler — assembly entry. No error code → push dummy 0.
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".global divide_error_handler_asm",
    "divide_error_handler_asm:",
    // No error code. Check CS at rsp+8.
    "    test qword ptr [rsp + 8], 3",
    "    jz 2f",
    // === User-mode #DE ===
    "    swapgs",
    "    push 0", // dummy error code
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11",
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",
    "    push rbx",
    "    push rax",
    "    mov rdi, rsp",
    "    lea rsi, [rsp + 120]",
    "    call de_fault_user_handler",
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
    "    add rsp, 8", // pop dummy error code
    "    swapgs",
    "    iretq",
    // === Kernel-mode #DE: panic ===
    "2:",
    "    call de_fault_kernel_handler",
    "    ud2",
);

/// Rust handler for user-mode #DE.
#[no_mangle]
extern "C" fn de_fault_user_handler(gprs: *mut u64, iframe: *mut u64) {
    let rip = unsafe { *iframe.add(1) };
    let tid = crate::sched::current_tid().map(|t| t.0).unwrap_or(0);
    kprintln!("#DE tid={} rip={:#x} (user)", tid, rip);

    // Deliver SIGFPE (signal 8) with real GPRs
    if deliver_fault_signal(gprs, iframe, 8, rip, 0) {
        return;
    }

    // No trampoline — kill thread
    crate::sched::exit_current();
}

/// Kernel-mode #DE handler — panics.
#[no_mangle]
extern "C" fn de_fault_kernel_handler() {
    panic!("EXCEPTION: #DE divide error (kernel)");
}

// ---------------------------------------------------------------------------
// Custom #PF handler — assembly entry saves all 15 GPRs for user-mode faults.
// The x86-interrupt ABI doesn't expose GPRs, but Wine's signal handler needs
// correct register values in the ucontext for exception dispatch.
//
// #PF stack layout (CPU pushes error code):
//   [rsp+0]  = error_code
//   [rsp+8]  = RIP
//   [rsp+16] = CS
//   [rsp+24] = RFLAGS
//   [rsp+32] = RSP (user)
//   [rsp+40] = SS
// ---------------------------------------------------------------------------

extern "C" {
    fn page_fault_handler_asm();
    fn general_protection_handler_asm();
    fn divide_error_handler_asm();
    fn invalid_opcode_handler_asm();
}

core::arch::global_asm!(
    ".global page_fault_handler_asm",
    "page_fault_handler_asm:",
    // Check if from user mode: CS & 3 (at rsp+16, after error code at rsp+0)
    "    test qword ptr [rsp + 16], 3",
    "    jz 2f",
    // === User-mode #PF ===
    // Swap user GS ↔ kernel GS so percpu is accessible via gs:xx
    "    swapgs",
    // Save all 15 GPRs
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11",
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",
    "    push rbx",
    "    push rax",
    // Call Rust handler:
    //   rdi = pointer to saved GPRs (15 u64s at rsp)
    //   rsi = pointer to interrupt frame (15*8=120 above: error_code, RIP, CS, RFLAGS, RSP, SS)
    "    mov rdi, rsp",
    "    lea rsi, [rsp + 120]",
    "    call page_fault_user_handler",
    // Restore all GPRs
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
    // Pop error code (CPU pushed it, we must remove it before iretq)
    "    add rsp, 8",
    // Swap kernel GS ↔ user GS before returning to user mode
    "    swapgs",
    "    iretq",
    // === Kernel-mode #PF: panic ===
    "2:",
    // GS_BASE already points to percpu — no swapgs needed.
    "    call page_fault_kernel_handler",
    // unreachable — kernel handler panics
    "    ud2",
);

/// Rust handler for user-mode page faults. Called from assembly with all GPRs saved.
/// `gprs`: pointer to 15 saved GPRs [rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15]
/// `iframe`: pointer to [error_code, rip, cs, rflags, rsp, ss]
#[no_mangle]
extern "C" fn page_fault_user_handler(gprs: *mut u64, iframe: *mut u64) {
    let error_code = unsafe { *iframe };
    let rip = unsafe { *iframe.add(1) };
    let rsp = unsafe { *iframe.add(4) };
    let rflags = unsafe { *iframe.add(3) };
    let addr = Cr2::read_raw();
    let code_bits = error_code;

    let tid = crate::sched::current_tid().map(|t| t.0).unwrap_or(0);
    let cr3 = crate::mm::paging::read_cr3();

    // Kernel-address fault from user mode → synchronous SIGSEGV.
    if addr >= 0xFFFF_8000_0000_0000 {
        let percpu = super::percpu::current_percpu();
        let idx = percpu.current_thread;
        if idx != usize::MAX {
            // Detect repeated fault at same RIP (signal handler didn't fix it).
            // Like Linux's force_sigsegv: if the handler returns without fixing
            // the fault, the same instruction faults again → force-kill.
            let last_rip = crate::sched::get_last_fault_rip_by_idx(idx as u32);
            if last_rip == rip && rip != 0 {
                kprintln!(
                    "#PF-REPEATED tid={} rip={:#x} cr2={:#x} → force kill",
                    tid,
                    rip,
                    addr
                );
                crate::sched::set_last_fault_rip_by_idx(idx as u32, 0);
                if let Some(tid) = crate::sched::current_tid() {
                    crate::sched::set_pending_signal(tid, 11);
                }
                crate::sched::exit_current();
            }
            crate::sched::set_last_fault_rip_by_idx(idx as u32, rip);

            let tramp = crate::sched::get_signal_trampoline_by_idx(idx as u32);
            if tramp != 0 {
                // Save real GPRs (not fake zeros!)
                let mut real_gprs = [0u64; 15];
                unsafe {
                    for i in 0..15 {
                        real_gprs[i] = *gprs.add(i);
                    }
                }
                // Force save even if signal_ctx_valid is true from a previous
                // undelivered signal — we need the NEW faulting context.
                crate::sched::clear_signal_ctx(crate::sched::ThreadId(tid));
                crate::sched::save_signal_context_current(&real_gprs, rip, rsp, rflags);
                // Store kernel-generated signal number and fault info.
                crate::sched::set_kernel_signal_current(11); // SIGSEGV
                crate::sched::set_fault_info_current(addr, code_bits);
                kprintln!(
                    "#PF-SIG tid={} rip={:#x} rsp={:#x} cr2={:#x} code={:#x}",
                    tid,
                    rip,
                    rsp,
                    addr,
                    code_bits
                );
                // Do NOT set pending_signals — we redirect directly below.
                // Redirect: overwrite RIP in interrupt frame → iret goes to trampoline.
                unsafe {
                    *iframe.add(1) = tramp;
                }
                return;
            }
        }
        // No trampoline registered → kill thread
        if let Some(tid) = crate::sched::current_tid() {
            crate::sched::set_pending_signal(tid, 11);
        }
        crate::sched::exit_current();
    }

    // Log null-pointer faults (diagnostic only — VMM maps page 0 on demand,
    // which is needed because glibc reads through NULL pointers when globals
    // like __environ aren't initialized, and handles the zero return gracefully).
    if addr == 0 || rip == 0 {
        kprintln!(
            "#PF-NULL tid={} addr={:#x} code={:#x} rip={:#x}",
            tid,
            addr,
            code_bits,
            rip
        );
    }
    if crate::fault::push_fault(tid, addr, code_bits, cr3) {
        crate::sched::fault_current();
    } else {
        kprintln!(
            "page fault (user, no VMM): addr={:#x} code={:#x} rip={:#x}",
            addr,
            code_bits,
            rip
        );
        crate::sched::exit_current();
    }
}

/// Kernel-mode #PF handler — panics.
/// Called from assembly when CS indicates kernel mode.
#[no_mangle]
extern "C" fn page_fault_kernel_handler() {
    let addr = Cr2::read_raw();
    panic!("page fault (kernel): addr={:#x}", addr);
}

// ---------------------------------------------------------------------------
// Remaining contributory exception handlers (IST 3) — kernel-only panics
// ---------------------------------------------------------------------------

extern "x86-interrupt" fn device_not_available_handler(frame: InterruptStackFrame) {
    panic!(
        "EXCEPTION: #NM device not available at rip={:#x}\n{:#?}",
        frame.instruction_pointer.as_u64(),
        frame
    );
}

extern "x86-interrupt" fn invalid_tss_handler(frame: InterruptStackFrame, code: u64) {
    panic!(
        "EXCEPTION: #TS invalid TSS (code {}) at rip={:#x}\n{:#?}",
        code,
        frame.instruction_pointer.as_u64(),
        frame
    );
}

extern "x86-interrupt" fn segment_not_present_handler(frame: InterruptStackFrame, code: u64) {
    panic!(
        "EXCEPTION: #NP segment not present (code {}) at rip={:#x}\n{:#?}",
        code,
        frame.instruction_pointer.as_u64(),
        frame
    );
}

extern "x86-interrupt" fn stack_segment_fault_handler(frame: InterruptStackFrame, code: u64) {
    panic!(
        "EXCEPTION: #SS stack segment fault (code {}) at rip={:#x}\n{:#?}",
        code,
        frame.instruction_pointer.as_u64(),
        frame
    );
}

extern "x86-interrupt" fn alignment_check_handler(frame: InterruptStackFrame, code: u64) {
    panic!(
        "EXCEPTION: #AC alignment check (code {}) at rip={:#x}\n{:#?}",
        code,
        frame.instruction_pointer.as_u64(),
        frame
    );
}

// ---------------------------------------------------------------------------
// Timer handlers
// ---------------------------------------------------------------------------

/// PIT timer handler (vector 32). Used during early boot before LAPIC.
extern "x86-interrupt" fn pit_timer_handler(frame: InterruptStackFrame) {
    let from_user = frame.code_segment.0 & 3 != 0;
    if from_user {
        unsafe {
            core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
        }
    }
    pic::send_eoi(0);
    crate::sched::tick();
    if from_user {
        unsafe {
            core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
        }
    }
}

// ---------------------------------------------------------------------------
// Custom LAPIC timer handler — assembly entry + Rust handlers
// ---------------------------------------------------------------------------
//
// The default x86-interrupt ABI doesn't expose general-purpose registers.
// For async signal delivery, the kernel needs to save ALL user GPRs when
// interrupting a user-mode thread, so we use a custom assembly entry point.
//
// Stack layout after CPU pushes interrupt frame:
//   [rsp+0]  = RIP       (return address)
//   [rsp+8]  = CS        (code segment, & 3 = CPL)
//   [rsp+16] = RFLAGS
//   [rsp+24] = RSP       (user stack pointer)
//   [rsp+32] = SS        (stack segment)

extern "C" {
    fn lapic_timer_handler_asm();
}

core::arch::global_asm!(
    ".global lapic_timer_handler_asm",
    "lapic_timer_handler_asm:",
    // Check if interrupted from user mode (CS & 3)
    "    test qword ptr [rsp + 8], 3",
    "    jz 2f",
    // === User mode interrupt ===
    // Swap user GS ↔ kernel GS so percpu is accessible via gs:xx
    "    swapgs",
    // Save all 15 GPRs
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11",
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",
    "    push rbx",
    "    push rax",
    // Call Rust handler:
    //   rdi = pointer to saved GPRs (15 u64s at rsp)
    //   rsi = pointer to interrupt frame (15*8 = 120 bytes above rsp)
    "    mov rdi, rsp",
    "    lea rsi, [rsp + 120]",
    "    call lapic_timer_user_handler",
    // Restore all GPRs (Rust handler may have modified the interrupt frame)
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
    // Swap kernel GS ↔ user GS before returning to user mode
    "    swapgs",
    "    iretq",
    // === Kernel mode interrupt: save caller-saved regs, call tick ===
    "2:",
    // GS_BASE already points to percpu — no swapgs needed.
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rdi",
    "    push rsi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    call lapic_timer_kernel_handler",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rsi",
    "    pop rdi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "    iretq",
);

/// Rust handler for user-mode LAPIC timer interrupts.
/// Called from assembly with full GPR access.
///
/// `gprs`: pointer to 15 saved GPRs [rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15]
/// `iframe`: pointer to interrupt frame [rip,cs,rflags,rsp,ss]
/// CR3 of a target process to profile. Set by init via SYS_DEBUG_SET_PROFILE_CR3.
/// When the LAPIC timer fires and the current CR3 matches, we sample the user RIP.
pub static DEBUG_PROFILE_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[no_mangle]
extern "C" fn lapic_timer_user_handler(gprs: *mut u64, iframe: *mut u64) {
    lapic::eoi();

    // Lock-free RIP profiler: sample user RIP when current CR3 matches target.
    // No scheduler locks — reads CR3 register and interrupt frame directly.
    {
        use core::sync::atomic::Ordering;
        let target_cr3 = DEBUG_PROFILE_CR3.load(Ordering::Relaxed);
        if target_cr3 != 0 {
            let current_cr3 = crate::mm::paging::read_cr3();
            if current_cr3 == target_cr3 {
                static PROF_COUNT: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                static PROF_LAST: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0);
                static PROF_REPEAT: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let user_rip = unsafe { *iframe };
                let user_rsp = unsafe { *iframe.add(3) };
                let n = PROF_COUNT.fetch_add(1, Ordering::Relaxed);
                let last = PROF_LAST.load(Ordering::Relaxed);

                // GPRs: [rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15]
                // Full register dump on first sample, then RSI+RBX+R10 every 50th
                let user_rsi = unsafe { *gprs.add(4) };
                let user_rbx = unsafe { *gprs.add(1) };
                let user_r10 = unsafe { *gprs.add(9) };
                let user_rax = unsafe { *gprs };

                if user_rip == last {
                    let rep = PROF_REPEAT.fetch_add(1, Ordering::Relaxed);
                    if rep < 3 || rep % 200 == 0 {
                        crate::kprintln!(
                            "PROF-SPIN n={} rip={:#x} rsp={:#x} rax={:#x} rep={}",
                            n,
                            user_rip,
                            user_rsp,
                            user_rax,
                            rep
                        );
                    }
                } else {
                    PROF_REPEAT.store(0, Ordering::Relaxed);
                    PROF_LAST.store(user_rip, Ordering::Relaxed);
                    if n < 10 || n % 100 == 0 {
                        crate::kprintln!(
                            "PROF n={} rip={:#x} rsp={:#x} rax={:#x} rsi={:#x}",
                            n,
                            user_rip,
                            user_rsp,
                            user_rax,
                            user_rsi
                        );
                    }
                }
            }
        }
    }

    // Check if current thread has pending async signals
    let percpu = super::percpu::current_percpu();
    let idx = percpu.current_thread;

    if idx != usize::MAX {
        let pending = crate::sched::get_pending_signals_by_idx(idx as u32);
        let tramp = crate::sched::get_signal_trampoline_by_idx(idx as u32);

        if pending != 0 && tramp != 0 {
            let sig = pending.trailing_zeros() as u64;

            // Signal 0 is not a real signal — never deliver it.
            if sig > 0 && sig < 64 {
                unsafe {
                    // Read original user state from the interrupt frame
                    let original_rip = *iframe;
                    let original_rsp = *iframe.add(3);
                    let original_rflags = *iframe.add(2);

                    // Build the full saved GPR array
                    let mut saved_gprs = [0u64; 15];
                    for i in 0..15 {
                        saved_gprs[i] = *gprs.add(i);
                    }

                    // Save context — returns false if a signal is already in progress
                    // (#PF handler saved it, or a previous timer delivery hasn't completed).
                    let did_save = crate::sched::save_signal_context_current(
                        &saved_gprs,
                        original_rip,
                        original_rsp,
                        original_rflags,
                    );

                    if did_save {
                        // New signal delivery — clear bit, set kernel_signal, redirect.
                        crate::sched::clear_pending_signal_by_idx(idx as u32, sig);
                        crate::sched::set_kernel_signal_current(sig);

                        if sig == 11 {
                            let cr2 = Cr2::read_raw();
                            crate::sched::set_fault_info_current(cr2, 5);
                        }

                        *iframe = tramp; // RIP = trampoline address
                    }
                    // If !did_save: signal already in progress. Leave the pending bit
                    // set — it will be delivered after the current handler completes
                    // and signal_ctx_valid is cleared by rt_sigreturn.
                }
            } else {
                // Clear stale bit 0 (signal 0) to prevent infinite checks
                crate::sched::clear_pending_signal_by_idx(idx as u32, sig);
            }
        }
    }

    crate::sched::tick();
}

/// Rust handler for kernel-mode LAPIC timer interrupts.
/// Simple: EOI + scheduler tick.
#[no_mangle]
extern "C" fn lapic_timer_kernel_handler() {
    lapic::eoi();
    crate::sched::tick();
}

/// Reschedule IPI handler (vector 49). Triggers a schedule on receiving CPU.
/// SMP fix: use try_schedule() to avoid blocking spin inside interrupt handler.
/// If SCHEDULER lock is contended, skip — next timer tick will reschedule.
extern "x86-interrupt" fn reschedule_ipi_handler(frame: InterruptStackFrame) {
    let from_user = frame.code_segment.0 & 3 != 0;
    if from_user {
        unsafe {
            core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
        }
    }
    lapic::eoi();
    crate::sched::try_schedule();
    if from_user {
        unsafe {
            core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags));
        }
    }
}

/// LAPIC spurious interrupt handler. No-op.
extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {
    // Spurious interrupts do NOT require an EOI.
}
