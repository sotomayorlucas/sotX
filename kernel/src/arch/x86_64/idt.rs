//! Interrupt Descriptor Table setup.
//!
//! Registers CPU exception handlers, hardware IRQ handlers (PIC),
//! and LAPIC timer/spurious handlers.

use crate::{kprintln, kdebug};
use spin::Lazy;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::gdt::DOUBLE_FAULT_IST_INDEX;
use super::pic;
use super::lapic;

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
        extern "x86-interrupt" fn $name(_frame: InterruptStackFrame) {
            if !super::percpu::current_percpu().is_bsp() {
                lapic::eoi();
                return;
            }
            pic::send_eoi($irq);
            pic::mask($irq);
            crate::irq::notify($irq);
        }
    };
}

irq_handler!(irq1_handler,  1);
irq_handler!(irq2_handler,  2);
irq_handler!(irq3_handler,  3);
irq_handler!(irq4_handler,  4);
irq_handler!(irq5_handler,  5);
irq_handler!(irq6_handler,  6);
irq_handler!(irq7_handler,  7);
irq_handler!(irq8_handler,  8);
irq_handler!(irq9_handler,  9);
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

    unsafe {
        idt.general_protection_fault
            .set_handler_fn(general_protection_handler)
            .set_stack_index(super::gdt::GP_FAULT_IST_INDEX);
    }
    // #PF does NOT use IST — user-mode faults use the per-thread kernel stack
    // (TSS RSP0), which is safe for context switching away faulted threads.
    // Using IST causes corruption when multiple threads fault before the first
    // returns through the IST stack (e.g., CoW fork marks all PTEs read-only).
    idt.page_fault.set_handler_fn(page_fault_handler);

    // Contributory exceptions on IST 3 — catch them before they chain into #DF
    unsafe {
        idt.divide_error
            .set_handler_fn(divide_error_handler)
            .set_stack_index(super::gdt::MISC_FAULT_IST_INDEX);
    }
    unsafe {
        idt.invalid_opcode
            .set_handler_fn(invalid_opcode_handler)
            .set_stack_index(super::gdt::MISC_FAULT_IST_INDEX);
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
        idt[LAPIC_TIMER_VECTOR]
            .set_handler_addr(x86_64::VirtAddr::new(lapic_timer_handler_asm as *const () as u64));
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

extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, code: u64) {
    // Check if fault is from user mode (RPL of CS selector)
    let cs = frame.code_segment.0;
    if cs & 3 != 0 {
        // User-mode #GP — kill the thread instead of panicking the kernel.
        let tid = crate::sched::current_tid().map(|t| t.0).unwrap_or(0);
        let rip = frame.instruction_pointer.as_u64();
        kprintln!(
            "#GP(user) tid={} code={} rip={:#x} rsp={:#x}",
            tid, code, rip, frame.stack_pointer.as_u64()
        );
        // Set SIGSEGV pending so parent sees WIFSIGNALED, then exit thread.
        if let Some(tid) = crate::sched::current_tid() {
            crate::sched::set_pending_signal(tid, 11);
        }
        crate::sched::exit_current();
        return;
    }
    panic!("EXCEPTION: general protection fault (code {})\n{:#?}", code, frame);
}

extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    code: PageFaultErrorCode,
) {
    let addr = Cr2::read_raw();

    if code.contains(PageFaultErrorCode::USER_MODE) {
        let tid = crate::sched::current_tid().map(|t| t.0).unwrap_or(0);
        let cr3 = crate::mm::paging::read_cr3();
        // Log null-pointer faults
        if addr == 0 || frame.instruction_pointer.as_u64() == 0 {
            kprintln!(
                "#PF-NULL tid={} addr={:#x} code={:#x} rip={:#x}",
                tid, addr, code.bits(), frame.instruction_pointer.as_u64()
            );
        }
        if crate::fault::push_fault(tid, addr, code.bits(), cr3) {
            crate::sched::fault_current();
        } else {
            kprintln!(
                "page fault (user, no VMM): addr={:#x} code={:?} rip={:#x}",
                addr, code, frame.instruction_pointer.as_u64()
            );
            crate::sched::exit_current();
        }
    } else {
        panic!(
            "page fault (kernel): addr={:#x} code={:?}\n{:#?}",
            addr, code, frame
        );
    }
}

// ---------------------------------------------------------------------------
// Contributory exception handlers (IST 3) — identify what chains into #DF
// ---------------------------------------------------------------------------

extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        let tid = crate::sched::current_tid().map(|t| t.0).unwrap_or(0);
        kprintln!("#DE tid={} rip={:#x} (user) — killing thread",
            tid, frame.instruction_pointer.as_u64());
        crate::sched::exit_current();
    }
    panic!("EXCEPTION: #DE divide error at rip={:#x}\n{:#?}",
        frame.instruction_pointer.as_u64(), frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        let tid = crate::sched::current_tid().map(|t| t.0).unwrap_or(0);
        kprintln!("#UD tid={} rip={:#x} (user) — killing thread",
            tid, frame.instruction_pointer.as_u64());
        crate::sched::exit_current();
    }
    panic!("EXCEPTION: #UD invalid opcode at rip={:#x}\n{:#?}",
        frame.instruction_pointer.as_u64(), frame);
}

extern "x86-interrupt" fn device_not_available_handler(frame: InterruptStackFrame) {
    panic!("EXCEPTION: #NM device not available at rip={:#x}\n{:#?}",
        frame.instruction_pointer.as_u64(), frame);
}

extern "x86-interrupt" fn invalid_tss_handler(frame: InterruptStackFrame, code: u64) {
    panic!("EXCEPTION: #TS invalid TSS (code {}) at rip={:#x}\n{:#?}",
        code, frame.instruction_pointer.as_u64(), frame);
}

extern "x86-interrupt" fn segment_not_present_handler(frame: InterruptStackFrame, code: u64) {
    panic!("EXCEPTION: #NP segment not present (code {}) at rip={:#x}\n{:#?}",
        code, frame.instruction_pointer.as_u64(), frame);
}

extern "x86-interrupt" fn stack_segment_fault_handler(frame: InterruptStackFrame, code: u64) {
    panic!("EXCEPTION: #SS stack segment fault (code {}) at rip={:#x}\n{:#?}",
        code, frame.instruction_pointer.as_u64(), frame);
}

extern "x86-interrupt" fn alignment_check_handler(frame: InterruptStackFrame, code: u64) {
    panic!("EXCEPTION: #AC alignment check (code {}) at rip={:#x}\n{:#?}",
        code, frame.instruction_pointer.as_u64(), frame);
}

// ---------------------------------------------------------------------------
// Timer handlers
// ---------------------------------------------------------------------------

/// PIT timer handler (vector 32). Used during early boot before LAPIC.
extern "x86-interrupt" fn pit_timer_handler(_frame: InterruptStackFrame) {
    pic::send_eoi(0);
    crate::sched::tick();
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

    // === User mode interrupt: save all 15 GPRs ===
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
    "    iretq",

    // === Kernel mode interrupt: save caller-saved regs, call tick ===
    "2:",
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
#[no_mangle]
extern "C" fn lapic_timer_user_handler(gprs: *mut u64, iframe: *mut u64) {
    lapic::eoi();

    // Check if current thread has pending async signals
    let percpu = super::percpu::current_percpu();
    let idx = percpu.current_thread;

    if idx != usize::MAX {
        let pending = crate::sched::get_pending_signals_by_idx(idx as u32);
        let tramp = crate::sched::get_signal_trampoline_by_idx(idx as u32);

        if pending != 0 && tramp != 0 {
            let sig = pending.trailing_zeros() as u64;

            unsafe {
                // Read original user state from the interrupt frame
                let original_rip    = *iframe;
                let original_rsp    = *iframe.add(3);
                let original_rflags = *iframe.add(2);

                // Build the full saved GPR array
                let mut saved_gprs = [0u64; 15];
                for i in 0..15 {
                    saved_gprs[i] = *gprs.add(i);
                }

                // Save complete pre-interrupt context into the thread struct
                crate::sched::save_signal_context_current(
                    &saved_gprs, original_rip, original_rsp, original_rflags,
                );

                // Clear the pending signal bit
                crate::sched::clear_pending_signal_by_idx(idx as u32, sig);

                // Redirect to signal trampoline by modifying the interrupt frame.
                // GPRs stay the same — trampoline runs with user's original registers.
                *iframe = tramp;  // RIP = trampoline address
                // RSP, RFLAGS, CS, SS unchanged
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
extern "x86-interrupt" fn reschedule_ipi_handler(_frame: InterruptStackFrame) {
    lapic::eoi();
    crate::sched::schedule();
}

/// LAPIC spurious interrupt handler. No-op.
extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {
    // Spurious interrupts do NOT require an EOI.
}
