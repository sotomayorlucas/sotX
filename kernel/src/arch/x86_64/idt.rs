//! Interrupt Descriptor Table setup.
//!
//! Registers CPU exception handlers, hardware IRQ handlers (PIC),
//! and LAPIC timer/spurious handlers.

use crate::kprintln;
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

    idt.general_protection_fault
        .set_handler_fn(general_protection_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);

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

    // LAPIC timer (vector 48)
    idt[LAPIC_TIMER_VECTOR].set_handler_fn(lapic_timer_handler);

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
    panic!("EXCEPTION: double fault\n{:#?}", frame);
}

extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, code: u64) {
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
// Timer handlers
// ---------------------------------------------------------------------------

/// PIT timer handler (vector 32). Used during early boot before LAPIC.
extern "x86-interrupt" fn pit_timer_handler(_frame: InterruptStackFrame) {
    pic::send_eoi(0);
    crate::sched::tick();
}

/// LAPIC timer handler (vector 48). Per-CPU preemption timer.
extern "x86-interrupt" fn lapic_timer_handler(_frame: InterruptStackFrame) {
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
