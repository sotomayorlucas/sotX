//! Interrupt Descriptor Table setup.
//!
//! Registers CPU exception handlers and hardware interrupt handlers.

use crate::kprintln;
use spin::Lazy;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::gdt::DOUBLE_FAULT_IST_INDEX;
use super::pic;

/// Timer interrupt vector (IRQ0 after PIC remap).
pub const TIMER_VECTOR: u8 = 32;

/// Generate an IRQ handler for a hardware IRQ line (1-15).
/// Each handler: send_eoi → mask → notify → iretq.
macro_rules! irq_handler {
    ($name:ident, $irq:expr) => {
        extern "x86-interrupt" fn $name(_frame: InterruptStackFrame) {
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

    idt[TIMER_VECTOR].set_handler_fn(timer_handler);

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

    idt
});

pub fn init() {
    IDT.load();
}

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
        if crate::fault::push_fault(tid, addr, code.bits()) {
            crate::sched::fault_current();
        } else {
            kprintln!(
                "page fault (user, no VMM): addr={:#x} code={:?} rip={:#x}",
                addr, code, frame.instruction_pointer.as_u64()
            );
            crate::sched::exit_current();
        }
    } else {
        // Kernel-mode page fault — this is a bug.
        panic!(
            "page fault (kernel): addr={:#x} code={:?}\n{:#?}",
            addr, code, frame
        );
    }
}

extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    pic::send_eoi(0);
    crate::sched::tick();
}
