//! IRQ-to-channel bridge.
//!
//! Maps a hardware IRQ line to a SOT async channel so that a driver
//! domain receives interrupt notifications as ordinary IPC messages
//! rather than needing direct IDT access.

/// What the handler wants the framework to do after servicing an IRQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqAction {
    /// IRQ was for this device and has been fully handled.
    Handled,
    /// IRQ was not for this device (shared IRQ line).
    NotMine,
    /// IRQ handled -- also wake a blocked thread (e.g. I/O completion).
    Wake,
}

/// Trait implemented by any driver that handles interrupts.
pub trait IrqHandler {
    /// Called when the IRQ fires.  Must return quickly.
    fn on_interrupt(&mut self) -> IrqAction;
}

/// A bridge between a hardware IRQ line and a SOT channel.
#[derive(Debug, Clone, Copy)]
pub struct IrqChannel {
    /// Hardware IRQ number (GSI or legacy pin).
    pub irq_line: u32,
    /// SOT channel capability that will receive the notification.
    pub channel_cap: u64,
    /// If true, the IRQ line is masked in the interrupt controller
    /// immediately when it fires; the driver must re-enable it after
    /// servicing.
    pub mask_on_fire: bool,
}
