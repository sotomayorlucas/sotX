//! IRQ virtualization — notification-based binding for userspace drivers.
//!
//! Maps hardware IRQ lines to notification objects. When an IRQ fires,
//! the kernel signals all bound notifications; drivers call
//! `NOTIFY_WAIT` to block and `IRQ_ACK` to unmask the line.
//!
//! Supports IRQ sharing: multiple drivers can register different
//! notifications on the same IRQ line.
//!
//! Lock ordering: IRQ_TABLE dropped before calling ipc::notify (which
//! acquires NOTIFICATIONS then SCHEDULER).

use crate::arch::x86_64::pic;
use crate::ipc::notify;
use crate::pool::PoolHandle;
use sotos_common::SysError;
use spin::Mutex;

/// Maximum IRQ lines managed (8259 PIC: 0-15).
const MAX_IRQ: usize = 16;

/// Maximum number of handlers sharing a single IRQ line.
const MAX_SHARED: usize = 4;

/// Per-IRQ binding: maps an IRQ line to one or more notification objects.
#[derive(Clone, Copy)]
struct IrqBinding {
    /// Bound notification handles. Supports up to MAX_SHARED per line.
    handles: [Option<PoolHandle>; MAX_SHARED],
}

impl IrqBinding {
    const fn empty() -> Self {
        Self {
            handles: [None; MAX_SHARED],
        }
    }

    /// Add a notification handle. Returns Err if full.
    fn add(&mut self, handle: PoolHandle) -> Result<(), SysError> {
        for slot in self.handles.iter_mut() {
            if slot.is_none() {
                *slot = Some(handle);
                return Ok(());
            }
        }
        Err(SysError::OutOfResources)
    }
}

static IRQ_TABLE: Mutex<[IrqBinding; MAX_IRQ]> = Mutex::new([IrqBinding::empty(); MAX_IRQ]);

/// Bind an IRQ line to a notification object and unmask the line.
///
/// Multiple drivers may share the same IRQ line (up to MAX_SHARED).
/// Rejects IRQ 0 (kernel timer).
pub fn register(irq: u8, notify_handle: PoolHandle) -> Result<(), SysError> {
    if irq == 0 || irq as usize >= MAX_IRQ {
        return Err(SysError::InvalidArg);
    }

    let mut table = IRQ_TABLE.lock();
    let entry = &mut table[irq as usize];
    entry.add(notify_handle)?;
    pic::unmask(irq);
    Ok(())
}

/// Acknowledge an IRQ by unmasking the line. Does not block.
///
/// The driver blocks separately via `SYS_NOTIFY_WAIT`.
pub fn ack(irq: u8) -> Result<(), SysError> {
    if irq as usize >= MAX_IRQ {
        return Err(SysError::InvalidArg);
    }

    pic::unmask(irq);
    Ok(())
}

/// Called from IDT interrupt handler (IF=0). Signals all bound
/// notification objects for this IRQ line.
///
/// The IRQ line is already masked by the IDT handler before calling this.
pub fn notify(irq: u8) {
    if irq as usize >= MAX_IRQ {
        return;
    }

    let handles = {
        let table = IRQ_TABLE.lock();
        table[irq as usize].handles
    };
    // IRQ_TABLE lock dropped — safe to call into notify subsystem.

    for handle in handles.iter().flatten() {
        let _ = notify::signal(*handle);
    }
}
