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

// ---------------------------------------------------------------------------
// Phase E — MSI vector allocator
// ---------------------------------------------------------------------------

/// First IDT vector available to MSI consumers. Below this:
///   0..31    CPU exceptions (#DE, #DB, #BP, #PF, #GP, ...)
///   32..47   8259 PIC IRQs 0..15 (timer, keyboard, ...)
///   48       LAPIC timer (`lapic::TIMER_VECTOR`)
///   49       Reschedule IPI (`idt::RESCHEDULE_VECTOR`)
const MSI_VECTOR_FIRST: u8 = 50;

/// Last IDT vector available to MSI consumers. 240..254 reserved
/// for things like the spurious LAPIC vector (255).
const MSI_VECTOR_LAST: u8 = 239;

/// Pre-reserved IDT vector for the Phase E self-IPI delivery test.
/// Picked from the upper end of the MSI range so it doesn't collide
/// with anything the kernel statically registers and so the bitmap
/// allocator can still hand out neighbouring vectors during the test.
pub const MSI_TEST_VECTOR: u8 = 200;

/// Bitmap of free MSI vectors. `false` = available, `true` = held by
/// some `CapObject::Msi` (or pre-reserved by `init`).
static MSI_BITMAP: Mutex<[bool; (MSI_VECTOR_LAST - MSI_VECTOR_FIRST + 1) as usize]> =
    Mutex::new([false; (MSI_VECTOR_LAST - MSI_VECTOR_FIRST + 1) as usize]);

/// Initialise the MSI vector allocator. Marks `MSI_TEST_VECTOR` as
/// pre-reserved so the Phase E delivery test can install its IDT
/// handler at a stable, known vector.
pub fn init_msi() {
    let mut bm = MSI_BITMAP.lock();
    let idx = (MSI_TEST_VECTOR - MSI_VECTOR_FIRST) as usize;
    bm[idx] = true;
}

/// Allocate the next free MSI vector. Returns `None` if every
/// vector in the range is taken.
pub fn alloc_msi_vector() -> Option<u8> {
    let mut bm = MSI_BITMAP.lock();
    for (i, slot) in bm.iter_mut().enumerate() {
        if !*slot {
            *slot = true;
            return Some(MSI_VECTOR_FIRST + i as u8);
        }
    }
    None
}

/// Return an MSI vector to the free pool. Silently ignores vectors
/// outside the MSI range and the pre-reserved test vector.
pub fn free_msi_vector(vector: u8) {
    if vector < MSI_VECTOR_FIRST || vector > MSI_VECTOR_LAST {
        return;
    }
    if vector == MSI_TEST_VECTOR {
        return; // never freed; lives for the lifetime of the kernel
    }
    let idx = (vector - MSI_VECTOR_FIRST) as usize;
    let mut bm = MSI_BITMAP.lock();
    bm[idx] = false;
}

/// Snapshot the number of currently-allocated MSI vectors. Test
/// helper, not on any hot path.
#[allow(dead_code)]
pub fn msi_allocated_count() -> usize {
    let bm = MSI_BITMAP.lock();
    bm.iter().filter(|b| **b).count()
}
