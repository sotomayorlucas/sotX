//! Lock ordering enforcement (debug builds only).
//!
//! Each lock in the kernel is assigned a `LockLevel`. A per-CPU bitmask
//! tracks which levels are currently held. Acquiring a lock at level N
//! when any lock at level >= N is held triggers a debug assertion.
//!
//! This is zero-cost in release builds (`#[cfg(debug_assertions)]`).
//!
//! Lock hierarchy (lower = acquired first):
//!   0: FaultState       (fault.rs)
//!   1: IrqTable          (irq.rs)
//!   2: Endpoints         (ipc/endpoint.rs)
//!   3: Channels          (ipc/channel.rs)
//!   4: Notifications     (ipc/notify.rs)
//!   5: CapTable          (cap/mod.rs)
//!   6: Scheduler         (sched/mod.rs)
//!   7: SlabAllocator     (mm/slab.rs)
//!   8: FrameAllocator    (mm/frame.rs)

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LockLevel {
    FaultState = 0,
    IrqTable = 1,
    Endpoints = 2,
    Channels = 3,
    Notifications = 4,
    CapTable = 5,
    Scheduler = 6,
    Slab = 7,
    FrameAllocator = 8,
}

/// Check that no lock at level >= `level` is currently held.
/// Panics on violation (debug builds only).
#[allow(dead_code)]
#[cfg(debug_assertions)]
pub fn check_lock_order(level: LockLevel) {
    // Guard: percpu may not be initialized during early boot (slab allocates
    // before percpu init). Check self_ptr to detect this.
    let self_ptr: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) self_ptr,
            options(nomem, nostack, preserves_flags),
        );
    }
    if self_ptr == 0 {
        return; // Early boot — percpu not ready
    }

    let percpu = crate::arch::x86_64::percpu::current_percpu();
    let held = percpu.held_locks;
    let level_bit = level as u8;

    // Check if any bit >= level_bit is set in held_locks.
    // Mask = all bits from level_bit to 15.
    let mask = !((1u16 << level_bit) - 1);
    if held & mask != 0 {
        panic!(
            "lock ordering violation: acquiring {:?} (level {}) while held_locks = {:#06x}",
            level, level_bit, held
        );
    }
}

#[cfg(not(debug_assertions))]
#[allow(dead_code)]
#[inline(always)]
pub fn check_lock_order(_level: LockLevel) {}

/// Mark a lock level as held.
#[allow(dead_code)]
#[cfg(debug_assertions)]
pub fn mark_lock_held(level: LockLevel) {
    let self_ptr: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) self_ptr,
            options(nomem, nostack, preserves_flags),
        );
    }
    if self_ptr == 0 {
        return;
    }
    let percpu = crate::arch::x86_64::percpu::current_percpu();
    percpu.held_locks |= 1u16 << (level as u8);
}

#[cfg(not(debug_assertions))]
#[allow(dead_code)]
#[inline(always)]
pub fn mark_lock_held(_level: LockLevel) {}

/// Mark a lock level as released.
#[allow(dead_code)]
#[cfg(debug_assertions)]
pub fn mark_lock_released(level: LockLevel) {
    let self_ptr: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) self_ptr,
            options(nomem, nostack, preserves_flags),
        );
    }
    if self_ptr == 0 {
        return;
    }
    let percpu = crate::arch::x86_64::percpu::current_percpu();
    percpu.held_locks &= !(1u16 << (level as u8));
}

#[cfg(not(debug_assertions))]
#[allow(dead_code)]
#[inline(always)]
pub fn mark_lock_released(_level: LockLevel) {}
