//! Kernel watchdog timer — detects hung CPUs.
//!
//! Each CPU calls `heartbeat(cpu)` from its timer tick handler.
//! A periodic `check()` call detects CPUs that haven't reported a
//! heartbeat within the timeout window (default: 500 ticks).

use core::sync::atomic::{AtomicU64, Ordering};
use crate::kdebug;
use crate::kprintln;

use sotos_common::MAX_CPUS;

/// Number of ticks without a heartbeat before a CPU is considered stale.
const WATCHDOG_TIMEOUT_TICKS: u64 = 500;

/// Per-CPU heartbeat timestamps. Each entry stores the global tick count
/// at the time of the last heartbeat. Value 0 means the CPU has not
/// been initialized or is offline.
static HEARTBEATS: [AtomicU64; MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_CPUS]
};

/// Record a heartbeat for the given CPU. Called from the timer tick handler.
///
/// `cpu` is the CPU index (0-based). `tick` is the current global tick count.
pub fn heartbeat(cpu: usize, tick: u64) {
    if cpu < MAX_CPUS {
        HEARTBEATS[cpu].store(tick, Ordering::Release);
    }
}

/// Check all CPUs for stale heartbeats. Called periodically (e.g., every
/// 100 ticks from the BSP timer).
///
/// `current_tick` is the current global tick count. Any CPU whose last
/// heartbeat is more than `WATCHDOG_TIMEOUT_TICKS` behind is reported
/// as potentially hung.
pub fn check(current_tick: u64) {
    for cpu in 0..MAX_CPUS {
        let last = HEARTBEATS[cpu].load(Ordering::Acquire);
        // Skip CPUs that have never heartbeated (offline or not yet started).
        if last == 0 {
            continue;
        }
        if current_tick > last && current_tick - last > WATCHDOG_TIMEOUT_TICKS {
            kprintln!(
                "WATCHDOG: CPU {} stale! last heartbeat at tick {}, current tick {} (delta={})",
                cpu,
                last,
                current_tick,
                current_tick - last
            );
        }
    }
}

/// Initialize the watchdog for a CPU (sets initial heartbeat).
pub fn init_cpu(cpu: usize, tick: u64) {
    heartbeat(cpu, tick);
    kdebug!("  watchdog: CPU {} initialized at tick {}", cpu, tick);
}
