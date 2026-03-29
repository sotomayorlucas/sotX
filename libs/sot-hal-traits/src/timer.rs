//! Timer abstraction.
//!
//! Provides a platform-portable interface for monotonic time and deadline-based
//! interrupt scheduling.

/// Timer abstraction -- implemented per platform.
///
/// On x86_64 in sotOS, the primary timer is the LAPIC timer (one-shot mode),
/// with TSC used for high-resolution monotonic timestamps.
/// On AArch64, this maps to the ARM Generic Timer (`CNTPCT_EL0` / `CNTP_CVAL_EL0`).
/// On RISC-V, this maps to the `mtime`/`mtimecmp` SBI timer.
pub trait Timer {
    /// Current time in nanoseconds since boot.
    ///
    /// On x86_64, this is derived from `RDTSC` scaled by the TSC frequency.
    /// On AArch64, this reads `CNTPCT_EL0` scaled by `CNTFRQ_EL0`.
    fn now(&self) -> u64;

    /// Set a deadline: fire a timer interrupt at the given nanosecond timestamp.
    ///
    /// On x86_64, this programs the LAPIC timer initial count register.
    /// On AArch64, this writes `CNTP_CVAL_EL0`.
    fn set_deadline(&mut self, ns: u64);

    /// Timer frequency in Hz.
    ///
    /// On x86_64, this returns the TSC frequency (e.g., 2_000_000_000 for 2 GHz).
    /// On AArch64, this reads `CNTFRQ_EL0`.
    fn frequency(&self) -> u64;

    /// Compute elapsed nanoseconds since a previous `now()` reading.
    ///
    /// Default implementation uses wrapping subtraction to handle counter overflow.
    fn elapsed_since(&self, start: u64) -> u64 {
        self.now().wrapping_sub(start)
    }
}
