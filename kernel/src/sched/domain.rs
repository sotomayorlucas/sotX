//! Scheduling Domains — budget-enforced thread groups.
//!
//! A domain groups threads that share a kernel-enforced time budget.
//! Each domain has a `quantum` (ticks per period) and a `period`
//! (how often the budget refills). When the budget is exhausted,
//! domain threads are suspended until the next refill.

use alloc::vec::Vec;

/// Maximum threads in a single domain.
pub const MAX_MEMBERS: usize = 64;

/// Whether a domain's budget is available or exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// Budget available — threads may run.
    Active,
    /// Budget exhausted — threads are parked until refill.
    Depleted,
}

/// A scheduling domain: a group of threads sharing a CPU time budget.
pub struct SchedDomain {
    /// Ticks allowed per period.
    pub quantum_ticks: u32,
    /// Period length in ticks.
    pub period_ticks: u32,
    /// Ticks consumed in the current period.
    pub consumed_ticks: u32,
    /// Global tick at which the next refill occurs.
    pub next_refill_tick: u64,
    /// Current budget state.
    pub state: DomainState,
    /// Member thread pool indices.
    pub members: [Option<u32>; MAX_MEMBERS],
    /// Number of members.
    pub member_count: usize,
    /// Thread indices suspended while domain is depleted.
    pub suspended: Vec<usize>,
}

impl SchedDomain {
    /// Create a new domain starting at `global_tick`.
    pub fn new(quantum: u32, period: u32, global_tick: u64) -> Self {
        Self {
            quantum_ticks: quantum,
            period_ticks: period,
            consumed_ticks: 0,
            next_refill_tick: global_tick + period as u64,
            state: DomainState::Active,
            members: [None; MAX_MEMBERS],
            member_count: 0,
            suspended: Vec::new(),
        }
    }

    /// Add a thread (by pool index) to this domain. Returns false if full.
    pub fn add_member(&mut self, idx: u32) -> bool {
        if self.member_count >= MAX_MEMBERS {
            return false;
        }
        // Check for duplicates.
        for slot in &self.members[..self.member_count] {
            if *slot == Some(idx) {
                return true; // already a member
            }
        }
        // Find first empty slot.
        for slot in self.members.iter_mut() {
            if slot.is_none() {
                *slot = Some(idx);
                self.member_count += 1;
                return true;
            }
        }
        false
    }

    /// Remove a thread from this domain.
    pub fn remove_member(&mut self, idx: u32) {
        for slot in self.members.iter_mut() {
            if *slot == Some(idx) {
                *slot = None;
                self.member_count -= 1;
                return;
            }
        }
        // Also remove from suspended list if present.
        self.suspended.retain(|&s| s != idx as usize);
    }

    /// Check if a thread is a member.
    #[allow(dead_code)]
    pub fn has_member(&self, idx: u32) -> bool {
        self.members[..].iter().any(|s| *s == Some(idx))
    }
}
