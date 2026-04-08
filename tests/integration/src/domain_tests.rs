//! Domain lifecycle integration tests.
//!
//! These tests verify scheduling domain creation, thread attachment,
//! budget enforcement, and domain destruction.

#[cfg(test)]
mod tests {
    use crate::{setup_test_domain, verify_cap_rights, TestRights};

    /// Verify domain creation returns a valid capability.
    ///
    /// Expected: DomainCreate(10ms quantum, 100ms period) returns a cap
    /// with ALL rights. DomainInfo on the cap returns the configured
    /// quantum and period values.
    #[test]
    fn domain_create_basic() {
        let domain = setup_test_domain();
        assert_eq!(domain.quantum_ms, 10);
        assert_eq!(domain.period_ms, 100);
        verify_cap_rights(&domain, 0, TestRights::ALL);
    }

    /// Verify thread attachment to a domain.
    ///
    /// Expected: DomainAttach(domain_cap, thread_cap) succeeds.
    /// The thread is now subject to the domain's scheduling budget.
    #[test]
    fn domain_attach_thread() {
        // TODO: Create domain, create thread, attach thread to domain.
        // Verify thread runs only within the domain's budget.
    }

    /// Verify domain budget enforcement.
    ///
    /// Expected: A domain with 10ms quantum and 100ms period runs its
    /// threads for ~10ms, then all threads are suspended until the next
    /// period. Serial output shows depletion/refill cycle.
    #[test]
    fn domain_budget_enforcement() {
        // TODO: Attach a CPU-intensive thread to a domain. Measure
        // its execution time per period via serial timestamps.
    }

    /// Verify domain budget adjustment.
    ///
    /// Expected: DomainAdjust(domain_cap, new_quantum) changes the
    /// domain's quantum. The next period uses the new budget.
    #[test]
    fn domain_budget_adjust() {
        // TODO: Create domain with 10ms quantum. Adjust to 20ms.
        // Verify the thread runs for ~20ms in the next period.
    }

    /// Verify thread detachment from a domain.
    ///
    /// Expected: DomainDetach(domain_cap, thread_cap) removes the thread
    /// from budget enforcement. The thread runs without limits.
    #[test]
    fn domain_detach_thread() {
        // TODO: Attach thread, verify budget enforcement, detach,
        // verify thread runs without budget limits.
    }

    /// Verify domain info query.
    ///
    /// Expected: DomainInfo returns accurate (quantum, consumed, period)
    /// values. Consumed ticks increase while threads run, reset on refill.
    #[test]
    fn domain_info_query() {
        // TODO: Query domain info at multiple points during execution.
    }

    /// Verify multiple domains with different budgets.
    ///
    /// Expected: Domain A (25% CPU) and Domain B (50% CPU) get
    /// proportional execution time. Measured over several periods.
    #[test]
    fn domain_proportional_sharing() {
        // TODO: Create two domains with different quantum/period ratios.
        // Attach one thread to each. Measure CPU share.
    }

    /// Verify that dead threads are cleaned up from domain membership.
    ///
    /// Expected: When a thread in a domain exits, it is removed from
    /// the domain's member list. The domain continues functioning
    /// with remaining threads.
    #[test]
    fn domain_dead_thread_cleanup() {
        // TODO: Attach two threads, kill one, verify domain still works.
    }
}
