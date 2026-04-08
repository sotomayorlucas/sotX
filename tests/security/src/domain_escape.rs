//! Domain escape tests.
//!
//! These tests verify that code running inside a domain cannot access
//! resources outside the domain's capability set. Every attempt to
//! escape the domain boundary must fail.

#[cfg(test)]
mod tests {
    /// Verify that a domain cannot access memory outside its address space.
    ///
    /// Attack: attempt to read/write to an address not mapped in the domain's
    /// page tables (e.g., kernel HHDM region, another domain's stack).
    /// Expected: page fault -> domain terminated (or fault delivered to VMM
    /// which refuses to map the page).
    #[test]
    fn cannot_access_kernel_memory() {
        // TODO: Boot with test domain that tries to read 0xFFFF800000000000.
        // Verify domain is terminated with a page fault.
    }

    /// Verify that a domain cannot access another domain's memory.
    ///
    /// Attack: guess the virtual address of another domain's stack or heap.
    /// Expected: page fault -> termination. Each domain has its own CR3,
    /// so the same virtual address maps to different (or no) physical frames.
    #[test]
    fn cannot_access_other_domain_memory() {
        // TODO: Create two domains. Domain A tries to read Domain B's stack
        // address. Verify page fault.
    }

    /// Verify that a domain cannot forge IPC messages to kernel objects.
    ///
    /// Attack: send an IPC message using a capability ID the domain does not
    /// own.
    /// Expected: InvalidCap error. The kernel validates the cap ID against
    /// the calling domain's CSpace.
    #[test]
    fn cannot_send_with_unowned_cap() {
        // TODO: Domain tries to send on cap ID 9999 (not in its CSpace).
        // Verify InvalidCap error.
    }

    /// Verify that a domain cannot create capabilities for arbitrary objects.
    ///
    /// Attack: call cap_derive with a source cap that belongs to another domain.
    /// Expected: InvalidCap error.
    #[test]
    fn cannot_derive_from_foreign_cap() {
        // TODO: Domain A owns cap 1. Domain B tries cap_derive(1, ALL).
        // Verify Domain B gets InvalidCap.
    }

    /// Verify that a domain cannot escalate to Ring 0.
    ///
    /// Attack: execute privileged instructions (e.g., WRMSR, MOV CR3, LGDT).
    /// Expected: #GP exception -> domain terminated.
    #[test]
    fn cannot_execute_privileged_instructions() {
        // TODO: Test domain executes `wrmsr` instruction.
        // Verify #GP fault -> termination.
    }

    /// Verify that a domain cannot map arbitrary physical frames.
    ///
    /// Attack: call sys_map with a frame capability the domain does not own.
    /// Expected: InvalidCap error. Frame mapping requires a valid frame cap.
    #[test]
    fn cannot_map_arbitrary_physical_memory() {
        // TODO: Domain tries sys_map with a fabricated frame cap.
        // Verify rejection.
    }

    /// Verify that domain budget enforcement prevents CPU monopolization.
    ///
    /// Attack: domain runs a tight loop, trying to consume more than its
    /// quantum.
    /// Expected: domain is preempted after quantum expires. Other domains
    /// get their fair share.
    #[test]
    fn cannot_monopolize_cpu() {
        // TODO: Domain with 10% budget runs tight loop. Verify it gets
        // ~10% CPU over several periods.
    }
}
