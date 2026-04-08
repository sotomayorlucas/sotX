//! exec() as a transactional domain reset.
//!
//! exec() atomically replaces the calling domain's code and resets its
//! capabilities according to the binary's exec policy. The transaction
//! ensures that either the entire exec succeeds or the domain is left
//! in its original state.
//!
//! Steps:
//!   1. tx_begin()        -- snapshot current state
//!   2. so_invoke(REPLACE) -- load new binary code
//!   3. caps_reset(policy) -- apply the binary's cap policy
//!   4. close cloexec fds  -- revoke fds marked O_CLOEXEC
//!   5. reset signals      -- handlers revert to default
//!   6. tx_commit()        -- finalize
//!
//! If any step fails, tx_abort() restores the previous state and exec()
//! returns an error to the caller.

use alloc::vec::Vec;

use crate::credentials::{BinaryHash, PolicyStore, resolve_exec_caps, CapClass};
use crate::posix::{Cap, SotOp, SoOperation};
use crate::proc::Process;
use crate::signal::SignalTable;

/// Errors that can occur during exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// The binary was not found or could not be loaded.
    NotFound,
    /// The binary hash does not match any registered policy and default
    /// policy does not allow execution.
    PermissionDenied,
    /// A step in the transaction failed and the domain was restored.
    TransactionFailed,
    /// The binary format is not recognized.
    InvalidFormat,
}

/// A prepared exec transaction, ready to be committed.
pub struct ExecTransaction {
    /// SOT operations to execute in order.
    pub ops: Vec<SotOp>,
    /// Caps to revoke (cloexec fds).
    pub revoke_caps: Vec<Cap>,
    /// The resolved cap classes for the new domain.
    pub effective_caps: Vec<CapClass>,
    /// Resource limits from the policy.
    pub resource_limits: crate::credentials::ResourceLimits,
}

/// Prepare an exec transaction.
///
/// This computes the full sequence of SOT operations without executing them.
/// The caller can inspect the plan and then commit or abort.
pub fn prepare_exec(
    code_cap: Cap,
    binary_hash: BinaryHash,
    policy_store: &PolicyStore,
    process: &mut Process,
    signal_table: &mut SignalTable,
    parent_caps: &[CapClass],
) -> Result<ExecTransaction, ExecError> {
    // 1. Look up the binary's exec policy.
    let policy = policy_store.lookup_or_default(binary_hash);

    // 2. Resolve effective caps.
    let effective_caps = resolve_exec_caps(&policy, parent_caps);

    // 3. Close cloexec fds and collect caps to revoke.
    let revoke_caps = process.close_cloexec_fds();

    // 4. Reset signal handlers (handled signals -> Default).
    signal_table.reset_on_exec();

    // 5. Build the SOT operation sequence.
    let policy_cap = 0; // placeholder: policy cap allocated by kernel
    let mut ops = Vec::new();
    ops.push(SotOp::TxBegin);
    ops.push(SotOp::SoInvoke {
        cap: code_cap,
        op: SoOperation::Replace,
        args: Vec::new(),
    });
    ops.push(SotOp::CapsReset { policy: policy_cap });
    for cap in &revoke_caps {
        ops.push(SotOp::CapRevoke { cap: *cap });
    }
    ops.push(SotOp::TxCommit);

    Ok(ExecTransaction {
        ops,
        revoke_caps,
        effective_caps,
        resource_limits: policy.resource_limits,
    })
}

/// Build the abort sequence if an exec transaction fails.
pub fn abort_exec() -> SotOp {
    SotOp::TxAbort
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{AllowedCap, CapExecPolicy, CapClass, ResourceLimits};

    fn test_hash() -> BinaryHash {
        [0xBB; 32]
    }

    #[test]
    fn prepare_exec_produces_transactional_ops() {
        let mut store = PolicyStore::new();
        let policy = CapExecPolicy {
            binary_hash: test_hash(),
            allowed_caps: alloc::vec![AllowedCap {
                class: CapClass::NetBind,
                restriction: None,
            }],
            resource_limits: ResourceLimits::DEFAULT,
            inherit_parent_caps: false,
        };
        store.register(policy);

        let mut process = Process::new(1, 0, 100);
        process.fd_alloc(10, true);  // cloexec fd
        process.fd_alloc(20, false); // regular fd

        let mut sig_table = SignalTable::new();
        let parent_caps = &[];

        let tx = prepare_exec(
            42, // code_cap
            test_hash(),
            &store,
            &mut process,
            &mut sig_table,
            parent_caps,
        )
        .unwrap();

        // Should be: TxBegin, SoInvoke, CapsReset, CapRevoke(cloexec), TxCommit
        assert!(matches!(tx.ops[0], SotOp::TxBegin));
        assert!(matches!(tx.ops[1], SotOp::SoInvoke { .. }));
        assert!(matches!(tx.ops[2], SotOp::CapsReset { .. }));
        assert!(matches!(tx.ops[3], SotOp::CapRevoke { cap: 10 }));
        assert!(matches!(tx.ops[4], SotOp::TxCommit));

        assert_eq!(tx.effective_caps, alloc::vec![CapClass::NetBind]);
        assert_eq!(tx.revoke_caps, alloc::vec![10]);
    }

    #[test]
    fn abort_returns_tx_abort() {
        assert!(matches!(abort_exec(), SotOp::TxAbort));
    }
}
