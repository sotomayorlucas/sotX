# ADR-001: Graph-Level Transaction Manager (GTXN)

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** Lucas Sotomayor  

## Context

sotFS models filesystem metadata as a typed graph and POSIX operations as DPO
(Double Pushout) graph rewriting rules. Each rule application must be atomic:
either the entire graph transformation succeeds (including all invariant checks)
or nothing changes.

The sotOS kernel already provides a generic transaction engine with three tiers
(specified in `formal/sot_transactions.tla`):

- **Tier 0 (RCU):** Read-only snapshots, no logging, < 100 ns.
- **Tier 1 (WAL):** Per-object write-ahead log, single-SO mutations, < 1 μs.
- **Tier 2 (2PC):** Multi-object two-phase commit, < 10 μs.

The question is whether sotFS should use the kernel's transaction engine
directly, or introduce its own graph-level transaction manager.

## Decision

**sotFS uses a separate graph-level transaction manager (GTXN)** that internally
composes SOT Tier 1 and Tier 2 transactions.

GTXN is a userspace component within the sotFS server domain. It wraps every
DPO rule application with the following protocol:

```
GTXN_BEGIN:
  1. Verify DPO gluing conditions on the current host graph G
  2. Verify treewidth invariant will be preserved by the rule
  3. For each SO affected by the rule:
     - If single SO: begin SOT Tier 1 (WAL)
     - If multiple SOs: begin SOT Tier 2 (2PC) with participant set
  4. Apply L → K → R morphisms (graph transformation)
  5. Verify post-conditions (global invariants)

GTXN_COMMIT:
  6. Commit all underlying SOT transactions
  7. Emit provenance entry for the rule application
  8. Update Ollivier-Ricci curvature for affected edges

GTXN_ROLLBACK:
  9. Abort all underlying SOT transactions (WAL restore / 2PC abort)
  10. Host graph G remains unchanged
```

## Consequences

**Positive:**
- The kernel transaction engine stays generic — no FS-specific logic in Ring 0.
- Graph-specific invariants (treewidth bound, no dangling edges, no orphan
  inodes) are checked in userspace where they belong.
- Rollback is clean: SOT Tier 1 WAL restore and Tier 2 abort guarantee
  the underlying SOs return to pre-transaction state.
- Provenance entries are emitted at the graph-operation level (e.g.,
  "CREATE /foo/bar") rather than at the SO-mutation level (e.g., "write
  sector 47"), providing meaningful audit trails.

**Negative:**
- Two levels of transaction management add latency (~1-5 μs overhead for
  gluing condition checks and treewidth verification).
- The GTXN must correctly compose SOT transactions — a bug here could leave
  the graph in an inconsistent state even though individual SOs are consistent.
- Testing requires exercising both layers together.

**Neutral:**
- Operations touching a single inode (CREATE, UNLINK on a file with link_count=1)
  map to SOT Tier 1. Operations touching multiple directories (RENAME across
  dirs) map to SOT Tier 2. The tier selection is deterministic from the DPO rule.

## Alternatives Considered

### A. Use SOT transactions directly (no GTXN)

Each DPO rule would be expressed as a sequence of SO reads/writes within a
single SOT Tier 1 or Tier 2 transaction. Graph invariants would be checked
as assertions within the transaction body.

**Rejected because:** The kernel has no concept of "graph" or "edge" or
"treewidth." Pushing these checks into the generic transaction engine would
either require kernel modifications (violating the microkernel principle) or
require the FS server to manually verify invariants before each SO write
(duplicating transaction logic without the atomicity guarantees of GTXN).

### B. Unified transaction manager in the kernel

Extend the kernel's transaction engine with graph-aware operations (e.g.,
`tx_graph_rewrite(rule, match)`).

**Rejected because:** This violates sotOS's core principle that the kernel
does not know about filesystems (see FOUNDATIONS.md §1.1). It would also
increase the kernel's trusted computing base, undermining the verification
effort.
