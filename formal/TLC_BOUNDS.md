# sotFS TLC Model Checking Bounds

This document describes the three tiers of model checking configurations
for the four sotFS TLA+ specifications, what each bound increase buys in
terms of verification coverage, and the practical trade-offs.

## Overview

Each spec has three `.cfg` files: **small** (original), **medium**, and **large**.
The runner script `run_tlc.sh` drives TLC across all combinations.

## Spec: sotfs_graph (Type Graph + DPO Rules)

Models the core metadata graph with inode/directory/block nodes and
contains/pointsTo edges. DPO rules: CreateFile, Mkdir, Rmdir, Link,
Unlink, RenameSameDir, RenameCrossDir, WriteBlock.

| Constant   | Small | Medium | Large | Semantics |
|------------|-------|--------|-------|-----------|
| InodeIds   | 5     | 6      | 8     | Max allocatable inodes (files + directories) |
| DirIds     | 3     | 4      | 5     | Max allocatable directory nodes |
| BlockIds   | 3     | 4      | 5     | Max allocatable data blocks |
| Names      | 3     | 4      | 5     | Distinct filenames per directory |
| MaxOps     | 6     | 8      | 10    | Max DPO rule applications per trace |

**What larger bounds buy:**
- **More inodes (8):** Exercises deeper directory hierarchies and more hard links.
  Stresses NoDirCycles with longer potential cycle chains.
- **More dirs (5):** Enables 4-level nesting (root + 4 subdirs), exercising
  RenameCrossDir cycle detection across deeper trees.
- **More blocks (5):** Tests block refcount tracking with more shared blocks
  (CoW snapshots where multiple inodes share blocks).
- **More names (5):** Increases branching factor per directory, exercising
  UniqueNamesPerDir with more rename/link collision patterns.
- **More ops (10):** Allows create-then-remove-then-recreate sequences that
  stress allocation/deallocation correctness over longer traces.

**State space growth:** This spec has the largest branching factor because
`Next` quantifies over `dirs x Names x inodes` (link), `dirs^2 x Names^2`
(cross-dir rename). Expected growth is super-exponential in bound size.

## Spec: sotfs_transactions (GTXN Protocol)

Models the graph-level transaction protocol: Tier 0 (read-only), Tier 1
(single-SO WAL), and Tier 2 (multi-SO 2PC). Actions: Begin, Read, Write,
CommitT1, PrepareT2, VoteYes, DecideCommit, Abort, Reset.

| Constant | Small | Medium | Large | Semantics |
|----------|-------|--------|-------|-----------|
| GTxnIds  | 2     | 3      | 4     | Concurrent graph transactions |
| SOIds    | 3     | 4      | 5     | Secure Objects (data granules) |
| MaxOps   | 8     | 10     | 12    | Max operations per trace |

**What larger bounds buy:**
- **More GTxnIds (4):** Tests isolation with 4 concurrent transactions.
  Critical for finding write-set overlap violations that only manifest
  with 3+ active GTXNs competing for the same SOs.
- **More SOIds (5):** Enables Tier 2 (2PC) transactions with larger write sets.
  Tests that the Tier 1/Tier 2 boundary (`Cardinality(writeSet) > 1`) is
  correctly enforced when many SOs are available.
- **More ops (12):** Allows full lifecycle sequences: begin -> write -> prepare ->
  vote -> commit -> reset -> begin again, testing GTXN reuse correctness.

**State space growth:** Moderate. The write value domain is fixed at 0..3.
Growth is primarily in `|GTxnIds| x |SOIds|` (write actions) and
`|GTxnIds|^2` (isolation pairs).

## Spec: sotfs_capabilities (Capability Graph)

Models capabilities as graph nodes with grants edges (cap -> inode) and
delegates edges (cap -> parent cap, forming the CDT). Actions: Derive,
Grant, Revoke, Access, AdvanceEpoch, AddInode.

| Constant   | Small | Medium | Large | Semantics |
|------------|-------|--------|-------|-----------|
| CapIds     | 4     | 5      | 6     | Max allocatable capabilities |
| InodeIds   | 2     | 3      | 4     | Target inodes for grants edges |
| DomainIds  | 2     | 3      | 4     | Protection domains (processes) |
| MaxOps     | 6     | 8      | 10    | Max operations per trace |

**What larger bounds buy:**
- **More CapIds (6):** Deeper delegation chains (up to 5 levels). Exercises
  transitive revocation with longer ancestor chains. Tests DelegationForest
  (no cycles) with more potential delegation topologies.
- **More InodeIds (4):** Tests GrantsConsistency when capabilities target
  different inodes. Enables Derive with targetOverride to different inodes.
- **More DomainIds (4):** Tests cross-domain Grant with 4 domains, exercising
  capability migration patterns (A grants to B, B derives and grants to C).
- **More ops (10):** Allows derive-grant-revoke-derive cycles that test
  whether revoked capability IDs are correctly excluded from descendant sets.

**State space growth:** The Derive action quantifies over
`DomainIds x CapIds x SUBSET(AllRights) x InodeIds`. Since
`|SUBSET(AllRights)| = 32` (5 rights), this creates a large branching
factor. The capabilities spec is typically the most expensive to check.

## Spec: sotfs_crash (Crash + WAL Recovery)

Models crash consistency: transactions write to a WAL, flush, commit, and
apply. A crash can occur at any point. Recovery replays committed WAL
entries or discards uncommitted ones.

| Constant | Small | Medium | Large | Semantics |
|----------|-------|--------|-------|-----------|
| SOIds    | 2     | 3      | 4     | Secure Objects with persistent state |
| MaxOps   | 8     | 10     | 12    | Max operations per trace |

**Note:** The `StateConstraint` limits `Len(walEntries) <= 4` in all configs
to bound the recursive WAL replay in `Recover`.

**What larger bounds buy:**
- **More SOIds (4):** Tests crash recovery with more SOs having interleaved
  writes. Verifies NoPartialApplication when 4 SOs are modified in one
  transaction but only some writes may have reached disk before crash.
- **More ops (12):** Allows longer pre-crash transaction sequences:
  begin -> write(S1) -> write(S2) -> write(S3) -> flush -> crash -> recover.
  Tests that longer WAL sequences are correctly replayed or discarded.

**State space growth:** Linear in `|SOIds|` (write actions have
`|SOIds| x 4` branches per step). The WAL length constraint is the
primary bound on depth; more SOs widen each level.

## Running

```bash
# Run everything
./formal/run_tlc.sh

# Run only small configs (quick sanity check)
./formal/run_tlc.sh small

# Run only the graph spec at all sizes
./formal/run_tlc.sh graph

# Run only large configs (longest, most thorough)
./formal/run_tlc.sh large

# Combine filters
./formal/run_tlc.sh medium capabilities
```

### Requirements
- Java 11+ on PATH
- `tla2tools.jar` in `formal/`, or set `TLC_JAR=/path/to/tla2tools.jar`
- Download: https://github.com/tlaplus/tlaplus/releases

### Environment variables
| Variable       | Default  | Description |
|----------------|----------|-------------|
| `TLC_JAR`      | (auto)   | Path to tla2tools.jar |
| `TLC_JVM_OPTS` | `-Xmx4g -Xms1g` | JVM heap options |
| `TLC_WORKERS`  | `auto`   | TLC worker threads (auto = all cores) |

### Output
- Per-run logs: `formal/tlc_output/<spec>_<size>.log`
- Summary table: `formal/tlc_output/summary.txt`

## Trade-offs

| Size   | Estimated Time | Memory  | Coverage |
|--------|---------------|---------|----------|
| Small  | seconds       | < 1 GB  | Basic correctness, catches most rule bugs |
| Medium | minutes       | 1-2 GB  | Deeper interleavings, multi-party interactions |
| Large  | minutes-hours | 2-4 GB  | Near-exhaustive for the bound, catches subtle races |

**When to use each:**
- **Small:** CI pipeline, quick iteration during spec development
- **Medium:** Pre-merge verification, catching interaction bugs
- **Large:** Release verification, deep assurance before design changes

The exponential nature of model checking means that even "large" bounds
are tiny compared to real system state spaces. The value is in catching
**classes** of bugs (e.g., "any cycle of length <= 5 is detected") rather
than exhaustive coverage. If TLC finds no violations at large bounds, it
provides high confidence that the DPO rules are correct for the modeled
invariants.
