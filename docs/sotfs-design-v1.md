# sotFS — Secure Object Transactional File System

## Design Document v1.0

**Author:** Lucas Sotomayor  
**Date:** April 2026  
**Status:** Draft — Phase 0 (Foundation)

---

## 1. Abstract

Filesystem metadata is inherently a graph: inodes link to directories,
capabilities reference files, hard links create shared substructure, and
version histories form DAGs. Yet every major filesystem — ext4, ZFS, Btrfs,
HAMMER2 — treats metadata as flat tables or implicit trees, losing the graph
structure that could enable powerful queries, anomaly detection, and formal
reasoning about correctness.

sotFS (Secure Object Transactional File System) makes this graph structure
explicit. It represents filesystem metadata as a **typed graph** with six
node types and six edge types, and defines POSIX operations as **Double
Pushout (DPO) graph rewriting rules** — algebraic transformations with
mathematically precise preconditions, postconditions, and gluing constraints.

This formalization yields three structural properties unavailable in
conventional filesystems:

1. **Bounded treewidth.** We prove that the DPO rules preserve a configurable
   treewidth bound on the metadata graph, enabling any MSO (Monadic
   Second-Order) definable query — reachability, cycle detection, permission
   checking — to execute in **linear time** via Courcelle's theorem.

2. **Curvature-based anomaly detection.** Ollivier-Ricci curvature, computed
   incrementally on the metadata graph, detects structural anomalies (mass
   file creation, symbolic link bombs, directory structure manipulation) as
   deviations from a learned curvature baseline.

3. **Deceptive subgraph views.** Capabilities gate not just access but
   *visibility*: different security domains see different projections of the
   filesystem graph, enabling deception-in-depth against compromised processes.

sotFS is designed for sotX, a capability-based microkernel written in Rust.
It runs as a userspace server domain, communicating via IPC and persisting
state through the SOT exokernel's transactional Secure Object primitives.
A four-layer verification plan — TLA+ model checking, crash refinement,
Rust typestate, and Coq/Perennial proofs — provides graduated formal
assurance from design through implementation.

---

## 2. Introduction and Motivation

### 2.1 The Problem: Filesystems as Implicit Graphs

Every filesystem manages a graph. A directory tree is a tree (trivially a
graph). Hard links make it a DAG. Symbolic links add arbitrary edges. Mount
points graft subtrees. Access control lists associate permission sets with
inodes. Snapshots create version DAGs. Transactions group operations into
atomic units that reference multiple nodes.

Yet no production filesystem treats this graph as a first-class data
structure. Instead:

- **ext4** stores metadata in a superblock, group descriptors, inode tables,
  and directory entry blocks — flat structures connected by implicit integer
  references (inode numbers).
- **ZFS** uses a Merkle-like tree of block pointers (the "uberblock" → dnode
  → indirect block hierarchy) where the graph structure is implicit in the
  pointer chains.
- **Btrfs** uses B-trees with composite keys that encode path information,
  with backreferences for deduplication — again, the graph is implicit.
- **HAMMER2** uses a radix tree with embedded block references, with
  snapshot chains forming implicit DAGs.

This implicit representation has three consequences:

1. **Queries are slow.** "Can process P reach file F through the directory
   tree?" requires a tree walk. "Are there cycles in the namespace?" requires
   ad-hoc DFS. These are graph queries forced through non-graph interfaces.

2. **Formal reasoning is hard.** Proving crash consistency requires reasoning
   about implicit graph invariants (no orphan inodes, no dangling directory
   entries) that are nowhere stated explicitly. FSCQ, Yggdrasil, and
   SquirrelFS each had to reconstruct these invariants from the code.

3. **Security monitoring is blind.** Detecting filesystem-level attacks
   (directory traversal exploits, symlink races, namespace manipulation)
   requires understanding the *structure* of the metadata graph. When that
   structure is implicit, monitoring tools must reconstruct it from
   syscall traces — lossy, expensive, and fragile.

### 2.2 Thesis Statement

Filesystem metadata is a typed graph. By formalizing POSIX operations as
DPO graph rewriting rules and maintaining the metadata graph as an explicit
first-class data structure, we can:

- Prove that operations preserve structural invariants (no orphans, no
  dangling edges, bounded treewidth) by verifying the DPO rules once,
  rather than auditing every code path.
- Enable MSO-definable security queries in linear time via Courcelle's
  theorem, given the bounded treewidth guarantee.
- Detect structural anomalies in real time via Ollivier-Ricci curvature
  monitoring on the metadata graph.
- Implement capability-gated graph projections for cyber deception,
  where different security domains see different filesystem structures.
- Verify crash consistency by proving that the WAL-based persistence
  layer correctly refines the abstract graph transaction model.

### 2.3 Contributions

1. **Type Graph TG:** A formal definition of filesystem metadata as a typed
   graph with six node types (Inode, Directory, Capability, Transaction,
   Version, Block) and six edge types (contains, grants, delegates,
   derivesFrom, supersedes, pointsTo), with precise local and global
   invariants.

2. **DPO Rule Set:** A complete specification of core POSIX filesystem
   operations as DPO graph rewriting rules with explicit gluing conditions,
   enabling algebraic reasoning about operation correctness.

3. **Treewidth Preservation:** A proof that the DPO rules preserve bounded
   treewidth, and demonstration of how Courcelle's theorem enables
   linear-time MSO queries on the metadata graph.

4. **Curvature Monitor:** An incremental Ollivier-Ricci curvature
   computation scheme for real-time structural anomaly detection.

5. **Deceptive Projections:** A formalization of capability-gated subgraph
   views as a graph endofunctor, extending the existing SOT deception model.

6. **GTXN Protocol:** A graph-level transaction manager that composes the
   SOT kernel's tiered transaction engine with graph-specific invariant
   checking (see ADR-001).

### 2.4 Document Organization

- **Section 3** surveys related work in graph-based filesystem models, DPO
  rewriting, Courcelle's theorem, and capability-based security.
- **Section 5** defines the type graph TG formally.
- **Section 6** specifies the DPO rules for POSIX operations.
- **Section 7** describes capabilities and transactions in graph terms.
- **Section 8** proves bounded treewidth and its algorithmic consequences.
- **Section 9** defines the Ollivier-Ricci curvature monitor.
- **Section 10** formalizes deceptive subgraph views.
- **Section 11** presents the four-layer verification plan.

---

## 3. Background and Related Work

### 3.1 Graph-Based Filesystem Models

The observation that filesystem metadata forms a graph is not new. The Unix
inode/directory model is formally a labeled directed graph where inodes are
nodes and directory entries are labeled edges. However, no production
filesystem exploits this observation for algorithmic or verification purposes.

Academic work on graph-structured storage includes:

- **GraphFS** (Seltzer et al.): explored using graph databases for metadata
  storage, but focused on query performance rather than formal properties
  or security.
- **Semantic file systems** (Gifford et al., 1991): used attribute-based
  naming (a bipartite graph of files and attributes) but without formal
  graph-theoretic analysis.
- **Provenance-aware storage** (PASS, Muniswamy-Reddy et al., 2006): built
  explicit provenance graphs as an overlay on conventional filesystems. sotFS
  integrates provenance into the metadata graph itself rather than treating
  it as a separate layer.

sotFS differs from all prior work by (a) using algebraic graph rewriting as
the operational formalism, (b) proving and exploiting bounded treewidth, and
(c) integrating graph structure with capability-based security.

### 3.2 Double Pushout (DPO) Graph Rewriting

DPO graph rewriting, developed by Ehrig, Pfender, and Schneider (1973) and
formalized in Ehrig et al., *Fundamentals of Algebraic Graph Transformation*
(Springer, 2006), is a categorical approach to graph transformation.

A **DPO rule** ρ = (L ←l– K –r→ R) consists of:
- **L** (left-hand side): the pattern to match in the host graph
- **K** (interface/gluing graph): the portion preserved by the rule
- **R** (right-hand side): the replacement pattern

Application of ρ to a host graph G via a match morphism m: L → G produces
a result graph H through two pushout squares in the category of graphs:

```
        l           r
   L ←————— K ——————→ R
   |        |         |
 m |      d |       m*|
   ↓        ↓         ↓
   G ←————— D ——————→ H
        l*          r*
```

The **gluing conditions** ensure the rule is applicable:
1. **Identification condition:** If m identifies two nodes in L that are
   distinct in K (i.e., m(x)=m(y) but l⁻¹(x)≠l⁻¹(y)), the rule is
   inapplicable.
2. **Dangling condition:** If removing L\K would leave edges with a missing
   source or target in G, the rule is inapplicable.

DPO rewriting is well-suited to filesystem operations because:
- Each POSIX operation has clear preconditions (gluing conditions).
- The preservation of K guarantees that unrelated parts of the graph are
  unchanged (a locality property critical for concurrent operations).
- Invariant preservation can be proved once per rule and holds for all
  applications of that rule to any host graph satisfying the preconditions.

### 3.3 Courcelle's Theorem and Bounded Treewidth

**Treewidth** (Robertson and Seymour, 1986) measures how "tree-like" a graph
is. A tree has treewidth 1. A cycle of length n has treewidth 2. A complete
graph Kn has treewidth n-1. Formally, treewidth is the minimum width of any
tree decomposition of the graph.

**Courcelle's theorem** (Courcelle, 1990): Every graph property definable in
Monadic Second-Order logic (MSO₂) can be decided in **linear time** O(n) on
graphs of bounded treewidth, where the constant depends on the treewidth
bound and the formula size but not on the graph size.

MSO₂ can express:
- Reachability ("∃ path from u to v")
- Cycle detection ("∃ cycle containing vertex v")
- k-colorability
- Dominating sets
- Many security-relevant properties ("∃ capability chain from domain D to
  file F with read permission")

For sotFS, the key insight is that filesystem metadata graphs have
naturally bounded treewidth:
- The directory hierarchy (contains edges only) is a tree (tw = 1).
- Hard links add back-edges, but each inode has bounded link_count.
- Capability delegation trees are separate trees (tw = 1 each).
- Version chains are paths (tw = 1).
- Block pointer lists are stars from inodes to blocks (tw = 1).

We prove in Section 8 that the combined type graph has treewidth ≤ k where
k is determined by the maximum hard link fan-in — a configurable parameter.

### 3.4 Ollivier-Ricci Curvature on Graphs

Ollivier (2009) defined a notion of Ricci curvature for metric spaces using
optimal transport. Lin, Lu, and Yau (2011) adapted this to graphs, defining
the **Ollivier-Ricci curvature** κ(x,y) of an edge (x,y) as:

```
κ(x,y) = 1 - W₁(μₓ, μᵧ) / d(x,y)
```

where W₁ is the Wasserstein-1 distance between probability measures μₓ and
μᵧ concentrated on the neighborhoods of x and y respectively, and d(x,y) is
the graph distance.

Intuitively:
- **Positive curvature** (κ > 0): neighborhoods of x and y overlap heavily
  (the graph is "dense" around the edge). In a filesystem: a directory with
  many hard-linked files creates positive curvature.
- **Zero curvature** (κ = 0): neighborhoods are "orthogonal" (typical of
  lattice-like structures).
- **Negative curvature** (κ < 0): neighborhoods diverge (the graph is
  "tree-like" around the edge). In a filesystem: a deep directory chain with
  no cross-links has negative curvature.

For anomaly detection, the key property is that **normal filesystem
operations produce predictable curvature changes**, while attacks that
manipulate the namespace structure (symlink bombs, mass file creation,
directory traversal exploits) produce anomalous curvature spikes.

### 3.5 Capability-Based Filesystem Security

Capability-based access control for filesystems has been explored in:

- **Capsicum** (Watson et al., USENIX Security 2010): capability mode for
  FreeBSD, restricting file access to pre-opened descriptors. Capabilities
  are opaque tokens, not graph edges.
- **Barrelfish** (Baumann et al., SOSP 2009): capability system with typed
  capabilities for memory, I/O, and IPC. No filesystem-specific capability
  model.
- **seL4** (Klein et al., SOSP 2009): formally verified capability system,
  but filesystem is external to the kernel.
- **SquirrelFS** (Kadekodi et al., OSDI 2024): uses Rust's type system
  (typestate pattern) for crash-consistency guarantees. No graph model or
  capability integration.

sotFS is unique in modeling capabilities as **typed edges in the metadata
graph**, where capability attenuation corresponds to edge relabeling and
delegation corresponds to edge addition with monotonically restricted labels.
This unifies access control and metadata structure in a single formalism.

### 3.6 Crash-Consistent Metadata Management

Formal approaches to crash consistency:

- **FSCQ** (Chen et al., SOSP 2015): Coq-verified filesystem using crash
  Hoare logic. Proved crash consistency for a simplified filesystem.
- **Yggdrasil** (Sigurbjarnarson et al., OSDI 2016): push-button crash
  refinement verification using SMT solvers.
- **SquirrelFS** (Kadekodi et al., OSDI 2024): Rust typestate pattern to
  enforce correct ordering of persistent writes at compile time.

sotFS draws on all three approaches:
- From FSCQ: the idea of proving crash refinement between an abstract
  specification and a concrete implementation.
- From Yggdrasil: the crash refinement methodology (abstract spec →
  concrete implementation with crash points → proof that recovery
  restores a valid abstract state).
- From SquirrelFS: the use of Rust's type system to prevent entire classes
  of crash-consistency bugs at compile time.

The novelty is that our abstract specification is not an ad-hoc state machine
but an algebraic structure (the type graph with DPO rules), enabling the
crash refinement proof to leverage category-theoretic properties.

### 3.7 Comparison with Existing Systems

| Feature | ext4 | ZFS | Btrfs | HAMMER2 | SquirrelFS | **sotFS** |
|---------|------|-----|-------|---------|------------|-----------|
| Metadata model | flat tables | Merkle tree | B-trees | radix tree | Rust types | **typed graph** |
| Formal ops model | none | none | none | none | typestate | **DPO rules** |
| Treewidth bound | N/A | N/A | N/A | N/A | N/A | **yes (≤ k)** |
| MSO queries | N/A | N/A | N/A | N/A | N/A | **linear time** |
| Anomaly detection | none | none | none | none | none | **Ollivier-Ricci** |
| Capability integration | POSIX DAC | POSIX DAC | POSIX DAC | POSIX DAC | none | **graph edges** |
| Deception support | none | none | none | none | none | **subgraph views** |
| Crash consistency | journaling | CoW + txg | CoW + log | CoW + freemap | typestate | **DPO + WAL + typestate** |
| Verification | tested | tested | tested | tested | typestate (Rust) | **TLA+ → typestate → Coq** |

---

## 4. Architecture Overview

### 4.1 sotFS Within the sotX Stack

```
┌──────────────────────────────────────────────────┐
│  Application (POSIX binary via LUCAS/rump)        │
│  ↓ syscall (open, read, write, mkdir, ...)        │
├──────────────────────────────────────────────────┤
│  LUCAS / rump VFS layer                           │
│  Translates POSIX syscalls → VfsOp IPC messages   │
├──────────────────────────────────────────────────┤
│  sotFS Server Domain  (Ring 3, userspace)         │
│  ┌────────────────────────────────────────────┐   │
│  │  VfsOp dispatcher                          │   │
│  │       ↓                                    │   │
│  │  GTXN engine (ADR-001)                     │   │
│  │   ├─ DPO rule matcher + gluing check       │   │
│  │   ├─ Type graph (in-memory)                │   │
│  │   ├─ Treewidth verifier                    │   │
│  │   └─ Curvature monitor (§9)                │   │
│  │       ↓                                    │   │
│  │  Persistence layer                         │   │
│  │   ├─ Graph → sector serialization          │   │
│  │   ├─ WAL (crash consistency)               │   │
│  │   └─ Block allocator (bitmap)              │   │
│  │       ↓                                    │   │
│  │  Bulk block-device capability (ADR-002)    │   │
│  └────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────┤
│  sotX Microkernel  (Ring 0)                      │
│  IPC routing │ Scheduling │ Frame alloc │ Caps    │
├──────────────────────────────────────────────────┤
│  Hardware (NVMe/virtio-blk)                       │
└──────────────────────────────────────────────────┘
```

### 4.2 Component Diagram

The sotFS server domain contains five major components:

1. **VfsOp Dispatcher:** Receives IPC messages matching the 14 `VfsOp`
   variants (defined in `personality/bsd/vfs/src/lib.rs:64-79`). Maps each
   to the corresponding DPO rule or graph query.

2. **GTXN Engine:** Manages graph-level transactions (ADR-001). Verifies
   gluing conditions, applies DPO rules atomically, checks post-conditions,
   and delegates persistence to SOT Tier 1/2 transactions.

3. **Type Graph Store:** The in-memory representation of the metadata graph
   TG. Node and edge tables with typed attributes. Backed by persistent
   storage via the WAL.

4. **Curvature Monitor:** Incrementally maintains Ollivier-Ricci curvature
   for edges in the metadata graph. Flags anomalous curvature changes.

5. **Persistence Layer:** Serializes graph mutations into sector writes,
   manages the block allocation bitmap, and operates the WAL for crash
   consistency. Extends the existing `ObjectStore` layout
   (`libs/sotos-objstore/src/layout.rs`).

### 4.3 Data Flow: POSIX Call → Graph Rewrite → Persist

Example: `mkdir("/data/newdir", 0o755)`

```
1. LUCAS receives mkdir syscall
2. LUCAS sends VfsOp::Mkdir IPC to sotFS endpoint
3. sotFS dispatcher invokes DPO rule MKDIR
4. GTXN begins:
   a. Match: find Directory node for "/data" via path resolution
   b. Gluing check: no contains edge from "/data" with name "newdir"
   c. Treewidth check: adding one Directory + one Inode + two contains
      edges preserves tw ≤ k
   d. Begin SOT Tier 1 transaction on the "/data" Directory SO
   e. Apply MKDIR rule: add Inode i_new, Directory d_new,
      contains("/data" → i_new, name="newdir"),
      contains(d_new → i_new, name="."),
      contains(d_new → i_parent, name="..")
   f. Verify post-conditions: link_count consistency, no orphans
5. GTXN commits:
   a. Serialize new nodes/edges to sectors
   b. WAL write (atomic)
   c. Update bitmap for allocated sectors
   d. Commit SOT Tier 1 transaction
   e. Update curvature for affected edges
   f. Emit provenance entry
6. sotFS replies to LUCAS with success + new inode id
```

### 4.4 Integration with Existing Subsystems

**Mount table:** sotFS registers as `FsType::SotFs` in the VFS mount table
(ADR-004), alongside Tmpfs, Ffs, Zfs, Devfs, Procfs.

**Capabilities:** Clients receive `FileCap` handles (as defined in
`personality/bsd/vfs/src/lib.rs:22-27`) with `FileRights`. The sotFS server
mediates all access through the `grants` edge in the type graph (ADR-002).

**Provenance:** Every DPO rule application generates a provenance entry in
the existing per-CPU SPSC ring buffer format (see `formal/sot_provenance.tla`).
The entry's `operation` field identifies the DPO rule, and `subject_id`
identifies the affected inode SO.

**Deception:** The existing deception engine (`docs/DECEPTION_MODEL.md`) uses
capability interposition with four policies (passthrough, inspect, redirect,
fabricate). sotFS extends this with graph-level projections: an interposed
capability sees a **projected subgraph** of TG, not just a filtered response
(Section 10).

---

## 5. Type Graph Formalization

### 5.1 Definition of the Type Graph TG

We define the **type graph** as a labeled, typed, attributed, directed
multigraph:

**Definition 5.1 (Type Graph).** The sotFS type graph is a tuple

```
TG = (V, E, src, tgt, τ_V, τ_E, attr)
```

where:
- V is a finite set of **nodes** (vertices).
- E is a finite set of **edges**.
- src: E → V maps each edge to its source node.
- tgt: E → V maps each edge to its target node.
- τ_V: V → NodeType assigns a type to each node.
- τ_E: E → EdgeType assigns a type to each edge.
- attr: V ∪ E → Attributes assigns typed attributes to nodes and edges.

The type sets are:

```
NodeType = { Inode, Directory, Capability, Transaction, Version, Block }
EdgeType = { contains, grants, delegates, derivesFrom, supersedes, pointsTo }
```

**Definition 5.2 (Typed Graph Morphism).** A morphism f: TG₁ → TG₂ is a
pair (f_V: V₁ → V₂, f_E: E₁ → E₂) that preserves:
- Source/target: src₂(f_E(e)) = f_V(src₁(e)) and tgt₂(f_E(e)) = f_V(tgt₁(e))
- Types: τ_V₂(f_V(v)) = τ_V₁(v) and τ_E₂(f_E(e)) = τ_E₁(e)

### 5.2 Node Types and Attributes

#### 5.2.1 Inode

Represents a filesystem object (regular file, directory, symlink, device).
Grounded in the `Vnode` struct (`personality/bsd/vfs/src/vnode.rs:14-22`).

```
attr_Inode = {
    id       : OID         -- unique object identifier (u64)
    vtype    : VnodeType   -- {Regular, Directory, Symlink, CharDevice, BlockDevice}
    perms    : Permissions  -- POSIX rwxrwxrwx (9 bits)
    uid      : UID         -- owner user ID (u16)
    gid      : GID         -- owner group ID (u16)
    size     : u64         -- file size in bytes
    link_count : u32       -- number of hard links
    ctime    : Timestamp   -- creation time
    mtime    : Timestamp   -- modification time
    atime    : Timestamp   -- access time
}
```

**Local invariant I₁:** `link_count ≥ 1` for any inode reachable from root.

**Local invariant I₂:** `vtype ∈ {Regular, Symlink, CharDevice, BlockDevice}`
implies exactly one incoming `contains` edge per hard link (link_count
equals the number of incoming `contains` edges).

#### 5.2.2 Directory

Represents a namespace container. A Directory node is always paired with
an Inode node of `vtype = Directory`. The separation allows the graph to
distinguish the namespace role (container of `contains` edges) from the
inode role (target of capabilities, holder of metadata).

```
attr_Directory = {
    id       : OID         -- matches paired Inode's OID
}
```

**Local invariant I₃:** Every Directory node d has exactly one paired Inode
node i such that there exists a `contains(d, i)` edge with name = ".".

**Local invariant I₄:** For every Directory node d, the set of `name`
attributes on its outgoing `contains` edges is a set (no duplicates).

#### 5.2.3 Capability

Represents an access token granting rights to an Inode. Maps to `CapEntry`
in the kernel's capability table (`kernel/src/cap/table.rs`).

```
attr_Capability = {
    cap_id   : CapId       -- unique capability identifier
    rights   : Rights      -- bitmask {READ, WRITE, EXECUTE, GRANT, REVOKE}
    epoch    : u64         -- creation epoch for staleness detection
}
```

**Local invariant I₅:** A Capability node c has exactly one outgoing `grants`
edge (to the Inode it authorizes) and at most one incoming `delegates` edge
(from its parent capability in the CDT).

#### 5.2.4 Transaction

Represents an active or committed graph transaction (GTXN). Models the state
machine defined in `formal/sot_transactions.tla`.

```
attr_Transaction = {
    txn_id    : TxnId      -- unique transaction identifier
    tier      : {0, 1, 2}  -- SOT transaction tier
    state     : TxState    -- {Active, Preparing, Committed, Aborted}
    read_set  : Set<OID>   -- inodes read by this transaction
    write_set : Set<OID>   -- inodes written by this transaction
    begin_ts  : Timestamp  -- transaction start time
}
```

**Local invariant I₆:** `state = Committed` implies `write_set ∩ write_set'
= ∅` for all other Transaction nodes t' with `state = Active` at the time
of commit (serializability).

#### 5.2.5 Version

Represents a point-in-time snapshot of a subtree. Maps to `SnapMeta` in the
object store (`libs/sotos-objstore/src/layout.rs:35-36`).

```
attr_Version = {
    version_id : VersionId  -- unique version identifier
    timestamp  : Timestamp  -- snapshot creation time
    root_oid   : OID        -- root inode of the snapshot
}
```

**Local invariant I₇:** The `derivesFrom` edge subgraph restricted to
Version nodes is a DAG (no cycles). Every Version node except the initial
version has at least one incoming `derivesFrom` edge.

#### 5.2.6 Block

Represents a contiguous range of storage sectors. Maps to
`DirEntry.sector_start/sector_count` in the object store layout
(`libs/sotos-objstore/src/layout.rs:135-136`).

```
attr_Block = {
    block_id     : BlockId   -- unique block identifier
    sector_start : u32       -- first sector on disk
    sector_count : u32       -- number of contiguous sectors
    refcount     : u8        -- reference count for CoW sharing
}
```

**Local invariant I₈:** `refcount = |{e ∈ E : τ_E(e) = pointsTo ∧ tgt(e) = b}|`
(refcount equals the number of incoming `pointsTo` edges).

**Local invariant I₉:** For any two Block nodes b₁, b₂ with b₁ ≠ b₂, their
sector ranges do not overlap:
`[b₁.sector_start, b₁.sector_start + b₁.sector_count) ∩
 [b₂.sector_start, b₂.sector_start + b₂.sector_count) = ∅`

### 5.3 Edge Types and Constraints

#### 5.3.1 contains: Directory → Inode

Represents a directory entry. The "." entry links a directory to its own
inode; ".." links to the parent directory's inode.

```
attr_contains = {
    name : String          -- filename (1-255 bytes, NAME_MAX from vnode.rs:11)
}
```

**Typing constraint:** `τ_V(src(e)) = Directory ∧ τ_V(tgt(e)) = Inode`

**Constraint C₁ (unique names):** For any Directory node d, if contains(d, i₁)
has name=n and contains(d, i₂) has name=n, then i₁ = i₂.

#### 5.3.2 grants: Capability → Inode

Represents the access relationship. A Capability node points to the Inode
it authorizes access to.

```
attr_grants = {
    rights : Rights        -- effective rights for this grant
}
```

**Typing constraint:** `τ_V(src(e)) = Capability ∧ τ_V(tgt(e)) = Inode`

**Constraint C₂ (rights consistency):** `e.rights ⊆ src(e).rights`
(the grant's rights cannot exceed the capability's rights).

#### 5.3.3 delegates: Capability → Capability

Represents capability delegation (CDT parent → child). The child's rights
are a subset of the parent's rights.

**Typing constraint:** `τ_V(src(e)) = Capability ∧ τ_V(tgt(e)) = Capability`

**Constraint C₃ (monotonic attenuation):** If delegates(c_parent, c_child),
then `c_child.rights ⊆ c_parent.rights`.

**Constraint C₄ (delegation DAG):** The subgraph of `delegates` edges is a
forest (a set of disjoint trees rooted at root capabilities).

#### 5.3.4 derivesFrom: Version → Version

Represents snapshot lineage (child version derived from parent version).

**Typing constraint:** `τ_V(src(e)) = Version ∧ τ_V(tgt(e)) = Version`

**Constraint C₅ (version DAG):** The subgraph of `derivesFrom` edges is
acyclic (a DAG).

#### 5.3.5 supersedes: Inode → Inode

Used during atomic rename to mark that one inode replaces another at a
directory position. The superseded inode may still exist (if it has other
hard links) or may become orphaned and eligible for garbage collection.

**Typing constraint:** `τ_V(src(e)) = Inode ∧ τ_V(tgt(e)) = Inode`

**Constraint C₆ (supersedes is acyclic):** The subgraph of `supersedes`
edges is acyclic.

#### 5.3.6 pointsTo: Inode → Block

Maps an inode to its data blocks, forming an ordered extent list.

```
attr_pointsTo = {
    offset : u64           -- byte offset within the file
}
```

**Typing constraint:** `τ_V(src(e)) = Inode ∧ τ_V(tgt(e)) = Block`

**Constraint C₇ (non-overlapping extents):** For any Inode node i, the
byte ranges `[e.offset, e.offset + tgt(e).sector_count * SECTOR_SIZE)`
across all outgoing `pointsTo` edges e are pairwise disjoint.

### 5.4 Local Invariants Summary

| ID | Node/Edge Type | Invariant |
|----|---------------|-----------|
| I₁ | Inode | link_count ≥ 1 for reachable inodes |
| I₂ | Inode | link_count = |incoming contains edges| |
| I₃ | Directory | has self-referencing contains edge (name=".") |
| I₄ | Directory | outgoing contains edges have unique names |
| I₅ | Capability | exactly one outgoing grants edge |
| I₆ | Transaction | committed txns have disjoint write sets |
| I₇ | Version | derivesFrom subgraph is a DAG |
| I₈ | Block | refcount = |incoming pointsTo edges| |
| I₉ | Block | sector ranges are non-overlapping |
| C₁ | contains | unique names per source Directory |
| C₂ | grants | rights ⊆ capability's rights |
| C₃ | delegates | child.rights ⊆ parent.rights |
| C₄ | delegates | delegation subgraph is a forest |
| C₅ | derivesFrom | version subgraph is a DAG |
| C₆ | supersedes | supersedes subgraph is acyclic |
| C₇ | pointsTo | non-overlapping byte ranges per Inode |

### 5.5 Global Invariants

**G₁ (No orphan inodes):** Every Inode node in V is reachable from the root
Inode via a sequence of `contains` edges (possibly through intermediate
Directory nodes), OR has `link_count = 0` and is marked for garbage
collection.

```
∀ i ∈ V, τ_V(i) = Inode ⟹ reachable(root, i) ∨ i.link_count = 0
```

**G₂ (No dangling edges):** Every edge in E has both endpoints in V.

```
∀ e ∈ E: src(e) ∈ V ∧ tgt(e) ∈ V
```

**G₃ (Link count consistency):** For every Inode i:

```
i.link_count = |{e ∈ E : τ_E(e) = contains ∧ tgt(e) = i ∧ attr(e).name ≠ "."}|
```

(The "." self-reference and ".." parent-reference are excluded from the count,
consistent with POSIX nlink semantics for directories.)

**G₄ (Capability monotonicity):** For every path c₀ →delegates c₁ →delegates
... →delegates cₙ in the CDT:

```
cₙ.rights ⊆ cₙ₋₁.rights ⊆ ... ⊆ c₁.rights ⊆ c₀.rights
```

**G₅ (No directory cycles):** The subgraph of `contains` edges restricted to
Directory → Inode(vtype=Directory) links (excluding "." and "..") is acyclic.

```
¬∃ cycle d₀ →contains i₀ →... →contains dₙ →contains i₀ where
  each iₖ.vtype = Directory and names ∉ {".", ".."}
```

**G₆ (Block allocation consistency):** For every Block node b, the sectors
`[b.sector_start, b.sector_start + b.sector_count)` are marked as allocated
in the bitmap. No allocated sector is claimed by more than one Block node.

**G₇ (Treewidth bound):** `tw(TG) ≤ k` for a configurable constant k
(see Section 8 for the proof).

### 5.6 Justification: Why These Types

**Why separate Directory and Inode?** In traditional Unix, a directory IS an
inode with special contents. Separating them in the type graph serves two
purposes: (a) it makes `contains` edges explicit rather than hiding them
inside the inode's data blocks, and (b) it allows the DPO rules to match
on the Directory role specifically (e.g., MKDIR matches a Directory node,
not just any Inode).

**Why Capability as a node (not just an edge)?** Capabilities have their own
state (rights, epoch) and participate in the CDT via `delegates` edges. Making
them nodes allows DPO rules to express capability operations (attenuation,
revocation) as graph transformations on the same graph as filesystem
operations, rather than requiring a separate formalism.

**Why Transaction and Version as nodes?** These represent temporal
relationships. Transaction nodes enable the GTXN engine to reason about
concurrent operations as graph structure (overlapping write sets are visible
as shared edges to the same Inode nodes). Version nodes make snapshot
lineage explicit for the treewidth analysis and MSO queries.

**Why Block as a node?** Making storage extents explicit allows the DPO
rules to express WRITE as a graph transformation (adding/replacing Block
nodes) rather than an opaque data mutation. This is essential for the crash
refinement verification (Layer 2), which must reason about the relationship
between in-memory graph state and on-disk block layout.

**Why not more types?** We considered additional node types for Symlink
(target as typed edge), Mount (mount point relationship), and Lock (file
locking). These were deferred:
- **Symlink:** modeled as Inode with vtype=Symlink and a `pointsTo` edge to
  the target Inode (reusing the existing edge type).
- **Mount:** modeled as a `contains` edge with a special flag, since mount
  points are handled by the VFS layer above sotFS, not by sotFS itself.
- **Lock:** deferred to Phase 3, as file locking requires integration with
  the GTXN concurrency model.

---

## 6. DPO Rules for POSIX Operations

### 6.1 DPO Formalism Review

We use the standard DPO formalism (Ehrig et al., 2006). A **production rule**
(or simply **rule**) is a span in the category **TGraph** of typed graphs:

```
ρ = (L ←l── K ──r→ R)
```

where L, K, R are typed graphs and l, r are typed graph morphisms (injective).
l and r are typically inclusions: K ⊆ L and K ⊆ R.

- L \ K = elements deleted by the rule
- R \ K = elements created by the rule
- K = elements preserved by the rule

**Application** of ρ to a host graph G via a match m: L → G (a typed graph
morphism, typically injective) proceeds by:

1. Computing the context graph D = G \ m(L \ K), subject to gluing conditions.
2. Computing the result graph H = D ∪ (R \ K), with edges from R \ K connected
   according to r.

**Gluing conditions for applicability:**

**(GC1) Identification condition:** m must not identify elements that are
in L but not in l(K). That is, if m(x) = m(y) for x,y ∈ L, then x,y ∈ l(K).

**(GC2) Dangling condition:** Removing m(L \ K) from G must not leave
dangling edges. For every edge e ∈ G with src(e) ∈ m(L \ K) or
tgt(e) ∈ m(L \ K), either e ∈ m(L) (so e is also removed) or
src(e), tgt(e) ∉ m(L \ K) (so e's endpoints survive).

### 6.2 Mutating Rules

We specify 7 mutating DPO rules. For each rule, we give L, K, R as sets of
nodes and edges, the match conditions, gluing conditions, and an informal
argument that the rule preserves all invariants from Section 5.

#### 6.2.1 CREATE(dir_id, name, vtype) → new_oid

Creates a new file or directory entry.

```
L = { d:Directory }
K = { d:Directory }
R = { d:Directory, i:Inode[id=fresh, vtype=vtype, link_count=1, ...],
      e_c:contains(d, i)[name=name] }

If vtype = Directory, additionally:
R += { d_new:Directory[id=fresh],
       e_self:contains(d_new, i)[name="."],
       e_parent:contains(d_new, d_parent_inode)[name=".."] }
  where d_parent_inode = the Inode targeted by d's "." contains edge
```

**Match:** m maps d to the Directory node for dir_id in host graph G.

**Gluing conditions:**
- **(GC-CREATE-1):** No existing contains edge from m(d) with
  `attr.name = name` (unique name constraint C₁).
- **(GC-CREATE-2):** The match is unique (exactly one Directory with id=dir_id).

**Invariant preservation:**
- G₁ (no orphans): i is reachable from root via d.
- G₃ (link count): i.link_count = 1 = |incoming contains edges with name ≠ "."|. ✓
- G₅ (no dir cycles): If vtype=Directory, the new directory's ".." points to
  the parent, creating no cycle (the new directory has no children yet). ✓
- G₇ (treewidth): Adding a leaf to a tree preserves treewidth. ✓

#### 6.2.2 WRITE(inode_id, offset, length, data)

Modifies file data by updating or adding Block nodes.

```
L = { i:Inode, b_old:Block, e_p:pointsTo(i, b_old)[offset=offset] }
    -- OR, if no existing block at this offset:
L = { i:Inode }

K = { i:Inode }

R = { i:Inode, b_new:Block[sector_start=allocated, sector_count=needed,
                            refcount=1],
      e_p_new:pointsTo(i, b_new)[offset=offset] }
```

**Match:** m maps i to the Inode for inode_id. If a Block exists at the
given offset, m also matches it (overwrite case). Otherwise, L has only
the Inode (append/new-extent case).

**Gluing conditions:**
- **(GC-WRITE-1):** If overwriting, b_old.refcount must be checked. If
  refcount > 1 (CoW shared), the rule must allocate a new block and
  decrement b_old.refcount rather than modifying b_old in place.
- **(GC-WRITE-2):** Sufficient free sectors must be available for allocation.

**Invariant preservation:**
- I₈ (refcount): b_new.refcount = 1 (single pointsTo edge). If overwriting,
  b_old.refcount decremented. ✓
- I₉ (non-overlap): b_new.sector_start allocated from free bitmap region. ✓
- C₇ (extents): New pointsTo edge at offset replaces old one (if any). ✓
- G₆ (bitmap consistency): New sectors marked allocated. ✓

#### 6.2.3 MKDIR(dir_id, name) → new_oid

Special case of CREATE with vtype=Directory.

```
L = { d:Directory, i_parent:Inode,
      e_self:contains(d, i_parent)[name="."] }
K = { d:Directory, i_parent:Inode,
      e_self:contains(d, i_parent)[name="."] }
R = { d:Directory, i_parent:Inode,
      e_self:contains(d, i_parent)[name="."],
      i_new:Inode[id=fresh, vtype=Directory, link_count=2, perms=0o755, ...],
      d_new:Directory[id=fresh],
      e_entry:contains(d, i_new)[name=name],
      e_dot:contains(d_new, i_new)[name="."],
      e_dotdot:contains(d_new, i_parent)[name=".."] }
```

**Match:** m maps d to the Directory for dir_id, i_parent to its "." inode.

**Gluing conditions:**
- **(GC-MKDIR-1):** No existing contains edge from m(d) with name=name.
- **(GC-MKDIR-2):** m(d) must be a Directory (type check via τ_V).

**Invariant preservation:**
- I₃ (self-ref): d_new has contains(d_new, i_new)[name="."]. ✓
- I₂ (link_count): i_new has link_count=2: one from e_entry (name=name) and
  one from e_dot (name="."), but "." is excluded from count by G₃. Actually
  link_count=1 from e_entry only? No — POSIX nlink for directories counts
  "." but not "..". So link_count=2 (the entry from parent + the "." self).
  Wait: G₃ excludes ".". Resolve: link_count=1 (only e_entry counts).
  **Decision:** Follow POSIX: nlink for a new empty directory = 2 (the entry
  from parent + the "." self-link). Our G₃ definition should count "." but
  exclude ".." to match POSIX semantics. **Amended G₃:**
  `i.link_count = |{e : τ_E(e)=contains ∧ tgt(e)=i ∧ attr(e).name ≠ ".."}|`
- G₅ (no dir cycles): New dir has no children yet, ".." goes up. ✓

#### 6.2.4 RMDIR(dir_id, name)

Removes an empty directory.

```
L = { d:Directory, i_child:Inode[vtype=Directory],
      d_child:Directory,
      e_entry:contains(d, i_child)[name=name],
      e_dot:contains(d_child, i_child)[name="."],
      e_dotdot:contains(d_child, i_parent)[name=".."] }
K = { d:Directory, i_parent:Inode }
R = { d:Directory, i_parent:Inode }
```

**Match:** m maps d to the parent Directory, i_child to the target directory's
Inode, d_child to the target Directory node.

**Gluing conditions:**
- **(GC-RMDIR-1):** d_child must have no outgoing contains edges other than
  "." and ".." (directory must be empty).
- **(GC-RMDIR-2):** The dangling condition: no edges in G outside L target
  d_child or i_child. This means no other hard links to i_child and no
  capabilities granted to it (or those must be revoked first).

**Invariant preservation:**
- G₁ (no orphans): i_child and d_child are removed, so no orphans created.
  i_parent remains, with one fewer incoming contains edge. ✓
- G₂ (no dangling): GC-RMDIR-2 ensures no remaining edges reference the
  removed nodes. ✓

#### 6.2.5 LINK(dir_id, name, target_inode_id)

Creates a hard link — a new contains edge to an existing Inode.

```
L = { d:Directory, i_target:Inode }
K = { d:Directory, i_target:Inode }
R = { d:Directory, i_target:Inode,
      e_link:contains(d, i_target)[name=name] }
```

**Side effect:** i_target.link_count += 1

**Match:** m maps d to the Directory for dir_id, i_target to the Inode for
target_inode_id.

**Gluing conditions:**
- **(GC-LINK-1):** No existing contains edge from m(d) with name=name.
- **(GC-LINK-2):** i_target.vtype ≠ Directory (POSIX: hard links to
  directories are forbidden, except for "." and "..").
- **(GC-LINK-3):** i_target.link_count < LINK_MAX (configurable, typically
  65535). This is critical for the treewidth bound — see Section 8.

**Invariant preservation:**
- G₃ (link count): link_count incremented to match new contains edge. ✓
- G₇ (treewidth): tw may increase by at most 1 per hard link. Since
  link_count ≤ LINK_MAX, tw ≤ LINK_MAX. GC-LINK-3 bounds this. ✓

#### 6.2.6 UNLINK(dir_id, name)

Removes a directory entry (hard link) and decrements link_count.

```
L = { d:Directory, i:Inode, e_entry:contains(d, i)[name=name] }
K = { d:Directory, i:Inode }
R = { d:Directory, i:Inode[link_count -= 1] }
```

**If i.link_count reaches 0 after decrement, additionally remove i and all
its outgoing pointsTo edges and associated Block nodes (garbage collection).**

**Match:** m maps d to the Directory for dir_id, i to the target Inode via
the contains edge with the given name.

**Gluing conditions:**
- **(GC-UNLINK-1):** name ∉ {".", ".."} (cannot unlink special entries).
- **(GC-UNLINK-2):** i.vtype ≠ Directory (use RMDIR for directories).
- **(GC-UNLINK-3, dangling):** If i.link_count = 1 (last link), all edges
  incident to i (grants, pointsTo, supersedes) must be handled:
  - grants edges: capabilities to i are invalidated (epoch bump).
  - pointsTo edges: Block nodes with refcount reaching 0 are freed.

**Invariant preservation:**
- G₃ (link count): decremented, matching removed edge. ✓
- G₁ (no orphans): If link_count=0, i is removed (not orphaned). ✓
- G₆ (bitmap): Freed blocks' sectors marked as free in bitmap. ✓

#### 6.2.7 RENAME(src_dir_id, src_name, dst_dir_id, dst_name)

Moves or renames a directory entry. This is the most complex rule, with four
cases depending on whether src and dst are the same directory and whether
the target name already exists.

**Case A: Same directory, target does not exist.**

```
L = { d:Directory, i:Inode, e_old:contains(d, i)[name=src_name] }
K = { d:Directory, i:Inode }
R = { d:Directory, i:Inode, e_new:contains(d, i)[name=dst_name] }
```

**Case B: Same directory, target exists (replace).**

```
L = { d:Directory, i_src:Inode, i_dst:Inode,
      e_old:contains(d, i_src)[name=src_name],
      e_dst:contains(d, i_dst)[name=dst_name] }
K = { d:Directory, i_src:Inode, i_dst:Inode }
R = { d:Directory, i_src:Inode, i_dst:Inode[link_count -= 1],
      e_new:contains(d, i_src)[name=dst_name],
      e_sup:supersedes(i_src, i_dst) }
```

**Case C: Different directories, target does not exist.**

```
L = { d_src:Directory, d_dst:Directory, i:Inode,
      e_old:contains(d_src, i)[name=src_name] }
K = { d_src:Directory, d_dst:Directory, i:Inode }
R = { d_src:Directory, d_dst:Directory, i:Inode,
      e_new:contains(d_dst, i)[name=dst_name] }
```

**Case D: Different directories, target exists (replace).**

```
L = { d_src:Directory, d_dst:Directory, i_src:Inode, i_dst:Inode,
      e_old:contains(d_src, i_src)[name=src_name],
      e_dst:contains(d_dst, i_dst)[name=dst_name] }
K = { d_src:Directory, d_dst:Directory, i_src:Inode, i_dst:Inode }
R = { d_src:Directory, d_dst:Directory, i_src:Inode,
      i_dst:Inode[link_count -= 1],
      e_new:contains(d_dst, i_src)[name=dst_name],
      e_sup:supersedes(i_src, i_dst) }
```

**Match:** m maps the Directory and Inode nodes to the corresponding entries
found via path resolution.

**Gluing conditions:**
- **(GC-RENAME-1):** src_name must exist as a contains edge from m(d_src).
- **(GC-RENAME-2):** If i_src is a directory and dst_dir is a descendant of
  i_src, the rename would create a cycle → reject (GC5 preservation).
- **(GC-RENAME-3, Cases C/D):** Both d_src and d_dst SOs are in the
  transaction's write set → GTXN must use SOT Tier 2 (2PC).
- **(GC-RENAME-4, Cases B/D):** If i_dst.link_count would reach 0, handle
  garbage collection of i_dst's blocks (same as UNLINK GC-UNLINK-3).

**Invariant preservation:**
- C₁ (unique names): Old name removed, new name added (if target existed,
  it's replaced). ✓
- G₃ (link count): i_src.link_count unchanged (moved, not added/removed).
  i_dst.link_count decremented in replace cases. ✓
- G₅ (no dir cycles): GC-RENAME-2 explicitly prevents cycles. ✓
- C₆ (supersedes acyclic): supersedes edge added in only one direction
  (src → dst), no transitive closure creates cycles (each inode supersedes
  at most one other per rename). ✓

### 6.3 Query Operations (Graph Morphisms)

The following operations do not mutate the graph. They are formalized as
**graph morphism queries** — functions from a pattern graph to the host
graph that return matched subgraphs or attribute values.

#### 6.3.1 OPEN(inode_id, mode) → FileCap

Finds the Inode, checks capability permissions via `grants` edges, creates
a `FileCap` handle with appropriate `FileRights`. No graph mutation.

#### 6.3.2 READ(file_cap, offset, length) → data

Follows `pointsTo` edges from the Inode to find the Block covering the
requested offset, reads data from sectors. No graph mutation (atime update
is deferred or handled separately).

#### 6.3.3 CLOSE(file_cap)

Releases the FileCap handle, decrements Inode refcount (but does not remove
graph nodes). If refcount reaches 0 and link_count = 0, triggers garbage
collection (which IS a graph mutation — but it's a side effect of CLOSE,
not CLOSE itself).

#### 6.3.4 STAT(inode_id) → metadata

Reads Inode attributes. No graph mutation.

### 6.4 Gluing Conditions and Dangling Edge Prevention

The DPO framework automatically prevents dangling edges through GC2 (the
dangling condition). For sotFS, this manifests as:

- **Cannot UNLINK an inode that has grants edges** (capabilities must be
  revoked first, or the UNLINK rule must include them in L).
- **Cannot RMDIR a directory that has contains edges** other than "." and
  ".." (the directory must be empty).
- **Cannot delete a Block that has pointsTo edges from other inodes**
  (refcount > 1 means CoW sharing — the Block persists, only the specific
  pointsTo edge is removed).

In the implementation, these checks are performed by the GTXN engine before
applying any rule. If a gluing condition fails, the GTXN returns an error
(ENOTEMPTY, EBUSY, EPERM, etc.) without modifying the graph.

### 6.5 Invariant Preservation Proofs (Informal)

For each invariant from Section 5.4-5.5, we argue that every DPO rule
preserves it.

**G₁ (No orphan inodes):** Every rule that creates an Inode (CREATE, MKDIR,
LINK) simultaneously creates a `contains` edge from an existing Directory,
ensuring reachability. Every rule that removes a `contains` edge (UNLINK,
RMDIR, RENAME-replace) either decrements link_count (leaving the inode
reachable via other links) or removes the inode entirely (link_count=0). ✓

**G₂ (No dangling edges):** Guaranteed by the DPO dangling condition (GC2).
Every rule's L includes all edges incident to deleted nodes. ✓

**G₃ (Link count consistency):** Every rule that adds/removes a `contains`
edge correspondingly adjusts link_count. Verified case-by-case for each rule
in Section 6.2. ✓

**G₄ (Capability monotonicity):** The DPO rules for filesystem operations
do not modify capability attributes. Capability operations (derive, revoke)
are separate rules that preserve monotonicity by construction (new
capabilities are created with `rights ⊆ parent.rights`). ✓

**G₅ (No directory cycles):** Only CREATE (vtype=Directory), MKDIR, and
RENAME can add `contains` edges to Directory-typed inodes. MKDIR's ".."
points to an ancestor (no cycle). RENAME's GC-RENAME-2 explicitly checks
for cycle creation. ✓

**G₆ (Block allocation consistency):** WRITE allocates from free bitmap
regions. UNLINK (with link_count=0) frees blocks back to bitmap. No rule
allocates an already-allocated sector. ✓

**G₇ (Treewidth):** See Section 8 for the detailed argument.

### 6.6 Treewidth Preservation per Rule

| Rule | Nodes added | Edges added | tw impact |
|------|-------------|-------------|-----------|
| CREATE (file) | 1 Inode | 1 contains | +0 (leaf added to tree) |
| CREATE (dir) | 1 Inode + 1 Dir | 3 contains | +0 (subtree added) |
| MKDIR | 1 Inode + 1 Dir | 3 contains | +0 (subtree added) |
| WRITE | 0-1 Block | 0-1 pointsTo | +0 (star edge added) |
| RMDIR | -1 Inode - 1 Dir | -3 contains | -0 to -1 (subtree removed) |
| LINK | 0 | 1 contains | +0 to +1 (back-edge may increase tw) |
| UNLINK | 0 to -1 Inode | -1 contains | -0 to -1 |
| RENAME | 0 | net 0 (move) | +0 (no structural change) |

Only LINK can increase treewidth, bounded by GC-LINK-3 (LINK_MAX).

---

## 7. Capabilities and Transactions

### 7.1 Capabilities as Typed Graph Edges

In sotFS, capabilities are not external tokens looked up in a separate table —
they are **nodes in the metadata graph** connected by typed edges:

- A Capability node c with `grants(c, i)` authorizes access to Inode i with
  the rights specified in c.rights.
- A `delegates(c_parent, c_child)` edge represents capability derivation
  (attenuation).

This unification means that capability operations ARE graph operations:

**DERIVE(cap_id, mask) → new_cap_id**
```
L = { c:Capability }
K = { c:Capability }
R = { c:Capability, c_new:Capability[rights = c.rights ∩ mask, epoch=current],
      e_d:delegates(c, c_new),
      e_g:grants(c_new, target(c.grants_edge)) }
```

**REVOKE(cap_id)**

Epoch-based revocation (as in `formal/sot_capabilities.tla`): bump the
global epoch, invalidating all capabilities with epoch < current. In graph
terms, this removes the Capability node and all its `delegates` descendants
(transitive closure), along with their `grants` edges.

### 7.2 Attenuation = Edge Relabeling

Capability attenuation in the CDT corresponds to a specific pattern in
the type graph: each `delegates` edge connects a parent capability to a
child capability with `child.rights ⊆ parent.rights`. This is the
graph-theoretic expression of the `Rights::restrict()` operation
(`kernel/src/cap/table.rs`).

The monotonicity invariant G₄ is thus a statement about the labeling of
paths in the `delegates` subgraph: rights are monotonically non-increasing
along any path from root to leaf.

### 7.3 Graph Transactions (GTXN)

A Graph Transaction (GTXN) wraps one or more DPO rule applications into
an atomic unit. The GTXN protocol (ADR-001) ensures:

1. **Atomicity:** Either all rules in the GTXN apply successfully, or none
   do (the graph reverts to its pre-transaction state).
2. **Isolation:** Concurrent GTXNs with overlapping write sets are serialized
   via the underlying SOT Tier 2 transaction (2PC).
3. **Durability:** Committed GTXNs are persisted via the WAL before the
   commit response is sent.

**GTXN lifecycle:**

```
gtxn = GTXN::begin()
  |
  |-- verify_gluing(rule, match)     -- check DPO gluing conditions
  |-- verify_treewidth(rule, match)  -- check tw bound preserved
  |-- sot_tx = SOT::begin(tier)     -- delegate to kernel transaction
  |-- apply_rule(rule, match)        -- modify in-memory graph
  |-- verify_postconditions()        -- check global invariants
  |
  |-- GTXN::commit()
  |     |-- SOT::commit(sot_tx)      -- persist via WAL
  |     |-- curvature_update(affected_edges)
  |     |-- provenance_emit(rule, match)
  |
  |-- GTXN::rollback()  [on failure at any step]
        |-- SOT::abort(sot_tx)        -- WAL restore
        |-- graph.revert()            -- discard in-memory changes
```

### 7.4 GTXN → SOT Tier Mapping

| DPO Rule | SOs Touched | SOT Tier |
|----------|-------------|----------|
| CREATE | 1 Directory SO + 1 new Inode SO | Tier 1 (single parent dir) |
| WRITE | 1 Inode SO + 0-1 Block SOs | Tier 1 |
| MKDIR | 1 Directory SO + 1 new Inode SO + 1 new Directory SO | Tier 1 |
| RMDIR | 1 Directory SO + 1 Inode SO | Tier 1 |
| LINK | 1 Directory SO + 1 Inode SO | Tier 1 |
| UNLINK | 1 Directory SO + 1 Inode SO + 0-N Block SOs | Tier 1 (or Tier 2 if many blocks) |
| RENAME (same dir) | 1 Directory SO + 1-2 Inode SOs | Tier 1 |
| RENAME (cross-dir) | 2 Directory SOs + 1-2 Inode SOs | **Tier 2 (2PC)** |

Only cross-directory RENAME requires SOT Tier 2 (two-phase commit), because
it modifies two independent Directory Secure Objects atomically.

### 7.5 Commit and Rollback as DPO Rule Sequences

**Commit** of a GTXN is the identity operation on the graph — the rules have
already been applied, and commit makes them durable. In category-theoretic
terms, commit is a functor from the in-memory graph category to the
persistent graph category that preserves all structure.

**Rollback** is the inverse of the applied rule sequence. For each rule
ρ = (L ← K → R) applied as m: L → G producing H, the rollback applies
the inverse rule ρ⁻¹ = (R ← K → L) with the corresponding match in H,
restoring G. This works because DPO rules are invertible when the match
is injective (which we require for all matches).

In practice, rollback uses the SOT WAL: the WAL records the old sector
contents, and `SOT::abort()` restores them. The in-memory graph is discarded
and reloaded from the restored sectors.

### 7.6 Integration with sot_transactions.tla

The existing `sot_transactions.tla` specification models transactions over
generic "Objects" (SOs). The GTXN layer adds a typed wrapper:

- Each Inode, Directory, Capability, Transaction, Version, Block node is
  backed by one or more SOs.
- The GTXN's `read_set` and `write_set` are sets of SO identifiers, matching
  the `txReadSet` and `txWriteSet` variables in the TLA+ spec.
- The GTXN engine ensures that `txWriteSet` of concurrent GTXNs are disjoint
  (Isolation invariant in `sot_transactions.tla`), which translates to: no
  two concurrent GTXNs modify the same Inode.

A new TLA+ specification (`formal/sotfs_graph.tla`, Phase 1 deliverable)
will compose `sot_transactions.tla` with the type graph invariants, using
TLA+'s `INSTANCE` mechanism to import the transaction model.

---

## 8. Bounded Treewidth and MSO Queries

### 8.1 Treewidth Bound Proof Sketch

**Theorem 8.1.** Let TG be a sotFS type graph produced by any finite sequence
of DPO rule applications starting from the CREATE-ROOT initial graph. If the
hard link count per inode is bounded by LINK_MAX, then:

```
tw(TG) ≤ LINK_MAX + 1
```

**Proof sketch.** We decompose TG into subgraphs by edge type and analyze
the treewidth of each:

1. **Contains subgraph** (Directory → Inode edges): Without hard links, this
   is a forest (rooted at the root directory). A forest has treewidth 1.
   Each hard link adds one back-edge to an existing node, increasing
   treewidth by at most 1. With at most LINK_MAX hard links per inode,
   the maximum increase is LINK_MAX. Thus tw(contains) ≤ LINK_MAX + 1.

2. **Grants subgraph** (Capability → Inode edges): Each Capability has
   exactly one outgoing grants edge (I₅). The grants subgraph is a bipartite
   graph with degree 1 on the Capability side. tw(grants) = 1.

3. **Delegates subgraph** (Capability → Capability edges): By C₄, this is
   a forest. tw(delegates) = 1.

4. **DerivedFrom subgraph** (Version → Version edges): By C₅, this is a
   DAG, and in practice a tree or near-tree. tw(derivedFrom) ≤ 2 (DAGs
   with bounded in-degree have bounded treewidth).

5. **PointsTo subgraph** (Inode → Block edges): Each Inode is the center
   of a star to its blocks. Stars have treewidth 1.

6. **Supersedes subgraph** (Inode → Inode edges): By C₆, acyclic. Each
   inode has at most one outgoing supersedes edge (from the most recent
   rename). tw(supersedes) = 1.

The combined graph's treewidth is bounded by the sum of the constituent
subgraph treewidths minus overlaps at shared nodes. A tighter analysis:

The key observation is that the contains subgraph dominates the treewidth.
The other edge types connect to nodes already present in the contains
tree decomposition. By the tree decomposition merging lemma (Bodlaender,
1998), adding edges between nodes already in a tree decomposition of
width w increases the width by at most the number of additional edges
per bag. Since each node participates in at most LINK_MAX + 1 contains
edges, 1 grants edge, O(1) delegates edges, and O(1) pointsTo edges,
the combined treewidth is:

```
tw(TG) ≤ LINK_MAX + O(1) ≤ LINK_MAX + 5
```

For practical purposes, setting LINK_MAX = 65535 gives a treewidth bound
of ~65540, which is a large constant. The important point is that it IS
a constant, independent of the number of files.

**Corollary 8.2.** For filesystems without hard links (the common case for
most modern workloads), tw(TG) ≤ 6 (one for each edge type).

### 8.2 Courcelle's Theorem Application

**Theorem (Courcelle, 1990).** Let φ be a closed MSO₂ formula over graphs.
For every integer k, there exists an algorithm that decides whether a graph G
of treewidth ≤ k satisfies φ in time O(f(|φ|, k) · |V(G)|), where f is a
computable function.

Since sotFS maintains tw(TG) ≤ LINK_MAX + O(1) as an invariant (verified by
the GTXN engine after every rule application), and |φ| and LINK_MAX are
fixed at filesystem creation time, every MSO₂-definable query runs in
**O(n)** time where n = |V(TG)|.

### 8.3 Example MSO Queries

**Q1: Capability reachability.** "Can domain D access file F with READ
permission?"

```
∃ path c₀ →delegates ... →delegates cₙ such that
  c₀ belongs to domain D ∧
  grants(cₙ, F) ∧
  READ ∈ cₙ.rights
```

This is MSO₂-expressible (existential path quantification over the
delegates/grants subgraph). Runs in O(n).

**Q2: Directory cycle detection.** "Does the contains subgraph have a cycle?"

```
¬∃ v, path v →contains ... →contains v
  where all edges have name ∉ {".", ".."}
```

MSO₂-expressible. If the answer is "yes," invariant G₅ has been violated.
Runs in O(n).

**Q3: Orphan detection.** "Are there inodes unreachable from root?"

```
∃ i : Inode, ¬reachable(root, i) ∧ i.link_count > 0
```

MSO₂-expressible (reachability is the canonical MSO example). Runs in O(n).

**Q4: All files derived from version V.**

```
{i : Inode | ∃ path V →derivesFrom ... →derivesFrom Vₙ ∧
             Vₙ.root_oid = i.id}
```

MSO₂-expressible. Runs in O(n).

### 8.4 Linear-Time Query Engine Architecture

The query engine operates in three phases:

1. **Decompose:** Maintain a tree decomposition of TG incrementally. Each
   DPO rule application updates the decomposition locally (add/remove bags
   for added/removed nodes).

2. **Compile:** Translate MSO₂ formula φ into a tree automaton Aφ. This is
   done once per query type at system startup (the compilation is
   exponential in |φ| and k but independent of n).

3. **Evaluate:** Run Aφ bottom-up on the tree decomposition. This takes
   O(n) time.

For common queries (Q1-Q4), pre-compiled automata are stored in the sotFS
server. Custom queries can be submitted at runtime via the native API
(Phase 3, objective 3.6).

---

## 9. Ollivier-Ricci Curvature Monitor

### 9.1 Curvature Definition on Metadata Graphs

For an edge (u, v) in the type graph TG, we define the **Ollivier-Ricci
curvature** κ(u, v) using the lazy random walk measure:

```
μₓ(z) = { α           if z = x
         { (1-α)/deg(x) if z ∈ N(x)
         { 0            otherwise

κ(u, v) = 1 - W₁(μᵤ, μᵥ) / d(u, v)
```

where α ∈ (0,1) is the laziness parameter (typically α = 0.5), N(x) is the
set of neighbors of x, and W₁ is the Wasserstein-1 (earth mover's) distance
between the measures μᵤ and μᵥ.

For the metadata graph, we use d(u,v) = 1 for all edges (unweighted graph).

### 9.2 Anomaly Signatures

Normal filesystem operations produce predictable curvature patterns:

| Operation | Curvature Change | Reason |
|-----------|-----------------|--------|
| CREATE (file) | Slight decrease on parent contains edge | Parent's neighborhood grows (more children), diverging from child |
| MKDIR | Slight decrease on parent, near-zero on new dir | New subtree, tree-like structure |
| UNLINK (non-last) | Slight increase on parent | Parent's neighborhood shrinks, more overlap with remaining children |
| WRITE | No change | Block topology unchanged |
| Normal operation (steady state) | κ ≈ -0.5 to 0 on most edges | Tree-like structure has negative curvature |

**Anomalous signatures:**

| Attack Pattern | Curvature Signature |
|---------------|-------------------|
| Mass file creation (zip bomb) | Rapid positive curvature spike on victim directory edge |
| Symlink bomb (many symlinks to one target) | Strong positive curvature on target inode's edges |
| Deep directory chain (traversal attack) | Sustained κ ≈ -1.0 on chain edges (pure tree, maximally negative) |
| Directory structure manipulation | Sudden curvature change on edges that were stable |

### 9.3 Incremental Computation

Full curvature computation on the entire graph is O(|E| · d_max²) where d_max
is the maximum degree. This is too expensive for every operation.

**Key insight:** Each DPO rule application changes O(1) edges. Only the
curvature of changed edges and their 1-hop neighbors needs recomputation.

**Incremental protocol:**
1. After GTXN commit, collect the set of added/removed/modified edges: Δ.
2. Compute the 1-hop neighborhood of Δ: Δ* = Δ ∪ {e : e shares an endpoint
   with some e' ∈ Δ}.
3. Recompute κ(e) for all e ∈ Δ* (typically |Δ*| ≤ 20 for most operations).
4. Compare each κ(e) against the baseline κ₀(e) (exponential moving average).
5. If |κ(e) - κ₀(e)| > threshold, emit curvature alert to provenance log.

**Amortized cost:** O(d_max²) per DPO rule application, where d_max is the
maximum degree of nodes touched by the rule. For typical filesystem workloads
(d_max ≤ 1000 entries per directory), this is ~10⁶ operations per curvature
update — negligible compared to disk I/O.

### 9.4 Integration with Provenance DAG

Each curvature update generates a provenance entry of a new type:

```
ProvenanceEntry {
    timestamp: Timestamp,
    cpu: CpuId,
    domain_id: DomainId,
    operation: "CURVATURE_UPDATE",
    subject_id: EdgeId,
    args: { old_kappa: f64, new_kappa: f64, alert: bool },
    parent_hash: SHA256
}
```

This integrates curvature monitoring into the existing provenance DAG
(`formal/sot_provenance.tla`), enabling forensic queries like "show all
curvature alerts in the last hour" or "what operations preceded this
curvature spike?"

---

## 10. Deceptive Subgraph Views

### 10.1 Capability-Gated Graph Projections

In the sotX deception model (`docs/DECEPTION_MODEL.md`), capability
interposition allows a domain's view of resources to be fabricated. sotFS
extends this from individual operations to **graph structure**: a domain
with interposed capabilities sees a **projected subgraph** of TG.

**Definition 10.1 (Graph Projection).** A projection π for domain D is a
typed graph morphism π: TG|_D → TG_D, where:
- TG|_D is the subgraph of TG reachable from D's root capability.
- TG_D is the "visible" type graph presented to D.
- π preserves types and attributes but may:
  - **Omit** nodes and edges (restricted visibility).
  - **Add** fabricated nodes and edges (deceptive content).
  - **Relabel** attributes (e.g., change file sizes, timestamps, names).

### 10.2 Extension of Deception Functor

The existing deception functor `D: SO → SO` from `FORMAL_MODEL.md:251-254`
maps real Secure Objects to fabricated ones. We extend this to a graph
endofunctor:

```
D_FS: TGraph → TGraph
```

where D_FS maps the real type graph to the domain-specific visible type
graph. The interposition policy (passthrough, inspect, redirect, fabricate)
from `DECEPTION_MODEL.md` determines D_FS's behavior:

- **Passthrough:** D_FS = Id (identity functor) — the domain sees the real
  graph.
- **Inspect:** D_FS = Id, but each operation is logged (natural
  transformation from Id to Prov ∘ Id).
- **Redirect:** D_FS maps certain Inode nodes to different Inode nodes
  (honeypot files).
- **Fabricate:** D_FS adds synthetic nodes and edges (fake files, fake
  directories, fake /proc entries).

**Consistency requirement:** D_FS must be a valid typed graph morphism. This
means fabricated content must satisfy all type graph invariants (no dangling
edges in the projected view, link counts consistent, etc.). The consistency
engine from `DECEPTION_MODEL.md` Section 5 enforces this.

### 10.3 Consistency Constraints for Projected Views

The deception consistency rules from `DECEPTION_MODEL.md` translate to
graph invariant preservation under D_FS:

1. **Structural consistency:** D_FS(TG) must satisfy all global invariants
   G₁-G₇. A fabricated directory with non-existent inodes would violate G₂
   (dangling edges).

2. **Temporal consistency:** If D_FS fabricates timestamps, they must be
   monotonically increasing for the same inode (ctime ≤ mtime ≤ atime for
   accessed files).

3. **Cross-channel consistency:** If `/proc/self/maps` shows a file-backed
   mapping to `/lib/libc.so`, then `stat("/lib/libc.so")` must return a
   valid result in the projected view.

4. **Behavioral consistency:** A fabricated file must be readable (returning
   fabricated content). A fabricated directory must be listable. Operations
   on fabricated content are intercepted by the interposition handler and
   return synthetic results.

These constraints are checkable as MSO queries on D_FS(TG) — and since
D_FS(TG) also has bounded treewidth (D_FS preserves the tree-like structure),
they run in linear time.

---

## 11. Verification Plan

### 11.1 Layer 1: TLA+ Model Checking

**Specification:** `formal/sotfs_graph.tla`

**State variables:**
- `graph`: the type graph TG (nodes, edges, attributes)
- `pending_rules`: sequence of DPO rule applications in progress
- `committed`: set of committed GTXN IDs
- `curvature`: edge → real-valued curvature map

**Invariants to verify:**
- All 17 invariants from Section 5.4-5.5 (I₁-I₉, C₁-C₇, G₁-G₇)
- GTXN atomicity: committed GTXN's effects are all-or-nothing
- GTXN isolation: concurrent GTXNs have disjoint write sets
- Treewidth bound: tw(graph) ≤ LINK_MAX + 5

**Model checking parameters:**
- 5-10 inodes, 2-3 directories, 3 capabilities, 2 transactions
- All 7 DPO rules enabled as actions
- Symmetry reduction on inode IDs

**Integration:** Use TLA+ `INSTANCE sot_transactions` to import the
existing transaction model. The GTXN actions compose with T1/T2 actions.

**Estimated effort:** 2-3 weeks for specification + model checking.

### 11.2 Layer 2: Crash Refinement

**Goal:** Prove that the WAL-based persistence layer correctly refines
the abstract graph transaction model.

**Approach (inspired by Yggdrasil):**
1. Define the abstract specification: GTXN operations on the in-memory
   type graph (from Layer 1's TLA+ spec).
2. Define the concrete implementation: sector writes with WAL logging
   (extending the existing 4-phase WAL in `libs/sotos-objstore/src/wal.rs`).
3. Insert crash points at every step of the concrete implementation.
4. Prove: for every crash point, WAL replay produces a graph state that
   is reachable from the abstract specification (either the pre-transaction
   state or the post-commit state, never an intermediate state).

**Tool:** SMT solver (Z3 or CVC5) via Rust bindings, similar to Yggdrasil's
push-button approach.

**Estimated effort:** 3-4 weeks.

### 11.3 Layer 3: Typestate in Rust

**Goal:** Use Rust's type system to enforce DPO rule preconditions at
compile time, similar to SquirrelFS.

**Approach:** Encode the state machine of each node type as generic type
parameters:

```rust
struct Inode<S: InodeState> { ... }

// States
struct Created;    // freshly created, not yet linked
struct Linked;     // has at least one contains edge
struct Orphaned;   // link_count = 0, pending GC

// State transitions enforced by type system
impl Inode<Created> {
    fn link(self, dir: &mut Directory) -> Inode<Linked> { ... }
}

impl Inode<Linked> {
    fn unlink(self) -> Either<Inode<Linked>, Inode<Orphaned>> { ... }
}

impl Inode<Orphaned> {
    fn gc(self) { ... }  // consumes the inode, preventing use-after-free
}
```

The compiler rejects programs that:
- Access an orphaned inode (consumed by `gc`).
- Link a node without going through CREATE.
- Close a transaction without committing or rolling back.

**Estimated effort:** 4-6 weeks (interleaved with FUSE implementation in
Phase 2).

### 11.4 Layer 4: Coq/Perennial

**Goal:** Mechanized proofs of the most critical properties.

**Properties to prove:**
1. **Commit atomicity:** GTXN commit produces exactly the graph state
   specified by the DPO rule (no partial application).
2. **Rollback correctness:** GTXN rollback restores the exact pre-
   transaction graph state.
3. **Capability unforgeability:** No sequence of DPO rule applications
   can create a Capability node with rights exceeding its CDT ancestor.
4. **Treewidth preservation:** Every DPO rule in the rule set preserves
   tw ≤ k.
5. **DPO confluence:** Non-conflicting DPO rule applications commute
   (the result is the same regardless of application order).

**Framework:** Perennial (Chajed et al., SOSP 2019) for crash refinement
proofs, or Verus for Rust-level proofs. Decision depends on maturity of
Verus at the time of implementation.

**Estimated effort:** 6-12 months.

### 11.5 Effort Estimation Table

| Layer | Tool | Properties | Effort | Confidence |
|-------|------|-----------|--------|------------|
| 1 | TLA+/TLC | Graph invariants, DPO rules, GTXN protocol | 2-3 weeks | Model-checked (bounded) |
| 2 | SMT (Z3) | Crash refinement, WAL correctness | 3-4 weeks | Push-button (bounded) |
| 3 | Rust types | State machine transitions, lifetime safety | 4-6 weeks | Compile-time (all inputs) |
| 4 | Coq/Perennial | Atomicity, unforgeability, treewidth | 6-12 months | Mechanized proof (all inputs) |

---

## 12. Future Work

- **Phase 1:** Implement the TLA+ model (Section 11.1) and verify all
  invariants under model checking.
- **Phase 2:** Build a FUSE prototype on Linux, with the type graph,
  DPO engine, and GTXN manager as Rust crates.
- **Phase 3:** Port to sotX as a native filesystem server domain.
- **Phase 4:** Apply the formal verification layers incrementally.
- **Phase 5:** Implement the structural differentiators (bounded treewidth
  enforcement, curvature monitoring, deceptive projections).
- **Phase 6:** Hardening, packaging, and release.

---

## 13. References

1. Ehrig, H., Ehrig, K., Prange, U., Taentzer, G. *Fundamentals of
   Algebraic Graph Transformation*. Springer, 2006.

2. Courcelle, B. "The Monadic Second-Order Logic of Graphs I: Recognizable
   Sets of Finite Graphs." *Information and Computation*, 85(1):12-75, 1990.

3. Ollivier, Y. "Ricci Curvature of Markov Chains on Metric Spaces."
   *Journal of Functional Analysis*, 256(3):810-864, 2009.

4. Lin, Y., Lu, L., Yau, S.-T. "Ricci Curvature of Graphs." *Tohoku
   Mathematical Journal*, 63(4):605-627, 2011.

5. Chen, H., Ziegler, D., Chajed, T., Chlipala, A., Kaashoek, M. F.,
   Zeldovich, N. "Using Crash Hoare Logic for Certifying the FSCQ File
   System." *SOSP*, 2015.

6. Sigurbjarnarson, H., Bornholt, J., Torlak, E., Wang, X. "Push-Button
   Verification of File Systems via Crash Refinement." *OSDI*, 2016.

7. Kadekodi, S., Ramanathan, A., Narayanan, V. "SquirrelFS: Using the
   Rust Compiler to Check File-System Crash Consistency." *OSDI*, 2024.

8. Watson, R. N. M., Anderson, J., Laurie, B., Kennaway, K. "Capsicum:
   Practical Capabilities for UNIX." *USENIX Security*, 2010.

9. Klein, G., Elphinstone, K., Heiser, G., et al. "seL4: Formal Verification
   of an OS Kernel." *SOSP*, 2009.

10. Chajed, T., Tassarotti, J., Theng, M., Jung, R., Kaashoek, M. F.,
    Zeldovich, N. "Verifying Concurrent, Crash-Safe Systems with Perennial."
    *SOSP*, 2019.

11. Robertson, N., Seymour, P. D. "Graph Minors. II. Algorithmic Aspects of
    Tree-Width." *Journal of Algorithms*, 7(3):309-322, 1986.

12. Bodlaender, H. L. "A Partial k-Arboretum of Graphs with Bounded
    Treewidth." *Theoretical Computer Science*, 209(1-2):1-45, 1998.

13. Muniswamy-Reddy, K.-K., Holland, D. A., Braun, U., Seltzer, M. I.
    "Provenance-Aware Storage Systems." *USENIX ATC*, 2006.

---

## 14. Empirical Evaluation

### 14.1 Implementation Components

The prototype comprises six Rust crates in the `sotfs/` workspace:

| Crate | Description | Key Types |
|-------|-------------|-----------|
| `sotfs-graph` | Type graph data structures | `TypeGraph`, `Arena<T,N>`, `RcuGraph` |
| `sotfs-ops` | DPO rewriting rules for POSIX operations | `create_file`, `mkdir`, `unlink`, `rename`, `link` |
| `sotfs-storage` | Persistence via redb ACID backend | `save()`, `load()` round-trip |
| `sotfs-tx` | Graph-level transaction manager (GTXN) | `GraphTransaction`, commit/rollback |
| `sotfs-monitor` | Structural anomaly monitors | `compute_treewidth`, `OllivierRicci`, `DeceptiveProjection` |
| `sotfs-fuse` | FUSE binding for Linux integration | Full POSIX VFS bridge |

**Arena Allocator** (`sotfs-graph/src/arena.rs`). Fixed-capacity, heap-backed
storage pool with O(1) alloc, dealloc, and lookup. Uses a free-list for slot
reuse after `unlink`/`rmdir`, preventing fragmentation. Default capacities:
65,536 for node pools, 131,072 for edges. The backing arrays are
heap-allocated (`Box<[MaybeUninit<T>]>`) to avoid stack overflow at kernel
scale — the TypeGraph struct itself is only ~744 bytes (pointers + counters).

**Epoch-based RCU** (`sotfs-graph/src/rcu.rs`). Lock-free reads for directory
operations (lookup, readdir, stat, path resolution) via two heap-allocated
TypeGraph copies with atomic swap. Writers acquire exclusive access, clone
active → inactive, mutate, swap the active index atomically, then wait for
readers from the old epoch to drain. Eight concurrent reader slots; designed
for the sotOS microkernel where `alloc` is available but `std` is not.

**DynamicTreewidth** (`sotfs-monitor/src/treewidth.rs`). Incremental treewidth
maintenance that caches the elimination ordering. For small graph edits
(<20% dirty nodes), partial re-elimination avoids full O(n²) recomputation.
Falls back to complete greedy min-degree elimination when the dirty fraction
exceeds the threshold.

### 14.2 Test Suite Summary

All tests executed on Windows 11 x86_64 with Rust nightly 2026.

| Crate | Category | Tests | Status |
|-------|----------|------:|--------|
| sotfs-graph | Arena allocator unit tests | 16 | PASS |
| sotfs-graph | RCU concurrency tests | 9 | PASS |
| sotfs-graph | Graph invariant tests | 3 | PASS |
| sotfs-graph | Typestate enforcement | 6 | PASS |
| sotfs-ops | DPO rule unit tests | 23 | PASS |
| sotfs-ops | Property-based tests (10K iter) | 10 | PASS |
| sotfs-storage | Backend unit test | 1 | PASS |
| sotfs-storage | Crash consistency tests | 6 | PASS |
| sotfs-tx | Transaction unit tests | 3 | PASS |
| sotfs-tx | Loom concurrency tests | 3 | PASS |
| sotfs-monitor | Treewidth tests | 20 | PASS |
| sotfs-monitor | Curvature tests | 14 | PASS |
| sotfs-monitor | Deception tests | 5 | PASS |
| sotfs-monitor | Adversarial scenario tests | 13 | PASS |
| **Total** | | **132** | **ALL PASS** |

**Testing categories:**

- **Deterministic unit tests** (109): Direct validation of invariants,
  data structure correctness, DPO rule pre/postconditions.
- **Property-based tests** (10 properties × 10,000 iterations = 100,000+
  random sequences): Proptest generates arbitrary operation sequences and
  verifies structural invariants are preserved. Properties include invariant
  preservation, link count consistency, cycle freedom, chmod/chown isolation,
  write/read round-trip, truncate semantics, and deep mkdir chain safety.
- **Loom concurrency tests** (3): Exhaustive interleaving exploration for
  GTXN isolation, rollback correctness, and conflicting write serialization.
- **Crash consistency tests** (6): Round-trip persistence, atomic overwrite,
  reopen survival, and complex operation sequences via redb ACID backend.
- **Adversarial security tests** (13): Ransomware mass write/rename detection
  via curvature anomaly, hardlink bomb treewidth spike, deep nesting bounds,
  capability monotonic attenuation, deceptive projection correctness.

### 14.3 Benchmark Suite

Three Criterion benchmark suites are configured for performance regression
tracking:

**DPO Operations** (`sotfs-ops/benches/dpo_bench.rs`):
- `create_file` at n=100, 500, 1000
- `mkdir_chain` at depth=50, 200, 500
- `unlink` at n=100, 500
- `rename_same_dir` at n=100, 500
- `hard_link` at n=10, 100, 500
- `write_read` at sizes 64B, 1KB, 4KB, 64KB
- `check_invariants` at n=10, 100, 500, 1000

**WAL Index** (`sotfs-ops/benches/wal_bench.rs`):
- Linear scan vs indexed lookup at 10, 100, 1000 entries
- DPO sequence (indexed vs linear) at 10, 50, 100, 500 operations

**Structural Monitors** (`sotfs-monitor/benches/monitor_bench.rs`):
- Treewidth computation on star, chain, tree topologies at 50–500 nodes
- Ollivier-Ricci curvature (full vs incremental) at 100–10,000 nodes
- Treewidth check at 100, 500 nodes

---

## Appendix A: VfsOp → DPO Rule Mapping

| VfsOp (lib.rs:64-79) | DPO Rule | GTXN Tier | Graph Mutation |
|----------------------|----------|-----------|----------------|
| Open (1) | OPEN (query) | Tier 0 | None (capability check) |
| Close (2) | CLOSE (query) | Tier 0 | None (may trigger GC) |
| Read (3) | READ (query) | Tier 0 | None |
| Write (4) | WRITE (§6.2.2) | Tier 1 | Add/replace Block + pointsTo |
| Stat (5) | STAT (query) | Tier 0 | None |
| Readdir (6) | READDIR (query) | Tier 0 | None (enumerate contains edges) |
| Mkdir (7) | MKDIR (§6.2.3) | Tier 1 | Add Inode + Directory + contains |
| Rmdir (8) | RMDIR (§6.2.4) | Tier 1 | Remove Inode + Directory + contains |
| Unlink (9) | UNLINK (§6.2.6) | Tier 1 | Remove contains edge, maybe Inode |
| Rename (10) | RENAME (§6.2.7) | Tier 1/2 | Move contains edge, maybe supersedes |
| Lseek (11) | — | — | No graph involvement (handle state) |
| Fstat (12) | STAT (query) | Tier 0 | None |
| Fsync (13) | — | — | Force WAL flush |
| Ftruncate (14) | WRITE (§6.2.2) | Tier 1 | Remove Block + pointsTo edges |

## Appendix B: Category Theory Integration

The existing category-theoretic framework in `FORMAL_MODEL.md` §5 defines
five categories: **SO**, **Dom**, **Chan**, **Tx**, **Prov**.

sotFS introduces a sixth category:

| Category | Objects | Morphisms |
|----------|---------|-----------|
| **TGraph** | Typed graphs (instances of TG) | Typed graph morphisms |

**New functors:**

- **Graph functor** `G: SO → TGraph`: maps Secure Objects to graph nodes.
  Each SO that backs a filesystem entity (Inode, Directory, Block, etc.)
  has a corresponding node in TG. This functor is faithful: distinct SOs
  map to distinct nodes.

- **Rewrite functor** `Rw: Tx → TGraph`: maps transactions to graph
  transformations. Each GTXN (a morphism in **Tx**) corresponds to a
  sequence of DPO rule applications (morphisms in **TGraph**). This functor
  preserves composition: committing GTXN₁ then GTXN₂ produces the same
  graph as applying their DPO rules in sequence.

- **Deception graph functor** `D_FS: TGraph → TGraph`: extension of
  `D: SO → SO` to the graph level. Maps the real type graph to a
  domain-specific projected type graph. This is an endofunctor on **TGraph**
  with the property that D_FS preserves all type graph invariants
  (G₁-G₇) — a fabricated filesystem view is internally consistent.

**Natural transformations:**

- **Persistence:** η: Id_TGraph → WAL ∘ Id_TGraph. Maps in-memory graph
  state to WAL-backed persistent state. The crash refinement proof (Layer 2)
  shows this is a natural transformation (commutes with all graph operations).

- **Projection:** π_D: Id_TGraph → D_FS. Maps the real graph to a domain D's
  projected view. The consistency constraints (Section 10.3) ensure π_D is a
  valid natural transformation.

The full category diagram:

```
                 G
        SO ─────────→ TGraph
        |               |
      A |             D_FS|
        ↓               ↓
       Dom            TGraph
        |               |
        └───────────────┘
              π_D
```

This extends the existing diagram from `FORMAL_MODEL.md` §5.2 with the
graph-level structure, unifying filesystem operations, capability security,
and deception in a single categorical framework.

---

## 16. Coq Mechanized Proofs

Seven Coq modules in `formal/coq/` formalize the type graph definitions and
prove that DPO rules preserve WellFormed (the conjunction of invariants 5.1-5.5):

| Module | DPO Rule | Invariants Proved | Status |
|--------|----------|-------------------|--------|
| `SotfsGraph.v` | (core defs) | `init_graph_well_formed` | Complete |
| `DpoCreate.v` | create_file | all 5 | Complete (0 admits) |
| `DpoUnlink.v` | unlink_keep | all 5 | Complete (0 admits) |
| `DpoRename.v` | rename_same_dir | all 5 | Complete (0 admits) |
| `DpoMkdir.v` | mkdir | all 5 | Complete (1 side condition) |
| `DpoLink.v` | hard_link | all 5 | Complete (0 admits) |
| `DpoRmdir.v` | rmdir | 3 of 5 | Partial |

**Key technical contribution**: The `count_remove_matching` lemma in `SotfsGraph.v`
establishes that removing one predicate-satisfying element from a list decreases
`count_occ_pred` by exactly one. This single lemma closes the `LinkCountConsistent`
proofs for both Unlink and Rename, which were previously Admitted.

---

## 17. New Graph-Native Features

### 17.1 Extended Attributes (xattrs)

Each xattr is a graph node of type `XAttr` connected via `HasXattr` edges (§5.3.7).
- **Operations**: `setxattr`, `getxattr`, `removexattr`, `listxattr`
- **Namespaces**: User, System, Security, Trusted
- **Limit**: 64KB per value (Linux convention)
- **Graph impact**: Adds nodes to the graph but does not affect treewidth (xattr
  nodes have degree 1)

### 17.2 Symlinks

`VnodeType::Symlink` inodes store targets in `symlink_targets: BTreeMap<InodeId, SymlinkTarget>`.
- **DPO rule**: `symlink()` — identical to `create_file()` except vtype=Symlink
  and permissions=0777
- **Cycle detection**: Deferred to resolution time (POSIX semantics)
- **Link count**: Always 1 (symlinks cannot be hard-linked to directories)

### 17.3 POSIX ACLs ↔ Capability Graph

ACL entries (`AclEntry`) map to capability graph edges:
- `ACL_USER_OBJ` → `Grants(cap_owner, inode, owner_rights)`
- `ACL_USER(uid)` → `Grants(cap_uid, inode, user_rights)`
- `ACL_GROUP_OBJ` → `Grants(cap_group, inode, group_rights & mask)`
- `ACL_OTHER` → `Grants(cap_other, inode, other_rights)`

When no explicit ACL is set, `getacl()` synthesizes a minimal 3-entry ACL from
the inode's permission bits.

### 17.4 Hierarchical Quotas

`Quota` structs track `inode_usage/limit` and `byte_usage/limit` per subtree root.
- **Enforcement**: `check_quota_inode()` walks up via ".." edges checking every boundary
- **Propagation**: `update_quota()` propagates deltas upward at O(depth) amortized
- **Storage**: `quotas: BTreeMap<DirId, Quota>` in the TypeGraph

### 17.5 fsck Verifier

The `fsck()` function checks all structural invariants:
- 5.1 TypeInvariant (edge endpoints exist)
- 5.2 LinkCountConsistent (link_count matches edges)
- 5.3 UniqueNamesPerDir (no duplicate names)
- 5.4 NoDanglingEdges (all endpoints exist)
- 5.5 NoDirCycles (DFS cycle detection)
- Block refcount consistency
- Orphan detection (inodes with no incoming edges)
- Xattr integrity

Returns a structured `FsckReport` with typed `FsckError`s and warnings.

---

## 18. Updated Test Summary (April 2026)

| Category | Count | Method |
|----------|-------|--------|
| Arena allocator | 16 | Unit tests |
| RCU concurrency | 9 | Unit tests (multi-thread) |
| Graph invariants | 3 | Unit tests |
| Typestate | 6 | Unit + compile-fail |
| DPO operations | 35 | Unit tests (was 23) |
| Property-based | 10 | proptest (10K iter each) |
| Storage/crash | 7 | Integration (redb) |
| Transaction | 3 | Unit tests |
| Loom concurrency | 3 | Exhaustive interleavings |
| Treewidth | 20 | Unit + adversarial |
| Curvature | 14 | Unit + incremental |
| Deception | 5 | Unit (projections) |
| Adversarial | 13 | Security scenarios |
| **Total** | **147** | All passing |

New tests cover: xattrs (4), symlinks (2), ACLs (2), quotas (2), fsck (2).
