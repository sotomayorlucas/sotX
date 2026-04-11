# ADR-003: Bootstrap Procedure

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** Lucas Sotomayor  

## Context

A fresh sotFS volume must be initialized with a minimal graph structure before
any POSIX operations can execute. The bootstrap must create the root directory,
the root inode, the initial capability, and the persistent storage layout.

The existing object store (`libs/sotos-objstore/src/store.rs`) uses
`ObjectStore::format()` which writes a superblock with `ROOT_OID = 1` and
initializes the bitmap, WAL, and directory table. sotFS needs an analogous
but graph-aware initialization.

## Decision

**`sotfs_format()` is itself a DPO rule application — the CREATE-ROOT rule.**

The CREATE-ROOT rule is a special DPO rule that operates on an empty host
graph (G = ∅) and produces the minimal valid type graph:

```
L = ∅  (empty graph — no preconditions)
K = ∅  (empty interface)
R = {
  Nodes:
    i_root : Inode    { id=1, vtype=Directory, perms=0o755, uid=0, gid=0,
                        size=0, link_count=2, ctime=now, mtime=now }
    d_root : Directory { id=1 }
    c_root : Capability { rights=AllRights, epoch=0, parent=None }
    b_super : Block   { sector_start=0, sector_count=METADATA_SECTORS }

  Edges:
    contains(d_root, i_root)  { name="." }
    grants(c_root, i_root)    { rights={R,W,X,Grant,Revoke} }
    pointsTo(i_root, b_super) { offset=0 }
}
```

The on-disk layout after format:

| Sector Range | Content |
|-------------|---------|
| 0 | Superblock (magic, version, root_oid=1, graph metadata offset) |
| 1-5 | WAL header + payload (empty, committed=false) |
| 6-133 | Block allocation bitmap |
| 134+ | Graph node/edge tables (initially: 1 inode, 1 directory, 1 cap, 3 edges) |

This layout extends the existing `ObjectStore` layout (defined in
`libs/sotos-objstore/src/layout.rs`) by replacing the flat 128-byte directory
entries with variable-size graph node/edge records. The superblock magic
changes from `0x534F544F_53465321` ("SOTOSFS!") to `0x534F5446_53475248`
("SOTFSGRH" — sotFS Graph).

## Consequences

**Positive:**
- Bootstrap is not a special case — it's the first DPO rule application,
  so all the invariant-checking machinery applies from the very first
  operation.
- The initial graph trivially satisfies all global invariants (no orphans,
  no dangling edges, link_count matches contains edge count, treewidth=1).
- The root capability (`c_root` with AllRights) is the ancestor of all
  future capabilities in the CDT, ensuring the capability derivation tree
  has a single root.

**Negative:**
- Applying a DPO rule to an empty graph is a degenerate case (L=K=∅) that
  doesn't exercise gluing conditions. The first "real" test is the second
  operation (e.g., `mkdir /bin`).

## Alternatives Considered

### A. Imperative initialization (like ObjectStore::format)

Write the initial graph nodes/edges directly via sector writes, outside the
DPO framework.

**Rejected because:** This creates a gap in the formal model — the initial
state would be "assumed correct" rather than "derived from a rule application."
For the verification effort (Phase 4), having CREATE-ROOT as a DPO rule means
the TLA+ model can start from G=∅ and verify invariants from the very first
state transition.
