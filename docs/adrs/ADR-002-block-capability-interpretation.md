# ADR-002: Block Capability Interpretation

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** Lucas Sotomayor  

## Context

sotFS needs to persist the metadata graph and file data to a block device.
The sotX capability system mediates all resource access — the question is
at what granularity block-level capabilities are exposed.

Two models are possible:

1. **Per-inode capabilities:** Each inode (or graph node) has its own block
   capability, and clients interact with blocks directly.
2. **Bulk capability:** The FS server holds a single capability to the entire
   block device and manages sub-allocation internally. Clients receive
   attenuated capabilities to inode Secure Objects, never raw block caps.

## Decision

**The sotFS server holds a bulk block-device capability.** Clients receive
attenuated `CapId`s referencing inode Secure Objects, never raw block
capabilities.

The architecture is:

```
Client Domain                    sotFS Server Domain
+-------------+                  +------------------+
| FileCap {   |  --- IPC --->    | GTXN engine      |
|   cap_id    |                  | Type graph (mem)  |
|   rights    |                  | Block allocator   |
|   vnode_id  |                  | Bulk block cap ---|---> Block Device
| }           |  <-- IPC ---     |                   |
+-------------+                  +------------------+
```

This matches the existing VFS pattern in `personality/bsd/vfs/src/lib.rs`
where `FileCap` carries `FileRights` (read/write/execute/append_only) and
a `vnode_id`, and the VFS server owns all vnodes internally.

## Consequences

**Positive:**
- Clients cannot bypass the filesystem to corrupt metadata or read other
  files' data blocks — the FS server is the sole mediator.
- The block allocator (bitmap) is managed in one place, eliminating
  double-allocation races between clients.
- Capability attenuation for files maps cleanly to the `grants` edge type
  in the type graph: each `grants` edge carries a `Rights` attribute that
  is monotonically restricted via `Rights::restrict()`.
- The FS server can enforce W^X on data blocks (no executable file data
  mapped as writable).

**Negative:**
- All I/O goes through the FS server, adding one IPC round-trip per
  operation compared to a direct-access exokernel model.
- The FS server becomes a potential bottleneck for I/O-heavy workloads.

**Neutral:**
- Future optimization: for trusted domains, the FS server could issue
  time-limited, read-only block capabilities for zero-copy reads (exokernel
  bypass). This is compatible with this ADR — it's an attenuation of the
  bulk cap, not a violation of the model.

## Alternatives Considered

### A. Per-inode block capabilities

Each inode SO would carry its own block range capability. Clients with
inode caps could read/write blocks directly.

**Rejected because:** This exposes the on-disk layout to clients, making
format changes impossible without updating all clients. It also allows a
compromised client to corrupt its own inode's metadata blocks (not just
data), since block-level access doesn't distinguish metadata from data
within the inode's block range.

### B. Hybrid: FS server for metadata, direct caps for data

Metadata blocks owned exclusively by FS server; data blocks accessible
via per-file capabilities.

**Deferred:** This is a valid optimization for Phase 6 (hardening). For
Phases 0-3, the simpler bulk-cap model is sufficient and easier to verify.
