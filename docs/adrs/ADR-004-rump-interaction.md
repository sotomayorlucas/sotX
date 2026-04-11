# ADR-004: Rump Kernel Interaction

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** Lucas Sotomayor  

## Context

sotBSD uses NetBSD rump kernels for POSIX compatibility. The rump adaptation
layer (`docs/RUMP_ADAPTATION.md`) maps rump hypercalls to sotOS IPC:

- `rumpuser_bio(dev, blkno, data, len, flags)` → `chan_send(blk_driver_cap, ...)`
- The rump VFS layer provides standard `mount`, `lookup`, `read`, `write` etc.

sotFS must coexist with the existing FFS (Fast File System) that rump already
supports. The question is how sotFS integrates with the rump VFS layer.

## Decision

**sotFS registers as `FsType::SotFs` in the VFS mount table**, alongside the
existing filesystem types. Rump accesses sotFS through the standard
`rumpuser_bio` IPC path.

Concretely:

1. The `FsType` enum in `personality/bsd/vfs/src/mount.rs` gains a new variant:
   ```rust
   pub enum FsType {
       Tmpfs,
       Ffs,
       Zfs,
       Devfs,
       Procfs,
       SotFs,  // <-- new
   }
   ```

2. When `mount -t sotfs /dev/sd0 /data` is issued, the VFS mount table creates
   a `MountEntry` with `fs_type: FsType::SotFs` and `backend_cap` pointing to
   the sotFS server domain's IPC endpoint.

3. The sotFS server receives block I/O requests through the same `rumpuser_bio`
   IPC channel used by FFS. Internally, it translates these into graph
   operations (DPO rule applications via GTXN).

4. For POSIX callers, sotFS looks like any other mounted filesystem. The VFS
   path resolution in `personality/bsd/vfs/src/lookup.rs` handles the mount
   point prefix matching transparently.

## Consequences

**Positive:**
- Zero changes to the rump hypercall interface — existing rump code works
  unmodified.
- Gradual migration path: boot from FFS root, mount sotFS on `/data` or
  `/experiments`, eventually make sotFS the root filesystem.
- Standard POSIX tools (ls, cat, git, cargo) work on sotFS mounts without
  modification, because the VFS layer handles the translation.
- The VFS `MountTable` already supports up to 64 concurrent mount points
  with longest-prefix matching, so sotFS mounts compose naturally with
  other filesystem types.

**Negative:**
- The `rumpuser_bio` path adds latency compared to a native sotFS IPC
  protocol: rump VFS → rumpuser_bio → IPC → sotFS server. For
  performance-critical paths, native clients can bypass rump and talk
  directly to the sotFS server endpoint (see ADR-002: clients get
  attenuated inode-SO capabilities).
- sotFS's advanced features (explicit transactions, graph queries,
  curvature monitoring) are not accessible through the POSIX/rump
  interface — they require the native API (Phase 3, objective 3.6).

**Neutral:**
- The rump VFS layer already handles the POSIX → VfsOp translation (14
  operations defined in `personality/bsd/vfs/src/lib.rs:64-79`). Each
  VfsOp maps to one or more DPO rules in the sotFS server. This mapping
  is documented in Appendix A of the design document.

## Alternatives Considered

### A. Replace rump VFS entirely with sotFS

Make sotFS the only filesystem layer, removing rump's VFS.

**Rejected because:** This would break compatibility with all existing
NetBSD-based tools and libraries that depend on the rump VFS interface.
sotFS should coexist with FFS during the transition period (Phases 2-3).

### B. Implement sotFS as a rump kernel component

Run sotFS inside the rump kernel's address space rather than as a
separate sotOS domain.

**Rejected because:** This would place the graph rewriting engine and
GTXN logic inside the rump kernel, making it harder to verify formally
(rump code is C, not Rust) and violating the principle that sotFS is a
capability-isolated userspace server.
