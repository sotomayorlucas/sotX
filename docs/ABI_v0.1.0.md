# sotBSD ABI v0.1.0 — Frozen

**Status**: frozen for Sprint 3 (2026-04-07).
**Source of truth**: `libs/sotos-common/src/lib.rs::ABI_VERSION`.

This document enumerates every syscall, capability type, and on-wire
struct that first-party kernel and userspace components rely on. A
version bump is required before any of these can be renumbered,
reshuffled, or removed. Additive changes (new trailing syscall, new
trailing struct field) are allowed within a minor bump.

## Compatibility contract

- **Major bump (0.1 → 1.0)**: renumbering, struct layout changes, removed syscalls.
- **Minor bump (0.1 → 0.2)**: new syscalls appended, new optional ioctls, new error codes.
- **Patch bump (0.1.0 → 0.1.1)**: documentation only; no source change.

Third-party crates that link `sotos-common` should pin to
`ABI_VERSION = "0.1.x"` and read `libs/sotos-common/src/lib.rs` to
detect additive changes.

## Core capability syscalls (0–99)

| #  | Name              | Direction | Summary                                     |
|----|-------------------|-----------|---------------------------------------------|
| 1  | CapDup            | → kernel  | Dup a capability, get a fresh cap slot      |
| 2  | CapRevoke         | → kernel  | Revoke all derived caps of one cap          |
| 10 | Protect           | → kernel  | mprotect-like region attr change            |
| 20 | Map               | → kernel  | Map a frame cap into the current AS         |
| 24 | UnmapFree         | → kernel  | Unmap page and free physical frame          |
| 30 | FrameAlloc        | → kernel  | Allocate a fresh physical frame cap         |
| 40 | EndpointCreate    | → kernel  | Create a sync IPC endpoint                  |
| 41 | Recv              | → kernel  | Block until a message arrives on endpoint   |
| 42 | Send              | → kernel  | Non-blocking send                           |
| 43 | Call              | → kernel  | Send + wait for reply                       |

## Scheduler syscalls (100–149)

| #   | Name             | Summary                                             |
|-----|------------------|-----------------------------------------------------|
| 125 | AsClone          | CoW fork an address space                           |
| 130 | SvcRegister      | Register a service name → endpoint                  |
| 131 | SvcLookup        | Look up a service, get a derived endpoint cap       |
| 132 | InitrdRead       | Read a file out of the CPIO initrd                  |
| 133 | BootInfoWrite    | Write a BootInfo page into a target address space   |
| 134 | Protect          | mprotect-like, W^X enforced                         |
| 135 | CallTimeout      | IPC call with a tick timeout                        |
| 140 | ThreadInfo       | Read a thread's state / priority / ticks            |
| 141 | ResourceLimit    | Set CPU / memory limits                             |
| 142 | ThreadCount      | Total live thread count                             |

## TLS / signals / debug (150–199)

| #   | Name            | Summary                                              |
|-----|-----------------|------------------------------------------------------|
| 158 | ArchPrctl       | Linux-ABI TLS setup (intercepted by kernel redirect) |
| 160 | SetFsBase       | Set FS_BASE MSR                                      |
| 161 | GetFsBase       | Get FS_BASE MSR                                      |
| 172 | GetThreadRegs   | Read saved user regs of a blocked tid                |
| 173 | SignalEntry     | Set async signal trampoline addr for a thread cap    |
| 174 | SignalInject    | Set a pending signal bit on a tid                    |

## Personality ABI (300–349)

| #   | Name                  | Summary                                          |
|-----|-----------------------|--------------------------------------------------|
| 300 | SotProvenanceDrain    | Drain the kernel provenance ring                 |
| 301 | SotProvenanceEmit     | Emit a provenance record                         |
| 302 | SotProvenanceStats    | Read counters for dropped / emitted records      |
| 310 | SotTxPrepare          | 2-phase commit prepare                           |
| 311 | SotTxCommit           | 2-phase commit commit                            |

## Linux personality (via `linux_abi` module)

The full list lives in `libs/sotos-common/src/linux_abi.rs::SYS_*`.
At v0.1.0 we guarantee 198 SYS_* constants and 127 match arms in
`child_handler`. See `MEMORY.md::Phase 9` for the invariant.

## IPC message layout

```
#[repr(C)]
pub struct IpcMsg {
    pub tag: u64,
    pub regs: [u64; 8],
    pub caps: [u64; 4],
}
```

- `tag` is the opcode namespace for the receiving service.
- `regs[0..8]` carries inline data (64 bytes).
- `caps[0..4]` carries capability handles (transferred, not copied).

Services agree on tag semantics per service; the kernel does not
interpret `tag`.

## Address space layout (process)

| Range                | Content                                    |
|----------------------|--------------------------------------------|
| 0x00200000           | process .text / .rodata (static ET_EXEC)   |
| 0x00900000–0x00A00000| stack (256K)                               |
| 0x00B00000           | BootInfo page (read-only from kernel)      |
| 0x00B80000           | vDSO page (R+X)                            |
| 0x02000000           | brk heap (1 MiB initial)                   |
| 0x03000000           | mmap region                                |
| 0x06000000           | INTERP_LOAD_BASE (ld-musl / ld-linux)      |

Any component that allocates virtual memory outside these ranges is
**not** covered by the ABI freeze.

## Frozen constants

- `sotos_common::ABI_VERSION = "0.1.0"`
- `sotos_common::IpcMsg` size = 72 bytes (tag + 8*u64 + 4*u64)
- `sotos_common::MAX_CPUS = 8`
- `sotos_common::KB_RING_ADDR = 0x510000`
- `sotos_common::MOUSE_RING_ADDR = 0x520000`

## What is *not* frozen

- Internal kernel APIs (`kernel/src/*`)
- Experimental personality crates under `personality/` (still 0.0.x)
- The `sot-cheri` software CHERI model (PANDORA T4 experimental)
- Any syscall number `>= 400`
