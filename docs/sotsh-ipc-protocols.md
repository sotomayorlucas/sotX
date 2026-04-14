# sotsh IPC protocols — VFS + deception query (design)

Worker: B1.5-design. Scope: propose minimal sotOS-native IPC protocols that let
`services/sotsh/` reach init-owned resources (VFS + deception profile list).
No code in this PR. Downstream PRs (B1.5a-impl, B1.5d-impl, B2a, B2d) implement
what this doc decides.

## Part 0 — Common ground

### Existing IPC primitives

- `IpcMsg { tag: u64, regs: [u64; 8] }` — 72 B per message (`libs/sotos-common/src/lib.rs:519`).
  `tag` low 32 bits = opcode, high 32 bits reserved for cap-transfer ID.
  `regs` map to `rdx/r8/r9/r10/r12/r13/r14/r15` in the syscall ABI (`:516`).
- `sys::send / recv / call / call_timeout` — `lib.rs:992, :1018, :1056, :1096`.
- `sys::svc_register(name_ptr, name_len, ep_cap)` — `lib.rs:1657`.
- `sys::svc_lookup(name_ptr, name_len) -> ep_cap` — `lib.rs:1668`.
- Reference client-server: `services/sotfs/src/main.rs` — endpoint_create →
  svc_register("sotfs") → `recv` loop dispatching on `VfsOp::from_tag`
  (`main.rs:130-189`, `graph.rs:27-44`). Packs up to 56 data bytes into
  `regs[1..8]` on reply, 40 input bytes in `regs[3..8]` on write
  (`main.rs:216, :251`). This is the pattern we mirror.

### Payload size budget

One IpcMsg carries at most 8 u64 = **64 B of data**, minus opcode-defined
fields (e.g. stat reply occupies 5 regs, leaving 24 B free). Any payload
larger than 64 B (file contents, directory listings, stat structs when we
want the full Linux layout) needs multi-chunk transfer. We follow the
LUCAS socket-proxy convention (`services/init/src/child_handler.rs`
family, see MEMORY.md Phase 7): **≤ 40 B per send-chunk, ≤ 64 B per
recv-chunk**, loop until count consumed. Sotsh and init agree on a
4 KiB shared scratch page *optional enhancement*; for B2a we stick with
per-IpcMsg chunks (simpler, no extra mapping).

### Service naming

- `"vfs"` — init's VFS-IPC endpoint. 3 bytes, cheap to pass by pointer+len.
- `"deception"` — init's deception-query endpoint. 9 bytes.

### How sotsh obtains the caps

At REPL init (before the loop at `services/sotsh/src/main.rs:93`) sotsh
calls `svc_lookup("vfs")` and `svc_lookup("deception")` and stashes the
resulting endpoint caps in `Context` (`services/sotsh/src/context.rs`).
Same pattern every other native client uses
(`services/sot-launcher/src/main.rs:708`,
`services/sot-statusbar/src/main.rs:913`). Fallback, if sotsh turns out
not to have the SvcLookup syscall in its cap space: pass the two
endpoint caps via BootInfo slots (`BootInfo.cap_count`,
`libs/sotos-common/src/lib.rs:467`). See Part D q5.

## Part A — VFS-IPC protocol

### Goal

Let sotsh's `ls`, `cat`, `cd` builtins read directories, read files, and
change their own logical cwd without having to speak the Linux ABI.
Semantics mirror the POSIX-ish operations init already implements for
LUCAS (`services/init/src/syscalls/fs/vfs_open.rs:21`,
`vfs_read_write.rs:18`, `fs_dir.rs:17 / :254`).

### Tag space

Reuse the sotfs numbering where it overlaps (`services/sotfs/src/graph.rs:27`),
extend with sotsh-only ops. All tags fit in u32:

| tag | op                 | notes                          |
|----:|--------------------|--------------------------------|
| 1   | `VFS_OPEN`         | path + flags → fd (O_CREAT/O_TRUNC/O_APPEND honoured) |
| 2   | `VFS_CLOSE`        | fd → 0 / -errno                |
| 3   | `VFS_READ`         | fd, count → chunked data       |
| 5   | `VFS_STAT`         | path → inline stat fields      |
| 6   | `VFS_GETDENTS64`   | fd → chunked dirent stream     |
| 11  | `VFS_CHDIR`        | path → 0 / -errno (server-side cwd) |
| 12  | `VFS_FSTAT`        | fd → inline stat fields        |
| 13  | `VFS_WRITE`        | fd + chunk → bytes written (chunked) |

Replies use `tag = 0` on success or `tag = (neg errno as u64)` on
failure, exactly like sotfs (`main.rs:182, :236`). Errno constants from
`sotos_common::linux_abi` (ENOENT=-2, EBADF=-9, etc.).

### Per-client state

Init tracks, per connecting process (keyed by `sender_tid` recovered in
the recv handler):

- FD table (64 slots of `{ oid: u64, kind: u8, off: u64, dir_pos: u16 }`).
  Reuse `fd_ops.rs` structures; store in a `ClientState` map indexed by
  sotsh's pid.
- cwd: a 128-byte buffer, mirroring `GRP_CWD` (MEMORY.md Phase 10).

**Decision**: cwd lives **server-side** (in init). Sotsh is short-lived
and per-user; shipping cwd in every request bloats the tag space. Init
already owns the canonical per-group cwd machinery; reuse it.

### Path marshalling

Paths up to 48 B travel inline in `regs[0..6]` (6 × 8 = 48 B, NUL-padded,
len in `regs[7] low 32`). B2a's builtins (`ls /tmp`, `cat /etc/hostname`,
`cd ~`) all fit. Paths > 48 B → error `-ENAMETOOLONG` for now; add a
`VFS_PATH_CHUNK` continuation op if a future builtin needs it (see
Part D q3).

### Per-op layout

**`VFS_OPEN` (tag=1)**
- request: `regs[0..6] = path bytes (NUL-pad)`, `regs[6] = flags`,
  `regs[7] low32 = path_len`.
- reply: `tag=0`, `regs[0] = fd`, `regs[1] = kind` (13=file, 14=dir),
  `regs[2] = size` (for files). Error: `tag = -errno`.

**`VFS_CLOSE` (tag=2)**
- request: `regs[0] = fd`.
- reply: `tag=0` ok, else `-errno`.

**`VFS_READ` (tag=3)**
- request: `regs[0] = fd`, `regs[1] = max_bytes`.
- reply: `tag = bytes_returned` (0 = EOF, negative = errno),
  `regs[0..7] = up to 56 B of data` (LE-packed, same scheme as
  sotfs `handle_read` at `services/sotfs/src/main.rs:216-236`).
- Client loops until `bytes_returned < 56` or EOF.

**`VFS_GETDENTS64` (tag=6)**
- request: `regs[0] = fd`.
- reply: `tag = name_len` (0 = EOF, negative = errno),
  `regs[0] = inode / oid`, `regs[1] = kind`,
  `regs[2..7] = up to 40 B of name bytes`.
- One directory entry per round-trip; client calls repeatedly until
  `tag == 0`. Matches sotfs's `handle_readdir`
  (`services/sotfs/src/main.rs:287-318`). Slower than a bulk
  Linux-style blob but trivially correct and streams cleanly.

**`VFS_STAT` (tag=5) / `VFS_FSTAT` (tag=12)**
- request: path inline (stat) or `regs[0] = fd` (fstat).
- reply: `tag=0`, `regs[0] = size`, `regs[1] = mode`, `regs[2] = nlink`,
  `regs[3] = uid`, `regs[4] = gid`, `regs[5] = mtime`, `regs[6] = kind`.
  No need for the full 144-byte Linux stat here — sotsh's `ls -l` just
  needs size+mode+mtime. If a future builtin wants full stat, switch
  to a chunked reply.

**`VFS_CHDIR` (tag=11)**
- request: path inline.
- reply: `tag=0` ok, else `-errno`.

**`VFS_WRITE` (tag=13)**
- request: `regs[0] = fd`, `regs[1] = chunk_len` (≤ 48),
  `regs[2..8] = up to 48 B of data` (LE-packed, 6 × 8 = 48 B — mirrors
  the 40-B send chunk convention but uses one extra reg since no
  `max_bytes` return field is needed).
- reply: `tag = bytes_written` (non-negative) or `tag = -errno`.
  Short writes are permitted — client loops with successive chunks
  until all data is transmitted. On success the fd's file offset
  advances by the written bytes.
- `O_APPEND` semantics: if the fd was opened with `O_APPEND`, the server
  re-seeks to end-of-file before each write.
- `O_CREAT`/`O_TRUNC` are honoured at `VFS_OPEN` time: opening with
  `O_CREAT` creates a zero-length file if missing; `O_TRUNC` zeroes an
  existing file. These flags are ignored for directory opens.

### Flow example — `ls > out.txt`

```text
1. sotsh → call(vfs_ep, VFS_OPEN "/out.txt",
                         flags=O_WRONLY|O_CREAT|O_TRUNC)
   reply: tag=0, regs[0]=fd=7, regs[1]=13, regs[2]=0.

2. loop over 48-B chunks of rendered output:
     sotsh → call(vfs_ep, VFS_WRITE fd=7, len=N, data=…)
     reply: tag=N (bytes_written).
   until all bytes transmitted.

3. sotsh → call(vfs_ep, VFS_CLOSE fd=7)
   reply: tag=0.
```

### Flow example — `ls /tmp`

```text
1. sotsh → call(vfs_ep, IpcMsg { tag=1, regs=["/tmp",0,0,0,0,0,
                                               O_RDONLY|O_DIRECTORY, 4] })
   reply: tag=0, regs[0]=fd=5, regs[1]=14 (dir), regs[2]=0.

2. loop:
     sotsh → call(vfs_ep, IpcMsg { tag=6, regs=[5,0,0,0,0,0,0,0] })
     reply: tag=12, regs[0]=42, regs[1]=13,
            regs[2..]="hello.txt\0..."
   until reply.tag == 0 (EOF).

3. sotsh → call(vfs_ep, IpcMsg { tag=2, regs=[5,0,0,0,0,0,0,0] })
   reply: tag=0.
```

### Server placement

**Decision**: **new dedicated init thread** (`vfs_service_thread`), not a
branch of `lucas_handler`. Three reasons:

1. `lucas_handler` is Linux-ABI specific (syscall numbers, signal
   redirect, errno). Adding a sotOS-tag dispatch makes the state
   machine harder to read.
2. Some day LUCAS may be disabled; sotsh must still work.
3. Implementation is tiny: ~200 LOC, a recv loop that grabs
   `VFS_LOCK`, calls into the existing `sotos_objstore::Vfs`
   helpers (`services/init/src/main.rs:190-203`), reuses
   `resolve_with_cwd` (`vfs_open.rs:33`).

The thread owns its own endpoint, registered as `"vfs"`. Concurrency:
the `VFS_LOCK` spinlock already in use for cross-thread ObjectStore
access (`main.rs:188`). Per-client FD tables live in a small
`BTreeMap<pid, ClientFdTable>` protected by a separate
`VFS_CLIENT_LOCK`.

## Part B — Deception query IPC protocol

### Goal

The `arm` builtin (`services/sotsh/src/builtins/arm.rs`) currently hard-
codes four names. Replace with an IPC call that returns the same list
plus an `active` bit per profile.

### Current reality

`personality/common/deception/src/profile.rs` defines
`DeceptionProfile` (name, fake files, fake services), but there is **no
runtime registry** and no `CURRENT_PROFILE` global. The only runtime
user is `services/init/src/deception_demo.rs`, which builds one profile
inline and feeds it through `MigrationOrchestrator`. The
`ProfileRegistry::with_builtins()` referenced in
`personality/common/deception/src/profiles/mod.rs:4` is aspirational —
not yet implemented.

B1.5d-impl therefore has two halves:

1. **Add a minimal registry** to `sotos-deception`:
   ```rust
   pub struct ProfileRegistry { entries: [Entry; 4] }
   pub struct Entry { pub name: [u8; 32], pub active: bool }
   pub fn builtin_registry() -> ProfileRegistry { ... } // reads profiles/*
   ```
   Four profile names are known at compile time
   (`personality/common/deception/src/profiles/mod.rs:6-9`). `active`
   is false by default; `deception_demo.rs` flips the bit for
   `ubuntu-22.04-webserver` when it installs that profile.

2. **Expose it over IPC.**

### Tag space

| tag | op                      |
|----:|-------------------------|
| 1   | `DECEPTION_QUERY_ARMS`  |

### Layout

`DECEPTION_QUERY_ARMS` (tag=1)
- request: no args (`regs = [0; 8]`).
- reply: **multi-chunk**, one IpcMsg per profile. Each reply IpcMsg:
  - `tag = index` (0..3), or `tag = 0xFFFF_FFFF` = end-of-list marker.
  - `regs[0] = active` (0 or 1),
  - `regs[1..5] = name_bytes[0..32]` (4 × 8 = 32 B, NUL-padded).
  - `regs[5] = name_len` (≤ 32).
  - `regs[6..8] = 0` (reserved).

Four profiles × 1 IpcMsg each + 1 terminator = 5 round-trips. Packing
all 4 into one IpcMsg doesn't fit (4 × (1 + 32) = 132 B ≫ 64 B).

### Flow example — `arm`

```text
sotsh → call(decep_ep, IpcMsg { tag=1, regs=[0;8] })
reply: tag=0, regs[0]=0, regs[1..5]="ubuntu_webserver\0..", regs[5]=16
sotsh → call(decep_ep, IpcMsg { tag=1, regs=[0;8] })  // or reuse a "next" tag
reply: tag=1, regs[0]=0, ...
...
reply: tag=0xFFFFFFFF → end
```

Client loops calling `tag=1`; server returns entries in order and
tracks a per-client cursor.

### Server placement

**Decision**: **new tiny init thread** (`deception_service_thread`),
registered as `"deception"`. ~80 LOC. Rationale: matches the VFS
decision (symmetry), and keeps `sotos-deception` itself
dependency-free (no IPC machinery leaking into the personality crate).
The thread holds an owned `ProfileRegistry` via
`sotos_deception::builtin_registry()` and a per-client cursor map.

If that feels like one thread too many: Part D lists this as an open
question — one alternative is to multiplex `"vfs"` + `"deception"` on
a single "init-services" endpoint with a high-bit tag prefix.

## Part C — Implementation plan for downstream PRs

| PR           | Scope                                                     | Files touched                                                           | Est. LOC |
|--------------|-----------------------------------------------------------|-------------------------------------------------------------------------|---------:|
| B1.5a-impl   | VFS-IPC server thread + client wrapper                    | `services/init/src/{main.rs,vfs_service.rs}`, `libs/sotos-common/src/vfs_client.rs` (new) | ~450     |
| B1.5d-impl   | `ProfileRegistry` in sotos-deception + IPC server thread + client wrapper | `personality/common/deception/src/{lib.rs,profile.rs}`, `services/init/src/deception_service.rs`, `libs/sotos-common/src/deception_client.rs` (new) | ~250     |
| B2a          | Rewrite `ls`, `cat`, `cd` over the VFS client             | `services/sotsh/src/builtins/{ls,cat,cd}.rs`, `services/sotsh/src/context.rs` | ~200     |
| B2d          | Rewrite `arm` over the deception client                   | `services/sotsh/src/builtins/arm.rs`                                    | ~40      |

Ordering: B1.5a-impl and B1.5d-impl can land in parallel (disjoint
files). B2a depends on B1.5a-impl. B2d depends on B1.5d-impl.

## Part D — Open questions for user

Short list. Recommended answers in **bold**.

1. **Separate endpoints vs multiplex?** Recommend **separate** (`"vfs"`
   and `"deception"` each register). Multiplexing saves one thread but
   fuses two unrelated failure domains. Reject until we have data
   showing thread-count pressure.

2. **Where does cwd live?** Recommend **server-side** in init's
   per-client state. Matches existing `GRP_CWD` for LUCAS children and
   keeps sotsh stateless across builtins.

3. **Path chunking in v1?** Recommend **no — 48 B inline cap** is fine
   for B2a's builtins. Add chunking only when a builtin needs it.

4. **Full Linux stat vs compact?** Recommend **compact 7-field reply**
   for sotsh (size/mode/nlink/uid/gid/mtime/kind). Swap to a chunked
   full-stat op later if a builtin ever needs it.

5. **Does sotsh already have SvcLookup in its cap space?** Need one
   line of verification in init's spawn code before B1.5a-impl starts.
   If not, pass the two endpoint caps via BootInfo slots
   (`BootInfo.cap_count`, `sotos-common/src/lib.rs:467`). **Verify at
   start of B1.5a-impl**; default path is svc_lookup.
