# SOT Exokernel Specification

## 1. Overview

SOT (Secure Object Transactional) is the kernel interface of sotBSD. It exposes
five primitive object types and 11 syscalls. All higher-level abstractions
(files, sockets, processes, device drivers) are built in userspace using these
primitives.

The design follows the exokernel principle: the kernel multiplexes hardware
and enforces isolation; applications choose their own abstractions.

---

## 2. Secure Objects (SO)

A Secure Object is the fundamental unit of storage and transfer in SOT.

### 2.1 Definition

An SO is an opaque, typed, variable-length blob managed by the kernel. SOs
have no inherent semantics -- the kernel stores and retrieves bytes. Meaning
is imposed by userspace through type tags and protocol conventions.

### 2.2 Properties

| Property | Value |
|----------|-------|
| Maximum size | 2^48 bytes (256 TiB, limited by physical memory) |
| Type tag | 16-bit, assigned at creation, immutable |
| Identity | 64-bit kernel-assigned OID, unique for the SO's lifetime |
| Epoch | 32-bit monotonic counter, incremented on revocation |
| Persistence | Volatile by default; persistent if backed by WAL-enabled store |

### 2.3 Operations

All SO operations require a capability with appropriate rights.

```
so_create(type: u16, size: u64) -> Result<Cap, Error>
so_read(cap: Cap, offset: u64, len: u64, buf: *mut u8) -> Result<u64, Error>
so_write(cap: Cap, offset: u64, len: u64, buf: *const u8) -> Result<u64, Error>
so_destroy(cap: Cap) -> Result<(), Error>
```

---

## 3. Capability System

### 3.1 Capability Structure

```
Capability {
    object_id:  u64      // Target SO, Channel, or Domain
    rights:     u32      // Bitmask (READ|WRITE|EXEC|GRANT|REVOKE)
    epoch:      u32      // Creation epoch (stale if < object.current_epoch)
    cdt_parent: u32      // PoolHandle of parent capability (0 = root)
}
```

Capabilities are stored in a kernel-managed pool with generation-checked
handles (`PoolHandle`). Userspace sees opaque 32-bit identifiers:

```
CapId = PoolHandle = generation[31:20] | index[19:0]
```

A stale handle (generation mismatch) is rejected with `InvalidCap`.

### 3.2 Rights Bitmask

```
READ    = 0x01    // so_read, chan_recv
WRITE   = 0x02    // so_write, chan_send
EXECUTE = 0x04    // domain_enter
GRANT   = 0x08    // cap_derive
REVOKE  = 0x10    // cap_revoke
ALL     = 0x1F
```

### 3.3 Derivation (Attenuation)

```
cap_derive(src_cap: Cap, rights_mask: u32) -> Result<Cap, Error>
```

Preconditions:
- `src_cap` must be alive (epoch check passes).
- `src_cap` must have the GRANT right.
- The new capability's rights are `src_cap.rights & rights_mask`.
  Rights can only decrease through derivation.

The new capability is a child of `src_cap` in the CDT.

**Monotonicity invariant** (TLA+ verified): for any capability `c` with
parent `p`, `c.rights` is a subset of `p.rights`.

### 3.4 Revocation

```
cap_revoke(cap: Cap) -> Result<(), Error>
```

Preconditions:
- `cap` must be alive.
- `cap` must have the REVOKE right.

Semantics:
- Increments the target object's `current_epoch`.
- All capabilities with `epoch < current_epoch` become stale.
- Stale capabilities are rejected on any subsequent operation.

This provides O(1) revocation of entire capability subtrees. The CDT
structure is preserved for provenance queries.

**Completeness invariant** (TLA+ verified): if capability `c` is revoked,
every descendant of `c` in the CDT is also effectively revoked.

### 3.5 Interposition

```
cap_interpose(target_cap: Cap, handler_domain: Cap) -> Result<Cap, Error>
```

Creates a new capability that redirects all operations to the handler
domain. The handler receives an IPC message describing the operation
and can respond with any of four policies:

| Policy | Behavior |
|--------|----------|
| Passthrough | Forward to real object, return real result |
| Inspect | Log operation, then forward |
| Redirect | Forward to a different object |
| Fabricate | Return synthetic result without touching any real object |

Interposition is transparent to the holder of the interposed capability.

---

## 4. Channels

Channels are unidirectional typed communication pipes.

### 4.1 Synchronous Channels (Endpoints)

L4-style rendezvous IPC. Sender blocks until receiver is ready (and vice
versa). Messages are transferred in registers during context switch -- zero
memory overhead.

```
chan_send(cap: Cap, msg: &Message) -> Result<(), Error>
chan_recv(cap: Cap, buf: &mut Message) -> Result<(), Error>
```

Message format:
```
Message {
    tag:  u64        // Lower 32 bits = user tag, upper 32 = cap transfer
    regs: [u64; 8]   // Payload (64 bytes)
}
```

### 4.2 Asynchronous Channels

Bounded ring buffers for high-throughput data transfer. Non-blocking when
the ring is not full/empty; notification-based wake on transitions.

### 4.3 Shared-Memory Channels (SPSC)

Lock-free single-producer single-consumer rings in userspace shared memory.
Zero syscalls on the hot path. The kernel is only involved for blocking
(notify_wait) and waking (notify_signal) on empty/full transitions.

SPSC ring layout (one 4 KiB page):
```
Offset   Field           Size
0x000    head (aligned)  64 bytes (cache line)
0x040    tail (aligned)  64 bytes (cache line)
0x080    reserved        64 bytes
0x0C0    slots[128]      1024 bytes (128 x u64)
```

---

## 5. Transactions

### 5.1 Overview

Transactions provide atomicity for state-mutating operations on Secure
Objects. Three tiers accommodate different consistency/performance
trade-offs.

### 5.2 Tier 0: Implicit Single-Operation

Every individual `so_read` or `so_write` is atomic with respect to
concurrent accessors. No explicit transaction handle is needed.

**Overhead target**: < 100 ns.

### 5.3 Tier 1: Single-Object Multi-Operation

For read-modify-write sequences on a single SO. The caller acquires a
transaction handle, performs multiple operations, and commits atomically.

```
tx = tx_begin(so_cap)
so_read(so_cap, ...)     // reads see pre-transaction state
so_write(so_cap, ...)    // writes are buffered
tx_commit(tx)            // all writes become visible atomically
```

On abort (explicit or domain death), all buffered writes are discarded.
Implemented via per-object WAL (Write-Ahead Log).

**Overhead target**: < 1 us.

### 5.4 Tier 2: Multi-Object

Atomic updates across multiple SOs. Uses two-phase commit with the kernel
as coordinator.

```
tx = tx_begin_multi([cap_a, cap_b])
so_write(cap_a, ...)
so_write(cap_b, ...)
tx_commit(tx)            // both writes visible atomically, or neither
```

**Overhead target**: < 10 us.

### 5.5 Rollback Semantics

- Tier 0: no rollback (single atomic operation).
- Tier 1: WAL replay discards uncommitted writes.
- Tier 2: two-phase abort rolls back all participants.

The WAL entries are themselves SOs, so rollback operations generate
provenance entries.

---

## 6. Provenance

### 6.1 Entry Format

```
ProvenanceEntry {
    timestamp:    u64       // TSC cycle counter
    cpu:          u8        // Originating CPU core
    domain_id:    u32       // Acting domain
    operation:    u16       // OpCode enum
    subject_id:   u64       // Primary object OID
    args:         [u64; 4]  // Operation-specific data
    parent_hash:  [u8; 32]  // SHA-256 link to causal parent
}
```

### 6.2 Operation Codes

| OpCode | Operation |
|--------|-----------|
| 0x01 | so_create |
| 0x02 | so_read |
| 0x03 | so_write |
| 0x04 | so_destroy |
| 0x10 | cap_derive |
| 0x11 | cap_revoke |
| 0x12 | cap_interpose |
| 0x20 | chan_send |
| 0x21 | chan_recv |
| 0x30 | domain_enter |
| 0x31 | domain_yield |
| 0x40 | tx_commit |
| 0x41 | tx_abort |

### 6.3 Collection Architecture

```
CPU 0: [kernel syscall path] ---> [SPSC ring 0] ---> [aggregator thread]
CPU 1: [kernel syscall path] ---> [SPSC ring 1] ---|        |
CPU 2: [kernel syscall path] ---> [SPSC ring 2] ---|        v
CPU 3: [kernel syscall path] ---> [SPSC ring 3] ---|  [DAG builder]
                                                          |
                                                    [persistent log]
```

### 6.4 Guarantees

- **Completeness**: every cap_derive, so_write, chan_send, domain_enter,
  and tx_commit generates exactly one entry.
- **Per-CPU total order**: entries from one CPU are strictly ordered by TSC.
- **Causal ordering**: cross-CPU causality is captured by hash links.
- **Tamper evidence**: modifying any entry invalidates its hash chain.

---

## 7. Domain Lifecycle

### 7.1 States

```
         create
  [empty] -----> [ready]
                   |  ^
           enter   |  | yield / preempt
                   v  |
                [active]
                   |
           destroy |
                   v
                [dead]
```

### 7.2 Creation

```
domain_create(quantum_ms: u32, period_ms: u32) -> Result<Cap, Error>
```

Allocates:
- Empty CSpace (capability table).
- Empty AS (page tables, CR3).
- Scheduling context with the given budget.

Returns a capability to the new domain with ALL rights.

### 7.3 Entry

```
domain_enter(cap: Cap) -> Result<(), Error>
```

Preconditions:
- `cap` must have EXECUTE right.
- The domain must be in `ready` or `active` state.

Semantics:
- Switches CR3 to the domain's page tables.
- Switches CSpace to the domain's capability table.
- Activates the domain's scheduling context.
- Begins execution at the domain's entry point.

### 7.4 Suspension

When a domain's scheduling quantum expires:
1. All threads in the domain are moved to a suspended list.
2. The domain transitions to `ready` state.
3. At the start of the next period, the budget is refilled.
4. Suspended threads are re-enqueued as `ready`.

### 7.5 Destruction

```
domain_destroy(cap: Cap) -> Result<(), Error>
```

1. Kills all threads in the domain.
2. Revokes all capabilities in the CSpace.
3. Frees all frames in the AS.
4. Deallocates the scheduling context.

---

## 8. Error Model

SOT uses a fail-stop error model for security-critical errors.

### 8.1 Error Codes

| Code | Name | Meaning |
|------|------|---------|
| 1 | InvalidCap | Capability does not exist or is stale (epoch mismatch) |
| 2 | InsufficientRights | Capability exists but lacks required rights |
| 3 | InvalidArg | Argument out of range or malformed |
| 4 | OutOfResources | No free slots in pool, no free frames |
| 5 | WouldBlock | Non-blocking operation would need to wait |
| 6 | TxAborted | Transaction was rolled back |
| 7 | DomainDead | Target domain has been destroyed |

### 8.2 Fail-Stop Behavior

Invalid capability operations (code 1 or 2) terminate the calling domain.
This prevents probing attacks where an adversary systematically tests
capability IDs to discover valid handles.

The rationale: a well-behaved domain never presents an invalid capability.
Invalid caps indicate either a bug or an attack. In both cases, termination
is the safe response.

### 8.3 Recovery

Domain termination generates a provenance entry and notifies the domain's
parent (via a registered notification capability). The parent can inspect
the provenance trail and decide whether to restart the domain.

---

## 9. Syscall ABI

### 9.1 Calling Convention

SOT syscalls use `SYSCALL`/`SYSRET` with the following register mapping:

| Register | Purpose |
|----------|---------|
| RAX | Syscall number (0-10) |
| RDI | Argument 1 / capability ID |
| RSI | Argument 2 |
| RDX | Argument 3 |
| R10 | Argument 4 |
| R8 | Argument 5 |
| R9 | Argument 6 |
| RAX (return) | Result (positive = success, negative = -Error) |

### 9.2 Complete Syscall Table

| # | Name | RDI | RSI | RDX | R10 | R8 | R9 | Returns |
|---|------|-----|-----|-----|-----|----|----|---------|
| 0 | so_create | type | size | -- | -- | -- | -- | cap_id |
| 1 | so_read | cap | offset | len | buf_ptr | -- | -- | bytes_read |
| 2 | so_write | cap | offset | len | buf_ptr | -- | -- | bytes_written |
| 3 | so_destroy | cap | -- | -- | -- | -- | -- | 0 |
| 4 | cap_derive | src_cap | rights_mask | -- | -- | -- | -- | new_cap_id |
| 5 | cap_revoke | cap | -- | -- | -- | -- | -- | 0 |
| 6 | chan_send | cap | msg_ptr | -- | -- | -- | -- | 0 |
| 7 | chan_recv | cap | buf_ptr | -- | -- | -- | -- | msg_len |
| 8 | domain_enter | cap | -- | -- | -- | -- | -- | 0 |
| 9 | domain_yield | -- | -- | -- | -- | -- | -- | 0 |
| 10 | tx_commit | tx_handle | -- | -- | -- | -- | -- | 0 or -Error |

---

## 10. Implementation Notes

### 10.1 Current State

The SOT specification describes the target design. The current sotOS/sotBSD
kernel implements the capability system (with CDT and generation-checked
handles), synchronous and asynchronous IPC, scheduling domains, and frame
allocation. The transaction engine and provenance system are specified but
not yet fully implemented in code.

### 10.2 Compatibility Bridge

To support existing POSIX and Linux binaries, the kernel also implements
a set of compatibility syscalls (numbers 20-302) that are intercepted and
redirected to userspace servers (LUCAS, LKL) via IPC endpoint forwarding.
These compatibility syscalls are not part of the SOT specification proper;
they are a transitional mechanism that will be replaced by pure userspace
personality servers.

### 10.3 Formal Verification

The capability system, scheduler, and IPC protocol are modeled in TLA+
(see `formal/`). The models verify safety properties including:

- No unauthorized access (capabilities checked on every operation)
- Monotonic rights (derivation never increases rights)
- Revocation completeness (revoking a cap invalidates all descendants)
- No message duplication or loss in IPC
- Mutual exclusion (each CPU runs exactly one thread)
- No starvation (every ready thread eventually runs)
