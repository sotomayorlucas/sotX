# Formal Verification Approach

## 1. Overview

sotX aims to provide mathematical guarantees about its security properties.
The verification strategy uses a layered approach: TLA+ model checking for
protocol-level properties, with a roadmap to Rust-level proofs via Verus/Kani.

---

## 2. TLA+ Specifications

Three TLA+ specifications model the core kernel subsystems. These are located
in the `formal/` directory and can be checked with the TLC model checker.

### 2.1 Capability System (`formal/capabilities.tla`)

Models the capability table, derivation, and revocation.

**State variables**:
- `caps`: sequence of capability entries (object, rights, parent, alive)
- `nextId`: next slot to allocate
- `accesses`: set of (capId, object, operation) access records

**Actions**:
- `CreateRoot(obj, rights)`: allocate a new root capability
- `Grant(srcId, mask)`: derive a child capability with restricted rights
- `Revoke(id)`: revoke a capability and all descendants (transitive closure)
- `Access(capId, operation)`: attempt an operation using a capability

**Properties verified**:

| Property | Type | Statement |
|----------|------|-----------|
| NoUnauthorizedAccess | Safety | Every access record corresponds to an alive capability with the required right |
| MonotonicRights | Safety | A derived capability's rights are a subset of its parent's rights |
| RevocationComplete | Safety | If a parent capability is dead, all its descendants are dead |

### 2.2 Scheduler (`formal/scheduler.tla`)

Models the preemptive priority scheduler with per-core run queues and
work stealing.

**State variables**:
- `threadState`: function Thread -> {ready, running, blocked, dead}
- `priority`: function Thread -> 0..MaxPriority
- `runQueues`: function CPU -> sequence of threads
- `running`: function CPU -> thread or NULL
- `ticks`, `timeslice`: per-thread counters
- `totalTicks`: global tick counter

**Actions**:
- `Enqueue(cpu, thread)`: add a ready thread to a CPU's run queue
- `Schedule(cpu)`: pick next thread from run queue, start executing
- `Tick(cpu)`: decrement timeslice, preempt if expired
- `WorkSteal(thief, victim)`: steal oldest thread from victim's queue
- `Block(cpu)`: running thread voluntarily blocks
- `Wake(thread, cpu)`: unblock a thread and enqueue it

**Properties verified**:

| Property | Type | Statement |
|----------|------|-----------|
| MutualExclusion | Safety | Each CPU runs at most one thread |
| SingleExecution | Safety | A thread runs on at most one CPU |
| QueueConsistency | Safety | Every thread in a run queue is in "ready" state |
| NoStarvation | Liveness | Every ready thread eventually runs (under fairness) |

### 2.3 IPC Protocol (`formal/ipc.tla`)

Models the synchronous rendezvous IPC mechanism (endpoints).

**State variables**:
- `state`: endpoint state (idle, recv_wait, send_wait)
- `receiver`: waiting receiver thread
- `sendQueue`: sequence of waiting senders
- `caller`: thread waiting for call reply
- `delivered`: set of (sender, receiver, message) delivery records

**Actions**:
- `Send(thread, msg)`: send a message (rendezvous or block)
- `Recv(thread)`: receive a message (rendezvous or block)
- `Call(thread, msg)`: combined send+wait-for-reply

**Properties verified**:

| Property | Type | Statement |
|----------|------|-----------|
| NoDoubleDel | Safety | No message is delivered twice |
| SingleReceiver | Safety | At most one receiver waits at any time |
| BlockedInQueue | Safety | Every send-blocked thread is in the send queue |

---

## 3. Model Checking Parameters

### 3.1 State Space Configuration

The TLC model checker explores all reachable states from the initial
configuration. The parameters used for checking:

| Specification | Threads | CPUs | MaxCaps / MaxQueue | States Explored |
|---------------|---------|------|--------------------|-----------------|
| capabilities.tla | -- | -- | MaxCaps=6, Objects={o1,o2,o3} | ~10^6 |
| scheduler.tla | 4 | 2 | Timeslice=3 | ~10^7 |
| ipc.tla | 3 | -- | MaxQueueLen=3 | ~10^5 |

### 3.2 Running the Model Checker

```bash
# Install TLA+ tools
# Option 1: TLA+ Toolbox (GUI)
# Option 2: tla2tools.jar (CLI)

# Check capabilities specification
java -jar tla2tools.jar -config capabilities.cfg formal/capabilities.tla

# Check scheduler specification
java -jar tla2tools.jar -config scheduler.cfg formal/scheduler.tla

# Check IPC specification
java -jar tla2tools.jar -config ipc.cfg formal/ipc.tla
```

### 3.3 Interpreting Results

TLC reports:
- Number of distinct states explored.
- Whether any property was violated (with a counterexample trace).
- Deadlock detection (states with no enabled actions).

A clean run (no violations, no deadlocks) provides confidence that the
modeled properties hold for all states reachable from the initial
configuration with the given parameters.

---

## 4. Future: Rust-Level Proofs

### 4.1 Verus Integration

Verus is a tool for verifying Rust code using SMT solvers. The roadmap
for Verus integration:

**Phase 1: Capability Table**

Annotate `kernel/src/cap/table.rs` with Verus pre/post-conditions:

```rust
#[verus::proof]
fn insert_preserves_monotonicity(
    table: &CapabilityTable,
    src: CapId,
    mask: Rights,
) {
    // Prove: derived cap's rights are subset of source's rights
    ensures(|new_cap| new_cap.rights.is_subset_of(table.lookup(src).rights));
}
```

Target properties:
- `cap_derive` never increases rights (monotonicity).
- `cap_revoke` invalidates all descendants (completeness).
- Generation checks reject stale handles (ABA safety).

**Phase 2: Frame Allocator**

Annotate `kernel/src/mm/frame.rs`:

```rust
#[verus::proof]
fn alloc_never_double_allocates(allocator: &FrameAllocator) {
    // Prove: if frame F is returned by alloc(), F was not already allocated
    ensures(|frame| !allocator.is_allocated(frame));
}
```

Target properties:
- No double allocation (same frame returned twice without intervening free).
- No use-after-free (freed frame is not accessible until re-allocated).
- Bitmap consistency (bit set iff frame is allocated).

**Phase 3: IPC Message Integrity**

Annotate `kernel/src/ipc/endpoint.rs`:

```rust
#[verus::proof]
fn send_recv_preserves_message(endpoint: &Endpoint, msg: &Message) {
    // Prove: received message equals sent message (no corruption)
    ensures(|received| received == msg);
}
```

### 4.2 Kani Integration

Kani is a model checker for Rust that uses bounded model checking via
CBMC. It is complementary to Verus: Kani finds bugs automatically (no
annotations needed), while Verus proves properties hold for all inputs.

Target use cases:
- **Syscall dispatch**: verify that every syscall number maps to the
  correct handler (no off-by-one, no missing cases).
- **Pool allocator**: verify that alloc/free sequences never corrupt
  the free list.
- **Context switch**: verify that register save/restore preserves all
  callee-saved registers.

```rust
#[kani::proof]
fn pool_alloc_free_roundtrip() {
    let mut pool: Pool<u64> = Pool::new();
    let handle = pool.alloc(42).unwrap();
    assert_eq!(pool.get(handle), Some(&42));
    pool.free(handle);
    assert_eq!(pool.get(handle), None); // stale handle rejected
}
```

---

## 5. Category Theory Foundations

The formal model has a category-theoretic interpretation that provides
a unified framework for reasoning about the system.

### 5.1 Categories

| Category | Objects | Morphisms |
|----------|---------|-----------|
| **SO** | Secure Objects | Capability-mediated operations |
| **Dom** | Domains | Domain transitions (enter/yield) |
| **Chan** | Channels | Message send/receive |
| **Tx** | Transactions | Commit/abort |
| **Prov** | Provenance entries | Causal links (hash pointers) |

### 5.2 Functors

The system's components are related by functors (structure-preserving maps):

- **Access functor** `A: SO -> Dom`: maps each SO to the set of domains
  that hold capabilities to it. Preserving structure means: if domain D
  can access object O, and O is linked to O' by a transaction, then D's
  view is consistent across both objects.

- **Provenance functor** `P: (SO + Dom + Chan + Tx) -> Prov`: maps every
  operation in any category to a provenance entry. This functor is
  faithful (injective on morphisms): distinct operations produce distinct
  provenance entries.

- **Deception functor** `D: SO -> SO`: maps "real" objects to "fabricated"
  objects. Interposition is a natural transformation from the identity
  functor to the deception functor. The consistency engine ensures D is
  a valid functor (preserves composition and identity).

### 5.3 Properties as Natural Transformations

Key security properties can be expressed as natural transformations:

- **Monotonicity**: the rights map `R: Cap -> Rights` is a natural
  transformation that is monotone with respect to the derivation order.
  For any morphism (derivation) `f: c1 -> c2`, `R(c2) <= R(c1)`.

- **Completeness**: revocation is a natural transformation from the
  CDT endofunctor to the "dead" constant functor. If the transformation
  is applied at node N, it is applied at all descendants of N.

### 5.4 Future Work

The category-theoretic framework is currently informal. Future work
includes:

1. Formalize the categories and functors in a proof assistant (Agda, Lean 4).
2. Prove that the deception functor preserves the consistency rules.
3. Prove that the provenance functor is faithful (no information loss).
4. Use the categorical framework to derive new security properties
   compositionally (e.g., composition of deception with transactions).

---

## 6. Verification Roadmap

| Phase | Tool | Target | Status |
|-------|------|--------|--------|
| 1 | TLA+ / TLC | Capability system | Specified, properties verified |
| 2 | TLA+ / TLC | Scheduler | Specified, properties verified |
| 3 | TLA+ / TLC | IPC protocol | Specified, properties verified |
| 4 | Verus | Capability table (Rust) | Planned |
| 5 | Verus | Frame allocator (Rust) | Planned |
| 6 | Kani | Syscall dispatch | Planned |
| 7 | Kani | Pool allocator | Planned |
| 8 | Lean 4 / Agda | Category theory formalization | Research |
