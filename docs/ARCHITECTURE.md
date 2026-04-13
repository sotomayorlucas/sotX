# sotX Architecture

## 1. Vision: A Fourth-Generation Operating System

sotX is an adversary-aware operating system designed for hostile environments.
It combines a verified exokernel with capability-based security, transactional
storage, mandatory provenance, and a deception engine that can present arbitrary
OS personalities to untrusted code.

### Generational Framing

| Generation | Era | Defining Property | Examples |
|------------|-----|-------------------|----------|
| 1st | 1960s-1970s | Multiprogramming, time-sharing | CTSS, Multics, early UNIX |
| 2nd | 1980s-1990s | Microkernel isolation, formal IPC | Mach, L4, QNX |
| 3rd | 2000s-2010s | Capability security, verified kernels | seL4, CHERI, Capsicum |
| 4th | 2020s- | Adversary-aware: deception, provenance, live personality switching | **sotX** |

A 4th-generation OS assumes the adversary has already achieved code execution
inside a domain. The question is not "can we prevent compromise?" but "can we
detect, contain, and deceive the adversary while maintaining a complete audit
trail?" sotX answers yes through three pillars:

1. **Capability confinement** -- no ambient authority, no escalation path.
2. **Mandatory provenance** -- every IPC message, every capability operation
   is recorded in a tamper-evident DAG.
3. **Active deception** -- capability interposition can fabricate an entire
   OS personality (Ubuntu, FreeBSD, Windows) around a compromised domain.

---

## 2. The SOT Exokernel

SOT stands for **Secure Object Transactional**. The kernel is an exokernel in
the Engler/Kaashoek tradition: it multiplexes hardware resources and enforces
isolation, but delegates all policy and abstraction to userspace.

### 2.1 Five Primitives

The SOT kernel exposes exactly five primitive object types. Everything else --
files, sockets, processes, device drivers -- is built in userspace.

| Primitive | Kernel Object | Purpose |
|-----------|---------------|---------|
| **SO** (Secure Object) | Opaque typed blob | Unit of storage and transfer |
| **Cap** (Capability) | Rights + epoch + CDT node | Access control token |
| **Domain** | CSpace + AS + scheduling context | Isolation boundary |
| **Channel** | Unidirectional typed pipe | IPC and data flow |
| **Tx** (Transaction) | Atomic operation group | Consistency and rollback |

### 2.2 Syscall Interface

The kernel exposes 11 syscalls. All other "system calls" are IPC messages to
userspace servers.

| # | Name | Arguments | Returns | Semantics |
|---|------|-----------|---------|-----------|
| 0 | `so_create` | type, size | cap | Allocate a Secure Object, return capability |
| 1 | `so_read` | cap, offset, len, buf | bytes_read | Read from SO via capability |
| 2 | `so_write` | cap, offset, len, buf | bytes_written | Write to SO via capability |
| 3 | `so_destroy` | cap | -- | Destroy SO, revoke all derived caps |
| 4 | `cap_derive` | src_cap, rights_mask | new_cap | Derive attenuated capability |
| 5 | `cap_revoke` | cap | -- | Epoch-bump revocation of cap and all descendants |
| 6 | `chan_send` | cap, msg | -- | Send typed message on channel |
| 7 | `chan_recv` | cap, buf | msg | Receive typed message from channel |
| 8 | `domain_enter` | cap | -- | Switch execution to target domain |
| 9 | `domain_yield` | -- | -- | Yield scheduling quantum |
| 10 | `tx_commit` | tx_handle | result | Commit or abort a transaction group |

### 2.3 Design Principles

- **Nothing in Ring 0 that can live in Ring 3.** If it does not require
  privilege (page tables, MSRs, interrupt routing), it runs in userspace.
- **No ambient authority.** Every operation requires an explicit capability.
  There is no superuser, no UID 0, no implicit permission.
- **Fail-stop on invalid capabilities.** A bad cap kills the calling domain,
  not the kernel.
- **Deterministic resource accounting.** Every frame, every cycle, every IPC
  slot is accounted to a domain's budget.

---

## 3. Capability Model

### 3.1 Capability Structure

A capability is a protected reference to a kernel object:

```
struct Capability {
    object_id: u64,         // Which kernel object
    rights: Rights,         // Bitmask: READ | WRITE | EXEC | GRANT | REVOKE
    epoch: u32,             // Revocation epoch (invalid if < object's epoch)
    cdt_parent: Option<CapId>, // Parent in the Capability Derivation Tree
}
```

### 3.2 Rights

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | READ | Can read SO contents, recv on channel |
| 1 | WRITE | Can write SO contents, send on channel |
| 2 | EXECUTE | Can enter domain, invoke channel as RPC |
| 3 | GRANT | Can derive child capabilities |
| 4 | REVOKE | Can revoke this cap and all descendants |

### 3.3 Epoch-Based Revocation

Instead of walking the CDT to invalidate descendants (O(n) in tree size),
sotX uses epoch-based revocation:

1. Each SO has a monotonic `current_epoch` counter.
2. Each capability records the epoch at which it was created.
3. `cap_revoke(cap)` increments the SO's epoch.
4. Any capability with `cap.epoch < so.current_epoch` is stale and rejected.

This provides O(1) revocation of entire subtrees. The CDT is retained for
audit and provenance purposes but is not on the revocation fast path.

### 3.4 Attenuation

`cap_derive(src, mask)` creates a child capability whose rights are
`src.rights & mask`. Rights can only decrease through derivation, never
increase. This is enforced by the kernel and verified by the TLA+
specification (see `formal/capabilities.tla`).

### 3.5 Interposition

A capability can be marked as **interposed**, meaning all operations on it
are redirected to a designated handler domain. This is the foundation of the
deception engine: the handler can inspect, modify, redirect, or fabricate
responses to any operation on the interposed object.

```
cap_interpose(target_cap, handler_domain) -> interposed_cap
```

Operations on `interposed_cap` are delivered as messages to `handler_domain`
instead of reaching the real object. The handler can then:

- **Passthrough**: forward to the real object unchanged.
- **Inspect**: log the operation, then forward.
- **Redirect**: forward to a different object.
- **Fabricate**: return a synthetic response without touching any real object.

---

## 4. Transaction Engine

All state-mutating operations on Secure Objects are wrapped in transactions.
Transactions provide atomicity, consistency, and durability guarantees.

### 4.1 Transaction Tiers

| Tier | Scope | Overhead Target | Use Case |
|------|-------|-----------------|----------|
| Tier 0 | Single SO, single op | < 100 ns | Hot-path reads and writes |
| Tier 1 | Single SO, multi-op | < 1 us | Read-modify-write sequences |
| Tier 2 | Multi-SO, multi-op | < 10 us | Cross-object atomic updates |

Tier 0 transactions are implicit -- every `so_read` / `so_write` is atomic
with respect to concurrent accessors. Tier 1 transactions use a per-object
WAL (Write-Ahead Log). Tier 2 transactions use two-phase commit across
objects, with the kernel as coordinator.

### 4.2 Rollback

If a transaction aborts (capability revoked mid-transaction, domain killed,
explicit abort), all modifications are rolled back using the WAL. The WAL
entries are themselves Secure Objects, so they participate in provenance
tracking.

---

## 5. Provenance System

Every significant kernel operation generates a provenance entry. Provenance
entries form a DAG (Directed Acyclic Graph) that records the causal history
of every object and capability in the system.

### 5.1 Entry Format

```
struct ProvenanceEntry {
    timestamp: u64,         // TSC value
    cpu: u8,                // Originating CPU
    domain: DomainId,       // Acting domain
    operation: OpCode,      // What happened
    subject: ObjectId,      // Primary object
    args: [u64; 4],         // Operation-specific arguments
    parent_hash: [u8; 32],  // SHA-256 of parent entry (DAG link)
}
```

### 5.2 Collection

Each CPU has a lock-free SPSC (Single-Producer Single-Consumer) ring buffer
for provenance entries. The producer is the kernel's syscall path; the
consumer is a userspace provenance aggregator that constructs the global DAG.

This design ensures provenance collection never blocks the syscall fast path.
The ring is sized to absorb bursts; if it fills, the kernel switches to
synchronous mode (blocking the caller until the consumer drains entries).

### 5.3 DAG Construction

The userspace aggregator:

1. Drains per-CPU SPSC rings.
2. Computes SHA-256 hashes linking entries to their causal parents.
3. Persists the DAG to a tamper-evident append-only log (SO-backed).
4. Serves queries: "show me every operation that led to this object's
   current state."

### 5.4 Guarantees

- **Completeness**: every cap_derive, so_write, chan_send, domain_enter, and
  tx_commit generates an entry.
- **Ordering**: entries from a single CPU are totally ordered by TSC.
  Cross-CPU ordering uses the DAG's hash links.
- **Tamper evidence**: modifying any entry invalidates its hash chain.

---

## 6. Domain Model

A domain is the unit of isolation. It combines three resources:

| Component | Description |
|-----------|-------------|
| **CSpace** | The domain's capability space -- its set of accessible capabilities |
| **Address Space** | Page tables (CR3) -- the domain's virtual memory view |
| **Scheduling Context** | CPU budget (quantum, period) and priority |

### 6.1 Lifecycle

1. **Create**: `domain_create(quantum_ms, period_ms)` allocates a new domain
   with empty CSpace, empty AS, and a scheduling budget.
2. **Populate**: The creating domain maps frames into the new AS, loads code,
   and grants capabilities into the new CSpace.
3. **Enter**: `domain_enter(cap)` switches the CPU to the target domain's AS,
   CSpace, and scheduling context.
4. **Suspend**: When the domain's quantum expires, it is suspended until the
   next period refill.
5. **Destroy**: Revokes all capabilities in the CSpace, frees all frames in
   the AS, and deallocates the scheduling context.

### 6.2 Budget Enforcement

The scheduler tracks per-domain tick consumption. When a domain exhausts its
quantum, all its threads are parked in a suspended list. At the start of the
next period, the budget is refilled and suspended threads are re-enqueued.

Threads without a domain association always run (no budget limit). This is
used for kernel-internal threads and the init service.

---

## 7. Personality Layers

sotX presents OS personalities to guest code through userspace servers.
The kernel knows nothing about POSIX, BSD, or Linux -- all translation
happens in Ring 3.

### 7.1 BSD Personality (Rump Kernel)

The primary personality uses NetBSD rump kernels -- the "anykernel"
architecture that extracts kernel subsystems (VFS, networking, drivers) into
userspace libraries.

The rump hypercall interface (~30 functions) maps to SOT primitives:

| Rump Hypercall | SOT Equivalent |
|----------------|----------------|
| `rumpuser_malloc` | `so_create` + frame alloc |
| `rumpuser_mutex_*` | Futex on shared SO |
| `rumpuser_bio` | Channel send to block driver |
| `rumpuser_sp_*` | Channel send/recv |
| `rumpuser_clock_gettime` | RDTSC + vDSO |

### 7.2 Linux Personality (LKL / LUCAS)

Linux compatibility is provided through two complementary mechanisms:

**LKL (Linux Kernel Library)**: The Linux kernel compiled as a static
library (`liblkl.a`). Runs in Ring 3 as a LibOS. Provides bug-for-bug
compatible Linux syscall semantics without any kernel-side emulation.
The host operations interface (~25 callbacks) maps to SOT IPC.

**LUCAS (Legacy UNIX Compatibility Abstraction System)**: A lighter-weight
translation layer that handles ~130 Linux syscalls directly in userspace.
Used for simple binaries; LKL handles complex applications.

### 7.3 Deception Personalities

Through capability interposition, sotX can present a fabricated OS
personality to a compromised domain. The domain sees Ubuntu 22.04 with
apt, systemd, and a full /proc filesystem -- but every operation is
mediated and logged. See the Deception Engine section below.

---

## 8. Deception Engine

The deception engine uses capability interposition to create convincing OS
illusions around untrusted domains.

### 8.1 Capability Interposition Pipeline

```
Untrusted Domain                Interposition Handler
     |                                |
     |-- so_read(interposed_cap) ---->|
     |                                |-- [policy decision]
     |                                |   passthrough? inspect?
     |                                |   redirect? fabricate?
     |                                |
     |<-- fabricated response --------|
```

### 8.2 Deception Profiles

A deception profile defines the complete illusion. It specifies:

- **Filesystem view**: what files exist, their contents, timestamps.
- **Process view**: what processes appear to be running (fake ps output).
- **Network view**: what interfaces exist, routing tables, DNS responses.
- **System view**: hostname, kernel version string, CPU info.

Profiles are composable. A base "Ubuntu 22.04 Server" profile can be
overlaid with a "production webserver" profile that adds specific
packages, log files, and network services.

### 8.3 Live Migration

An untrusted domain can be migrated from passthrough mode to deception
mode atomically:

1. Snapshot the domain's current capability set.
2. For each capability, create an interposed wrapper.
3. Atomically swap the domain's CSpace entries to the wrapped versions.
4. From this point, all operations go through the deception handler.

The migration is invisible to the domain -- no system call fails, no
timing anomaly occurs. The domain continues executing without any
observable discontinuity.

---

## 9. Address Space Layout

```
Virtual Address          Content                    Size
-------------------      -------------------------  ----------
0x0000_0000_0020_0000    User .text (ELF)           varies
0x0000_0000_0051_0000    Keyboard ring buffer       4 KiB
0x0000_0000_0052_0000    Mouse ring buffer          4 KiB
0x0000_0000_0090_0000    User stack                 16 KiB
0x0000_0000_00A0_0000    SPSC ring (shared mem)     4 KiB
0x0000_0000_00B0_0000    BootInfo page              4 KiB
0x0000_0000_00B8_0000    vDSO page (R+X)            4 KiB
0x0000_0000_00C0_0000    MMIO (virtio, etc.)        varies
0x0000_0000_00D0_0000    ObjectStore + VFS          12+ KiB
0x0000_0000_00E0_0000    LUCAS stacks + blk buf     varies
0x0000_0000_00E3_0000    Child process stacks       varies
0x0000_0000_0100_0000    Shell ELF load area        varies
0x0000_0000_0200_0000    brk heap                   1 MiB
0x0000_0000_0300_0000    mmap region                grows up
0x0000_0000_0400_0000    Framebuffer (UC)           varies
0x0000_0000_0500_0000    Spawn/DL/Exec buffers      varies
0x0000_0000_0600_0000    Interpreter load base      varies
0x0000_0000_0A00_0000    Interpreter buffer base    varies
  ...
0xFFFF_8000_0000_0000    Kernel HHDM (direct map)   all phys
0xFFFF_FFFF_8000_0000    Kernel .text               varies
```

---

## 10. Repository Structure

```
sotX/
  kernel/                    The microkernel (Ring 0, ~10K LOC target)
    src/
      arch/x86_64/           CPU-specific: serial, GDT, IDT, LAPIC, percpu
      mm/                    Bitmap physical frame allocator
      cap/                   Capability table + CDT
      ipc/                   Endpoints (sync) + Channels (async) + Mailbox + Route
      sched/                 Thread pool, 4-level MLQ, per-core queues, domains
      sync/                  Ticket spinlocks, lock ordering
      syscall/               Syscall dispatch (11 SOT syscalls + legacy compat)
      pool.rs                Generic Pool<T> with generation-checked handles
      fault.rs               Page fault routing to VMM
      irq.rs                 IRQ virtualization
      main.rs                kmain entry point

  libs/                      Shared libraries
    sotos-common/            Kernel-userspace ABI contract
    sotos-pci/               PCI bus enumeration
    sotos-virtio/            Virtio transport + block/net drivers
    sotos-objstore/          Transactional object store + VFS
    sotos-nvme/              NVMe SSD driver
    sotos-xhci/              USB xHCI host controller driver
    sotos-ld/                Dynamic linker
    sotos-wasm/              WebAssembly runtime
    sotos-net/               IP/UDP/TCP/ICMP stack

  services/                  Userspace servers (Ring 3)
    init/                    Init service + LUCAS (Linux compat layer)
    vmm/                     Virtual memory manager (handles page faults)
    kbd/                     PS/2 keyboard driver
    net/                     Network service (virtio-net + IP stack)
    nvme/                    NVMe block device service
    xhci/                    USB host controller service
    compositor/              Wayland compositor
    lucas-shell/             LUCAS interactive shell

  formal/                    TLA+ specifications
    capabilities.tla         Capability system model
    scheduler.tla            Scheduler correctness model
    ipc.tla                  IPC protocol model

  docs/                      Documentation
    ARCHITECTURE.md          This file
    SOT_SPEC.md              SOT exokernel specification
    RUMP_ADAPTATION.md       Rump kernel adaptation guide
    DECEPTION_MODEL.md       Deception system design
    FORMAL_MODEL.md          Formal verification approach

  tests/                     Test suites
    integration/             Boot and IPC integration tests
    security/                Capability escalation, domain escape tests
    posix/                   POSIX conformance (LTP subset)
    deception/               Deception consistency and detection tests

  boot/                      Bootloader config (limine.conf)
  scripts/                   Build tools (mkimage.py, mkinitrd.py)
```

---

## 11. Build and Boot

### Prerequisites

- Rust nightly toolchain with `x86_64-unknown-none` target
- `just` command runner
- Python 3 (for mkimage.py)
- QEMU x86_64

### Quick Start

```bash
just build              # Compile kernel
just run                # Build + disk image + boot in QEMU (serial)
just run-gui            # Same with QEMU display window
just debug              # Boot with GDB server (port 1234)
```

### Manual Build

```bash
cargo build --package sotos-kernel
python scripts/mkimage.py
qemu-system-x86_64 \
    -drive format=raw,file=target/sotx.img \
    -serial stdio \
    -display none \
    -no-reboot \
    -m 512M
```

### Key Build Details

- Target triple: `x86_64-unknown-none`
- Relocation model: `static` (Limine rejects ET_DYN binaries)
- Nightly features: `build-std`, `abi_x86_interrupt`
- Boot protocol: Limine v8 BIOS
- Image format: GPT + FAT32 (built by `scripts/mkimage.py`)

---

## 12. Comparison with Prior Art

| System | Kernel | Personality | Deception | Provenance | Verification |
|--------|--------|-------------|-----------|------------|--------------|
| seL4 | Verified microkernel | None (bare) | No | No | Full (Isabelle/HOL) |
| Genode | Framework | L4Linux server | No | No | Partial |
| macOS/XNU | Mach hybrid | BSD server | No | Limited (DTrace) | No |
| Qubes OS | Xen hypervisor | Full VMs | No | No | No |
| **sotX** | SOT exokernel | Rump + LKL + deception | **Yes** | **Mandatory** | TLA+ + Verus |

sotX is unique in combining capability security, mandatory provenance,
and active deception in a single verified kernel. No prior system offers
all three.

---

## 13. Security Model Summary

```
Layer           Mechanism                  Protects Against
-----------     -------------------------  --------------------------
Hardware        W^X, ASLR, guard pages     Code injection, stack smash
Kernel          Capabilities, epochs       Privilege escalation
IPC             Type-checked channels      Message forgery
Domains         Separate AS + CSpace       Cross-domain access
Transactions    WAL + rollback             Inconsistent state
Provenance      Hash-linked DAG            Evidence destruction
Deception       Cap interposition          Adversary reconnaissance
```

Every layer is independent. Compromising one does not compromise the others.
An adversary who achieves code execution in a domain faces: no ambient
authority, no escalation path, full audit trail, and a potentially
fabricated view of the entire system.
