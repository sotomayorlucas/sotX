# sotX (Secure Object Transactional Operating System) — Development Roadmap

> Current state: SMP-capable microkernel with scheduling domains, transactional object
> store with WAL for crash consistency, and a POSIX-like VFS shim. All five kernel
> primitives run across multiple CPU cores with per-core run queues and work stealing.
> Scheduling domains provide kernel-enforced CPU time budgets (seL4-inspired). Lock-free
> SPSC shared-memory channels provide zero-syscall hot-path messaging. The object store
> (`sotos-objstore`) provides named blob storage on top of virtio-blk with WAL-based
> atomic metadata updates, block bitmap allocation, and a VFS with file handles
> (open/read/write/seek/close/delete). Data persists across re-mounts. Userspace PCI
> enumeration and virtio-blk driver demonstrate device driver model. 12+ userspace
> threads demonstrate sync/async IPC, capabilities, notifications, shared-memory, IRQ
> virtualization, demand paging (VMM), ELF loading, SPSC streaming, IPC benchmarks,
> virtio block I/O, and filesystem operations. Technical hardening complete:
> generation-checked Pool<T>, O(1) thread lookup, lock ordering, per-CPU slab caches.

---

## Phase 0 — Foundation (DONE)

- [x] Project scaffold (Cargo workspace, toolchain, linker script)
- [x] Limine boot protocol integration (v0.5 crate, v8 bootloader)
- [x] Serial output driver (COM1 16550 UART)
- [x] GDT + TSS (double fault IST stack)
- [x] IDT with CPU exception handlers (breakpoint, double fault, GPF, page fault)
- [x] Bitmap physical frame allocator (from bootloader memory map)
- [x] Capability table with CDT revocation
- [x] IPC endpoint skeleton (create only)
- [x] Thread Control Block definition
- [x] Syscall ABI definition (`sotos-common`)
- [x] QEMU boot pipeline (`just run` → build → mkimage → QEMU serial)

---

## Phase 1 — Preemption & Context Switching (DONE)

**Goal**: The CPU can run multiple kernel threads and switch between them on a timer tick.

- [x] 8254 PIT at 100 Hz, 8259 PIC remapped to vectors 32+
- [x] Assembly `context_switch` trampoline (callee-saved regs + RSP swap)
- [x] Thread creation with initial stack frame, `#[unsafe(naked)]` trampoline
- [x] Round-robin scheduler with 10-tick timeslice, circular run queue

### Milestone: Multiple kernel threads printing interleaved output to serial.

---

## Phase 2 — Syscall Interface & Ring 3 (DONE)

**Goal**: Userspace code can execute, trap into the kernel via `syscall`, and return.

- [x] SYSCALL/SYSRET via EFER/STAR/LSTAR/FMASK MSRs
- [x] Syscall entry/exit assembly (kernel stack swap, TrapFrame, dispatcher)
- [x] GDT restructured for SYSRET segment ordering
- [x] Bootstrap paging (`AddressSpace::new_user()`, 4-level page table walk)
- [x] First userspace process (assembly blob, prints "INIT\n" via `SYS_DEBUG_PRINT`)

### Milestone: A userspace process runs, syscalls into the kernel, and returns.

---

## Phase 3 — IPC: Send, Receive, Call (DONE)

**Goal**: Two userspace threads can exchange messages through kernel endpoints.

- [x] Synchronous endpoint IPC: `sys_send`, `sys_recv`, `sys_call` (rendezvous)
- [x] Register-based transfer: 8 regs × 8 bytes = 64 bytes per message
- [x] Ping-pong integration test (sender/receiver IPC demo)
- [x] Capability transfer via IPC (upper 32 bits of tag = cap ID, kernel grants to receiver)
- [x] IPC round-trip latency benchmark (rdtsc in init service)

### Milestone: Two processes communicate via IPC.

---

## Phase 4 — IRQ Virtualization (DONE)

**Goal**: Hardware interrupts are delivered to userspace driver threads via notifications.

- [x] Notification-based IRQ binding (`irq.rs` rewritten, ~55 LOC)
- [x] `sys_irq_register(irq_cap, notify_cap)`: bind IRQ line to notification
- [x] `sys_irq_ack(irq_cap)`: unmask IRQ line after handling
- [x] `sys_port_in(cap, port)` / `sys_port_out(cap, port, val)`: I/O port access
- [x] Userspace keyboard driver (IRQ 1 → notification → port 0x60 read)
- [x] Userspace serial driver (COM1 IRQ 4, receive interrupt, hex echo)
- [x] LAPIC driver with per-CPU timer (Phase 8 delivered this)
- [x] Userspace serial output via `sys::port_out` syscall wrapper (COM1 port cap)

### Milestone: Userspace drivers handle keyboard and serial via IRQ notifications.

---

## Phase 5 — Userspace VMM Server (DONE)

**Goal**: Virtual memory is managed by a userspace server, not the kernel.

- [x] `sys_frame_alloc()` / `sys_frame_free()`: physical frame management with caps
- [x] `sys_map(vaddr, frame_cap, flags)` / `sys_unmap(vaddr)`: page table manipulation
- [x] Page fault handler delivers fault info to VMM server via notification
- [x] VMM server: receives faults, allocates frames, maps pages, resumes threads
- [x] Demand paging proven: fault test touches unmapped 0x600000, VMM handles it
- [x] Exokernel bypass: `sys_map()` callable directly with frame cap (no VMM needed)
- [x] `ThreadState::Faulted` distinct from Blocked (prevents accidental wake)
- [x] `sys_thread_resume(tid)` for VMM to resume faulted threads

### Milestone: Page faults handled by userspace. Demand paging works.

---

## Phase 6 — ELF Loader & Initramfs (DONE)

**Goal**: Load Rust-compiled ELF binaries from disk and run them in userspace.

- [x] ELF64 ET_EXEC loader in kernel (`elf.rs`): maps PT_LOAD segments
- [x] CPIO newc parser in kernel (`initrd.rs`): finds files in archive
- [x] CPIO initrd builder (`scripts/mkinitrd.py`)
- [x] Limine ModuleRequest delivers initrd as boot module
- [x] `sotos-common::sys` module: raw syscall wrappers for userspace
- [x] First Rust userspace program (`services/init/`): SPSC demo + benchmarks
- [x] Build pipeline: `build-user` → `initrd` → `image` → `run`
- [x] Init reads BootInfo page (0xB00000) with root capabilities
- [x] Root capability delegation from kernel to init (BootInfo struct at well-known page)
- [x] Simplified init ABI: BootInfo struct in `sotos-common` (no argc/argv needed)

### Milestone: Rust userspace binary loaded from initrd, runs, and exits.

---

## Phase 7 — Shared-Memory Channels (Fast IPC) (DONE)

**Goal**: High-throughput zero-copy data transfer between services.

Basic async channels (kernel ring buffers) already exist from Phase 3 extras.
This phase adds the lock-free userspace-only fast path.

### 7.1 Lock-Free SPSC Ring Buffer (DONE)
- [x] Lock-free SPSC ring buffer library in `sotos-common` (`spsc.rs`)
  - Head/tail on separate cache lines (align(64)) to avoid false sharing on SMP
  - 128 u64 slots in one 4 KiB shared page (192B header + 1024B data)
  - Producer writes data + updates tail (atomic Release store)
  - Consumer reads data + updates head (atomic Release store)
  - Zero syscalls on the hot path
- [x] Syscall only on block/wake: `notify_wait`/`notify_signal` on empty→non-empty / full→non-full transitions
- [x] Typed syscall wrappers in `sotos-common::sys`: `frame_alloc`, `map`, `notify_create/wait/signal`, `thread_create`
- [x] Multi-argument syscall helpers: `syscall2`, `syscall3`
- [x] Init service rewritten as SPSC demo: consumer/producer stream 1000 messages, verified sum=499500
- [x] No new kernel primitives — composes existing syscalls from userspace
- [x] **Kernel bugfix**: `percpu.user_rsp_save` per-CPU corruption on blocking syscalls — saved/restored per-thread in `syscall_dispatch()`

### 7.2 Typed Channels (DONE — simplified)
- [x] Generic typed wrappers over SPSC in `sotos-common::typed_channel`
- [x] `TypedSender<T>` / `TypedReceiver<T>` with compile-time size checks
- [x] Single-u64 types: direct cast. Multi-word: sequential slot send/recv.
- [ ] Full IDL + code generator (deferred — typed wrappers suffice for now)

### 7.3 Benchmarks (DONE)
- [x] SPSC round-trip latency benchmark (rdtsc, single-threaded hot path)
- [x] SPSC throughput benchmark (10K messages, cycles/msg)
- [x] Results printed by init service: `BENCH: spsc_rt=Xcy/msg`, `BENCH: spsc_tput=Xcy/msg`

### Milestone: Lock-free SPSC ring buffer working in userspace shared memory. 1000 messages streamed with zero-syscall hot path. Benchmarks report latency and throughput.

---

## Phase 8 — SMP (Multi-Core) (DONE)

**Goal**: The kernel runs on all available CPU cores.

### 8.1 AP Startup
- [x] Limine MpRequest: get list of CPUs from bootloader
- [x] Boot Application Processors (APs) into the kernel
- [x] Per-CPU data via GS segment base (`PerCpu` struct, `IA32_GS_BASE` MSR)
- [x] Per-CPU GDT+TSS (heap-allocated after slab init)
- [x] Per-CPU SYSCALL MSRs, IDT reload, LAPIC init per AP

### 8.2 SMP Scheduler
- [x] Per-core run queues with work stealing (ticket-locked VecDeque per CPU)
- [x] Per-CPU idle threads (never enqueued, only active when CPU has no work)
- [x] Post-switch re-enqueue pattern (fixes race: old thread RSP saved before re-enqueue)
- [x] `tick()` uses `try_lock()` to avoid deadlock when timer fires during SCHEDULER lock
- [x] Thread affinity hints (`preferred_cpu` field, enqueue to preferred CPU's queue)
- [x] Work stealing: empty CPU steals oldest thread from other CPUs (round-robin victim)

### 8.3 Synchronization
- [x] Serial lock (`spin::Mutex`) for SMP-safe `kprintln!`
- [x] SYSCALL assembly uses GS-relative access (no `static mut` globals)
- [x] BSP guard on PIC IRQ handlers (APs EOI LAPIC on spurious PIC IRQ)
- [x] CPU index in panic output
- [x] IPI (Inter-Processor Interrupt): ICR register support, reschedule IPI vector 49
- [x] Ticket spinlocks (`kernel/src/sync/ticket.rs`) — FIFO fair, used in scheduler and IPC endpoint

### 8.4 LAPIC Timer
- [x] LAPIC MMIO driver (`lapic.rs`): init, calibrate, periodic timer, EOI
- [x] Calibrated against PIT channel 2 (~10ms interval, ~100Hz)
- [x] Replaces PIT for preemption (PIT IRQ masked)
- [x] LAPIC timer vector 48, spurious vector 0xFF

### 8.5 Slab Allocator Fix
- [x] Allocations > 4096 bytes now use `alloc_contiguous()` from frame allocator
- [x] Matching dealloc path frees contiguous frames
- [x] SMP 4-CPU boots without slab panic

### Milestone: Kernel utilizes all cores. Per-core scheduling with work stealing. Tested 1-4 cores.

---

## Phase 16 — Technical Hardening (DONE)

**Goal**: Fix latent security bugs, eliminate performance bottlenecks, and prepare for assembly→Rust migration.

### 16.1 Pool<T> Generation Counters (ABA Protection)
- [x] `PoolHandle` type: 12-bit generation counter + 20-bit slot index packed into u32
- [x] `Pool::alloc()` returns `PoolHandle`; `get/get_mut/free` verify generation match
- [x] Stale handles (revoked caps, freed objects) → `None` instead of accessing wrong object
- [x] `CapId(PoolHandle)`: userspace passes opaque u32, generation bits embedded transparently
- [x] `get_by_index/get_mut_by_index/free_by_index` for scheduler (raw indices, guaranteed live)
- [x] All IPC pools (endpoints, channels, notifications) use `PoolHandle` throughout

### 16.2 O(1) Thread Lookup
- [x] `tid_to_slot: [Option<u32>; 256]` mapping table in Scheduler
- [x] `resume_faulted()`, `wake()`, `write_ipc_msg()`, `read_ipc_msg()` rewritten O(1)
- [x] Eliminates O(n) linear scans over thread pool (was 4 functions × n threads)
- [x] Registration on spawn, deregistration on death

### 16.3 Lock Ordering Enforcement
- [x] `LockLevel` enum with 9 levels: FaultState → IrqTable → Endpoints → Channels →
      Notifications → CapTable → Scheduler → Slab → FrameAllocator
- [x] Per-CPU `held_locks: u16` bitmask in PerCpu struct
- [x] `check_lock_order()` / `mark_lock_held()` / `mark_lock_released()` with debug assertions
- [x] All behind `#[cfg(debug_assertions)]` — zero cost in release builds
- [x] CHANNELS and NOTIFICATIONS converted from `spin::Mutex` to `TicketMutex` (FIFO fair)

### 16.4 Per-CPU Slab Caches
- [x] `[Mutex<SlabAllocator>; 16]` — one cache per CPU, eliminates global lock contention
- [x] `cpu_owner: u8` stamped in slab header; dealloc routes to owner's cache
- [x] Remote free: lock only the owner CPU's cache (2-CPU contention max, not N-CPU)
- [x] `AtomicBool` guard for early boot (slab allocates before percpu init)

### 16.5 spawn_init_process() Cleanup
- [x] `init_layout` module with named constants for all virtual addresses
- [x] `map_code_page()` / `map_stack_page()` helper functions
- [x] `map_all_blobs()`, `map_all_stacks()`, `create_init_caps()` sub-functions
- [x] Main function reduced from ~375 lines to ~30 lines of orchestration

### 16.6 Complete Syscall Wrappers
- [x] `IpcMsg` struct in `sotos-common` (tag + 8 regs, full register ABI)
- [x] `FaultInfo` struct for fault_recv return values
- [x] 17 new wrappers: `send/recv/call` (10-register custom asm), `channel_create/send/recv/close`,
      `endpoint_create`, `cap_grant/revoke`, `frame_free`, `unmap`, `thread_resume`,
      `irq_register/ack`, `fault_register/recv`
- [x] `debug_assert!` in typed_channel.rs for multi-slot capacity validation
- [x] `SpscRing::capacity()` made public for runtime assertions

### Milestone: ABA-safe object pools, O(1) scheduler lookups, lock ordering enforcement, per-CPU allocation, complete userspace syscall ABI.

---

## Phase 9 — Scheduling Domains (DONE)

**Goal**: Userspace can implement custom schedulers for their own threads via
budget-enforced thread groups (seL4-inspired model).

### 9.1 Domain Kernel Object
- [x] `SchedDomain` struct: quantum_ticks, period_ticks, consumed_ticks, state (Active/Depleted)
- [x] Per-domain member list (64 threads max) + suspended list for depleted threads
- [x] `Pool<SchedDomain>` in Scheduler — dynamic, generation-checked
- [x] `CapObject::Domain { id }` — domains accessed via capability system

### 9.2 Budget Enforcement
- [x] `GLOBAL_TICKS` atomic counter — incremented unconditionally on every timer tick
- [x] `tick()`: tracks per-domain consumed_ticks, transitions Active → Depleted at quantum
- [x] `check_domain_refills()`: scans domains on each tick, refills when period elapses
- [x] `dequeue_non_depleted()`: skips threads in depleted domains, parks them in suspended list
- [x] Refill drains suspended list → re-enqueue Ready threads
- [x] Threads without a domain always run (no budget limit)
- [x] Dead thread cleanup: remove from domain membership on exit

### 9.3 Syscall Interface (90–94)
- [x] `DomainCreate(quantum_ms, period_ms)` — create domain with CPU budget (ms→ticks conversion)
- [x] `DomainAttach(domain_cap, thread_cap)` — add thread to domain
- [x] `DomainDetach(domain_cap, thread_cap)` — remove thread from domain (re-enqueue if suspended)
- [x] `DomainAdjust(domain_cap, new_quantum_ms)` — dynamic budget adjustment
- [x] `DomainInfo(domain_cap)` → (quantum, consumed, period) — query budget state
- [x] All operations cap-validated (WRITE for create/attach/detach/adjust, READ for info)

### 9.4 Userspace ABI
- [x] `Syscall::DomainCreate/Attach/Detach/Adjust/Info` enum variants (90–94)
- [x] `sys::domain_create/attach/detach/adjust/info` wrappers in sotos-common
- [x] `domain_info` uses custom asm with 3 output registers (rdi, rsi, rdx)

### 9.5 Use Cases
- [ ] Go-style M:N green thread runtime as a scheduling domain
- [ ] Dedicated-core domain for latency-sensitive workloads
- [ ] Work-stealing pool domain for parallel compute

### 9.6 Deferred (Future Work)
- [ ] CPU pinning: `cpu_affinity: u16` bitmask — threads only on selected CPUs
- [ ] Priority inheritance across domain boundaries for IPC chains
- [ ] Domain destruction: detach all threads, drain suspended, free slot
- [ ] Exclusive cores: domain reserves CPU(s), other threads excluded

### Milestone: Kernel-enforced time budgets work. Domain threads deplete/refill cycles visible in serial output. 25% CPU share demonstrated with sender+receiver threads.

---

## Phase 10 — LUCAS (Legacy UNIX Compatibility Abstraction System) (IN PROGRESS ~80%)

**Goal**: Run unmodified Linux/POSIX ELF binaries on sotX.

LUCAS is a set of coordinated userspace servers that present a complete Linux illusion
to legacy binaries. It translates monolithic UNIX semantics into sotX's decentralized,
capability-based primitives — entirely in Ring 3.

### 10.1 Syscall Interceptor (Trap Handler) (DONE)
- [x] Capture `syscall` instructions from the guest ELF binary in Ring 3
- [x] Redirect to LUCAS translation engine via `redirect_ep` + `child_handler`
- [x] Map Linux syscall numbers (read=0, write=1, open=2, ...) to LUCAS handlers
- [x] Handle the full lifecycle: `execve` → setup → syscall translation → `exit`
- [x] 200+ Linux syscalls handled (127 match arms in child_handler, 198 SYS_* constants)
- [x] musl-static, musl-dynamic, and glibc binary support (ELF loader, PT_INTERP, auxv)

### 10.2 Capability Mapper (Ambient Authority Emulator) (DONE)
- [x] Maintain internal table: Linux file descriptors (FDs) → sotX capabilities
- [x] Emulate UID/GID/permission model on top of capabilities
- [x] Map Linux PIDs to sotX ThreadIds (PROC_TGID, PROC_KERNEL_TID)
- [x] Hide CDT complexity from guest processes — present flat POSIX view
- [x] Translate `open("/dev/...")` to capability lookups for device endpoints
- [x] Per-process FD tables with shared FD groups (GRP_FDS, GRP_INITRD, GRP_VFS)
- [x] FD kinds: file, dir, pipe, socket TCP/UDP, eventfd, timerfd, memfd, socketpair, procfs

### 10.3 VFS Bridge (Virtual File System Translator) (DONE)
- [x] Intercept POSIX file operations: `open`, `read`, `write`, `close`, `stat`, `lseek`
- [x] Translate path-based access to Object Store transactions
- [x] Expose typed objects as flat byte streams (what POSIX expects)
- [x] Implement `/proc` and `/sys` as synthetic views of sotX state
- [x] Support `opendir`/`readdir` for directory enumeration (getdents64)
- [x] Per-process CWD with `resolve_with_cwd()` for relative paths
- [x] Sysroot initialization: /lib, /lib64, /bin, /usr/*, /tmp, virtual /etc/*
- [x] vDSO injection (ELF ET_DYN at 0xB80000, __vdso_clock_gettime, AT_SYSINFO_EHDR)

### 10.4 Process & Memory Coordinator (DONE)
- [x] Emulate `fork()`: real Copy-on-Write via `clone_cow()` + VMM CoW fault handler
- [x] Emulate `execve()`: parse ELF, map segments, transfer FD table (`exec_loaded_elf()`)
- [x] Emulate `mmap()`/`munmap()`: delegate to VMM server via `sys_map`/`sys_unmap`
- [x] Emulate `brk()` for heap growth
- [x] Emulate `clone()` with CLONE_VM/FILES/SIGHAND/THREAD/SETTLS/PARENT_SETTID/CHILD_CLEARTID
- [x] Emulate `wait()`/`waitpid()`/`wait4()` via IPC notifications
- [x] Futex: `futex_wait` + `futex_wake` (64-slot global wait queue, pthread_join works)
- [x] Nested fork: P4->P5->P6 verified (git remote helper protocol)

### 10.5 IPC & Network Translator (DONE)
- [x] Translate UNIX pipes → sotX pipe FDs with reference counting
- [x] Translate UNIX signals → async signal delivery (LAPIC timer + vDSO trampoline)
- [x] Translate UNIX sockets:
  - [x] TCP sockets via IPC proxy to net service (connect, send, recv, close)
  - [x] UDP sockets via IPC proxy (bind, sendto, recvfrom with src_addr fill)
  - [x] AF_UNIX socketpair (bidirectional, SOCK_CLOEXEC)
- [x] Emulate `select()`/`poll()`/`epoll()` over sotX IPC primitives
- [x] eventfd, timerfd, memfd_create, pipe2, signalfd stubs

### 10.6 Security: Confinement by Design (DONE)
- [x] LUCAS processes run in a strict capability sandbox
- [x] No ambient authority: a compromised Linux binary cannot escape the LUCAS illusion
- [x] RCE inside LUCAS = attacker trapped in emulated UNIX, no access to sotX primitives
- [ ] Optional: per-binary capability policy (restrict which "Linux files" map to which capabilities)

### 10.7 LKL Fusion (IN PROGRESS)
- [x] Linux 6.6 kernel compiled as LibOS (`personality/linux/lkl/`)
- [x] Boot via `just run-lkl` — Linux kernel runs as a userspace library
- [ ] Full ext4/networking passthrough from LKL to sotX services

### 10.8 Remaining Work
- [ ] Full IDL code generator (typed wrappers suffice for now)
- [ ] `clone3` (currently returns -ENOSYS, forces fallback to clone)
- [ ] Priority inheritance across IPC chains
- [ ] Per-binary capability policy files
- [ ] HTTPS/TLS support (git clone blocks at TLS handshake)

### Milestone (ACHIEVED): Busybox (wget, sh, ls, cat, grep, wc), Alpine git (init, clone over
dumb HTTP), links, nano, musl-static/dynamic binaries, and glibc binaries (Ubuntu echo, ls)
all run unmodified on sotX via LUCAS. 200+ Linux syscalls translated. Real CoW fork, nested
fork, pipe infrastructure, async signals, futex, and epoll all working.

---

## Phase 11 — Filesystem & Storage

**Goal**: Persistent storage accessible through the object store interface.

### 11.1 Block Device Driver (DONE)
- [x] Virtio-blk driver (userspace, talks to QEMU via legacy transport)
- [x] Block layer abstraction: read/write sectors through capabilities
- [x] PCI enumeration library (`libs/sotos-pci`): bus 0 scan, config space R/W
- [x] Virtio driver library (`libs/sotos-virtio`): split virtqueue + blk driver
- [x] 5 new syscalls (100–104): FramePhys, IoPortCreate, FrameAllocContig, IrqCreate, MapOffset
- [x] 16/32-bit port I/O (inw/outw/inl/outl) + PORT_IN/OUT width parameter
- [x] PCI config space cap (0xCF8–0xCFF) in init BootInfo
- [x] Integration demo: PCI enumerate → find virtio-blk → read/write/verify sectors

### 11.2 Object Store (DONE)
- [x] Transactional object store library (`libs/sotos-objstore`)
- [x] On-disk layout: superblock, WAL (4-entry), block bitmap (2 sectors), directory (32 entries)
- [x] Write-Ahead Log (WAL) for crash consistency (4-phase commit protocol)
- [x] Block bitmap allocator: contiguous allocation, free, count
- [x] CRUD operations: create, read_obj, write_obj, delete, find, stat, list
- [x] WAL replay on mount (committed-but-not-applied transactions replayed)
- [x] In-memory store placed at 0xD00000 (3 pages) to avoid stack overflow
- [ ] Copy-on-Write snapshots for object versioning (deferred)
- [ ] Schema-based typed objects with 128-bit OIDs (deferred)

### 11.3 POSIX VFS Shim (DONE)
- [x] VFS shim in `sotos-objstore::vfs`: translates open/read/write/seek/close/delete
- [x] 16 file handles with position tracking and access flags (O_RDONLY/O_WRONLY/O_RDWR)
- [x] Read-modify-write for partial writes (temp buffer at 0xD03000)
- [x] Integration demo: format → create files → read/write → list → delete → re-mount verify
- [ ] Enough for basic utilities (shell, coreutils) — needs syscall integration (deferred)

### Milestone: Data persists across re-mounts. Object store with WAL transactional guarantees. VFS file operations work end-to-end.

---

## Phase 12 — Networking & Distribution (IN PROGRESS ~90%)

**Goal**: Nodes communicate; IPC is transparent across the network.

### 12.1 Network Stack (DONE)
- [x] Virtio-net driver (userspace, `services/net/` + `libs/sotos-net/`)
- [x] Full IP/UDP/TCP stack in userspace service (`libs/sotos-net/`)
- [x] Socket-like API through IPC endpoints (socket proxy in LUCAS child_handler)
- [x] ARP: request/reply, cache
- [x] DHCP: dynamic IP acquisition (dynamic xid)
- [x] DNS: UDP resolver (10.0.2.3 via QEMU user-mode)
- [x] ICMP: echo request/reply (ping)
- [x] UDP: bind, sendto, recvfrom with src_addr fill (DNS, NTP)
- [x] TCP: connect, send, recv, close, retransmit, RST handling
- [x] HTTP: full page download via busybox wget, git clone over dumb HTTP
- [x] Multi-chunk IPC assembly for large transfers (64B per round-trip, 16KB RX buffer)

### 12.2 Remote IPC
- [ ] Transparent IPC proxy: local endpoint → network → remote endpoint
- [ ] Explicit failure semantics: `Result<T, RemoteError>` with timeouts
- [ ] OID resolution: distributed hash table for object location

### 12.3 Cluster Management
- [ ] Failure domains: process → node → cluster → swarm
- [ ] Raft consensus for critical shared state
- [ ] Service migration on node failure

### Milestone (Partial): Full local networking operational — DHCP, DNS, TCP, UDP, HTTP all
working. Busybox wget downloads pages, git clone fetches repos over HTTP. Remote IPC and
cluster management remain.

---

## Phase 13 — Formal Verification & Hardening

**Goal**: Mathematical proof that the kernel is correct.

### 13.1 Verification
- [ ] Annotate kernel code with Verus/Prusti pre/post-conditions
- [ ] Prove: capability enforcement never bypassed
- [ ] Prove: frame allocator never double-allocates
- [ ] Prove: IPC transfer preserves message integrity
- [ ] Model check scheduler with TLA+ (no deadlocks, no starvation)

### 13.2 Hardware Security
- [ ] CHERI capability support (when hardware is available)
  - 128-bit fat pointers with hardware bounds checking
  - Spatial memory safety at instruction level
- [ ] IOMMU integration: device isolation for DMA
- [ ] Measured boot: TPM-backed chain of trust

### 13.3 Audit
- [ ] Security audit of syscall interface
- [ ] Fuzz all syscall paths (syzkaller-style)
- [ ] Penetration testing: escape from a confined process

### Milestone: Core kernel invariants formally verified. Hardware security integrated.

---

## Phase Summary

```
Phase  Scope                          Dependencies    Status
─────  ─────────────────────────────  ──────────────  ──────
  0    Foundation                     —               DONE
  1    Preemption + Context Switch    Phase 0         DONE
  2    Syscall + Ring 3               Phase 1         DONE
  3    IPC Send/Recv/Call + extras    Phase 2         DONE (cap transfer + benchmarks)
  4    IRQ Virtualization             Phase 3         DONE (LAPIC + PIC + userspace serial)
  5    VMM Server                     Phase 2         DONE
  6    ELF Loader + Initramfs         Phase 3,5       DONE (BootInfo + init ABI)
  7    Shared-Memory Channels         Phase 3         DONE (SPSC + typed wrappers + benchmarks)
  8    SMP (Multi-Core)               Phase 1         DONE (per-core queues, work stealing, IPI, ticket locks)
 16    Technical Hardening            Phase 8         DONE (ABA protection, O(1) lookup, lock ordering, per-CPU slab)
  9    Scheduling Domains             Phase 8         DONE (budget enforcement, 5 syscalls, cap-based)
 10    LUCAS (UNIX Compat Layer)      Phase 6,7,11    IN PROGRESS (~80%)
 11    Filesystem + Object Store      Phase 6         DONE (block driver + objstore + VFS)
 12    Networking + Distribution      Phase 6,11      IN PROGRESS (~90%)
 13    Verification + Hardening       Phase 3+        TODO
```

```
                         Phase 0 (DONE)
                              │
                         Phase 1 (DONE)
                        ╱          ╲
                Phase 2              Phase 8
                (DONE)               (DONE)
              ╱     ╲                   │
        Phase 3    Phase 5         Phase 9
        (DONE)     (DONE)          (DONE)
        ╱    ╲        │
  Phase 4   Phase 7   │
  (DONE)    (DONE)     │
        ╲    ╱        ╱
         Phase 6
         (DONE)
           │
     ┌─────┼─────┐
  Phase 11 │  Phase 12
  (Storage) │  (Net ~90%)
        ╲  │  ╱
       Phase 10
     (LUCAS ~80%)
           │
       Phase 13
    (Verification)
```

---

## Immediate Next Steps

Phases 0–9, 11, 16 are complete. Phase 10 (LUCAS) is ~80% done — 200+ Linux syscalls,
fork/exec/wait, CoW, signals, pipes, sockets, busybox/git/wget/nano all working. Phase 12
(Networking) is ~90% done — full IP/UDP/TCP/DNS/DHCP/HTTP stack operational. Current
priorities:

- **STYX boot verification**: sotX personality layer boot path + syscall wrappers (`personality/bsd/`).
- **Wine PE compatibility**: Windows PE binary loading via Wine personality routing.
- **Wayland compositor**: Native compositor (`services/compositor/`) + Weston DRM integration.
- **Rump kernel integration**: NetBSD rump kernel for driver reuse (`personality/bsd/rump-sot/`).
- **Remote IPC routing**: Phase 12.2 — transparent IPC proxy across network nodes.
- **LUCAS remaining**: per-binary capability policy, IDL code generator, clone3, HTTPS/TLS.
- **Domain extensions**: CPU pinning, priority inheritance, domain destruction, exclusive cores.
