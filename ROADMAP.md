# sotOS Development Roadmap

> Current state: Kernel boots via Limine BIOS, runs preemptive multitasking with userspace
> processes, sync/async IPC, capability enforcement, notifications, shared-memory zero-copy,
> and a slab allocator for kernel heap. 8 userspace threads demonstrate all primitives.

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

### 1.1 Timer Interrupt
- [x] Initialize the PIT (Programmable Interval Timer) at ~100 Hz for initial preemption
  - Configure PIT channel 0, mode 2 (rate generator)
  - Wire IRQ0 through the legacy 8259 PIC (remap to vectors 32+)
- [x] Add PIC initialization (remap IRQ 0–15 to IDT vectors 32–47)
- [x] Register timer interrupt handler in the IDT (vector 32)
- [x] Handler increments a global tick counter and calls `sched::tick()`

### 1.2 Context Switch
- [x] Write the assembly trampoline `context_switch(old: *mut CpuContext, new: *const CpuContext)`
  - Save callee-saved registers (rbx, rbp, r12–r15) + rsp + rflags to `old`
  - Restore from `new`
  - `ret` jumps to new thread's saved rip
- [x] Allocate kernel stacks for threads (one 16 KiB page per thread from the frame allocator)
- [x] Implement `Thread::new()` that sets up initial context (rip = entry function, rsp = top of stack)

### 1.3 Scheduler Core
- [x] Implement a run queue (fixed-size circular buffer of `ThreadId`)
- [x] Round-robin `schedule()`: pick next Ready thread, mark Running, context switch
- [x] `sched::tick()`: decrement current thread's timeslice, if expired → preempt
- [x] Create an idle thread (hlt loop) that runs when no other thread is Ready
- [x] Create 2–3 test kernel threads that print to serial in a loop to demonstrate preemption

### Milestone: Multiple kernel threads printing interleaved output to serial.

---

## Phase 2 — Syscall Interface & Ring 3 (DONE)

**Goal**: Userspace code can execute, trap into the kernel via `syscall`, and return.

### 2.1 Syscall Entry/Exit
- [x] Configure MSRs for `syscall`/`sysret` (STAR, LSTAR, SFMASK)
  - LSTAR → `syscall_entry` assembly stub
  - STAR → kernel CS/SS in bits 47:32, user CS/SS in bits 63:48
  - SFMASK → mask IF (disable interrupts on syscall entry)
- [x] Write `syscall_entry` asm: swap to kernel stack (from TSS RSP0), save user registers, call Rust dispatcher
- [x] Write `syscall_exit` asm: restore user registers, `sysret`
- [x] Implement syscall dispatcher: match on rax (syscall number from `sotos-common::Syscall`)
- [x] Implement `sys_yield()` as first working syscall

### 2.2 User Segments & Address Space
- [x] Add user code/data segments to the GDT (Ring 3, 64-bit)
- [x] Create a minimal page table for the first userspace process:
  - Identity-map (or HHDM-map) the kernel in the higher half
  - Map the user binary at a fixed low address (e.g., 0x400000)
- [x] Implement basic page table construction in the kernel (4-level: PML4 → PDPT → PD → PT)
  - Use frames from the allocator for page table pages

### 2.3 First Userspace Process
- [x] Embed a minimal user binary (flat binary or simple ELF) in the kernel image
- [x] Parse it and map its segments into the user address space
- [x] Create a user thread: set Ring 3 CS/SS, rip = entry point, rsp = user stack
- [x] Jump to userspace via `sysret` (or `iretq` for initial transition)
- [x] User program calls `sys_yield()` → traps to kernel → returns to user → prints confirmation

### Milestone: A userspace process runs, syscalls into the kernel, and returns.

---

## Phase 3 — IPC: Send, Receive, Call (DONE)

**Goal**: Two userspace threads can exchange messages through kernel endpoints.

### 3.1 Endpoint Send/Recv
- [x] Implement `sys_send(endpoint_cap, msg)`:
  - Validate capability (cap table lookup + rights check)
  - If receiver is waiting → direct transfer (copy registers) + wake receiver
  - Else → block sender, add to endpoint's send queue
- [x] Implement `sys_recv(endpoint_cap)`:
  - If sender is waiting → direct transfer + wake sender
  - Else → block receiver
- [x] Implement `sys_call(endpoint_cap, msg)` = send + recv in one syscall (atomic rendezvous)

### 3.2 Register-Based Transfer
- [x] On rendezvous, copy message registers directly between thread CpuContexts
  - 8 registers × 8 bytes = 64 bytes per message, zero allocation
- [ ] Include capability transfer: one message register can carry a CapId
  - Kernel validates and clones the capability into the receiver's cap space

### 3.3 Integration Test
- [x] Create a "ping-pong" test: two user threads exchange messages in a loop
- [ ] Measure IPC round-trip time (rdtsc before/after)
- [ ] Target: < 1000 cycles per one-way message on modern hardware

### 3.4 Extra (not in original plan)
- [x] Capability enforcement on all syscalls (cap validate + rights checks)
- [x] Async IPC channels (bounded ring buffers, 64 channels × 16 messages)
- [x] Notification objects (binary semaphore, wait/signal)
- [x] Shared-memory zero-copy IPC (userspace data, kernel only wake/sleep)
- [x] Slab allocator (`#[global_allocator]`, 8 size classes, enables `alloc` crate)
- [x] Keyboard IRQ driver (userspace, via IRQ cap + I/O port cap)
- [x] `sys_thread_create` syscall (spawn threads from userspace)

### Milestone: Two processes communicate via IPC. Latency measured.

---

## Phase 4 — IRQ Virtualization

**Goal**: Hardware interrupts are delivered to userspace driver threads via IPC.

### 4.1 PIC/APIC Setup
- [ ] Detect APIC via CPUID / ACPI MADT parsing
- [ ] For initial bring-up: keep using the 8259 PIC (simpler)
- [ ] Implement IRQ masking/unmasking per line

### 4.2 IRQ → IPC Delivery
- [ ] `sys_irq_register(irq_cap, endpoint_cap)`: bind an IRQ line to an endpoint
  - Requires IRQ capability in the caller's cap space
- [ ] When IRQ fires: kernel handler sends a notification message to the bound endpoint
  - If the driver thread is blocked on `recv()` → wake it immediately
- [ ] `sys_irq_ack(irq_cap)`: driver acknowledges the IRQ, kernel unmasks the line
- [ ] Implement for COM1 (serial input) as proof of concept

### 4.3 Userspace Serial Driver
- [ ] Move serial output to a userspace driver (keep `kprintln!` as kernel fallback)
- [ ] Driver registers for COM1 IRQ, reads input, provides a simple terminal service

### Milestone: A userspace driver handles serial I/O via IRQ notifications.

---

## Phase 5 — Userspace VMM Server

**Goal**: Virtual memory is managed by a userspace server, not the kernel.

### 5.1 Kernel Support
- [ ] `sys_frame_alloc()` / `sys_frame_free()`: allocate/free physical frames (returns frame capability)
- [ ] `sys_map(address_space_cap, vaddr, frame_cap, flags)`: insert a mapping into a page table
  - The kernel owns the page table structures but the VMM decides the policy
- [ ] `sys_unmap(address_space_cap, vaddr)`: remove a mapping
- [ ] Page fault handler → deliver fault info to the VMM server via IPC

### 5.2 VMM Server
- [ ] Userspace server that receives page fault messages
- [ ] Maintains a per-process virtual memory layout (regions, permissions)
- [ ] On fault: allocate frame → map it → resume the faulting thread
- [ ] Support lazy allocation (map on first access)

### 5.3 Exokernel Bypass
- [ ] A process with the right capability can call `sys_map()` directly, bypassing the VMM
- [ ] This is the exokernel escape hatch for databases, ML engines, etc.
- [ ] The kernel only checks: does this process own the frame cap? Does the vaddr not overlap kernel space?

### Milestone: Page faults handled by userspace. Processes can grow their heap.

---

## Phase 6 — Init Service & Process Loading

**Goal**: The system boots into an init service that spawns further processes.

### 6.1 ELF Loader
- [ ] Parse ELF64 headers (in userspace, not kernel)
- [ ] Map PT_LOAD segments into a new address space
- [ ] Set up the initial stack with argc/argv/envp (or a simplified ABI)

### 6.2 Init Service
- [ ] First process loaded by the kernel at boot
- [ ] Receives root capabilities for all resources (memory, IRQs, I/O ports)
- [ ] Reads a config (embedded or from a ramdisk) listing services to launch
- [ ] Spawns: VMM server, device manager, filesystem server

### 6.3 Process Management
- [ ] `sys_thread_create(entry, stack_cap, cap_space)`: create a thread in a new address space
- [ ] `sys_thread_destroy(thread_cap)`: terminate a thread
- [ ] Process abstraction in userspace (init tracks child processes, restarts on crash)

### Milestone: System boots to init → spawns VMM + device manager. Self-hosting boot chain.

---

## Phase 7 — Shared-Memory Channels (Fast IPC)

**Goal**: High-throughput zero-copy data transfer between services.

### 7.1 Ring Buffer Channels
- [ ] Kernel allocates shared memory region between two processes
- [ ] Lock-free SPSC ring buffer (single producer, single consumer)
  - Producer writes data + updates write pointer (atomic store)
  - Consumer reads data + updates read pointer (atomic store)
  - Zero syscalls on the hot path
- [ ] Syscall only needed for: create channel, and block/wake when ring is full/empty

### 7.2 Typed Channels (IDL)
- [ ] Design an Interface Definition Language for message schemas
- [ ] Code generator: IDL → Rust stubs for serialize/deserialize
- [ ] Type checking at compile time, zero parsing at runtime

### 7.3 Benchmarks
- [ ] Throughput test: stream N MiB between two processes
- [ ] Compare: endpoint IPC vs shared-memory channel vs raw memcpy baseline
- [ ] Target: channel throughput within 10% of raw memcpy

### Milestone: Zero-copy data streaming between services at near-memcpy speed.

---

## Phase 8 — SMP (Multi-Core)

**Goal**: The kernel runs on all available CPU cores.

### 8.1 AP Startup
- [ ] Parse ACPI MADT to find all local APICs
- [ ] Limine SMP request: get list of CPUs from bootloader
- [ ] Boot Application Processors (APs) into the kernel
- [ ] Per-CPU data structures (current thread, local APIC, per-CPU run queue)

### 8.2 SMP Scheduler
- [ ] Per-core run queues with work stealing
- [ ] Affinity hints: a thread can prefer a specific core (cache locality)
- [ ] Global load balancer: periodically rebalance across cores

### 8.3 Synchronization
- [ ] Audit all spinlocks for SMP safety (interrupt disable + spin)
- [ ] Add ticket locks or MCS locks where contention is expected
- [ ] IPI (Inter-Processor Interrupt) for cross-core notifications

### Milestone: Kernel utilizes all cores. Threads migrate between cores.

---

## Phase 9 — Scheduling Domains

**Goal**: Userspace can implement custom schedulers for their own threads.

### 9.1 Domain API
- [ ] `sys_sched_domain_create(quantum_us)`: create a scheduling domain with a budget
- [ ] The kernel schedules domains (not individual user threads within a domain)
- [ ] Domain manager thread receives its quantum and distributes it internally

### 9.2 Use Cases
- [ ] Go-style M:N green thread runtime as a scheduling domain
- [ ] Dedicated-core domain for latency-sensitive workloads
- [ ] Work-stealing pool domain for parallel compute

### 9.3 Enforcement
- [ ] If a domain exceeds its quantum → kernel preempts unconditionally
- [ ] Domains can request more/less quantum dynamically (kernel mediates)
- [ ] Priority inheritance across domain boundaries for IPC chains

### Milestone: A user-level scheduler manages green threads without kernel involvement.

---

## Phase 10 — LUCAS (Legacy UNIX Compatibility Abstraction System)

**Goal**: Run unmodified Linux/POSIX ELF binaries on sotOS.

LUCAS is a set of coordinated userspace servers that present a complete Linux illusion
to legacy binaries. It translates monolithic UNIX semantics into sotOS's decentralized,
capability-based primitives — entirely in Ring 3.

### 10.1 Syscall Interceptor (Trap Handler)
- [ ] Capture `syscall` instructions from the guest ELF binary in Ring 3
- [ ] Redirect to LUCAS translation engine instead of letting them reach Ring 0
- [ ] Map Linux syscall numbers (read=0, write=1, open=2, ...) to LUCAS handlers
- [ ] Handle the full lifecycle: `execve` → setup → syscall translation → `exit`

### 10.2 Capability Mapper (Ambient Authority Emulator)
- [ ] Maintain internal table: Linux file descriptors (FDs) → sotOS capabilities
- [ ] Emulate UID/GID/permission model on top of capabilities
- [ ] Map Linux PIDs to sotOS ThreadIds
- [ ] Hide CDT complexity from guest processes — present flat POSIX view
- [ ] Translate `open("/dev/...")` to capability lookups for device endpoints

### 10.3 VFS Bridge (Virtual File System Translator)
- [ ] Intercept POSIX file operations: `open`, `read`, `write`, `close`, `stat`, `lseek`
- [ ] Translate path-based access to Object Store (Layer 2) transactions
- [ ] Expose typed objects as flat byte streams (what POSIX expects)
- [ ] Implement `/proc` and `/sys` as synthetic views of sotOS state
- [ ] Support `opendir`/`readdir` for directory enumeration

### 10.4 Process & Memory Coordinator
- [ ] Emulate `fork()`: create new address space + CoW via VMM server
- [ ] Emulate `execve()`: parse ELF, map segments, transfer FD table
- [ ] Emulate `mmap()`/`munmap()`: delegate to VMM server via `sys_map`/`sys_unmap`
- [ ] Emulate `brk()` for heap growth
- [ ] Emulate `clone()` for thread creation via `sys_thread_create`
- [ ] Emulate `wait()`/`waitpid()` via IPC notifications

### 10.5 IPC & Network Translator
- [ ] Translate UNIX pipes → sotOS shared-memory channels (ring buffers)
- [ ] Translate UNIX signals → sotOS endpoint messages
- [ ] Translate UNIX sockets:
  - Small control messages → sotOS sync endpoints
  - High-throughput streams → sotOS async channels (zero-copy)
- [ ] Emulate `select()`/`poll()`/`epoll()` over sotOS IPC primitives

### 10.6 Security: Confinement by Design
- [ ] LUCAS processes run in a strict capability sandbox
- [ ] No ambient authority: a compromised Linux binary cannot escape the LUCAS illusion
- [ ] RCE inside LUCAS = attacker trapped in emulated UNIX, no access to sotOS primitives
- [ ] Optional: per-binary capability policy (restrict which "Linux files" map to which capabilities)

### Milestone: `ls`, `cat`, `grep` and a basic shell run unmodified on sotOS via LUCAS.

---

## Phase 11 — Filesystem & Storage

**Goal**: Persistent storage accessible through the object store interface.

### 10.1 Block Device Driver
- [ ] Virtio-blk driver (userspace, talks to QEMU)
- [ ] Block layer abstraction: read/write sectors through capabilities

### 10.2 Object Store
- [ ] Transactional object store (userspace service)
- [ ] Write-Ahead Log (WAL) for crash consistency
- [ ] Copy-on-Write snapshots for object versioning
- [ ] Schema-based typed objects with 128-bit OIDs

### 10.3 POSIX Compatibility
- [ ] VFS shim: translates open/read/write/close to object store operations
- [ ] Enough for basic utilities (shell, coreutils)

### Milestone: Data persists across reboots. Object store with transactional guarantees.

---

## Phase 12 — Networking & Distribution

**Goal**: Nodes communicate; IPC is transparent across the network.

### 11.1 Network Stack
- [ ] Virtio-net driver (userspace)
- [ ] Minimal IP/UDP/TCP stack (userspace service)
- [ ] Socket-like API through IPC endpoints

### 11.2 Remote IPC
- [ ] Transparent IPC proxy: local endpoint → network → remote endpoint
- [ ] Explicit failure semantics: `Result<T, RemoteError>` with timeouts
- [ ] OID resolution: distributed hash table for object location

### 11.3 Cluster Management
- [ ] Failure domains: process → node → cluster → swarm
- [ ] Raft consensus for critical shared state
- [ ] Service migration on node failure

### Milestone: Two sotOS nodes exchange IPC messages over the network.

---

## Phase 13 — Formal Verification & Hardening

**Goal**: Mathematical proof that the kernel is correct.

### 12.1 Verification
- [ ] Annotate kernel code with Verus/Prusti pre/post-conditions
- [ ] Prove: capability enforcement never bypassed
- [ ] Prove: frame allocator never double-allocates
- [ ] Prove: IPC transfer preserves message integrity
- [ ] Model check scheduler with TLA+ (no deadlocks, no starvation)

### 12.2 Hardware Security
- [ ] CHERI capability support (when hardware is available)
  - 128-bit fat pointers with hardware bounds checking
  - Spatial memory safety at instruction level
- [ ] IOMMU integration: device isolation for DMA
- [ ] Measured boot: TPM-backed chain of trust

### 12.3 Audit
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
  3    IPC Send/Recv/Call + extras    Phase 2         DONE (partial: no cap transfer, no benchmarks)
  4    IRQ Virtualization             Phase 3         TODO
  5    VMM Server                     Phase 2         TODO
  6    Init Service + ELF Loader      Phase 3,5       TODO
  7    Shared-Memory Channels         Phase 3         TODO (basic version done in Phase 3 extras)
  8    SMP (Multi-Core)               Phase 1         TODO
  9    Scheduling Domains             Phase 8         TODO
 10    LUCAS (UNIX Compat Layer)      Phase 6,7,11    TODO
 11    Filesystem + Object Store      Phase 6         TODO
 12    Networking + Distribution      Phase 6,11      TODO
 13    Verification + Hardening       Phase 3+        TODO
```

```
                         Phase 0 (DONE)
                              │
                         Phase 1 (DONE)
                        ╱          ╲
                Phase 2              Phase 8
                (DONE)               (SMP)
              ╱     ╲                   │
        Phase 3    Phase 5         Phase 9
        (DONE)     (VMM)      (Sched Domains)
        ╱    ╲        │
  Phase 4   Phase 7   │
  (IRQ)    (Channels)  │
        ╲    ╱        ╱
         Phase 6
    (Init + ELF Loader)
           │
     ┌─────┼─────┐
  Phase 11 │  Phase 12
  (Storage) │  (Network)
        ╲  │  ╱
       Phase 10
       (LUCAS)
           │
       Phase 13
    (Verification)
```

---

## Immediate Next Steps

Phases 0–3 are complete. The next unlocked phases are:

- **Phase 4 (IRQ Virtualization)**: full IRQ→IPC delivery with `sys_irq_register`/`sys_irq_ack`, userspace serial driver. Basic keyboard IRQ already works as a proof of concept.
- **Phase 5 (VMM Server)**: page fault delivery to userspace, full `sys_map`/`sys_unmap` with VMM policy. Bootstrap paging syscalls (`sys_frame_alloc`, `sys_map`) already exist.
- **Phase 8 (SMP)**: independent of Phases 4–7, can be started in parallel. Requires APIC, per-CPU state, and lock audit.
