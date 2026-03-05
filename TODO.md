# sotOS — TODO

## Completed

### Core Kernel
- [x] GDT, IDT, serial, physical frame allocator, slab allocator
- [x] Capability system (generation-checked pool, delegation/revocation)
- [x] Preemptive scheduler with per-core run queues + work stealing
- [x] SYSCALL/SYSRET, PIC, LAPIC timer (~100 Hz)
- [x] SMP boot (4 CPUs), per-CPU GDT+TSS, per-CPU data (GS base)
- [x] Priority-based scheduling — 4-level MLQ (realtime/high/normal/low)
- [x] Per-process resource limits (CPU ticks, memory pages, enforced in scheduler + frame_alloc)
- [x] Kernel panic handler — recursive prevention, thread info, stack trace via RBP chain, NMI broadcast
- [x] Conditional debug prints — `kdebug!` macro gated behind `verbose` feature flag
- [x] Multi-core IPC — cross-core endpoint delivery via global TicketMutex + scheduler wake

### IPC & Services
- [x] Sync endpoints (rendezvous, send/recv/call semantics)
- [x] Async channels (bounded ring buffers)
- [x] Service registry (kernel-side name→endpoint map, SvcRegister/SvcLookup syscalls)
- [x] Capability transfer via IPC (GRANT right, upper 32 bits of tag)

### Userspace
- [x] ELF loader (initrd CPIO → load segments → spawn user thread)
- [x] Multi-address-space support (per-process CR3, MapInto, ThreadCreateIn)
- [x] Dynamic linking (sotos-ld, dl_open/dl_sym/dl_close, PIC .so support)
- [x] Userspace process spawning (InitrdRead/BootInfoWrite syscalls, spawn_process())

### Security
- [x] W^X enforcement (NX on writable pages, SYS_PROTECT for mprotect-like)
- [x] Stack guard pages (unmapped page below each process stack)
- [x] ASLR (stack base randomized, RDTSC-seeded xorshift64, 0-64KB jitter)
- [x] Stack canaries (`-Z stack-protector=strong`, fixed sentinel, ~1800 check sites)

### Drivers
- [x] Virtio-BLK (legacy MMIO, DMA, disk I/O)
- [x] PS/2 keyboard driver (separate process, shared KB ring)
- [x] Virtio-NET (RX/TX, SLIRP networking)
- [x] NVMe SSD — MMIO controller init, sector read/write, PRP List multi-page transfers, IPC service protocol
- [x] USB xHCI — full xHCI init, HID boot protocol keyboard → PS/2 scancodes → shared KB ring

### Filesystem
- [x] Object store (transactional, WAL-based crash recovery)
- [x] VFS shim (path resolution, file descriptors)
- [x] Large file support (streaming I/O, 512 KB max)
- [x] Directory hierarchy (parent_oid, mkdir/rmdir/cd/pwd)
- [x] CoW snapshots (refcounted blocks, snap create/restore/delete/list)
- [x] File permissions / ownership model (permissions, owner_uid, owner_gid on DirEntry)

### Networking
- [x] IP/UDP/TCP/ICMP stack (libs/sotos-net)
- [x] ARP, DHCP client, DNS resolver
- [x] Socket API for LUCAS (socket/connect/send/recv/close)
- [x] TCP retransmission with exponential backoff (saved segments, max 5 retries)
- [x] ping, wget, traceroute shell commands

### Shell (LUCAS)
- [x] Linux ABI compatibility layer (syscall redirection)
- [x] Pipe operator (`cmd1 | cmd2`) with buffer-based capture
- [x] Background jobs (`command &` via clone)
- [x] Environment variables (`export`, `$VAR` expansion, `env`)
- [x] Shell scripting (if/then/fi, for/in/do/done)
- [x] Builtins: cat, head, tail, grep, top, echo, ls, cd, pwd, mkdir, rmdir, etc.
- [x] Framebuffer console + keyboard input

### Tech Debt
- [x] Assembly blob migration (all 11 removed)
- [x] IRQ sharing (up to 4 handlers per IRQ line)
- [x] Separate processes: VMM, kbd, net, nvme, xhci (each with own CR3)

---

## In Progress / Next Steps

### Driver Improvements
- [ ] NVMe: interrupt-driven completion (replace polling loop)
- [ ] xHCI: multi-device support (enumerate all connected ports, per-device contexts)
- [ ] xHCI: USB hub support
- [ ] xHCI: hot-plug / disconnect handling

### Filesystem Enhancements
- [ ] NVMe-backed ObjectStore (replace virtio-blk backend with NVMe IPC)
- [ ] `chmod` / `chown` syscalls (permissions infrastructure is in place)
- [ ] Permission enforcement on open/read/write/exec
- [ ] Larger directory table (currently 32 entries max)
- [ ] File timestamps (real clock, not tick counter)

### Networking Enhancements
- [ ] TCP congestion control (slow start, congestion avoidance)
- [ ] TCP receive window scaling
- [ ] IPv6 support
- [ ] TLS / crypto primitives
- [ ] HTTP client library

### Kernel Enhancements
- [ ] Real-time / deadline scheduling class
- [ ] Kernel watchdog timer
- [ ] Memory-mapped I/O framework (generic MMIO helper for drivers)
- [ ] Page cache / buffer cache for disk I/O
- [ ] Lazy page mapping / demand paging

### Shell / Userspace
- [ ] Job control (`jobs`, `fg`, `bg`, Ctrl+C / Ctrl+Z signals)
- [ ] Command history (up/down arrow)
- [ ] Tab completion
- [ ] `wc`, `sort`, `uniq`, `diff` builtins
- [ ] Redirect operators (`>`, `>>`, `<`)
- [ ] Here documents (`<<EOF`)
- [ ] Shell functions

### New Drivers
- [ ] Audio (AC97 or Intel HDA)
- [ ] AHCI / SATA storage
- [ ] USB mass storage
- [ ] Mouse input (PS/2 or USB HID)

---

## Research & Development: Evolución a SO de 4ta Generación

### Multikernel Architecture
- [x] Per-core IPC queues (eliminate global TicketMutex on endpoint pool)
- [x] Per-core mini-kernels (local scheduling + IPC, no shared mutable state)
- [x] PCIe-style message passing between cores (IPI-based wake, lock-free transfer)

### Software Fault Isolation via WASM
- [x] Bare-metal WASM runtime in kernel (no_std interpreter, i32/i64/control flow)
- [ ] Compile services to WASM modules (bytecode loading from initrd)
- [ ] Ring 0 execution with SFI guarantees (memory bounds checking, stack isolation)

### Transparent Distributed Computing ("Swarm OS")
- [x] IPC over network (message serialization + routing layer)
- [ ] Live process migration (checkpoint thread state + transfer to remote node)
- [ ] Unified distributed VFS (object store replication across nodes)

### Native Heterogeneous Computing
- [x] CPU+GPU+NPU scheduler (compute target abstraction in thread model)
- [ ] Tensor/shader as first-class IPC payloads (typed message extensions)

### Formal Mathematical Verification
- [x] TLA+ specification of IPC protocol (safety + liveness properties)
- [x] TLA+ specification of capability system (no unauthorized access)
- [x] TLA+ specification of scheduler (no starvation, bounded latency)

---

## Dream Goals
- [ ] GUI — framebuffer window compositor + mouse input
- [ ] Port a real application (e.g., Lua, MicroPython, or a simple text editor)
- [ ] Self-hosting (port the Rust compiler or a simpler language toolchain)
- [ ] UEFI boot support (currently BIOS-only via Limine)
- [ ] 64-bit long mode from scratch (replace Limine with custom bootloader)
- [ ] Multiuser support (login, user accounts, permission enforcement)
- [ ] Package manager / app store for sotOS binaries
