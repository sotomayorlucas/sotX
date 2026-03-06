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
- [x] Real-time / deadline scheduling class (EDF — earliest deadline first)
- [x] Kernel watchdog timer (per-CPU heartbeat tracking, stale detection)
- [x] Memory-mapped I/O framework (generic MMIO helper with volatile reads/writes)
- [x] Page cache / buffer cache (64-entry LRU, write-back dirty tracking)
- [x] Lazy page mapping / demand paging (fault-driven allocation)

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
- [x] Dynamic binary execution — PT_INTERP, ld-musl loader, file-backed mmap, initrd FDs
- [x] GNU nano 8.2 running as dynamically-linked musl binary (read-only mode)

### Security
- [x] W^X enforcement (NX on writable pages, SYS_PROTECT for mprotect-like)
- [x] Stack guard pages (unmapped page below each process stack)
- [x] ASLR (stack base randomized, RDTSC-seeded xorshift64, 0-64KB jitter)
- [x] Stack canaries (`-Z stack-protector=strong`, fixed sentinel, ~1800 check sites)
- [x] Multiuser support (user accounts, SHA-256 password hashing, permission enforcement)

### Drivers
- [x] Virtio-BLK (legacy MMIO, DMA, disk I/O)
- [x] PS/2 keyboard driver (separate process, shared KB ring)
- [x] Virtio-NET (RX/TX, SLIRP networking)
- [x] NVMe SSD — MMIO controller init, sector read/write, PRP List multi-page transfers, IPC service protocol
- [x] NVMe: interrupt-driven completion (notify_wait-based, polling fallback)
- [x] USB xHCI — full xHCI init, HID boot protocol keyboard → PS/2 scancodes → shared KB ring
- [x] xHCI: multi-device support (per-device contexts, slot allocation, port enumeration)
- [x] xHCI: USB hub support (hub descriptor, port power/reset, recursive enumeration)
- [x] xHCI: hot-plug / disconnect handling (port status change events, device removal cleanup)
- [x] Audio (AC97) — mixer, BDL DMA, PCM playback, volume control, sample rate config
- [x] AHCI / SATA storage — HBA init, port enumeration, IDENTIFY DEVICE, READ/WRITE DMA EXT (48-bit LBA)
- [x] USB mass storage — BBB (Bulk-Only Transport), SCSI commands, sector read/write
- [x] Mouse input — PS/2 (3/4-byte packets, IntelliMouse scroll) + USB HID (boot protocol)

### Filesystem
- [x] Object store (transactional, WAL-based crash recovery)
- [x] VFS shim (path resolution, file descriptors)
- [x] Large file support (streaming I/O, 512 KB max)
- [x] Directory hierarchy (parent_oid, mkdir/rmdir/cd/pwd)
- [x] CoW snapshots (refcounted blocks, snap create/restore/delete/list)
- [x] File permissions / ownership model (permissions, owner_uid, owner_gid on DirEntry)
- [x] NVMe-backed ObjectStore (BlockDevice trait, NVMe IPC backend)
- [x] `chmod` / `chown` syscalls (syscall 150/151)
- [x] Permission enforcement on open/read/write/exec
- [x] Larger directory table (128 entries, FS_VERSION=4)
- [x] File timestamps (real clock — Unix epoch seconds, created/modified/accessed)

### Networking
- [x] IP/UDP/TCP/ICMP stack (libs/sotos-net)
- [x] ARP, DHCP client, DNS resolver
- [x] Socket API for LUCAS (socket/connect/send/recv/close)
- [x] TCP retransmission with exponential backoff (saved segments, max 5 retries)
- [x] ping, wget, traceroute shell commands
- [x] TCP congestion control (Reno: slow start, congestion avoidance, loss recovery)
- [x] TCP receive window scaling (RFC 7323 negotiation)
- [x] IPv6 support (header parse/build, ICMPv6 echo, neighbor solicitation/advertisement)
- [x] TLS / crypto primitives (SHA-256, HMAC-SHA256, ChaCha20, X25519)
- [x] HTTP client library (HTTP/1.1 GET/POST, response parsing)

### Shell (LUCAS)
- [x] Linux ABI compatibility layer (syscall redirection)
- [x] Pipe operator (`cmd1 | cmd2`) with buffer-based capture
- [x] Background jobs (`command &` via clone)
- [x] Environment variables (`export`, `$VAR` expansion, `env`)
- [x] Shell scripting (if/then/fi, for/in/do/done)
- [x] Builtins: cat, head, tail, grep, top, echo, ls, cd, pwd, mkdir, rmdir, etc.
- [x] Framebuffer console + keyboard input
- [x] Job control (`jobs`, `fg`, `bg`, Ctrl+C / Ctrl+Z signals)
- [x] Command history (up/down arrow, 64-entry circular buffer)
- [x] Tab completion (file path + builtin command name completion)
- [x] `wc`, `sort`, `uniq`, `diff` builtins
- [x] Redirect operators (`>`, `>>`, `<`)
- [x] Here documents (`<<EOF`)
- [x] Shell functions (define/call, positional args $1-$8, return)

### Tech Debt
- [x] Assembly blob migration (all 11 removed)
- [x] IRQ sharing (up to 4 handlers per IRQ line)
- [x] Separate processes: VMM, kbd, net, nvme, xhci (each with own CR3)

---

## CRITICO (bloqueadores de calidad)
- [x] C1: Testing framework — 18-test Linux ABI suite (hello-linux), auto-run on boot
- [ ] C2: SMP scheduler race — hang intermitente con >1 CPU (known issue, reliable single-core)
- [ ] C3: nano file write — child_handler necesita open(O_WRONLY|O_CREAT|O_TRUNC), write(fd), ftruncate, rename para que nano pueda guardar archivos (actualmente solo read-only desde initrd)
- [ ] C4: CWD en child processes — getcwd devuelve "/" pero stat(".") falla; nano muestra "Directory '.' does not exist". Necesita que fstatat/stat de "." devuelva un directorio válido
- [ ] C5: PF log noise — page faults de demand paging (dynamic linker stack growth) contaminan la salida serial. Suprimir PF logs para faults manejados exitosamente en userspace
- [ ] C6: VFS access desde child processes — child_handler no tiene acceso al VFS/ObjectStore; necesita IPC al lucas_handler o acceso directo para crear/escribir/leer archivos persistentes

## ALTO (funcionalidad seria)
- [x] A1: child_handler completo — brk/mmap/munmap/mprotect, FD table, /dev/null+zero, dup/dup2, pipe, openat, getrandom, prlimit64, ioctl, getcwd, gettimeofday, sysinfo
- [x] A2: Signals reales — rt_sigaction stores handlers, sigprocmask tracks masks, SIGCHLD delivery, default actions, -EINTR on pending signals
- [x] A3: Binario dinámico musl — hello_dynamic + nano 8.2 corren bajo LUCAS via PT_INTERP + ld-musl
- [ ] A4: Busybox milestone — correr un binario musl-static real bajo LUCAS (hello-musl placeholder, 64 bytes)

## MEDIO (completitud UNIX)
- [x] M1: mmap file-backed — seek to offset, read file content into mapped pages, restore position
- [x] M2: /dev/null, /dev/zero, /dev/urandom — supported in both lucas_handler and child_handler openat

---

## Research & Development: Evolución a SO de 4ta Generación

### Multikernel Architecture
- [x] Per-core IPC queues (eliminate global TicketMutex on endpoint pool)
- [x] Per-core mini-kernels (local scheduling + IPC, no shared mutable state)
- [x] PCIe-style message passing between cores (IPI-based wake, lock-free transfer)

### Software Fault Isolation via WASM
- [x] Bare-metal WASM runtime in kernel (no_std interpreter, i32/i64/control flow)
- [x] Compile services to WASM modules (bytecode loading from initrd, import/start sections)
- [x] Ring 0 execution with SFI guarantees (metered execution, instruction limits, memory bounds)

### Transparent Distributed Computing ("Swarm OS")
- [x] IPC over network (message serialization + routing layer)
- [x] Live process migration (checkpoint thread state + transfer to remote node)
- [x] Unified distributed VFS (object store replication across nodes, conflict resolution)

### Native Heterogeneous Computing
- [x] CPU+GPU+NPU scheduler (compute target abstraction in thread model)
- [x] Tensor/shader as first-class IPC payloads (typed message extensions)

### Formal Mathematical Verification
- [x] TLA+ specification of IPC protocol (safety + liveness properties)
- [x] TLA+ specification of capability system (no unauthorized access)
- [x] TLA+ specification of scheduler (no starvation, bounded latency)

---

## Dream Goals
- [x] GUI — framebuffer window compositor + mouse input (16 windows, z-ordering, decorations)
- [x] Port a real application — Lua 5.4 interpreter (lexer, compiler, stack-based VM, tables, stdlib)
- [ ] Self-hosting (port the Rust compiler or a simpler language toolchain)
- [x] UEFI boot support — design + type definitions (UEFI boot flow, GOP, memory map)
- [ ] 64-bit long mode from scratch (replace Limine with custom bootloader)
- [x] Multiuser support (user accounts, SHA-256 auth, login, permission enforcement)
- [x] Package manager / app store for sotOS binaries (registry, deps, install/uninstall)
