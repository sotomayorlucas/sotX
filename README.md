# sotOS — Secure Object Transactional Operating System

A microkernel operating system written from scratch in Rust, designed around five
kernel primitives: scheduling, IRQ virtualization, IPC, capabilities, and frame
allocation. Virtual memory is managed entirely in userspace.

**sotOS** stands for **Secure Object Transactional Operating System** — reflecting
its capability-based security model, object-oriented kernel design, and the
transactional object store at its core.

## Architecture

- **Verified microkernel** (~10K LOC target) with selective exokernel bypass
- **Capability-based security**: every kernel object accessed through capabilities with delegation and revocation
- **Per-core scheduling**: ticket-locked run queues with work stealing across CPUs
- **EDF deadline scheduling**: real-time threads with earliest-deadline-first priority
- **Per-core IPC**: each core has its own endpoint pool (no global lock contention), cross-core delivery via mailbox + IPI
- **IPC**: synchronous endpoints (L4-style register transfer) + lock-free SPSC shared-memory channels
- **Network-transparent IPC**: routing layer for distributed computing ("Swarm OS") with message serialization
- **Typed IPC payloads**: tensor, shader, and image descriptors for heterogeneous compute dispatch
- **Heterogeneous scheduling**: CPU/GPU/NPU compute targets in thread model
- **WASM SFI**: bare-metal WebAssembly interpreter for software fault isolation (no_std, 50+ opcodes, metered execution)
- **Formal verification**: TLA+ specifications of IPC, capabilities, and scheduler with safety proofs
- **Userspace VMM**: page faults handled by a userspace server, not the kernel
- **Multi-address-space**: each process gets its own CR3 + page tables
- **SMP**: runs on 1-4+ CPU cores with per-CPU LAPIC timers, IPI, and per-core state
- **Multiuser**: user accounts with SHA-256 password hashing, UID/GID permission model
- **Live migration**: thread checkpoint/restore for process migration across nodes

## Current State

All core kernel primitives are implemented and tested on x86_64.

### Kernel
- Preemptive round-robin scheduler with per-core queues and work stealing
- **EDF deadline scheduling**: real-time threads with earliest-deadline-first, automatic period renewal
- **Kernel watchdog timer**: per-CPU heartbeat tracking, stale detection (>500 ticks)
- **Per-core IPC endpoint pools**: each CPU core has its own endpoint pool with core-encoded handles — eliminates global lock contention
- **Cross-core mailbox + IPI**: per-core bounded message queues with LAPIC IPI for immediate cross-core wake
- **Heterogeneous compute targets**: threads tagged with CPU/GPU/NPU target; scheduler filters by compute target
- SYSCALL/SYSRET Ring 3 transitions with GS-relative per-CPU state
- Synchronous IPC endpoints with capability transfer
- Async channels (kernel ring buffers) + lock-free SPSC (userspace shared memory)
- **Network-transparent IPC routing**: routing table maps endpoints to remote nodes, 80-byte wire message format
- **Typed IPC payloads**: TensorDesc, ShaderDesc, ImageDesc for heterogeneous compute
- IRQ virtualization with shared IRQ support — drivers run in userspace
- Demand paging via userspace VMM server (separate process, own CR3)
- **Lazy page mapping**: fault-driven physical allocation (DemandPageTable with 256 regions)
- **Page cache**: 64-entry LRU sector cache with write-back dirty tracking
- **MMIO framework**: generic volatile read/write helpers for driver development
- ELF loader + CPIO initramfs
- Slab allocator (kernel heap) with per-CPU caches and multi-page support
- Multi-address-space: per-process page tables with MapInto/UnmapFrom syscalls
- Service registry: kernel-side name→endpoint map (SvcRegister/SvcLookup syscalls)
- Userspace process spawning: InitrdRead/BootInfoWrite syscalls + ELF parser
- Dynamic linking: userspace linker (dl_open/dl_sym/dl_close) with PIC .so support
- **Multiuser support**: user accounts, SHA-256 password auth, UID/GID tracking
- **Live process migration**: thread checkpoint/restore with memory region serialization

### Userspace Services (each in separate address space)
- **init** — VMM server, LUCAS syscall interceptor, framebuffer console, process spawner
- **kbd** — PS/2 keyboard driver (IRQ 1, shared ring buffer with init)
- **xhci** — USB xHCI host controller driver (multi-device, hub support, hot-plug)
- **net** — Virtio-NET driver + full IP stack with IPC command interface
- **nvme** — NVMe SSD driver (interrupt-driven completion, sector read/write, PCI discovery)
- **vmm** — Demand paging server (page fault handler for init's address space)
- **hello** — Minimal test process (spawned from userspace via spawn_process)
- **lucas-shell** — Linux-ABI compatible shell (fork/exec/signals/FD table/functions/job control)

### Storage
- Virtio-BLK driver with transactional object store (WAL, bitmap, directory)
- NVMe SSD driver — interrupt-driven MMIO hardware driver (controller init, admin/IO queues, sector read/write)
- **AHCI/SATA driver** — HBA initialization, port enumeration, IDENTIFY DEVICE, DMA EXT 48-bit LBA
- **USB mass storage** — BBB (Bulk-Only Transport), SCSI commands over USB
- VFS shim with file handles, read/write, stat, chmod/chown
- **NVMe-backed ObjectStore** — BlockDevice trait with NVMe IPC backend
- **128-entry directory table** (FS_VERSION=4), real Unix timestamps, permission enforcement
- Page cache (64-entry LRU, write-back)
- **Distributed VFS** — object store replication across nodes, sync log, conflict resolution

### Networking
- Virtio-NET driver (legacy v0.9.5)
- Ethernet + ARP (32-entry cache) + IPv4
- **IPv6** — header parse/build, ICMPv6 echo, neighbor solicitation/advertisement
- ICMP echo (send + reply) — **can ping Google (8.8.8.8)!**
- UDP (16 sockets, echo server on port 5555)
- TCP (16 connections, 3-way handshake, data transfer, FIN teardown, echo on port 7)
- **TCP congestion control** — Reno (slow start, congestion avoidance, loss recovery)
- **TCP window scaling** — RFC 7323 negotiation in SYN/SYN-ACK
- DNS resolver (A-record queries to QEMU SLIRP DNS at 10.0.2.3)
- DHCP client (Discover/Offer/Request/Ack, falls back to 10.0.2.15)
- **TLS / crypto primitives** — SHA-256, HMAC-SHA256, ChaCha20, X25519 (Curve25519)
- **HTTP client** — HTTP/1.1 GET/POST, response parsing
- IPC bridge: net↔init communication via service registry + IPC commands
- Socket API for LUCAS shell (socket/connect/send/recv/close)
- Shell commands: `ping`, `wget`, `resolve`, `traceroute` (all accept hostnames)

### Security
- **W^X enforcement**: SYS_MAP/MAP_INTO/MAP_OFFSET auto-add NX bit to writable pages
- **SYS_PROTECT**: mprotect-like syscall (134) for post-mapping permission changes, W^X enforced
- **Stack guard pages**: unmapped page below each process stack (triggers page fault on overflow)
- **ASLR**: stack base randomized with RDTSC-seeded xorshift64 (0–64 KB jitter)
- **Stack canaries**: `-Z stack-protector=strong` on kernel + all services (~1800 check sites per binary)
- **Multiuser**: user accounts with SHA-256 password hashing, UID/GID permission enforcement
- **chmod/chown syscalls**: Unix-style permission model (owner/group/other, 9-bit rwx)

### LUCAS — Linux-ABI Compatibility
- Syscall interceptor: fork, exec, waitpid, exit, kill
- FD table (32 entries): open, close, read, write, stat, lseek, dup/dup2
- Socket FDs: socket, connect, sendto, recvfrom (routed to net service via IPC)
- Memory: brk, mmap, munmap
- Signals: Ctrl+C (SIGINT), Ctrl+Z (SIGTSTP), kill command
- VFS bridge to object store
- Custom syscalls: DNS resolve (200), traceroute hop (201), chmod (150), chown (151)
- Shell builtins: ls, cat, echo, ps, uptime, kill, touch, rm, ping, wget, resolve, traceroute, uname, help, wc, sort, uniq, diff, jobs, fg, bg, history
- **Job control**: jobs table (16 slots), fg/bg, Ctrl+C/Ctrl+Z signal delivery
- **Command history**: 64-entry circular buffer, up/down arrow navigation
- **Tab completion**: file path + builtin name completion
- **Redirect operators**: `>`, `>>`, `<` with combined redirects
- **Here documents**: `<<DELIM` syntax for inline stdin
- **Shell functions**: define/call with positional args ($1-$8), return statement

### Input / Display
- USB xHCI keyboard driver (multi-device enumeration, HID boot protocol, 116+ key mapping)
- PS/2 keyboard driver (IRQ 1, scancode set 1)
- **Mouse input**: PS/2 (3/4-byte, IntelliMouse scroll wheel) + USB HID boot protocol
- Framebuffer console (1024x768, VGA 8x16 font, 128x48 text grid)
- **GUI window compositor**: 16 windows, z-ordering, decorations, mouse cursor, event system
- Serial output (COM1)

### Audio
- **AC97 audio driver**: codec initialization, mixer volume control, BDL DMA, PCM playback, sample rate config

### Dynamic Linking
- Userspace linker (`libs/sotos-ld/`): dl_open, dl_sym, dl_close
- PIC shared library support (ET_DYN ELFs with relocations)
- W^X compatible: pages mapped RW for loading, then changed to R+X via SYS_PROTECT
- Test library (`libs/sotos-testlib/`) verified: `add(3,4)=7`, `mul(6,7)=42`

### WASM Runtime (Software Fault Isolation)
- Bare-metal `no_std` WebAssembly bytecode interpreter (`libs/sotos-wasm/`)
- Full WASM binary parser (type, function, memory, global, export, import, start, code sections)
- Stack-based execution: 1024-value operand stack, 64-level call depth
- 50+ opcodes: i32/i64 arithmetic, comparison, bitwise, control flow, memory
- SFI guarantee: every memory load/store bounds-checked against linear memory
- **Metered execution**: instruction counting, configurable limits (SfiRuntime)
- **Host function interface**: register up to 16 host functions callable from WASM
- Linear memory up to 1 MiB (16 × 64 KiB WASM pages)

### Formal Verification
- TLA+ specification of IPC protocol (`formal/ipc.tla`): no duplicate delivery, single receiver
- TLA+ specification of capability system (`formal/capabilities.tla`): monotonic rights, revocation completeness
- TLA+ specification of scheduler (`formal/scheduler.tla`): mutual exclusion, no starvation

### Embedded Applications
- **Lua 5.4 interpreter** (`libs/sotos-lua/`): lexer, compiler, stack-based VM, tables, string/math stdlib
- **Package manager** (`libs/sotos-pkg/`): package registry, dependency resolution, install/uninstall

### Distributed Computing ("Swarm OS")
- Network-transparent IPC routing with 80-byte wire message format
- **Live process migration**: thread checkpoint/restore with memory region serialization
- **Distributed VFS**: object store replication across nodes, sync log, conflict resolution

## Build & Run

Requires: Rust nightly, Python 3, QEMU, [just](https://github.com/casey/just)

```bash
just run        # build + boot in QEMU (serial output)
just run-gui    # with QEMU display window (framebuffer + keyboard)
just run-net    # with virtio-net networking (SLIRP)
just run-smp    # with 4 CPU cores
just run-blk    # with virtio-blk test disk
just run-nvme   # with NVMe SSD test disk
just run-xhci   # with USB xHCI controller + keyboard
just run-full   # ALL devices (virtio-blk, virtio-net, NVMe, xHCI, AC97, AHCI, 512MB, SMP4)
just debug      # with GDB server (connect: gdb -ex "target remote :1234")
just flash DISK=/dev/sdX  # flash to USB drive for real hardware
```

### Testing Networking
```bash
# From host, while sotOS is running with `just run-net`:
echo hello | nc -u localhost 5555   # UDP echo (port 5555)
echo hello | nc localhost 7777      # TCP echo (port 7777 → guest port 7)
```

From the sotOS shell (`just run-net`):
```
$ resolve google.com        # DNS lookup → 142.251.x.x
$ ping google.com           # ICMP ping (resolves hostname)
$ wget http://example.com/  # HTTP GET (DNS + TCP)
$ traceroute 10.0.2.2       # ICMP traceroute with TTL probes
```

### Booting on Real Hardware
```bash
just flash DISK=/dev/sdX    # flash to USB drive
```
Requirements: x86_64 CPU, BIOS/CSM boot enabled, Secure Boot disabled, 256MB+ RAM.

## Project Structure

```
kernel/                 The microkernel (Ring 0)
  arch/x86_64/          CPU-specific: serial, GDT, IDT, LAPIC, SYSCALL, per-CPU
  mm/                   Physical frame allocator + slab allocator + paging + page cache + MMIO + demand paging
  cap/                  Capability table + CDT for delegation/revocation
  ipc/                  Endpoints (sync) + Channels (async) + Notifications + Mailbox + Routing + Typed Payloads
  sched/                Per-core scheduler with work stealing + EDF deadline scheduling
  sync/                 Ticket spinlocks + lock ordering
  svc_registry.rs       Service name → endpoint registry
  watchdog.rs           Per-CPU heartbeat watchdog timer
  migrate.rs            Live process migration (checkpoint/restore)
  user.rs               Multiuser support (accounts, auth, UID/GID)
  boot_uefi.rs          UEFI boot protocol type definitions (design)
libs/
  sotos-common/         Shared kernel-userspace ABI (syscalls, errors, SPSC, ELF parser)
  sotos-pci/            Userspace PCI bus enumeration
  sotos-virtio/         Virtio drivers (virtqueue, blk, net)
  sotos-objstore/       Transactional object store + VFS + distributed VFS
  sotos-net/            Protocol stack (eth, arp, ip, ipv6, icmp, udp, tcp, dns, dhcp, crypto, http)
  sotos-ld/             Userspace dynamic linker (dl_open, dl_sym, dl_close)
  sotos-testlib/        PIC test shared library for dynamic linking verification
  sotos-nvme/           NVMe SSD driver library (MMIO regs, queues, controller, interrupt-driven I/O)
  sotos-xhci/           xHCI USB host controller library (TRBs, rings, ports, HID keyboard, hub, hot-plug)
  sotos-wasm/           Bare-metal WASM interpreter (SFI, no_std, 50+ opcodes, metered execution)
  sotos-audio/          AC97 audio driver (mixer, BDL DMA, PCM playback)
  sotos-ahci/           AHCI/SATA storage driver (HBA, port enumeration, DMA EXT)
  sotos-usb-storage/    USB mass storage (BBB protocol, SCSI commands)
  sotos-mouse/          Mouse input driver (PS/2 + USB HID, event ring buffer)
  sotos-gui/            GUI window compositor (windows, z-ordering, decorations, drawing primitives)
  sotos-lua/            Lua 5.4 interpreter (lexer, compiler, VM, tables, stdlib)
  sotos-pkg/            Package manager (registry, dependencies, install/uninstall)
services/
  init/                 Init process (VMM, LUCAS interceptor, framebuffer, process spawner)
  kbd/                  PS/2 keyboard driver (separate process)
  xhci/                 USB xHCI keyboard driver (separate process)
  net/                  Network driver + protocol handler (separate process)
  nvme/                 NVMe SSD driver (separate process)
  vmm/                  Demand paging VMM server (separate process)
  hello/                Minimal test process (spawned from userspace)
  lucas-shell/          Linux-ABI compatible shell (job control, history, functions, redirects)
boot/                   Bootloader configuration (limine.conf)
scripts/                Build tools (mkimage.py, mkinitrd.py, mkdisk.py, mksharedlib.py)
formal/                 TLA+ formal specifications (IPC, capabilities, scheduler)
docs/                   Technical paper (LaTeX, CLRS-style)
```

## Key Technical Details

- **Target**: `x86_64-unknown-none` with `-C relocation-model=static` (must be ET_EXEC)
- **Boot**: Limine v8 BIOS. Config: `boot/limine.conf`
- **Nightly Rust** for `build-std`, `abi_x86_interrupt`, and `-Z stack-protector=strong`
- **Image builder**: `scripts/mkimage.py` — pure Python GPT+FAT32 with LFN support
- **Initrd**: `scripts/mkinitrd.py` — CPIO newc archive with all services + shared libs
- **Shared libraries**: `scripts/mksharedlib.py` — staticlib (.a) → PIC .so conversion
- **NVMe test disk**: `scripts/mknvmedisk.py` — 64 MiB raw disk with test marker

## Roadmap

See [TODO.md](TODO.md) for pending work.
See [docs/MEMORY_BUDGET.md](docs/MEMORY_BUDGET.md) for the kernel static memory inventory.

## License

All rights reserved.
