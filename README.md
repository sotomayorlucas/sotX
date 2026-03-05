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
- **IPC**: synchronous endpoints (L4-style register transfer) + lock-free SPSC shared-memory channels
- **Userspace VMM**: page faults handled by a userspace server, not the kernel
- **Multi-address-space**: each process gets its own CR3 + page tables
- **SMP**: runs on 1-4+ CPU cores with per-CPU LAPIC timers, IPI, and per-core state

## Current State

All core kernel primitives are implemented and tested on x86_64.

### Kernel
- Preemptive round-robin scheduler with per-core queues and work stealing
- SYSCALL/SYSRET Ring 3 transitions with GS-relative per-CPU state
- Synchronous IPC endpoints with capability transfer
- Async channels (kernel ring buffers) + lock-free SPSC (userspace shared memory)
- IRQ virtualization with shared IRQ support — drivers run in userspace
- Demand paging via userspace VMM server (separate process, own CR3)
- ELF loader + CPIO initramfs
- Slab allocator (kernel heap) with per-CPU caches and multi-page support
- Multi-address-space: per-process page tables with MapInto/UnmapFrom syscalls

### Userspace Services (each in separate address space)
- **init** — VMM server, LUCAS syscall interceptor, framebuffer console
- **kbd** — PS/2 keyboard driver (IRQ 1, shared ring buffer with init)
- **net** — Virtio-NET driver + full IP stack (ARP, ICMP, UDP, TCP)
- **lucas-shell** — Linux-ABI compatible shell (fork/exec/signals/FD table)

### Storage
- Virtio-BLK driver with transactional object store (WAL, bitmap, directory)
- VFS shim with file handles, read/write, stat

### Networking
- Virtio-NET driver (legacy v0.9.5)
- Ethernet + ARP (32-entry cache) + IPv4
- ICMP echo (send + reply) — **can ping Google (8.8.8.8)!**
- UDP (16 sockets, echo server on port 5555)
- TCP (16 connections, 3-way handshake, data transfer, FIN teardown, echo on port 7)

### LUCAS — Linux-ABI Compatibility
- Syscall interceptor: fork, exec, waitpid, exit, kill
- FD table (32 entries): open, close, read, write, stat, lseek, dup/dup2
- Memory: brk, mmap, munmap
- Signals: Ctrl+C, kill command
- VFS bridge to object store
- Shell builtins: ls, cat, echo, ps, uptime, kill, touch, rm

### Display
- Framebuffer console (1024x768, VGA 8x16 font, 128x48 text grid)
- Serial output (COM1)

## Build & Run

Requires: Rust nightly, Python 3, QEMU, [just](https://github.com/casey/just)

```bash
just run       # build + boot in QEMU (serial output)
just run-gui   # with QEMU display window (framebuffer + keyboard)
just run-net   # with virtio-net networking (SLIRP)
just run-smp   # with 4 CPU cores
just run-blk   # with virtio-blk test disk
just debug     # with GDB server (connect: gdb -ex "target remote :1234")
```

### Testing Networking
```bash
# From host, while sotOS is running with `just run-net`:
echo hello | nc -u localhost 5555   # UDP echo (port 5555)
echo hello | nc localhost 7777      # TCP echo (port 7777 → guest port 7)
```

The net service automatically pings 8.8.8.8 on boot via the QEMU SLIRP gateway.

## Project Structure

```
kernel/                 The microkernel (Ring 0)
  arch/x86_64/          CPU-specific: serial, GDT, IDT, LAPIC, SYSCALL, per-CPU
  mm/                   Physical frame allocator + slab allocator
  cap/                  Capability table + CDT for delegation/revocation
  ipc/                  Endpoints (sync) + Channels (async) + Notifications
  sched/                Per-core scheduler with work stealing
  sync/                 Ticket spinlocks + lock ordering
libs/
  sotos-common/         Shared kernel-userspace ABI (syscalls, errors, SPSC)
  sotos-pci/            Userspace PCI bus enumeration
  sotos-virtio/         Virtio drivers (virtqueue, blk, net)
  sotos-objstore/       Transactional object store + VFS
  sotos-net/            Protocol stack (eth, arp, ip, icmp, udp, tcp)
services/
  init/                 Init process (VMM, LUCAS interceptor, framebuffer)
  kbd/                  PS/2 keyboard driver (separate process)
  net/                  Network driver + protocol handler (separate process)
  lucas-shell/          Linux-ABI compatible shell
boot/                   Bootloader configuration (limine.conf)
scripts/                Build tools (mkimage.py, mkinitrd.py, mkdisk.py)
```

## Key Technical Details

- **Target**: `x86_64-unknown-none` with `-C relocation-model=static` (must be ET_EXEC)
- **Boot**: Limine v8 BIOS. Config: `boot/limine.conf`
- **Nightly Rust** for `build-std` and `abi_x86_interrupt`
- **Image builder**: `scripts/mkimage.py` — pure Python GPT+FAT32 with LFN support
- **Initrd**: `scripts/mkinitrd.py` — CPIO newc archive with init + shell + kbd + net

## Roadmap

See [TODO.md](TODO.md) for pending work.

## License

All rights reserved.
