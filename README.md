# sotOS — Secure Object Transactional Operating System

A microkernel operating system written from scratch in Rust, designed around five
kernel primitives: scheduling, IRQ virtualization, IPC, capabilities, and frame
allocation. Virtual memory is managed entirely in userspace.

**sotOS** stands for **Secure Object Transactional Operating System** — reflecting
its capability-based security model, object-oriented kernel design, and the planned
transactional object store at its core.

## Architecture

- **Verified microkernel** (~10K LOC target) with selective exokernel bypass
- **Capability-based security**: every kernel object accessed through capabilities with delegation and revocation
- **Per-core scheduling**: ticket-locked run queues with work stealing across CPUs
- **IPC**: synchronous endpoints (L4-style register transfer) + lock-free SPSC shared-memory channels
- **Userspace VMM**: page faults handled by a userspace server, not the kernel
- **SMP**: runs on 1-4+ CPU cores with per-CPU LAPIC timers, IPI, and per-core state

## Current State

All core kernel primitives are implemented and tested on x86_64:

- Preemptive round-robin scheduler with per-core queues and work stealing
- SYSCALL/SYSRET Ring 3 transitions with GS-relative per-CPU state
- Synchronous IPC endpoints with capability transfer
- Async channels (kernel ring buffers) + lock-free SPSC (userspace shared memory)
- IRQ virtualization: keyboard and serial drivers run in userspace
- Demand paging via userspace VMM server
- ELF loader + CPIO initramfs
- Slab allocator (kernel heap) with multi-page support
- Typed SPSC channel wrappers for compile-time safe IPC
- IPC latency and throughput benchmarks

## Build & Run

Requires: Rust nightly, Python 3, QEMU, [just](https://github.com/casey/just)

```bash
just run       # build + create disk image + boot in QEMU (serial to terminal)
just run-smp   # same but with 4 CPU cores
just run-gui   # with QEMU display window
just debug     # boot with GDB server (connect: gdb -ex "target remote :1234")
```

Manual steps:
```bash
# Build userspace
cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static')" cargo build

# Build kernel
cargo build --package sotos-kernel

# Create initrd
python scripts/mkinitrd.py --output target/initrd.img --file init=services/init/target/x86_64-unknown-none/debug/sotos-init

# Create disk image
python scripts/mkimage.py --kernel target/x86_64-unknown-none/debug/sotos-kernel --initrd target/initrd.img --output target/sotos.img

# Boot
qemu-system-x86_64 -drive format=raw,file=target/sotos.img -serial stdio -display none -no-reboot -m 256M
```

## Project Structure

```
kernel/                 The microkernel (Ring 0)
  arch/x86_64/          CPU-specific: serial, GDT, IDT, LAPIC, SYSCALL, per-CPU
  mm/                   Physical frame allocator + slab allocator
  cap/                  Capability table + CDT for delegation/revocation
  ipc/                  Endpoints (sync) + Channels (async) + Notifications
  sched/                Per-core scheduler with work stealing
  sync/                 Ticket spinlocks
libs/sotos-common/      Shared kernel-userspace ABI (syscalls, errors, SPSC, typed channels)
services/init/          First Rust userspace program (SPSC demo + benchmarks)
boot/                   Bootloader configuration (limine.conf)
scripts/                Build tools (mkimage.py, mkinitrd.py)
```

## Key Technical Details

- **Target**: `x86_64-unknown-none` with `-C relocation-model=static` (must be ET_EXEC)
- **Boot**: Limine v8 BIOS. Config: `boot/limine.conf`
- **Nightly Rust** for `build-std` and `abi_x86_interrupt`
- **Image builder**: `scripts/mkimage.py` — pure Python GPT+FAT32 with LFN support

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full development plan. Phases 0-8 are complete.
Next up: scheduling domains, filesystem/storage, and the LUCAS UNIX compatibility layer.

## License

All rights reserved.
