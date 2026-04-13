# sotX — Microkernel Operating System

## Architecture
Verified microkernel (~10K LOC target) with selective exokernel bypass.
Five kernel primitives: scheduling, IRQ virtualization, IPC, capabilities, frame allocation.
Virtual memory managed in userspace (VMM server).

## Build & Run
```
just build    # compile kernel
just run      # build + create disk image + boot in QEMU (serial to terminal)
just run-gui  # same but with QEMU display window
just debug    # boot with GDB server (connect: gdb -ex "target remote :1234")
```

Manual steps:
```
cargo build --package sotos-kernel
python scripts/mkimage.py
"C:/Program Files/qemu/qemu-system-x86_64.exe" -drive format=raw,file=target/sotx.img -serial stdio -display none -no-reboot -m 256M
```

## Key Technical Details
- Target: `x86_64-unknown-none` with `-C relocation-model=static` (must be ET_EXEC, not ET_DYN)
- Boot: Limine v8 BIOS. Config: `boot/limine.conf`. `serial: yes` enables Limine serial output.
- Limine binaries: `limine/` dir (clone v8.x-binary branch). `limine.exe bios-install` writes bootloader.
- Image: `scripts/mkimage.py` — pure Python GPT+FAT32 image builder with LFN support.
- Nightly Rust for `build-std` and `abi_x86_interrupt`.

## Project Structure
- `kernel/` — The microkernel (Ring 0)
  - `arch/x86_64/` — CPU-specific: serial, GDT, IDT
  - `mm/` — Physical frame allocator (bitmap-based)
  - `cap/` — Capability table + CDT for delegation/revocation
  - `ipc/` — Endpoints (sync) + Channels (async, future)
  - `sched/` — Thread management, preemptive scheduler
- `libs/sotos-common/` — Shared kernel-userspace ABI (syscalls, errors)
- `services/` — Userspace servers (VMM, FS, drivers — future)
- `boot/` — Bootloader configuration (limine.conf)
- `scripts/` — Build tools (mkimage.py)
- `limine/` — Bootloader binaries (gitignored, clone separately)

## Conventions
- `kprintln!()` for kernel debug output (serial COM1)
- Capabilities are the ONLY way to access kernel objects
- No heap in kernel — fixed-size arrays, will add slab allocator later
- All subsystems behind spinlocks (`spin::Mutex`) — will optimize later
- Initialize serial FIRST in kmain() — before any assertions
