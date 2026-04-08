# Rump Kernel Adaptation Guide

## 1. What is a Rump Kernel?

A rump kernel is a NetBSD kernel subsystem compiled to run in userspace.
The concept originates from the NetBSD "anykernel" architecture designed
by Antti Kantee: the same kernel source code can be compiled either as a
traditional monolithic kernel or as a set of userspace libraries.

### 1.1 Key Properties

- **Real kernel code**: Not an emulation or reimplementation. The VFS, TCP/IP
  stack, device drivers, and other subsystems are the actual NetBSD kernel
  source, compiled with a userspace-compatible runtime.
- **Modular extraction**: Individual subsystems can be used independently.
  You can use the VFS without networking, or networking without the VFS.
- **Hypercall interface**: The rump kernel communicates with its host
  environment through a well-defined set of ~30 hypercalls (`rumpuser_*`).
  The host implements these to provide threading, memory, synchronization,
  and I/O.
- **Mature and tested**: Rump kernels have been in development since 2007
  and are used in production by Rumprun unikernels and various testing
  frameworks.

### 1.2 Why Rump Kernels for sotBSD

sotBSD's BSD personality layer uses rump kernels to provide POSIX/BSD
semantics without any kernel-side implementation:

1. The SOT kernel knows nothing about files, sockets, or processes.
2. A rump kernel running in Ring 3 provides the complete BSD VFS,
   networking stack, and device driver framework.
3. The rumpuser hypercall interface maps to SOT primitives (channels,
   capabilities, secure objects).
4. Bug-for-bug compatibility with NetBSD syscall semantics, with zero
   ongoing maintenance burden on the sotBSD kernel.

---

## 2. The rumpuser Interface

The rumpuser interface consists of approximately 30 functions that the host
must implement. They fall into five categories.

### 2.1 Thread Management

| Function | Description | SOT Mapping |
|----------|-------------|-------------|
| `rumpuser_thread_create` | Create a new thread | `domain_enter` + thread creation |
| `rumpuser_thread_exit` | Terminate current thread | Thread exit syscall |
| `rumpuser_thread_join` | Wait for thread completion | `chan_recv` on exit notification |
| `rumpuser_curlwp` | Get current LWP pointer | Thread-local storage (FS_BASE) |
| `rumpuser_set_curlwp` | Set current LWP pointer | TLS write |

### 2.2 Synchronization

| Function | Description | SOT Mapping |
|----------|-------------|-------------|
| `rumpuser_mutex_init` | Create a mutex | Allocate futex word in shared SO |
| `rumpuser_mutex_enter` | Lock mutex | Spin + futex_wait on SO |
| `rumpuser_mutex_tryenter` | Try-lock mutex | Atomic CAS on SO |
| `rumpuser_mutex_exit` | Unlock mutex | Store-release + futex_wake |
| `rumpuser_rw_init` | Create reader-writer lock | Allocate RW futex in shared SO |
| `rumpuser_rw_enter` | Acquire RW lock | Read: shared; Write: exclusive |
| `rumpuser_rw_exit` | Release RW lock | Store + wake |
| `rumpuser_cv_init` | Create condition variable | Allocate notify channel |
| `rumpuser_cv_wait` | Wait on CV | `chan_recv` with mutex release |
| `rumpuser_cv_signal` | Signal one waiter | `chan_send` to first waiter |
| `rumpuser_cv_broadcast` | Signal all waiters | `chan_send` to all waiters |

### 2.3 Memory

| Function | Description | SOT Mapping |
|----------|-------------|-------------|
| `rumpuser_malloc` | Allocate host memory | `so_create` + frame alloc into arena |
| `rumpuser_free` | Free host memory | `so_destroy` + frame free |
| `rumpuser_anonmmap` | Anonymous mmap | Frame alloc + map at arena offset |

### 2.4 I/O

| Function | Description | SOT Mapping |
|----------|-------------|-------------|
| `rumpuser_bio` | Block I/O request | `chan_send` to virtio-blk service |
| `rumpuser_ioconf_*` | Device configuration | Static config table |

### 2.5 Clock and Misc

| Function | Description | SOT Mapping |
|----------|-------------|-------------|
| `rumpuser_clock_gettime` | Get current time | RDTSC via vDSO |
| `rumpuser_clock_sleep` | Sleep for duration | Timer + `chan_recv` |
| `rumpuser_getparam` | Query host parameters | Static answers (page size, ncpu) |
| `rumpuser_putchar` | Debug character output | `debug_print` syscall (COM1) |
| `rumpuser_exit` | Fatal exit | Domain termination |
| `rumpuser_dprintf` | Debug printf | Serial output loop |

---

## 3. Mapping Table: rumpuser to SOT

The following table provides the concrete mapping from each rumpuser
hypercall to SOT kernel primitives and userspace mechanisms.

| rumpuser Call | SOT Primitive | Implementation Notes |
|---------------|---------------|----------------------|
| thread_create | Thread create in domain | New thread shares domain AS |
| mutex_enter | Futex on SO word | Spin first, then futex_wait |
| cv_wait | Channel recv + mutex | Release lock, recv, re-acquire |
| malloc | Frame alloc + map | Arena allocator in domain AS |
| bio | Channel send | Async send to block device service |
| clock_gettime | RDTSC / vDSO | 2 GHz assumed, same as LUCAS |
| clock_sleep | Timer + notification | Set timer, wait on notify cap |

### 3.1 Arena Allocator

The rump kernel's memory allocator (`rumpuser_malloc` / `rumpuser_free`)
is backed by a contiguous virtual region (arena) within the domain's
address space. Physical frames are allocated on demand via `so_create`
(which internally calls the frame allocator) and mapped into the arena.

Arena layout:
```
RUMP_ARENA_BASE (e.g., 0x7A000000)
  |
  +-- [page 0] [page 1] [page 2] ... [page N]
  |
  +-- Free list header at arena base
  |
RUMP_ARENA_END  (e.g., 0x7A000000 + 128 MiB)
```

### 3.2 Block I/O Path

```
Rump VFS
  |
  +-- rumpuser_bio(dev, offset, buf, len, op)
      |
      +-- Serialize into IPC message:
      |     tag = BIO_READ or BIO_WRITE
      |     regs[0] = sector number
      |     regs[1] = sector count
      |     regs[2] = buffer physical address (via frame_phys)
      |
      +-- chan_send(blk_service_cap, msg)
      |
      +-- chan_recv(blk_service_cap, reply)
      |
      +-- Copy data to/from rump's buffer if needed
```

---

## 4. Build Instructions

### 4.1 Prerequisites

- NetBSD source tree (or rump kernel release tarball)
- Cross-compiler targeting x86_64-elf (freestanding)
- sotBSD build environment (Rust nightly, just, Python 3)

### 4.2 Building the Rump Components

```bash
# 1. Clone NetBSD source (rump kernels are part of the NetBSD tree)
git clone https://github.com/NetBSD/src netbsd-src

# 2. Build rump kernel components for freestanding target
cd netbsd-src
./build.sh -m amd64 -T /path/to/tools tools
./build.sh -m amd64 rump

# 3. Extract the static libraries
ls lib/librump*.a
# librumpvfs.a     - VFS subsystem
# librumpnet.a     - Networking stack
# librumpdev.a     - Device framework
# librump.a        - Core rump runtime

# 4. Cross-compile rumpuser implementation for sotBSD
cd /path/to/sotbsd/services/rump-host
make RUMP_LIBS=/path/to/netbsd-src/lib
```

### 4.3 Integrating with sotBSD

The rump host service is a freestanding binary loaded from the initrd,
similar to the LKL server:

```
services/rump-host/
  src/
    main.rs         -- Service entry, IPC registration
    rumpuser.c      -- rumpuser_* implementations (calls SOT syscalls)
    arena.rs        -- Arena memory allocator
  Cargo.toml
  build.rs          -- Links librump*.a
```

The service registers as "rump" via `SvcRegister(130)` and receives
forwarded BSD syscalls via IPC.

---

## 5. Testing Strategy

### 5.1 Unit Tests (Host-Side)

Test the rumpuser implementation in isolation on the host (Linux/macOS)
using mock SOT primitives:

```bash
cd tests/integration
cargo test -- --test-threads=1 rump
```

Tests verify:
- Arena allocator correctness (alloc, free, fragmentation).
- Mutex and CV semantics (lock ordering, wake correctness).
- BIO request serialization and deserialization.

### 5.2 Integration Tests (QEMU)

Boot sotBSD with the rump host service and run NetBSD test programs:

```bash
just run-rump-test
```

Test sequence:
1. Rump host registers as "rump" service.
2. Test binary opens a file via rump VFS.
3. Reads and writes data.
4. Verifies data persistence across close/reopen.
5. Tests directory operations (mkdir, readdir, unlink).

### 5.3 Conformance Tests

Run the NetBSD ATF (Automated Testing Framework) test suite through
the rump personality:

- VFS tests: create, read, write, rename, unlink, symlink, hardlink.
- Network tests: socket, bind, connect, send, recv.
- Device tests: block device read/write, character device I/O.

### 5.4 Stress Tests

- Concurrent file creation and deletion from multiple domains.
- High-throughput block I/O (sustained read/write).
- Lock contention (many threads competing for rump mutexes).
- Memory pressure (arena exhaustion and recovery).

---

## 6. Known Limitations

1. **Signal handling**: Rump kernels assume the host can deliver async
   signals. SOT's signal model differs; the rumpuser adapter must
   translate between notification-based SOT signals and POSIX signals.

2. **Clock resolution**: The vDSO clock assumes 2 GHz TSC frequency.
   Rump code that requires precise wall-clock time may need NTP or
   PTP integration through a network personality.

3. **Driver support**: Only block devices (via virtio-blk) are currently
   supported. Network devices require the rump networking stack plus
   a rumpuser_shmif or similar backend.

4. **Memory overhead**: The rump kernel maintains its own internal caches
   (buffer cache, name cache, inode cache). The arena must be sized
   generously (128 MiB or more) to avoid cache pressure.
