# LKL Architecture for sotOS

## 1. Problem Statement

### The Linux ABI Compatibility Wall

Clean-room Linux ABI emulation is architecturally unsustainable. There is no formal
specification for the Linux system call interface. What exists is the kernel source
itself, plus decades of accumulated behavior that userspace depends on. Emulating
this surface faithfully requires matching:

- Struct layouts (padding, alignment, size) for hundreds of structures
- Edge-case return values and errno semantics for 400+ syscalls
- Signal delivery timing and interaction with blocking calls
- epoll/poll/select readiness semantics and edge-triggered corner cases
- procfs/sysfs virtual filesystem content and format
- ioctl command encoding and per-driver response formats

**The symptom**: Each new application (Wine, git, htop, nano, busybox applets)
exposes a new batch of missing or subtly wrong syscall behaviors. Debugging
cycles grow superlinearly because fixes for one program can regress another.

### Industry Precedent: Everyone Hits This Wall

Every project that attempted clean-room Linux ABI emulation eventually
faced the same scaling problem:

| Project | Approach | Outcome |
|---------|----------|---------|
| WSL1 (Microsoft) | Kernel-mode Linux syscall translation in NT | Abandoned for WSL2 (real Linux kernel in VM) |
| SmartOS lx-brand (Joyent) | Linux syscall emulation in illumos kernel | Perpetual incomplete coverage, many apps broken |
| FreeBSD Linuxulator | Linux ABI layer in FreeBSD kernel | Works for simple apps, breaks on complex ones (Wine, Docker) |
| Darling (macOS) | Linux syscall translation for running Linux on macOS | Incomplete, stalled development |

The common pattern: initial progress is fast (basic syscalls are straightforward),
but the long tail of compatibility is effectively infinite. The only projects that
achieved full compatibility did so by running the real Linux kernel.

### Where sotOS Stands Today

LUCAS (Legacy UNIX Compatibility Abstraction System) currently handles ~130 Linux
syscall numbers in `child_handler.rs` with ~200 match arms. This is sufficient
for musl-static binaries (busybox, links, nano), Alpine dynamic binaries (git,
wget), and partial Wine support. But each new application requires weeks of
struct-padding fixes, missing ioctl stubs, and signal-timing adjustments.

The cost of maintaining this approach grows without bound.

---

## 2. Solution: LKL as LibOS

### What is LKL?

LKL (Linux Kernel Library) is the Linux kernel compiled as a static library
(`liblkl.a`). It is an official Linux kernel architecture (`arch/lkl/`) that
strips out hardware-specific code and exposes the kernel's functionality through
a host operations interface.

Key properties:

- **It IS Linux**: not an emulation, not a translation layer. The VFS, scheduler,
  networking stack, signal handling, and every other subsystem are the real kernel
  code, compiled from the same source tree.
- **Runs in Ring 3**: LKL executes entirely in userspace. It never touches
  privileged CPU state directly; instead it calls back into the host OS for
  threading, memory, and I/O.
- **~25 host operations**: The host OS implements a small, well-defined callback
  interface (`lkl_host_operations`). LKL calls these for thread creation,
  synchronization, memory allocation, timers, and disk/network I/O.
- **Bug-for-bug compatible**: Because `lkl_sys_write()` runs the same code path
  as a `write()` inside a normal Linux kernel, every struct layout, every errno,
  every edge case is correct by construction.

### Why LKL Fits sotOS

sotOS's core architectural principle is: **nothing in Ring 0 that can live in
userspace**. LKL is the purest expression of this principle applied to Linux
compatibility. The real Linux kernel runs entirely as a userspace library,
mediated by capabilities and IPC. The sotOS microkernel remains untouched ---
it continues to know nothing about files, sockets, or POSIX.

---

## 3. Three-Layer Architecture

```
+-------------------------------------------------------------+
|                                                             |
|  Layer 3: Application + LKL                    (Ring 3)     |
|                                                             |
|  Wine, busybox, glibc/musl apps, Alpine packages           |
|  Each process (or server) links/loads liblinux.so           |
|  LKL handles ALL POSIX semantics: VFS, signals, epoll,     |
|  sockets, mmap file-backed, /proc, /sys, ioctls, etc.      |
|                                                             |
+--------------------------+----------------------------------+
                           |
                      IPC messages
                           |
+--------------------------v----------------------------------+
|                                                             |
|  Layer 2: LUCAS Bridge                         (Ring 3)     |
|                                                             |
|  Thin IPC router — NOT a syscall emulator                   |
|  Exposes sotOS resources to LKL host_ops:                   |
|    - ObjectStore (block device backing)                     |
|    - Network queues (virtio-net via net service)            |
|    - Shared memory channels (frame-backed)                  |
|    - Timer/clock primitives                                 |
|                                                             |
+--------------------------+----------------------------------+
                           |
                      syscall (SYSCALL/SYSRET)
                           |
+--------------------------v----------------------------------+
|                                                             |
|  Layer 1: sotOS Kernel                         (Ring 0)     |
|                                                             |
|  Pure pipeline engine — unchanged                           |
|    - CPU scheduling (4-level MLQ + work stealing)           |
|    - IPC (sync endpoints + async channels)                  |
|    - Capability-based access control (CDT)                  |
|    - Physical frame allocation (bitmap)                     |
|    - IRQ virtualization                                     |
|                                                             |
+-------------------------------------------------------------+
```

The critical insight: Layer 2 shrinks from a 10,000+ line syscall emulator to
a ~500 line host operations adapter. LUCAS stops translating POSIX semantics
and becomes a thin bridge between LKL callbacks and sotOS IPC.

---

## 4. Phase 1 Architecture: Separate Service Model

Phase 1 runs LKL in a dedicated server process (`lkl-server`) that receives
forwarded syscalls via IPC. This is the minimal-risk integration path: Init's
existing child_handler forwards FS/net syscalls to the LKL server instead of
emulating them locally.

### Component Layout

```
lkl-server (C, freestanding)
  |
  +-- links liblkl.a (Linux kernel as static library)
  +-- implements lkl_host_operations callbacks
  +-- registers as "lkl" service via SvcRegister(130)
  +-- receives syscall-forwarding IPC messages
  +-- calls lkl_sys_*() and returns results
```

### Syscall Flow

```
Child process                 sotOS Kernel              Init (child_handler)
     |                            |                            |
     |--- syscall (e.g. open) --->|                            |
     |                            |--- redirect IPC msg ------>|
     |                            |                            |
     |                            |    +-- classify syscall    |
     |                            |    |   FS/net? --> forward |
     |                            |    |   brk/mmap? -> local  |
     |                            |    |   fork/signal? local  |
     |                            |                            |
     |                            |                     LKL Server
     |                            |                        |
     |                            |<-- IPC forward ------->|
     |                            |                        |
     |                            |                   lkl_sys_open()
     |                            |                        |
     |                            |                   host_ops.disk_read()
     |                            |                        |
     |                            |<-- IPC to virtio-blk ->| (sotOS IPC)
     |                            |                        |
     |                            |<-- reply (fd or err) --|
     |                            |                            |
     |<-- result in rax ----------|<-- reply ------------------|
```

### Syscall Classification: Forwarded vs. Local

| Category | Syscalls | Handled by |
|----------|----------|------------|
| Filesystem | open, read, write, close, stat, fstat, lseek, getdents64, rename, mkdir, unlink, readlink, openat, fstatat, faccessat, ioctl(disk), readv, writev, pread64, pwrite64, fallocate, ftruncate, fsync, statfs | LKL server |
| Networking | socket, bind, listen, accept, connect, send, recv, sendto, recvfrom, sendmsg, recvmsg, shutdown, getsockopt, setsockopt, poll, epoll_*, select | LKL server |
| Memory | brk, mmap, munmap, mprotect, mremap | Init (local) |
| Process | fork, clone, execve, exit, exit_group, wait4, waitid | Init (local) |
| Signals | rt_sigaction, rt_sigprocmask, rt_sigreturn, kill, tgkill, sigaltstack | Init (local) |
| Threading | clone(CLONE_THREAD), futex, set_tid_address, gettid | Init (local) |
| Identity | getpid, getppid, getuid, getgid, geteuid, getegid | Init (local) |
| Time | clock_gettime, gettimeofday, nanosleep | Init (local, RDTSC) |
| Info | uname, sysinfo, getrandom, prlimit64 | Init (local) |
| Procfs | open /proc/*, read /proc/* | LKL server (real procfs) |

### Fallback Mechanism

If the LKL service endpoint is not available (`LKL_EP_CAP == 0`), Init falls
back to the existing LUCAS emulation code. This allows incremental migration:

```rust
if lkl_ep_cap != 0 && is_forwarded_syscall(nr) {
    // Forward to LKL server
    let mut fwd = IpcMsg::empty();
    fwd.tag = nr;                    // syscall number
    fwd.regs[0..6].copy_from_slice(&args[0..6]);
    fwd.regs[6] = pid as u64;       // caller PID
    fwd.regs[7] = child_as_cap;     // AS cap for vm_read/vm_write
    let reply = sys::call(lkl_ep_cap, &fwd);
    // reply.regs[0] = result (or -errno)
} else {
    // Existing LUCAS emulation
    match nr { ... }
}
```

### Guest Memory Access

LKL syscalls that read/write userspace buffers (e.g., `read(fd, buf, count)`)
need access to the child process's address space. The forwarding message
includes the child's AS capability in `regs[7]`. The LKL server uses
`sys::vm_read(as_cap, guest_addr, local_buf, len)` and
`sys::vm_write(as_cap, guest_addr, local_buf, len)` to copy data across
address spaces via the kernel's HHDM mapping.

---

## 5. Phase 2 Vision: Per-Process LKL (LibOS Model)

Phase 2 eliminates the IPC forwarding overhead by loading LKL directly into
each child process's address space as `liblinux.so`.

### Architecture

```
+-----------------------------------------+
| Child Process Address Space              |
|                                          |
|  Application (.text, .data, heap, stack) |
|                                          |
|  liblinux.so (LKL as shared library)    |
|    - lkl_sys_*() functions               |
|    - Host ops call sotOS syscalls        |
|                                          |
+-----------------------------------------+
         |
    sotOS syscalls (frame_alloc, map, IPC)
         |
+-----------------------------------------+
| sotOS Kernel (Ring 0)                    |
+-----------------------------------------+
```

### How It Works

1. The kernel's syscall redirect intercepts Linux syscalls from the application
2. Instead of forwarding via IPC to Init, the redirect jumps to LKL's
   `lkl_sys_*()` entry point within the SAME address space
3. LKL processes the syscall internally (VFS lookup, socket operation, etc.)
4. When LKL needs I/O, its host_ops callbacks issue sotOS IPC to device services
5. The result returns to the application with zero IPC hops for pure computation

### Benefits

| Property | Phase 1 (IPC) | Phase 2 (in-process) |
|----------|---------------|----------------------|
| Syscall latency | ~2 IPC round trips | Direct function call |
| State isolation | Natural (separate AS) | Natural (separate AS, each has own LKL instance) |
| Memory overhead | One LKL server for all | LKL pages per process (can share .text via CoW) |
| Concurrency | Single-threaded server bottleneck | O(1) state isolation, no contention |

This is the true exokernel/LibOS model: each application carries its own
operating system personality. The sotOS kernel provides only multiplexing
(CPU, memory, IPC), and applications choose their own abstraction layer.

---

## 6. Host Operations Interface

LKL requires the host to implement `struct lkl_host_operations`. Each callback
maps to a sotOS primitive:

### Thread Management

| Host Op | Description | sotOS Implementation |
|---------|-------------|---------------------|
| `thread_create` | Create a new kernel thread | `sys::thread_create()` or `sys::thread_create_in()` |
| `thread_detach` | Detach thread (fire and forget) | No-op (sotOS threads are always detached) |
| `thread_join` | Wait for thread exit | `sys::recv()` on thread's notification cap |
| `thread_exit` | Terminate current thread | `sys::thread_exit()` |

### Synchronization

| Host Op | Description | sotOS Implementation |
|---------|-------------|---------------------|
| `sem_alloc` | Create a semaphore | `sys::notify_create()` (binary semaphore) |
| `sem_free` | Destroy a semaphore | Capability revocation |
| `sem_up` | Signal semaphore (V) | `sys::notify_signal(cap)` |
| `sem_down` | Wait on semaphore (P) | `sys::notify_wait(cap)` |
| `mutex_alloc` | Create a mutex | Spinlock in shared memory or notify cap |
| `mutex_lock` | Acquire mutex | Spin + `sys::yield_now()` fallback |
| `mutex_unlock` | Release mutex | Store-release + `sys::notify_signal()` |

### Memory

| Host Op | Description | sotOS Implementation |
|---------|-------------|---------------------|
| `mem_alloc` | Allocate host memory | `sys::frame_alloc()` + `sys::map()` from arena region |
| `mem_free` | Free host memory | `sys::unmap_free()` to return frame |

The LKL heap is backed by a contiguous virtual region (arena). The host_ops
allocator manages this arena, requesting physical frames from sotOS on demand.

### Timers

| Host Op | Description | sotOS Implementation |
|---------|-------------|---------------------|
| `timer_alloc` | Create a timer | Allocate slot in timer table |
| `timer_set_oneshot` | Arm one-shot timer | Record RDTSC deadline; polling thread checks |
| `timer_free` | Destroy timer | Free slot |
| `time` | Current time (ns) | RDTSC with assumed 2 GHz frequency (same as vDSO) |

### Console/Print

| Host Op | Description | sotOS Implementation |
|---------|-------------|---------------------|
| `print` | Debug output | `sys::debug_print()` (COM1 serial, byte at a time) |
| `panic` | Fatal error | Print message + `sys::thread_exit()` |

### I/O (Disk and Network)

LKL does not directly perform disk/network I/O through host_ops. Instead, LKL's
internal virtio drivers or custom block/net backends issue I/O requests that the
host translates to IPC messages:

| I/O Path | sotOS Mechanism |
|----------|----------------|
| Block read/write | IPC to virtio-blk service (existing) |
| Network TX/RX | IPC to net service (existing TCP/UDP/ICMP stack) |
| Initrd access | `sys::initrd_read()` (syscall 132) |

The existing sotOS device services (virtio-blk, net) are unchanged. LKL
interacts with them through the same IPC protocol that LUCAS uses today.

---

## 7. Syscall Forwarding Protocol

### IPC Message Format

sotOS IPC messages use the `IpcMsg` structure:

```rust
#[repr(C)]
pub struct IpcMsg {
    pub tag: u64,       // lower 32 bits = message tag, upper 32 = cap transfer
    pub regs: [u64; 8], // maps to rdx/r8/r9/r10/r12/r13/r14/r15
}
```

### Forwarding Encoding (Phase 1)

When Init forwards a Linux syscall to the LKL server:

```
Forward message:
  tag        = linux_syscall_number (e.g., 2 for open, 0 for read)
  regs[0]    = arg0 (rdi)
  regs[1]    = arg1 (rsi)
  regs[2]    = arg2 (rdx)
  regs[3]    = arg3 (r10)
  regs[4]    = arg4 (r8)
  regs[5]    = arg5 (r9)
  regs[6]    = caller_pid
  regs[7]    = caller_as_cap   (for vm_read/vm_write of guest buffers)

Reply message:
  tag        = 0 (success) or error indicator
  regs[0]    = syscall return value (positive = success, negative = -errno)
```

### Buffer Transfer Protocol

For syscalls that pass pointers to userspace buffers:

1. **Init copies path strings** before forwarding (already done by `copy_guest_path()`)
2. **LKL server uses `sys::vm_read/vm_write`** for data buffers (read/write/readv/writev)
3. **Large transfers** are chunked: the 64-byte IPC inline limit does not apply
   because `vm_read`/`vm_write` operate directly on the guest's address space
   via the kernel's HHDM (Higher Half Direct Map)

### Redirect Mechanism

The existing kernel-level syscall redirect (`RedirectSet = 110`) is unchanged.
The child process's `redirect_ep` sends Linux syscalls to Init, which then
decides whether to handle locally or forward to LKL. This two-hop path
(child -> Init -> LKL) is eliminated in Phase 2.

---

## 8. Address Space Layout (lkl-server)

The LKL server is a freestanding C binary loaded from the initrd. Its address
space is laid out to avoid conflicts with Init's existing mappings:

```
Address             Content                     Size
-----------         -------------------------   -----------
0x78000000          .text (lkl-server ELF)      ~8 MB
0x79000000          .data / .bss                ~4 MB
0x7A000000          LKL heap arena              128 MB
0x82000000          LKL stack pool (threads)    1 MB (16 stacks x 64 KB)
0x82100000          Host ops state tables       64 KB
                    (timers, semaphores, etc.)

--- Standard sotOS service layout ---
0x900000            Service stack               16 KB (4 pages)
0xB00000            BootInfo page               4 KB
0xC00000+           MMIO (if needed)            varies
```

The 128 MB arena at `0x7A000000` is the backing region for LKL's `mem_alloc`
host op. Physical frames are allocated on demand via `sys::frame_alloc()` and
mapped into this region. This is substantially larger than the existing LUCAS
heap (1 MB brk + mmap region) because LKL maintains internal VFS caches,
inode tables, dentry caches, and the network stack's socket buffers.

---

## 9. Preserved Guarantees

The transition to LKL preserves every security and architectural property
of sotOS:

| Property | Before (LUCAS emulation) | After (LKL) | Reason |
|----------|--------------------------|--------------|--------|
| Kernel purity | No POSIX in Ring 0 | No POSIX in Ring 0 | LKL runs in Ring 3 |
| Kernel size | ~10K LOC | ~10K LOC (unchanged) | No kernel modifications needed |
| Capability security | All access gated | All access gated | LKL uses capabilities via host_ops |
| W^X enforcement | Enforced | Enforced | sys::protect() unchanged |
| Process isolation | Separate CR3 per process | Separate CR3 per process | Address spaces unchanged |
| IPC-only communication | Enforced | Enforced | LKL I/O goes through IPC |
| POSIX compatibility | Partial (~130 syscalls) | 100% bug-for-bug | It IS the Linux kernel |
| Stack canaries | Enabled | Enabled | Compiler-inserted, unchanged |
| ASLR | Stack jitter via RDTSC | Stack jitter via RDTSC | Unchanged |

### What Changes

| Aspect | Before | After |
|--------|--------|-------|
| Syscall emulation code | ~10K LOC in child_handler.rs | ~500 LOC host_ops adapter |
| Debugging effort | Per-syscall, per-application | One-time host_ops implementation |
| New app support | Weeks of struct/errno fixes | Zero (if LKL supports the syscall, it works) |
| Binary size | Small (Rust init service) | Larger (liblkl.a is ~30 MB) |
| Memory footprint | Low (LUCAS is minimal) | Higher (LKL caches, internal state) |
| Build complexity | Rust only | Rust + cross-compiled Linux kernel |

The trade-off is clear: significantly more memory and binary size in exchange
for complete, correct Linux compatibility with near-zero ongoing maintenance.

---

## 10. Industry Precedents

The pattern of running a real OS kernel as a library or server on top of a
microkernel is well-established in systems research and production:

### L4Linux (TU Dresden / UNSW)

The canonical example. L4Linux runs a full Linux kernel as a userspace server
on top of the L4 microkernel family (Fiasco.OC, seL4). Linux system calls go
through L4 IPC to the Linux server. Used in production by Genode OS and
automotive systems. Demonstrates that the approach scales to full Linux
compatibility with acceptable overhead (~5-10% vs native).

### Mach + BSD Server (macOS / NeXTSTEP)

macOS runs a BSD personality server on top of the Mach microkernel. All POSIX
semantics (VFS, sockets, signals) live in the BSD server. The Mach layer
handles only IPC, VM, and scheduling. This is the most commercially successful
microkernel-based OS, shipping on billions of devices.

### MIT Exokernel (Engler & Kaashoek, 1995)

The original theoretical foundation. The exokernel multiplexes hardware
resources (CPU, memory, disk) and delegates all abstraction to application-level
library operating systems (LibOS). Each application links its own LibOS with its
preferred abstractions. LKL on sotOS is a direct realization of this model:
sotOS is the exokernel, LKL is the LibOS.

### SGX-LKL (Imperial College London)

Runs LKL inside Intel SGX enclaves to provide a full Linux environment in a
trusted execution context. Demonstrates that LKL's host_ops interface is
clean enough to work in extremely constrained environments (no direct syscalls,
limited memory, no threading support from the host). If LKL works inside SGX,
it can work on sotOS.

### Unikraft LKL Port

Unikraft uses LKL as one of its backend kernel options for unikernels, proving
that LKL integrates cleanly with non-Linux host environments. The host_ops
adaptation layer is straightforward and well-documented.

### Rump Kernels (NetBSD Anykernel)

The NetBSD equivalent of LKL. Rump kernels extract NetBSD kernel subsystems
(VFS, networking, drivers) into userspace libraries. Used by Rumprun unikernels
and the pho toolkit. Validates the concept that a real kernel's subsystems can
run reliably as libraries.

### Common Thread

All of these systems share the same insight: **do not re-implement OS semantics;
reuse a proven kernel's implementation and adapt the interface**. The host
operations interface is always small (~20-30 functions) relative to the syscall
surface it replaces (~400 calls). This is a fundamentally better engineering
trade-off than clean-room reimplementation.

---

## Summary

LKL integration transforms sotOS from a microkernel with an ever-growing
compatibility layer into a microkernel with a finished compatibility layer.
The sotOS kernel remains pure (5 primitives, ~10K LOC, capability-secured).
LUCAS evolves from a syscall translator into a thin bridge. And the real Linux
kernel, running in Ring 3 as a library, provides the POSIX semantics that
applications expect --- not approximately, but exactly.
