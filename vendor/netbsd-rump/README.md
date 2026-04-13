# SOT Rump Hypervisor (`rumpuser_sot`)

Adaptation layer mapping NetBSD rump kernel hypercalls to SOT exokernel primitives.

## Architecture

The rump kernel requires ~30 `rumpuser_*` functions (the "hypervisor") to interact with
its host.  The standard implementation (`librumpuser`) uses pthreads, malloc, mmap, etc.
`rumpuser_sot.c` replaces all of that with SOT syscalls:

| Rump concept | SOT mapping |
|---|---|
| Threads | `SYS_THREAD_CREATE(40)` / `SYS_THREAD_EXIT(42)` + notification-based join |
| Mutexes | Atomic spinlock + `SYS_NOTIFY_WAIT(71)` / `SYS_NOTIFY_SIGNAL(72)` |
| RW locks | Atomic reader count + writer flag + notification |
| Cond vars | Generation counter + notification |
| `malloc` / `free` | Arena bump allocator backed by `SYS_FRAME_ALLOC(20)` + `SYS_MAP(22)` |
| `mmap` / `munmap` | Direct frame allocation + mapping |
| Block I/O | IPC to `blk` service via `SYS_CALL(3)` |
| Clock | RDTSC (2 GHz assumed) |
| Random | RDRAND instruction + xorshift64 fallback |
| Console | `SYS_DEBUG_PRINT(255)` (serial COM1) |
| Dynamic loader | No-op (static linking) |

## Files

- `rumpuser_sot.h` -- Internal structures, SOT syscall wrappers, arena interface
- `rumpuser_sot.c` -- Full implementation of all rumpuser functions
- `Makefile` -- Build rules for freestanding cross-compilation

## Building

```
make                    # default: x86_64-elf-gcc
make CC=clang           # use Clang
make check              # syntax-check only
```

The output is `rumpuser_sot.o`, which is linked with the rump kernel object files
and the sotX server binary.

## Arena allocator

64 MiB at `0x40000000`, backed by SOT physical frames.  Bump allocation with
16-byte alignment and a size-tagged free list for reuse.

## Limitations

- Single-CPU: `RUMPUSER_PARAM_NCPU` returns 1 (matches sotX default).
- Clock resolution limited by RDTSC granularity and assumed 2 GHz frequency.
- No host filesystem: `rumpuser_open` returns ENOENT; all components must be
  statically linked.
- Synchronous block I/O: `rumpuser_bio` completes inline and calls `biodone`
  immediately.
