# Linux ABI ownership map — Phase 0 inventory

**Generated**: 2026-04-14 (baseline for lucas/child_handler deprecation).
**Source of truth**: `services/init/src/{lucas_handler,child_handler}.rs`, `services/init/src/syscalls/*`.

## 1. Handler size baseline (freeze point for grep-gate)

| File | LOC | `SYS_*` match arms | Delegation calls to `syscalls::*` |
|---|---:|---:|---:|
| `services/init/src/lucas_handler.rs` | 1064 | **108** | 112 |
| `services/init/src/child_handler.rs` | 2626 | **137** | 140 |
| **Total** | **3690** | **245** | **252** |

(Arm counts via the freeze-gate regex `^\s*(SYS_\w+|\d+)\s*=>` with Python re.MULTILINE; grep produces a stricter 87/137 because of different `\s` semantics at line start. The gate uses the Python count as baseline.)

Unique `SYS_*` constants referenced across both: **211**
Linux-ABI constants defined in `libs/sotos-common/src/linux_abi.rs`: **~225** (198 cited in MEMORY; +27 newer — includes io_uring, tee, splice, utimensat).

## 2. Overlap (duplicated lucas↔child)

- **Shared** (appear in both handlers): **134** syscalls
- **LUCAS-only**: **4** — all PID-1 debug/registry primitives
- **child-only**: **73** — real-Linux process syscalls

### LUCAS-only (move to `lucas_shell.rs`)
| Syscall | Purpose |
|---|---|
| `SYS_DEBUG_FREE_FRAMES` (252) | `meminfo` builtin |
| `SYS_SVC_LOOKUP` (131) | `services` builtin |
| `SYS_THREAD_COUNT` (142) | `threads` builtin |
| `SYS_TKILL` | shell signal delivery helper |

These are **not Linux ABI**. They stay in LUCAS's mini-handler. Dispatcher never sees them.

### child-only (Linux-ABI proper, goes through `LinuxBackend`)
`SYS_ALARM`, `SYS_CAPSET`, `SYS_CHMOD`, `SYS_COPY_FILE_RANGE`, `SYS_CREAT`, `SYS_DEBUG_PROFILE_CR3`, `SYS_EXECVE`, `SYS_FADVISE64`, `SYS_FALLOCATE`, `SYS_FCHMOD`, `SYS_FCHMODAT`, `SYS_FCHOWN`, `SYS_FCHOWNAT`, `SYS_FLOCK`, `SYS_FORK`, `SYS_FUTIMESAT`, `SYS_GETGROUPS`, `SYS_GETITIMER`, `SYS_GETPRIORITY`, `SYS_GET_ROBUST_LIST`, `SYS_INOTIFY_ADD_WATCH`, `SYS_INOTIFY_RM_WATCH`, `SYS_IO_*` (5), `SYS_LCHOWN`, `SYS_LINK`, `SYS_LINKAT`, `SYS_MADVISE`, `SYS_MINCORE`, `SYS_MKNOD`, `SYS_MKNODAT`, `SYS_MLOCK`, `SYS_MLOCKALL`, `SYS_MSYNC`, `SYS_MUNLOCK`, `SYS_MUNLOCKALL`, `SYS_PAUSE`, `SYS_PERSONALITY`, `SYS_RT_SIGQUEUEINFO`, `SYS_SCHED_*` (6), `SYS_SETFSGID`, `SYS_SETFSUID`, `SYS_SETGID`, `SYS_SETGROUPS`, `SYS_SETITIMER`, `SYS_SETPRIORITY`, `SYS_SETREGID`, `SYS_SETRESGID`, `SYS_SETRESUID`, `SYS_SETREUID`, `SYS_SETRLIMIT`, `SYS_SETUID`, `SYS_SHMAT`, `SYS_SHMCTL`, `SYS_SHMGET`, `SYS_SIGNAL_TRAMPOLINE`, `SYS_SPLICE`, `SYS_SYMLINK`, `SYS_SYMLINKAT`, `SYS_TEE`, `SYS_UNSHARE`, `SYS_UTIMENSAT`, `SYS_UTIMES`, `SYS_VFORK`, `SYS_WAITID`.

## 3. Dispatcher `static mut` footprint

### lucas_handler.rs — **0** ← already clean
### child_handler.rs — **8**
| Name | Kind | Phase to migrate |
|---|---|---|
| `LKL_FDS[MAX_PROCS][2]` (128 bits/proc) | LKL fd bitmap | Phase 3 — move to `lkl_fdset.rs`, widen to 256 |
| `RETRY_COUNT[16]` | pipe retry debug | Phase 2 — SpinLock |
| `PIPE_STALL[16]` | pipe stall counter | Phase 2 — SpinLock |
| `PIPE_STALL_ID[16]` | pipe id per proc | Phase 2 — SpinLock |
| `DEADLOCK_EOF[16]` | deadlock detector mark | Phase 2 — SpinLock |
| `PWC_FIRED` (fn-local) | one-shot debug | Phase 1 — delete (dead debug) |
| `AS_TRACE_N[16]` (fn-local) | AS trace debug | Phase 1 — delete |
| `MP_COUNT` (fn-local) | mprotect debug | Phase 1 — delete |

All other `static mut` in `services/init/src/` belong to other modules (`fd.rs:24`, `vfs_service.rs:2`, `fork.rs:3`, `framebuffer.rs:10`, `vma.rs:1`, etc.) and are **out of scope** for the dispatcher cleanup. Phase 2's `FORK_STACK_BUF`/`PIPE_WRITE_REFS`/`FUTEX_ADDR` live in `fork.rs` + `fd.rs` respectively.

## 4. Existing delegation infrastructure (to reuse, not rebuild)

| Module | Arms owned | Called from |
|---|---|---|
| `syscalls::fs` (+ `fs/*`: vfs_open, vfs_read_write, vfs_path, fs_pipe, fs_dir, fs_initrd, fs_sotfs, fs_special, fs_stdio, fs_fd, vfs_delete, vfs_metadata) | ~40 arms (read/write/open/close/fstat/lseek/ioctl/readv/writev/access/pipe/dup/dup2/dup3/fcntl/ftruncate/fsync/getcwd/chdir/rename/mkdir/rmdir/unlink/readlink/getdents64/openat/fstatat/readlinkat/faccessat/unlinkat/mkdirat/pread64/pwrite64/preadv/pwritev/pipe2/sendfile/umask) | both |
| `syscalls::mm` | brk/mmap/munmap/mprotect/mremap/madvise/shmget/shmat/shmctl | both |
| `syscalls::net` | poll/ppoll/socket/connect/sendto/sendmsg/recvfrom/recvmsg/bind/listen/getsockopt/shutdown/epoll_ctl/socketpair | both |
| `syscalls::task` | getpid/gettid/getppid/kill/wait4/setpgid/getpgrp/setsid | both |
| `syscalls::info` | nanosleep/sysinfo/prlimit64/getrandom/futex/getrusage/getrlimit/times/prctl/capget/pause/sched_yield/identity_stubs | both |
| `syscalls::signal` | check_pending_signals, sigaction helpers | both (via `check_pending_signals` in loop head) |
| `syscalls::context::SyscallContext` | struct carrying pid/ep_cap/child_as_cap + all per-group FD/VMA references | both (via `make_ctx!` macro) |

**Implication for Phase 1**: LucasBackend::syscall just has to fan out into these same functions. The bulk of logic already lives in `syscalls/`. Each handler is a **thick adapter**, not a new rewrite target.

## 5. Trait seed status (`libs/sotos-linux-abi/`)

| File | LOC | Status |
|---|---:|---|
| `lib.rs` | 25 | trait re-export only |
| `trait_def.rs` | 29 | `LinuxBackend` trait defined |
| `ctx.rs` | 25 | `SyscallCtx` minimal shape |
| `types.rs` | 44 | `SyscallResult` |
| `lucas.rs` | 46 | **stub** — `panic!("LucasBackend::syscall called -- route through child_handler directly")` |

`child_handler.rs` imports `LinuxBackend` but `#[allow(unused_imports)]` — wave-1 marker only. Real dispatch still in match arms.

## 6. LKL bridge status (`services/init/src/lkl.rs`, 52 LOC)

- `lkl::syscall(nr, args, cr3, pid) -> i64` — FFI into `lkl_bridge_syscall` (C, `services/init/lkl/lkl_bridge.c`).
- Gated: `cfg(lkl)` set by `SOTOS_LKL=1` env var (see `build.rs` or `justfile.lkl`).
- `LKL_READY: AtomicBool` → flipped after `lkl_bridge_init()`.
- No syscall currently routes to LKL by default: `child_handler` has `LKL_FDS` bitmap but **no active whitelist**. Net/FS still LUCAS.

## 7. Fork/CoW footprint (to extract in Phase 2)

Currently in `fork.rs` (86 LOC): `clone_child_trampoline`, `FORK_STACK_BUF`, `FORK_HEAP_BUF`, `FORK_HEAP_USED`.
Currently **inline in `child_handler.rs`**: `SYS_CLONE` (L1029), `SYS_FORK`, `SYS_VFORK`, CoW page-copy logic, fork_rsp save/restore, pipe refcount inheritance on fork-exec.
**Goal Phase 2**: all CoW + trampoline + fork-save/restore in `fork.rs`; dispatcher only calls `LinuxBackend::create_process`.

## 8. Phase 1 target deltas

| File | Today | After Phase 1 | Delta |
|---|---:|---:|---:|
| `lucas_handler.rs` | 1064 LOC | **deleted** | -1064 |
| `child_handler.rs` | 2626 LOC | **deleted** | -2626 |
| `dispatch.rs` | — | ~150 LOC | +150 |
| `lucas_shell.rs` | — | <200 LOC | +200 |
| `init_boot.rs` | — | ~250 LOC | +250 |
| `libs/sotos-linux-abi/src/lucas.rs` | 46 LOC | ~500 LOC | +450 |
| **Net** | | | **~-2640 LOC** |

## 9. Grep-gate policy

To prevent regrowth before fase 1 lands, `scripts/test_system.py` enforces:

```python
ABI_ARMS_BASELINE = {
    "services/init/src/lucas_handler.rs": 108,
    "services/init/src/child_handler.rs": 137,
}
```

If either file grows new `SYS_*` arms, CI fails with "new arms added to frozen dispatcher — migrate via `syscalls/*` or `LinuxBackend` instead". Baseline shrinks monotonically as arms move to `syscalls/*` or are deleted.

When the files themselves are deleted in Phase 1, the gate switches to a new baseline: `dispatch.rs` must have **<5** `SYS_*` references (only catch-alls / debug-print).
