# Phase 5 — Net domain routing to LKL

**Status (2026-04-15)**: plumbing consolidated (Phase 5a). Runtime activation
blocked on ROADMAP §10.7 — virtio-net passthrough from LKL to sotX's native
net service. This doc captures the design so Phase 5b is a single flag flip.

## What Phase 5 does

Routes Linux-ABI networking (and filesystem/time/sync as a superset) from
the LUCAS hand-rolled proxy to the LKL kernel library. The mechanism was
already present in `child_handler.rs` but mixed with unrelated state.
Phase 5a extracts it into a single policy module.

### Entry point

`services/init/src/lkl_route.rs`
```
pub(crate) fn try_route(syscall_nr, msg, pid, child_as_cap, ep_cap) -> bool
```

Returns `true` if the syscall was forwarded to LKL and replied to (caller
should `continue`). Returns `false` if LUCAS must handle it.

### Gate

```
if !lkl::LKL_READY.load(Ordering::Acquire) { return false; }
```

`LKL_READY` is `true` only when:
1. The init binary was built with `SOTOS_LKL=1` (sets `cfg(lkl)`), AND
2. The LKL kernel has passed its internal boot + `lkl_bridge_ready()` returns non-zero.

With `SOTOS_LKL=0` (default), `LKL_READY` is wired to constant `false` and
`lkl::syscall` returns `-ENOSYS`. Every path through `try_route` short-
circuits. Behavior is byte-identical to a build without the module.

## Syscall categories

`lkl_route::try_route` implements two tiers:

### Category A — unconditional forwarding to LKL

When `LKL_READY`, these always go to LKL regardless of LUCAS state:

**Path-only (no fd arg)** — filesystem metadata reads/writes:
```
SYS_STAT, SYS_LSTAT, SYS_ACCESS, SYS_GETCWD, SYS_CHDIR,
SYS_MKDIR, SYS_RMDIR, SYS_UNLINK, SYS_RENAME, SYS_CHMOD,
SYS_FSTATAT, SYS_READLINKAT, SYS_FACCESSAT, SYS_MKDIRAT, SYS_UNLINKAT
```

**Stateless info/time/sync**:
```
SYS_UNAME, SYS_SYSINFO, SYS_GETRANDOM,
SYS_GETTIMEOFDAY, SYS_CLOCK_GETTIME, SYS_CLOCK_GETRES,
SYS_NANOSLEEP, SYS_CLOCK_NANOSLEEP, SYS_FUTEX
```

**fd-creating** — LKL allocates a guest-visible fd and returns it; we
register that fd in `LKL_FDS` so subsequent ops on it route to LKL via
Category B. Includes socket creation:
```
SYS_OPEN, SYS_OPENAT,
SYS_SOCKET, SYS_ACCEPT, SYS_ACCEPT4, SYS_SOCKETPAIR,
SYS_PIPE, SYS_PIPE2,
SYS_EPOLL_CREATE, SYS_EPOLL_CREATE1,
SYS_EVENTFD, SYS_EVENTFD2,
SYS_TIMERFD_CREATE, SYS_MEMFD_CREATE,
SYS_INOTIFY_INIT1
```

`SYS_PIPE/PIPE2` and `SYS_SOCKETPAIR` read back the two fds the kernel
wrote to guest memory and register both.

### Category B — route by `LKL_FDS[pid][fd]` ownership

For fd-indexed ops, consult the per-pid bitmap. If the target fd is
LKL-owned, forward; otherwise let LUCAS handle it.

**Single-fd ops** (`regs[0]` is the fd):
```
SYS_READ, SYS_WRITE, SYS_LSEEK, SYS_FSTAT,
SYS_PREAD64, SYS_PWRITE64, SYS_READV, SYS_WRITEV,
SYS_FTRUNCATE, SYS_FSYNC, SYS_FDATASYNC,
SYS_GETDENTS64, SYS_FCNTL, SYS_IOCTL,
SYS_CONNECT, SYS_BIND, SYS_LISTEN, SYS_SHUTDOWN,
SYS_SENDTO, SYS_SENDMSG, SYS_RECVFROM, SYS_RECVMSG,
SYS_GETSOCKOPT, SYS_SETSOCKOPT,
SYS_GETSOCKNAME, SYS_GETPEERNAME,
SYS_EPOLL_CTL, SYS_EPOLL_WAIT, SYS_EPOLL_PWAIT,
SYS_TIMERFD_SETTIME, SYS_TIMERFD_GETTIME,
SYS_INOTIFY_ADD_WATCH, SYS_INOTIFY_RM_WATCH
```

**Multi-fd polling** (`pollfd`/`FD_SET` arrays):
```
SYS_POLL, SYS_PPOLL, SYS_SELECT, SYS_PSELECT6
```
Best-effort: forward whole call to LKL if the pid owns any LKL fd.
LKL's poll returns early for fds it doesn't recognize, which is safe.

**fd-lifecycle** — maintain `LKL_FDS` bitmap:
- `SYS_CLOSE` on LKL fd: forward, then `lkl_fd_clear(pid, fd)` on success.
- `SYS_DUP`/`SYS_DUP2`/`SYS_DUP3` on LKL fd: forward, register returned fd.

## PID 1 (LUCAS shell) — different path

`lucas_shell::shell_main` is **not** routed through `lkl_route::try_route`.
Reason: the shell's own file access (`/snap/`, `/proc/` virtuals, command
history) is backed by LUCAS's ObjectStore, not LKL's ext4 image. Routing
PID 1's `SYS_OPEN` to LKL would break the shell's self-operation.

Instead, PID 1 uses the narrower pre-route in `dispatch::dispatch_linux_arm`
(Phase 4): only stateless info-domain arms (via
`sotos_linux_abi::hybrid::LKL_WHITELIST`) can go to LKL from PID 1. See
`libs/sotos-linux-abi/src/hybrid.rs` for the whitelist.

## LKL fd allocation invariant (CRITICAL)

The `LKL_FDS` bitmap is 128 bits per pid — it indexes guest fd 0..127.
The LKL bridge **must** return fd numbers in that range AND that do not
collide with LUCAS-allocated fds for the same pid. The current bridge
design (`services/init/lkl/lkl_bridge.c`) assumes a per-pid allocator.

If the bridge allocates from a global pool or returns values ≥ 128,
`lkl_fd_set` silently drops the registration and subsequent ops route
to LUCAS instead of LKL — with no visible error. Verify at activation.

## Activation checklist (Phase 5b)

1. ROADMAP §10.7 — virtio-net passthrough: LKL's virtio-net driver
   reaches sotX's `net` service through the existing IPC / shared-mem
   interface. Without this, LKL sockets have no network carrier.
2. ROADMAP §10.7 — virtio-blk passthrough: LKL's ext4 mount reaches
   a sotX-owned blob. Without this, LKL sees an empty fs.
3. Fd collision audit: confirm the bridge's fd allocator respects
   the 0..127 range and avoids LUCAS's allocations.
4. Build with `SOTOS_LKL=1`, boot, verify `LKL: forwarding activated`
   appears in the serial log.
5. Smoke tests:
   - `scripts/test_signal_regression.py --timeout 120` — must stay green.
   - `scripts/test_alpine_wget.py` — LKL network should now serve the TCP
     connection; LUCAS's socket proxy is still there as fallback.
   - `scripts/test_apk.py` — heavy FS + networking; gate on this before
     declaring Phase 5 done.

## What's NOT handled by Phase 5a

- **Process management** (`fork`/`exec`/`exit`/`wait`) stays in LUCAS.
  LKL's task model diverges from sotX's pid space; forking under LKL
  would require a guest-pid shadow table. Deferred to Phase 7.
- **Memory** (`brk`/`mmap`) stays in LUCAS. LKL's mm subsystem is not
  wired to sotX's frame allocator.
- **Signals** stay in LUCAS. Rt_sigaction routing is gated on the
  signal regression harness (`docs/signal_invariants.md`).

## Related code

| File | Role |
|---|---|
| `services/init/src/lkl_route.rs` | Phase 5 routing policy (this doc). |
| `services/init/src/lkl.rs` | Init-side FFI shim to `lkl_bridge_*`. |
| `services/init/lkl/lkl_bridge.c` | C bridge between init and LKL kernel. |
| `libs/sotos-linux-abi/src/lkl.rs` | Lib-side trait impl + fn-pointer register. |
| `libs/sotos-linux-abi/src/hybrid.rs` | PID 1 whitelist (info-domain only). |
| `services/init/src/child_handler.rs` | Calls `lkl_route::try_route` in pre-match. |
| `services/init/src/dispatch.rs` | PID 1 pre-route via hybrid whitelist. |
| `justfile.lkl` | `SOTOS_LKL=1` build targets. |
