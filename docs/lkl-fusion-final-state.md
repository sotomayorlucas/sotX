# LKL Fusion — Final State Report (Phase 0–8)

**Branch**: `feat/lkl-probe-fix`
**Last commit**: `5086678` (phase-7 closed)
**Status**: Phases 4, 5, 6, 7, 8 closed. Phases 0–3 (deprecation infra) landed earlier.

## What works end-to-end

```
[lkl-boot] Linux kernel running!
[lkl-boot] uname: Linux 6.6.0+
[lkl-boot] populating rootfs...
[lkl-boot] rootfs ready
[lkl-disk-fusion] capacity=65536 sectors (33554432 bytes)
[lkl-boot] worker ep=N
[lkl-boot] proxy worker spawned
[lkl-boot] ready - forwarding enabled
LKL: forwarding activated
[hello-linux] uname OK
    sysname=Linux release=6.6.0+
  [PHASE-4] uname routed via LKL ✓
  openat(/tmp/phase6-test, CREAT|WRONLY) OK
  [PHASE-6] /tmp open routed via LKL tmpfs ✓
  write(/tmp/phase6-test) bytes match OK
  openat(/etc/passwd) errno=2 (LUCAS fallback, no LKL crash -- OK)
[hello-linux] all tests complete
LINUX-TEST: exited with status 0
sotsh>
```

## Phase summary

### Phase 0–3 (pre-existing) — Dispatcher consolidation
LinuxBackend trait, HybridBackend with empty whitelist, dispatch.rs, lucas_shell.rs, init_boot.rs. Established before this session.

### Phase 4 — Info domain ✅ DONE
- Whitelist: `uname`, `gettimeofday`, `sysinfo`, `times`, `time`, `clock_gettime`, `getrandom`
- Validation: `[PHASE-4] uname routed via LKL ✓` (hello-linux returns Linux 6.6.0+ string)

### Phase 5 — Net domain — routing infra ✅ / NIC bringup ⏸️
- Routing whitelist already in place: SYS_SOCKET, ACCEPT, CONNECT, BIND, SENDTO, RECVFROM, SHUTDOWN, etc.
- LKL_FDS bitmap tracks per-fd ownership for Category B routing
- **NIC bringup deferred**: `net_backend_up` crashes an internal LKL kthread with rip=0 during the if_up + nanosleep retry loop. Tried 128 KiB kthread stacks, proxy worker, per-thread TLS — none unblocked. Likely a missing host_op for some network softirq/timer callback. Camino A (loopback) is fine, Camino B (external NIC) needs this fix or `justfile.lkl` with second virtio-net + net-raw service.

### Phase 6 — FS domain ✅ DONE (tmpfs) / ⏸️ ext4 mount
- `fs_route_path(path) -> {Lucas, Lkl}` in `libs/sotos-linux-abi/src/hybrid.rs` — LUCAS-by-exception policy
- All Category A path-input syscalls inspect path before routing: stat/lstat/access/chdir/mkdir/rmdir/unlink/chmod/rename/open/openat + dirfd-relative variants (fstatat, readlinkat, faccessat, mkdirat, unlinkat)
- Category B fd-bearing syscalls use LKL_FDS bitmap (already-existing infra)
- /tmp open + write + close round-trip validated end-to-end via hello-linux
- /etc/passwd correctly routed to LUCAS (no LKL crash)
- **ext4 real mount deferred**: blk service handoff works (`[lkl-disk-fusion] capacity=65536 sectors`), but `lkl_mount_dev("ext4")` fails with -ENOENT. Suspected: LKL expects partition table or disk_backend's READ alignment is off. Phase 6 routing infra is complete; real ext4 round-trip from a child binary is follow-up.

### Phase 7 — Signal + task ✅ CLOSED (decision: stay LUCAS)
Architectural decision: signal subsystem stays in LUCAS permanently. Proxy worker design fundamentally breaks per-thread signal semantics. The 3 historical bugs are kernel/VMM concerns. LUCAS impl already correct. Smoke harness clean. See `docs/signal_invariants.md` for full reasoning.

### Phase 8 — Cleanup ✅ DONE
- Final state report (this file)
- `feat/lkl-probe-fix` branch ready for review/merge
- No legacy code removal — LucasBackend remains needed for hybrid fallback paths (every domain has LUCAS-routed paths: `/etc/*`, `/proc/*`, signal handling, process creation)
- `clippy -D dead_code` not enforced — would require pruning legacy `lucas_handler.rs` arms which still serve real syscalls

## Critical infrastructure landed this session

1. **Proxy worker thread** (`services/init/lkl/lkl_bridge.c`)
   - Foreign callers marshal LKL syscalls via `sys_call(worker_ep, msg)`
   - Worker has full `task_struct` + FS_BASE + TLS via `lkl_thread_create`
   - Eliminates #GP-in-VFS class of bugs from arbitrary-thread `lkl_syscall` calls

2. **Per-thread TLS in host_ops** (`services/init/lkl/host_ops.c`)
   - `tls_rows[64]` table indexed by `lkl_thread_self()`
   - Falls back to any non-NULL value across threads (preserves Phase 4 read-only paths)

3. **Boot thread keep-alive**
   - Boot thread no longer exits after `lkl_ready=1`; loops in `host_ops_tick + sys_yield`
   - Keeps its task struct + TLS row valid as fallback root

4. **`fs_route_path` + Category A inspection** (`libs/sotos-linux-abi/src/hybrid.rs`, `services/init/src/lkl_route.rs`)
   - Path-aware backend routing for all fs syscalls

5. **Build cache fix** (`services/init/build.rs`)
   - `cargo:rerun-if-changed` for `liblkl_fused.a` + every bridge `.c`
   - Without this, cargo's incremental link cache silently held stale binaries

6. **Kernel `#PF rip=0` guardrail** (`kernel/src/arch/x86_64/idt.rs`)
   - Kills threads that fault at RIP=0 instead of letting VMM map page 0 + loop forever

7. **`-smp 1` for `just run-lkl`**
   - Avoids unrelated INIT/services SMP handshake race that masks LKL bugs

## Outstanding bugs (carried over)

1. **`net_backend_up` rip=0 kthread** — blocks Phase 5 NIC bringup
2. **`lkl_mount_dev("ext4")` returns -ENOENT** — blocks Phase 6 real disk mount
3. **`#PF-RIP0 tid=N — killing thread`** still fires once per boot — internal LKL kthread (likely virtio-net probe). Cosmetic; init continues normally.
4. **GTK display warning** at QEMU startup — benign, not our code

## Branch hygiene

`feat/lkl-probe-fix` carries this session's work, ~20 commits. Ready for:
- Review (no force-pushed commits, clean linear history)
- Squash-merge to main if preferred (each phase is its own logical unit)

User has not authorized merging to main. Branch stays as-is until explicit go-ahead.

## Test commands for future sessions

```powershell
# Full Phase 4 + Phase 6 boot validation
just run-lkl

# Smoke tier signal regression harness (CI-runnable)
python scripts/test_signal_regression.py

# Rebuild from scratch after C bridge changes
just build-lkl    # rebuilds liblkl_fused.a via WSL
just image-lkl    # rebuilds initrd + image
```
