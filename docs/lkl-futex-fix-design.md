# LKL Bridge FUTEX Deadlock — Fix Design

**Status:** Proposal. Code changes in follow-up PRs A2/A3 once this is approved.
**Author:** A1 (audit + design only — no code changes in this PR).
**Scope:** `services/init/lkl/lkl_bridge.c`. Unblocks migration of `SYS_FUTEX` (and other blocking-capable syscalls) from LUCAS to LKL.

---

## 1. Problem statement

When a child process issues `SYS_FUTEX(FUTEX_WAIT)` the init handler must block the caller inside LKL until another child issues `FUTEX_WAKE`. But `lkl_bridge_syscall()` currently serializes the whole switch body behind a single process-wide spinlock:

```c
/* services/init/lkl/lkl_bridge.c:303-306 */
/* Serialize access to static scratch buffers (g_data_buf, g_path_buf, etc.)
 * to prevent data races when multiple child handlers call us concurrently. */
while (__sync_lock_test_and_set(&bridge_lock, 1))
    sys_yield();
```

Thread A takes `bridge_lock`, enters `lkl_syscall(FUTEX_WAIT)`, and blocks inside LKL. Thread B then wants `FUTEX_WAKE`, but first has to acquire `bridge_lock` — which A still holds — so B spins forever on `sys_yield()`. A cannot wake because nobody can reach the wake code. Deadlock.

The consequence is documented at `services/init/src/child_handler.rs:376`:

```rust
// Note: SYS_FUTEX stays in LUCAS — bridge_lock would deadlock on FUTEX_WAIT.
```

This forces every pthread-using binary to split sync calls (LUCAS) from I/O calls (LKL), preventing full migration.

## 2. Root-cause trace

Actors: two child processes P1 (pid=1) and P2 (pid=2), each with its dedicated init handler thread H1 and H2. Both handlers call into the one-instance LKL inside init's address space.

1. P1 calls `futex(uaddr, FUTEX_WAIT, val, ...)`. H1 receives the IPC and calls `forward_to_lkl_ret` (`services/init/src/child_handler.rs:71`) → `lkl_bridge_syscall` (`lkl_bridge.c:293`).
2. H1 acquires `bridge_lock` at `lkl_bridge.c:305`.
3. H1 calls `lkl_syscall(__NR_futex, ...)` at `lkl_bridge.c:992`.
4. Inside LKL, `lkl_syscall` calls `lkl_cpu_get()` (`lkl/linux/arch/lkl/kernel/syscalls.c:111`), runs the futex handler, and schedules H1 off the LKL CPU via `__switch_to` + `sem_down(_prev->sched_sem)` (`lkl/linux/arch/lkl/kernel/threads.c:111`). H1 is now blocked inside LKL with `bridge_lock` still held.
5. P2 calls `futex(uaddr, FUTEX_WAKE, ...)`. H2's `lkl_bridge_syscall` reaches the spin at `lkl_bridge.c:305` and spins indefinitely. The wake never runs, so LKL never schedules H1 back. Both handlers are stuck.

Critical observation: LKL itself is internally thread-safe. `lkl_cpu_get/put` (`lkl/linux/arch/lkl/kernel/cpu.c:95-150`) is the Big-Kernel-Lock equivalent, and `__switch_to` releases CPU ownership via `lkl_cpu_change_owner` (`threads.c:99`) when a host thread blocks, so a second host thread entering `lkl_syscall` can acquire the LKL CPU and run FUTEX_WAKE. The lockup is caused entirely by the **host-side** `bridge_lock`, not by LKL.

## 3. Proposed fix — Solution A: per-pid scratch, eliminate `bridge_lock`

(The task spec called this "per-thread scratch buffers", but since each pid has exactly one init-side handler thread, per-pid indexing is the natural granularity. Same idea.)

Evidence for Solution A:
- `lkl/linux/arch/lkl/kernel/syscalls.c:106-138` — `lkl_syscall` takes `lkl_cpu_get()` itself and sets up per-host-thread `task_struct` via `lkl_ops->tls_get(task_key)`. The entry point is designed for concurrent host callers.
- `lkl/linux/arch/lkl/kernel/cpu.c:11-54` — the header comment is explicit about handling "various synchronization requirements between idle thread, system calls, interrupts, reentrancy, CPU shutdown, imbalance wake up". Internal locking is LKL's job.
- `lkl/linux/arch/lkl/kernel/threads.c:107-112` — when a task blocks, `__switch_to` does `sem_up(_next->sched_sem); sem_down(_prev->sched_sem);` while holding the CPU only transiently, letting another owner enter.

Since LKL handles serialization internally, the only purpose of `bridge_lock` is protecting the static scratch buffers at `lkl_bridge.c:29-33`. Give each logical caller its own slot and the lock is gone.

### 3.1 Data structure

```c
struct bridge_scratch {
    char path_buf[4096];
    char path_buf2[4096];
    char data_buf[4096];
    char stat_buf[256];
    char sockaddr_buf[128];
};
/* 12,672 bytes per slot. */

#define BRIDGE_SCRATCH_SLOTS 64   /* matches services/init/src/process.rs:18 MAX_PROCS */
static struct bridge_scratch g_scratch[BRIDGE_SCRATCH_SLOTS];
```

Total BSS cost: ~810 KiB. Static allocation is simplest and keeps the bridge alloc-free in the hot path (lkl's arena is already 128 MiB at 0x30000000 per `project_lkl_pivot.md`, so the budget is not tight).

### 3.2 Indexing scheme

The bridge already receives `pid` as its fourth argument (`lkl_bridge.c:293`, currently discarded by `(void)pid;` on line 296). Use `pid - 1` as the slot index after validation:

```c
unsigned slot = (pid > 0 && pid <= BRIDGE_SCRATCH_SLOTS) ? (unsigned)(pid - 1) : 0;
struct bridge_scratch *s = &g_scratch[slot];
```

Why `pid` and not a raw host tid: each child pid has exactly one init-side IPC handler thread (per `services/init/src/child_handler.rs`), so all `lkl_bridge_syscall` calls for a given pid are naturally serialized at the IPC layer — `g_scratch[pid-1]` cannot race with itself, and CLONE_THREAD groups share the slot safely because they all funnel through that one handler. Using the host-side tid would need a dynamic hash table and gain nothing.

### 3.3 Lines that change

The mechanical edits in `lkl_bridge.c`:
- Remove `bridge_lock` declaration (line 36) and both spin/release sites (305-306, 310, 1021).
- Remove `g_path_buf`, `g_path_buf2`, `g_data_buf`, `g_stat_buf`, `g_sockaddr_buf` globals (29-33); add `g_scratch` array.
- At the top of `lkl_bridge_syscall` after the `lkl_ready` check, resolve `s = &g_scratch[pid-1]`.
- Replace every `g_path_buf`/`g_data_buf`/etc. reference in the switch body with `s->path_buf`/`s->data_buf`/etc. (roughly 60 call sites across the case labels).
- Drop the `(void)pid;` on line 296.

### 3.4 Concurrent-safety analysis

- **Same-pid concurrency:** impossible (see 3.2 — one handler per pid).
- **Cross-pid concurrency:** safe. Each pid touches only its own slot.
- **Early startup:** if a bridge call arrives with `pid == 0` or `pid > 64`, the fallback maps to slot 0. That is a degradation for malformed inputs, not a correctness issue — slot 0 is still a valid buffer. The kernel-side pid allocator in `services/init/src/process.rs` only hands out 1..=64, so in normal operation the fallback is unreachable.
- **Reentrancy inside LKL:** if LKL calls back into a host op (it doesn't call back into `lkl_bridge_syscall`, only into `host_ops.c`), no scratch is touched. `host_ops.c` uses its own buffers and the arena.
- **Pid reuse:** on process exit the slot is implicitly reclaimed. A new pid only occupies the slot when the old handler thread has returned, so there is no overlap.

## 4. Verification plan

1. Build with `SOTOS_LKL=1` and boot `just run-lkl`. Check for `LKL: forwarding activated` on serial.
2. Route `SYS_FUTEX` through LKL (A3 work). Remove the "stays in LUCAS" comment at `services/init/src/child_handler.rs:376` and add `SYS_FUTEX` to the Category A match arms alongside `SYS_NANOSLEEP`.
3. Smoke test — `busybox sh -c 'echo cowfork-ok | cat'` must still pass (currently documented working in MEMORY.md Phase 12).
4. Stress test from A4: 8-thread `pthread_mutex_lock/unlock` loop. Before: hang at first FUTEX_WAIT. After: completes within a few seconds with no lost wake-ups.
5. Regression: run the `scripts/test_alpine_wget.py` end-to-end test and the `run_busybox_test()` auto-test to confirm Category A syscalls (`openat`, `read`, `write`, `connect`, `recvfrom`, …) still function under the now lock-free bridge.
6. Under `-smp 2 -accel whpx` (per `gotchas.md` WHPX strictness) confirm no regressions in the existing LKL-forwarded FS traffic.

## 5. Risks

- **LKL reentrancy into host ops.** If any LKL host callback (`host_ops.c`) were to recurse into `lkl_bridge_syscall` for the same pid, the simple pid indexing would still be safe (same thread = no race), but deadlock against `lkl_cpu_get` could appear. Audit of `host_ops.c` shows no such path — callbacks talk only to sotOS primitives.
- **Assumption that LKL releases its CPU on block.** Verified in `threads.c:99` via `lkl_cpu_change_owner`, but only on a single-CPU LKL build (default). If we ever compile LKL with SMP enabled inside init, concurrency semantics shift and this design needs re-review.
- **Category A breakage under concurrency.** Once the spinlock is gone, bugs that were masked by serialization (e.g., a subtle aliasing bug in `sendmsg`/`recvmsg` flattening on lines 796-885) become observable. Mitigated by the wget and git-init smoke tests, but a targeted parallel-I/O test is worth adding.
- **Pid collision with slot 0 fallback.** Extremely unlikely given `MAX_PROCS=64`, but if a future refactor passes `pid=0` as a legitimate value, slot 0 would be shared. Mitigation: assert `pid >= 1` or extend slots to include a dedicated "bootstrap" entry.
- **BSS size.** ~810 KiB is material if init is ever memory-constrained. If so, move `g_scratch` into the existing LKL arena via `arena_alloc` on first `lkl_bridge_init`; straightforward but adds a pointer indirection.

## 6. Open questions for the user

- **Storage placement:** static BSS (fast, simple, +810 KiB at link time) versus `arena_alloc` inside `lkl_bridge_init` (keeps BSS small, one extra deref per call). Recommendation: BSS, decide otherwise only if image size matters.
- **Keep the lock as a debug assert?** An optional `#ifdef DEBUG` check that no two host threads ever touch the same slot could catch handler-thread bugs early. Low cost, adds one atomic.
