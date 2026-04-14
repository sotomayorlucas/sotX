# futex-stress

Regression stress test for the LUCAS → LKL `SYS_FUTEX` routing work (A1–A4).

## Why C?

The test is stress-testing `pthread_mutex_lock` / `pthread_mutex_unlock`,
which on musl compiles down to raw `SYS_futex(FUTEX_WAIT/WAKE)`
syscalls. C + pthread is the most direct, least-noise way to exercise
that path — no runtime, no std scheduler, just `clone + futex`.

## What it does

1. Spawns 8 `pthread_create` worker threads.
2. Each worker does 10,000 iterations of
   `pthread_mutex_lock + counter++ + pthread_mutex_unlock` on a single
   shared mutex — 80,000 contended critical sections total.
3. `pthread_join`s all workers.
4. Verifies `counter == 8 * 10_000`.
5. Prints
   - `FUTEX-STRESS: PASS (N ops in M ms)` on success, exit 0
   - `FUTEX-STRESS: FAIL (...)` on counter mismatch, exit 3
   - `FUTEX-STRESS: HUNG` from a 60-second `SIGALRM` watchdog, exit 2

## Build

Native Linux:

```sh
cd services/futex-stress
make           # -> ./futex-stress  (static, x86_64 ELF)
```

From Windows via WSL:

```sh
wsl -- make -C services/futex-stress
```

Or use the Justfile target from the repo root:

```sh
just build-futex-stress
```

## Run on sotOS

After building, drop `services/futex-stress/futex-stress` into the
initrd (the standard LUCAS build flow already supports arbitrary
static musl binaries — see `services/hello-linux` for the pattern).
Then from a LUCAS shell on a booted image:

```
/ # futex-stress
FUTEX-STRESS: PASS (80000 ops in 312 ms)
```

Boot-time auto-run is intentionally left manual in this PR to keep the
diff small. To wire it into `services/init` add a driver around
`exec_from_initrd("futex-stress", &[])` gated on a boot flag (e.g.
`SOTOS_FUTEX_STRESS=1`) — see the A4 task notes for design.

## Expected results

| Tree state | Behaviour |
|---|---|
| Pre-A2 (bridge_lock alive, #123 unmerged) | Deadlocks within a few hundred ops — SIGALRM fires → `FUTEX-STRESS: HUNG` |
| Post-A3 (`SYS_FUTEX` routed to LKL, #126 merged) | Completes. 80,000 ops in well under 60 s |

Actual millisecond numbers must come from a real boot run on a
post-#126 tree; do not fill them in speculatively.

## Methodology

- **Thread count (8)**: matches the LKL per-pid scratch fanout from A2
  (#123) and exercises per-CPU contention under `-smp 4` QEMU.
- **Iteration count (10,000)**: empirically long enough to expose
  missed `FUTEX_WAKE` races but short enough to finish inside the
  WHPX `just run-fast` budget.
- **Single shared mutex**: maximises contention — every thread goes
  through the kernel FUTEX fast path, then the wait-queue slow path
  on collision. This is the worst case for the bridge_lock.
- **Watchdog (60 s)**: the pre-A2 deadlock reproduces in seconds, so
  60 s is conservative but keeps CI budget sane.

## References

- A1 — FUTEX-in-LKL design: PR #118
- A2 — per-pid scratch + bridge_lock elimination: PR #123
- A3 — `SYS_FUTEX` routing to LKL: PR #126
- A4 — this stress test: `batch/futex-stress-test`
