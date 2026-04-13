# Sprint 1 — "Unblock the beta"

Goal: a third party can run `just install TARGET=out.img` followed by
`qemu-system-x86_64 -drive format=raw,file=out.img` and get a working
sotX boot without touching the rest of the build system.

## Status

| Item                         | State   | Notes                                                                                 |
|------------------------------|---------|---------------------------------------------------------------------------------------|
| Installer script             | Done    | `scripts/sotx-install.py` + `just install TARGET=...`                               |
| Persistent rootdisk builder  | Done    | `just rootdisk` wraps `scripts/mkdisk.py`, creates ObjectStore v6 disk                |
| `run-with-rootdisk` recipe   | Done    | Attaches `target/rootdisk.img` as a second virtio-blk drive                           |
| SMP default = single CPU     | Done    | `just run` / `run-with-rootdisk` default to `-smp 1`; see scheduler race park below   |
| rump_init wedge fix          | **Parked** | See below — requires `curlwp` hypercall rewrite + TLS runtime init                 |
| SMP work-stealing race       | **Parked** | Intermittent hang with `-smp 2+`; `just run-smp` kept for regression tests         |
| Installer → real block dev   | Partial | `--force` + Linux `dd` path wired, but not verified on a live USB stick              |

## Installer contract

```
just install TARGET=out.img            # writes a 512 MiB bootable image to out.img
just install TARGET=/dev/sdb FORCE=1   # raw block device (Linux dd path)
python scripts/sotx-install.py --target out.img --with-rootdisk --rootdisk-size 128
```

The installer is intentionally minimalist:

1. It never touches a path that wasn't named on the command line.
2. It refuses to overwrite anything unless `--force` is set.
3. It ensures `target/sotx.img` exists (rebuilds via `just image` if
   missing or stale) before copying.
4. `--with-rootdisk` stages `target/rootdisk.img` alongside but does
   **not** merge it into the boot image — both files travel as
   separate LUNs, matching real-world "two drives on one system".

## Parked items

### rump_init wedge

**Symptom**: `rump_init()` issues ~64 hypercalls then wedges inside
the NetBSD rump kernel code downstream of `curlwp` / `cpu_info`
access. Confirmed via instrumentation in `rumpuser_sot.c`.

**Why not fixed yet**: the fix requires rewriting the `curlwp`
hypercall path to use per-thread TLS (`__thread` with
`FS_BASE`-relative addressing) instead of the global variable that
the current shim uses. That in turn needs the rump build to be
rebuilt with `-F CFLAGS=-DRUMP_CURLWP=20502` and a TLS runtime
initializer called before `rump_init`. An earlier attempt to set
`-V RUMP_CURLWP=__thread` failed because that's a NetBSD `build.sh`
variable, not a C preprocessor define — `nm librump.a | grep curlwp`
still shows the global `rump_lwproc_curlwp_hypercall` after rebuild.

**Workaround**: LKL is the path forward for the "real Linux kernel
as a LibOS" story (see `docs/lkl-architecture.md` and the
`project_lkl_pivot.md` memory). Rump stays in the tree as the
clean-room reference and its `rumpuser_sot.c` shim compiles
cross-freestanding in CI.

**Gated behind**: set `SOTX_RUMP=1` env var to re-enable rump
boot-time init; default off.

### SMP work-stealing race

**Symptom**: with `-smp 2+`, the SPSC producer/consumer test
occasionally hangs because a work-stealing thief races with a local
`push_back`. Reliable with `-smp 1`; the default for `just run`.

**Why not fixed yet**: the scheduler uses a single `spin::Mutex`
around the per-core runqueue, which is correct but unfair. The race
is in the path that drops the lock before probing a victim queue.
The fix needs either:

1. Lock-free deque (Chase-Lev) for the runqueues, or
2. A seqlock-style version counter so a thief can retry cleanly.

Both are scheduler surgery that risks boot regression, so it's
deferred behind a `just run-smp` regression-only recipe and is not
on the Sprint 1 critical path.

**Workaround**: `just run` defaults to single CPU; boot tests,
installer, and `run-with-rootdisk` all use it.

## What this unlocks

With Sprint 1 landed, the workflow for a third party is:

1. Clone the repo
2. `just image` (one build)
3. `just install TARGET=out.img`
4. Boot the resulting image

No LFS, no pkgsrc, no rump, no manual mkinitrd. This is the minimum
viable "install and boot" story — the "useful" and "production"
parts ride on Sprints 2 + 3.
