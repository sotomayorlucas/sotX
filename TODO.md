# sotOS / sotBSD / sotFS — TODO

**Status**: sotFS complete (Phases 0-5 + QA). Kernel endpoint_close fix shipped. Manual + paper written.
**Branch**: `main`
**Updated**: 2026-04-11

---

## sotFS

- [ ] Run TLC model checker on 4 TLA+ specs (verify 24 invariants)
- [ ] Mechanical proofs in Coq/Perennial (commit atomicity, rollback correctness, cap unforgeability, treewidth preservation)
- [ ] Custom storage backend (replace redb with COW B+ tree for native sotBSD)
- [ ] End-to-end VFS delegation (LUCAS open("/sotfs/x") -> IPC -> sotfs service -> reply with data)
- [ ] Persistent storage in bare-metal service (currently in-memory, lost on reboot)
- [ ] Native API for explicit transactions and graph queries from sotBSD processes

## Kernel / IPC

- [ ] Close or archive the 11 open PRs on GitHub
- [ ] Add endpoint_close to existing services that leak endpoints (kernel-test, posix-test, styx-test)
- [ ] Per-process endpoint cleanup on thread exit (auto-close leaked endpoints)

## QA

- [ ] Run 3 fuzz targets with 1M+ iterations (did 100K)
- [ ] fio benchmarks on FUSE mount (real throughput, not just latency)
- [ ] Criterion benchmarks at 10K+ nodes (expose O(n^2) bottlenecks in treewidth and block refcount)
- [ ] End-to-end matrix test service (services/e2e-matrix/)

## Formal Verification

- [ ] Verus annotations on kernel code (cap table, frame allocator, IPC integrity)
- [ ] Kani bounded model checking (syscall dispatch, pool allocator)
- [ ] Formalize categories in Lean 4 / Agda

## Documentation

- [ ] Translate manual to Spanish (or maintain bilingual)
- [ ] Update README.md with badges and quickstart
- [ ] GitHub Actions CI pipeline (cargo test + proptest + kernel build)

## Drivers / Networking

- [ ] TLS/HTTPS (git clone over HTTPS blocked by missing crypto)
- [ ] virtio-gpu for real compositor (currently direct framebuffer)
- [ ] AHCI/SATA driver (currently only NVMe and virtio-blk)
- [ ] Audio playback (AC97 driver exists but no userspace player)

## Personalities

- [ ] LKL (Linux Kernel Library) as alternative to LUCAS for full compat
- [ ] Real rump VFS mount (currently 3 hardcoded files)
- [ ] Wine PE loader (stalled at Phase 7 -- hello.exe hangs)

## bhyve / VM

- [ ] VT-x only works with -accel kvm -cpu host,+vmx (not TCG)
- [ ] Guest userspace (Linux shell inside VM guest)
- [ ] Live migration of attacker process to deception VM (hook exists but doesn't execute)

## Phase 5 Advanced

- [ ] Persistent homology on temporal graph evolution (applied TDA)
- [ ] Incremental curvature monitor integrated in bare-metal service
- [ ] Treewidth enforcement in GTXN (reject ops that exceed the bound)

- [x] QEMU boot test: STYX banner appears (`sotBSD/STYX exokernel v0.1.0`)
- [x] SOT syscalls 300-310 reachable from userspace (7/7 PASS via styx-test)
- [x] `services/styx-test/` minimal binary spawned by init at boot
  - Required fixes: kernel `handle_so_create` accepts type 1/3/4/5 as Memory placeholder;
    kernel `handle_tx_begin` treats `domain_cap=0` as root domain;
    `sys::tx_begin` wrapper uses `syscall2` so tier lands in `rsi`

