# sotX — a verified microkernel personality OS

**sotX** a microkernel operating system written from scratch in Rust. The kernel
itself is `sotos-kernel`; sotX is what you get when you boot it with the
SOT exokernel layer, the deception subsystem, the BSD personality
services, and the production-hardening pipeline all wired together.

It exposes:

* a 5-primitive verified microkernel (scheduling, IPC, capabilities,
  IRQ virtualization, frame allocation),
* a SOT exokernel layer (transactional Secure Objects, two-phase commit,
  per-CPU provenance ring, capability interposition),
* an in-process NetBSD rump kernel linked into a `rump-vfs` service,
* a deception subsystem (anomaly detector + migration orchestrator +
  Ed25519/SHA-256 signed boot chain),
* a Linux ABI personality (LUCAS shell, glibc/musl binaries, vDSO),
* a v0.2.0+ "Illumos Heirlooms" layer (SMF service manager, Project
  Crossbow VNIC switch, FMA predictive self-healing engine), and
* a Wayland compositor with Tokyo Night theme, layer-shell, popups,
  fractional scaling stub, anti-aliased fonts, multi-shape cursors,
  and per-rect damage tracking,
* an active-respawn supervisor wired through `SYS_THREAD_NOTIFY` (143),
* a six-tier boot-time demo pipeline plus 16 PASS markers in a single
  boot end-to-end (`compositor input WIRED`, `Signify`, `STYX TEST`,
  `posix-test`, `kernel-test`, `RUMP-VFS-TEST`, `Tier 3`, `FMA`,
  `Tier 4`, `Crossbow`, `Tier 5`, `abi-fuzz: 10000/10000 survived`,
  `SMF respawn`, `DLTEST + DLTEST mul` (TLS reloc)).

```
=== Signify boot chain (SHA-256) ===
signify: pubkey matches embedded const
signify: Ed25519 signature OK (573 body bytes)
signify: verified=14 failed=0 missing=0
=== Signify boot chain: PASS ===
STYX TEST: ALL PASS                          (Tier 1: SOT syscalls 300-310)
RUMP-VFS-TEST: PASS                          (Tier 2: real librump linked)
=== Tier 3 deception live demo: PASS ===    (real provenance ring + AnomalyDetector + migrate)
=== Tier 4 demo: PASS ===                   (ZFS+HAMMER2 snapshots, bhyve CPUID spoof, PF firewall)
=== Tier 5 demo: PASS ===                   (perf benchmarks, 2PC, fuzz, concurrent stress)
```

## Tiered demo pipeline

Every tier runs in `init` immediately after the kernel hands off, drives
real type-level code paths from the personality crates, and either
prints `PASS` or aborts the boot.

| Tier | What it exercises | Where |
|---|---|---|
| **0 — Signify** | SHA-256 streaming hash of every signed initrd binary against an embedded manifest, then **Ed25519 verification** of the manifest itself with a public key compiled into init via `services/init/src/sigkey_generated.rs`. Pubkey-pinning rejects swap-with-self-signed attempts. Tampering test verified: corrupting one byte in `hello` after signing produces `signify: MISMATCH hello / want=... got=...`. | `services/init/src/signify.rs`, `scripts/build_signify_manifest.py` |
| **1 — STYX** | All 11 SOT exokernel syscalls (300–310 + tx_prepare 311) called from a userspace test binary. `so_create`, `so_invoke`, `so_grant`, `so_observe`, `tx_begin/prepare/commit/abort`, channel create. | `services/styx-test/`, `kernel/src/syscall/sot.rs` |
| **2 — rump-vfs** | A real **NetBSD rump kernel** built via `buildrump.sh` (`librump.a + librumpvfs.a + librumpfs_ffs.a + ...`, ~2 MiB) linked into a freestanding sotOS service. `rumpuser_sot.c` satisfies all 60 `rumpuser_*` hypercalls against SOT primitives. `rump_init()` boots on a worker thread (panic-isolated from the IPC server); the service exposes OPEN/READ/CLOSE/STAT IPC and serves `/etc/passwd` to init at boot. | `services/rump-vfs/`, `vendor/netbsd-rump/` |
| **3 — deception** | An **attacker** binary emits 3 provenance entries (`Write SystemBinary /sbin/sshd`, `Read Credential /etc/shadow`, `Read ConfigFile /proc/version`) under `owner_domain=7`. Init drains the kernel per-CPU provenance ring via `SYS_PROVENANCE_DRAIN (260)`, runs the SAME entries through `sotos_provenance::GraphHunter` AND `sotos_deception::AnomalyDetector`, fires `CredentialTheftAfterBackdoor` (confidence 90), calls `MigrationOrchestrator::migrate()` with the `ubuntu-22.04-webserver` profile, and prints the spoofed `Linux 5.15.0-91-generic` `/proc/version` the migrated attacker now sees. A `DECEPTION-WATCHDOG` worker thread keeps draining post-demo and detects subsequent attacker runs. | `services/init/src/deception_demo.rs`, `services/attacker/`, `kernel/src/sot/provenance.rs` |
| **4 — advanced** | Three sub-sections: **storage** (real `tx_begin/commit/abort` syscalls produce `OP_TX_COMMIT/ABORT` provenance events that drive `sot_zfs::SnapshotManager` and `sot_hammer2::Hammer2SnapshotManager` to create snapshots and resolve rollback targets), **bhyve** (instantiates a `VmDomain` with the `bare_metal_intel` `VmDeceptionProfile`, decodes spoofed CPUID to verify `GenuineIntel`, Cascade Lake `family=6 model=85 stepping=7`, hypervisor bit OFF, hypervisor leaf zero, plus `IA32_FEATURE_CONTROL` MSR), and **PF firewall** (a `PfInterposer` with default-pass + UDP log rule and an attacker domain in deception mode is intercepted with `PfDecision::Deception` before any rule runs). | `services/init/src/tier4_demo.rs`, `personality/bsd/{zfs,hammer2,bhyve,network}/` |
| **5 — hardening** | Seven sections: **A** IPC throughput (`sys::yield_now`, `sys::provenance_emit` cy/op), **B** provenance ring throughput (4000 push / drain), **C** `MigrationOrchestrator::check_interposition` overhead on a 32-cap migrated domain, **D** real **two-phase commit** for the new `TxTier::MultiObject` — `BEGIN→PREPARE→COMMIT` and `BEGIN→PREPARE→ABORT` happy paths plus negative paths, **E** 5000 randomized SOT syscalls with garbage args (survival 5000/5000), **F** concurrent transaction stress (main + worker thread, 1000/1000), **G** TCG-calibrated perf comparison: a tight `lfence; rdtsc` loop derives the inflation factor (~17×), then prints `sys::yield_now` and `sys::provenance_emit` in both raw-TCG and estimated-native columns next to published seL4 / NOVA / Fiasco / Linux pipe reference numbers. | `services/init/src/tier5_demo.rs`, `kernel/src/sot/tx.rs` |
| **5b — POSIX smoke** | `services/posix-test/`, a no_std sotOS-native binary that covers the OTHER side of the personality split from the LUCAS Linux ABI runners. Asserts the SOT primitives the Linux personalities ride on: `frame_alloc + map + unmap_free + readback`, `thread_create + worker sync via AtomicU32`, `endpoint_create + call_timeout`, `provenance_emit + drain`. 11/11 PASS at boot. | `services/posix-test/` |

## SOT — the exokernel layer

`kernel/src/sot/` adds 12 syscalls on top of the microkernel core:

| Syscall | # | Purpose |
|---|---|---|
| `so_create` | 300 | Create a Secure Object (file/dir/process/socket/credential type) |
| `so_invoke` | 301 | Method call on an SO; routed through interposition if applicable |
| `so_grant` | 302 | Grant SO access to a domain (with optional interposition policy) |
| `so_revoke` | 303 | Revoke an SO grant (with epoch barrier) |
| `so_observe` | 304 | Observe an SO without acquiring rights |
| `sot_domain_create` | 305 | Create an isolation domain |
| `sot_domain_enter` | 306 | Switch into a domain |
| `sot_channel_create` | 307 | Create a typed SOT channel |
| `tx_begin` | 308 | Begin a transaction (`ReadOnly` / `SingleObject` / `MultiObject`) |
| `tx_commit` | 309 | Commit (single phase for tiers 0/1, second phase for tier 2) |
| `tx_abort` | 310 | Abort + rollback |
| `tx_prepare` | 311 | **Tier 5: Tier 2 (MultiObject) prepare phase** for two-phase commit |

Plus two diagnostic / observation syscalls:

| `provenance_drain` | 260 | Pop entries from the per-CPU provenance ring into a userspace buffer |
| `provenance_emit` | 261 | Inject a synthetic provenance entry (used by the attacker simulator) |

The kernel `ProvenanceEntry` carries `epoch`, `domain_id`, `operation`,
`so_type`, `so_id`, `version`, `tx_id`, `timestamp` (48 bytes total).
Every `handle_tx_commit` / `handle_tx_abort` emits an
`OP_TX_COMMIT` / `OP_TX_ABORT` event with `so_type = SOTYPE_TX_EVENT`
so userspace observers can drive snapshot managers from real kernel
transaction events.

## KARL — per-boot ID randomization

`kernel/src/karl.rs` derives a 64-bit `boot_seed` from RDTSC at boot
time and exposes per-pool offsets:

```
Boot 1: boot_seed = 0x2895a574d42c28d7   tx_id starts at 3559653379
Boot 2: boot_seed = 0x726387273efe151f   tx_id starts at 1056833539
```

This gives the same downstream effect as OpenBSD's KARL (kernel
re-link per boot) for everything visible through the SOT syscall ABI:
attackers can't predict transaction IDs by counting from a known
baseline.

## Formal verification

`formal/` contains six TLA+ specifications and matching `.cfg` files.
`just tlc-mc` runs **real model checking** on every spec via `TLC` and
reports per-spec pass/fail with state counts:

```
==> TLC  ok  capabilities      (79137 distinct states, depth 10)
==> TLC  ok  ipc               ( 1498 distinct states, depth  5)
==> TLC  ok  scheduler         (  514 distinct states, depth 18)
==> TLC  ok  sot_capabilities  (  850 distinct states, depth  4)
==> TLC  ok  sot_provenance    ( 1462 distinct states, depth 13)
==> TLC  ok  sot_transactions  (  602 distinct states, depth  9)
tlc: 6 passed, 0 failed, 0 skipped
```

The first run found and fixed real bugs in five specs (unbounded
`CHOOSE`, over-strict `Rollback` invariant, stale WAL after abort,
duplicate-thread `Enqueue`, looping `RECURSIVE Descendants`). One open
finding is parked: `sot_transactions::Atomicity` is violated when
Tier 1 `T1Write` and Tier 2 `T2Begin` interleave on the same object;
the `.cfg` restricts checking to a single transaction so the
structural invariants still verify.

`just tlc` runs the SANY syntax/level checker as a faster pre-check.

## Architecture

- **Verified microkernel** (~10K LOC target) with selective exokernel bypass
- **Capability-based security**: every kernel object accessed through capabilities with delegation and revocation
- **Per-core scheduling**: ticket-locked run queues with work stealing across CPUs
- **EDF deadline scheduling**: real-time threads with earliest-deadline-first priority
- **Per-core IPC**: each core has its own endpoint pool, cross-core delivery via mailbox + IPI
- **Synchronous endpoints + lock-free SPSC channels**
- **Userspace VMM**: page faults handled by a userspace server, not the kernel
- **Multi-address-space**: each process gets its own CR3 + page tables
- **SMP**: 1–4+ CPU cores with per-CPU LAPIC timers, IPI, per-core state
- **Network-transparent IPC**: routing layer for distributed computing
- **WASM SFI**: bare-metal `no_std` WebAssembly interpreter
- **Live migration**: thread checkpoint/restore for process migration across nodes

## Personality crates

`personality/` contains the BSD/Linux personality layer that the SOT
microkernel hosts. Every crate is `no_std` and links into init or a
dedicated service.

| Crate | Purpose |
|---|---|
| `personality/common/provenance` | Graph Hunter (anomaly detection over a provenance graph) + BlastRadius (capability attack-path analysis) |
| `personality/common/deception` | `AnomalyDetector`, `InterpositionEngine`, `MigrationOrchestrator`, `DeceptionProfile` (ubuntu/centos/iot/windows variants) |
| `personality/common/policy` | Policy DSL types (used by interposition rules) |
| `personality/bsd/zfs` | `ZfsPool`, `Dataset`, `SnapshotManager`, `TxgBridge` (transactional snapshots tied to SOT tx events) |
| `personality/bsd/hammer2` | `Hammer2SnapshotManager`, `Hammer2Cluster` (CoW snapshots, distributed clustering stubs) |
| `personality/bsd/bhyve` | `VmDomain`, `VCpu`, `VmcsConfig`, `VmDeceptionProfile::bare_metal_intel/amd/vmware_guest`, `VmIntrospector` |
| `personality/bsd/network` | `PfInterposer`, `PfRule`, `ProvenanceOracle`, `PacketInfo`, `PfDecision` |
| `personality/bsd/vfs` | BSD VFS server, vnodes, mount table, capability-gated file handles |
| `personality/bsd/process` | POSIX-to-SOT translation layer for the process server |
| `personality/bsd/rump-sot` | NetBSD rump kernel adaptation layer (predecessor of `vendor/netbsd-rump/rumpuser_sot.c`) |
| `personality/linux/linuxulator` | Linux personality layer, syscall table, procfs emulation |
| `personality/linux/lkl` | Linux Kernel Library domain wrapper |
| `personality/linux/lucas` | LUCAS evolution bridge |

## Userspace services

Each runs in its own address space.

| Service | Purpose |
|---|---|
| `services/init` | Init process: VMM server, LUCAS interceptor, framebuffer console, all 6 tier demos, watchdog threads, signify boot chain verifier, **SMF active-respawn supervisor** |
| `services/lucas-shell` | Linux-ABI compatible shell (fork/exec/signals/job control/history/functions). Builtins split across `text/files/system/apt/util` sub-modules |
| `services/kbd` | PS/2 keyboard driver |
| `services/xhci` | USB xHCI host controller driver |
| `services/net` | Virtio-NET driver + full IP stack |
| `services/nvme` | NVMe SSD driver |
| `services/vmm` | Demand paging server |
| `services/compositor` | Wayland compositor with **Tokyo Night theme**, layer-shell, popups, fractional scaling stub, multi-shape cursors, anti-aliased font, animation framework, per-rect damage tracking |
| `services/hello` | Minimal test process |
| `services/styx-test` | **Tier 1**: validates SOT syscalls 300–311 |
| `services/rump-vfs` | **Tier 2**: links real `librump_fused.a`, exposes IPC VFS |
| `services/attacker` | **Tier 3**: emits provenance entries for the deception demo |
| `services/posix-test` | **Tier 5b**: POSIX-equivalence smoke over native SOT primitives (11/11 PASS) |
| `services/abi-fuzz` | **Nightly**: 10 000-iteration random syscall fuzzer with deterministic xorshift64 seed |
| `services/sot-statusbar` | Wayland layer-shell client (Top layer): Tokyo Night status bar with TSC clock + free memory + thread count |

## Storage

- Virtio-BLK driver with transactional object store (WAL, bitmap, directory)
- NVMe SSD driver — interrupt-driven MMIO hardware driver
- AHCI/SATA driver — HBA initialization, port enumeration, DMA EXT 48-bit LBA
- USB mass storage — BBB protocol, SCSI commands over USB
- VFS shim with file handles, read/write, stat, chmod/chown
- Page cache (64-entry LRU, write-back)
- Distributed VFS — object store replication across nodes

## Networking

- Virtio-NET driver
- Ethernet + ARP (32-entry cache) + IPv4 + IPv6
- ICMP / UDP / TCP (Reno congestion control, RFC 7323 window scaling)
- DNS resolver, DHCP client
- TLS / crypto primitives (SHA-256, HMAC-SHA256, ChaCha20, X25519)
- HTTP client (HTTP/1.1 GET/POST)
- Socket API for LUCAS shell

## Security

- **Ed25519 + SHA-256 boot chain** — every signed initrd binary verified before spawn (Tier 0)
- **W^X enforcement** — `SYS_MAP/MAP_INTO/MAP_OFFSET` auto-add NX to writable pages, `SYS_PROTECT` enforces W^X
- **Stack guard pages** — unmapped page below each process stack
- **ASLR** — stack base randomized with RDTSC-seeded xorshift64
- **KARL ID randomization** — `kernel/src/karl.rs` adds per-boot offsets to the SOT tx pool (more pools wired in follow-up)
- **Stack canaries** — `-Z stack-protector=strong` on kernel + every service
- **Multiuser** — user accounts, SHA-256 password hashing, UID/GID enforcement
- **chmod/chown** syscalls — Unix permission model
- **Capability interposition** — `so_invoke` on an interposed cap is routed through a proxy domain (`InterpositionPolicy::{Passthrough, Inspect, Redirect, Fabricate}`)
- **Deception migration** — anomaly detection (`CredentialTheftAfterBackdoor`, `ReconnaissanceSweep`, `DataExfiltration`, `PersistenceInstall`, `StagedPayload`, `PrivilegeEscalation`, `AnomalousFanOut`) feeds the `MigrationOrchestrator` which interposes the offending domain's caps with a `DeceptionProfile`

## CI

The `.github/workflows/` tree ships **15+ jobs** across multiple workflows
(`ci.yml`, `audit.yml`, `repro.yml`, `release.yml`, `abi-diff.yml`, `fuzz.yml`):

| Job | Purpose |
|---|---|
| `build-kernel` | Build `sotos-kernel` and `services/init` on every push/PR |
| `build-personality` | Build all `personality/{common,bsd,linux}/*` crates |
| `clippy-strict` | `cargo clippy -- -D warnings` on the kernel and `sotos-common` (legacy non-blocking) |
| **`lint-strict-core`** | NEW: hard-fail `cargo fmt --check` + `cargo clippy -D warnings` on `sotos-kernel`, `sotos-common`, `sot-fma`, `sot-crossbow`, `sotos-ld`. No `continue-on-error`. |
| `python-scripts` | Smoke test for `scripts/build_signify_manifest.py` |
| `deception-tests` | Host-side `cargo test` for `personality/common/deception` |
| `tla-sany` | `scripts/run_sany.sh formal` — TLA+ syntax/level checker |
| `tla-tlc` | `scripts/run_tlc.sh formal` — full TLC model checking on all 6 specs |
| `rumpuser-sot-smoke` | Cross-compile `vendor/netbsd-rump/rumpuser_sot.c` with clang freestanding (`--target=x86_64-unknown-none -mno-red-zone -mno-sse -mcmodel=large`) and audit symbol coverage against `rumpuser.h` (60/60 must be defined) |
| `boot-smoke` | QEMU TCG boot, asserts the 16 PASS markers (Signify, STYX, posix-test, kernel-test, RUMP-VFS-TEST, Tier 3, FMA, Tier 4, Crossbow, Tier 5, abi-fuzz, SMF respawn, DLTEST + DLTEST mul, compositor input WIRED), uploads `serial.log` on failure |
| **`audit / cargo-audit`** | NEW: `cargo audit` (RustSec) on every push/PR. Hard-fail on advisories. |
| **`audit / cargo-deny`** | NEW: `cargo deny check` against `deny.toml` license / source / advisory allowlist. |
| **`abi-diff`** | NEW: per-PR ABI diff bot. Parses `libs/sotos-common::Syscall` enum from base + head, posts a sticky markdown diff comment. |
| **`repro / build-linux + build-windows + compare`** | NEW: matrix builds `target/sotos.img` twice per host then cross-compares SHA-256 to enforce reproducibility (`SOURCE_DATE_EPOCH`). |
| **`fuzz` (nightly cron)** | NEW: runs the `services/abi-fuzz` random-syscall harness for 10 000 iterations under QEMU; fails if the kernel panics. |
| **`release` (on tag `v*`)** | NEW: builds the SDK tarball, runs the boot-smoke pass, signs with Ed25519 (`SIGNIFY_KEY_BYTES` base64 secret), uploads `.tar.gz + .sha256 + .sig` to the GitHub Release. |

## Build & Run

Requires: Rust nightly, Python 3, QEMU, [just](https://github.com/casey/just).

```bash
just run        # build + boot in QEMU (serial output, -cpu max)
just run-gui    # with QEMU display window
just run-net    # with virtio-net networking (SLIRP)
just run-smp    # with 4 CPU cores
just run-full   # ALL devices (virtio-blk, virtio-net, NVMe, xHCI, AC97, AHCI, SMP4)

just sigmanifest  # regenerate the SHA-256 + Ed25519 boot manifest
just tlc          # SANY syntax/level check on the 6 TLA+ specs
just tlc-mc       # full TLC model checking on the 6 TLA+ specs
just clippy       # cargo clippy -- -D warnings on kernel + sotos-common
just fmt-check    # cargo fmt --check across the workspace
just debug        # boot with GDB server (gdb -ex "target remote :1234")
just flash DISK=/dev/sdX  # flash to USB for real hardware
```

## Project structure

```
kernel/                 The microkernel (Ring 0)
  arch/x86_64/          CPU-specific: serial, GDT, IDT, LAPIC, SYSCALL, per-CPU
  mm/                   Frame allocator + slab + paging + page cache + MMIO + demand paging
  cap/                  Capability table + CDT for delegation/revocation
  ipc/                  Endpoints (sync) + Channels (async) + Notifications + Routing
  sched/                Per-core scheduler with work stealing + EDF
  sot/                  Secure Object exokernel layer (cap_epoch, domain, tx, tx_wal,
                        provenance, fast_ipc, aslr, crypto, wx, ...)
  syscall/              Per-handler split: cap, ipc, memory, thread, sot, debug, ...
  karl.rs               KARL per-boot ID randomization
  ...
libs/                   Userspace libraries (sotos-common, sotos-net, sotos-objstore,
                        sotos-virtio, sotos-pci, sotos-nvme, sotos-xhci, sotos-wasm,
                        sotos-ld, sotos-ahci, sotos-audio, sotos-gui, sotos-mouse,
                        sotos-lua, sotos-pkg, sotos-usb-storage)
personality/            BSD + Linux + common personality crates (see table above)
services/               Userspace services (see table above)
vendor/netbsd-rump/     NetBSD rump kernel sources + rumpuser_sot.c hypervisor +
                        librump_fused.a (built artifact)
formal/                 TLA+ specifications + .cfg files for TLC
boot/                   Bootloader configuration (limine.conf)
scripts/                Build tools: mkimage.py, mkinitrd.py, build_signify_manifest.py,
                        run_sany.sh, run_tlc.sh, ...
docs/                   Technical paper (LaTeX, CLRS-style)
.github/workflows/      CI: build, clippy, SANY, TLC, boot-smoke
```

## Documentation

- [docs/sotBSD_v0.2.0_whitepaper.pdf](docs/sotBSD_v0.2.0_whitepaper.pdf) — **comprehensive system + proposal whitepaper** (architecture, SOT layer, deception model, GUI stack, v0.2.0 Illumos heirlooms)
- [docs/manual.pdf](docs/manual.pdf) — full user / developer manual
- [docs/sotos-architecture.pdf](docs/sotos-architecture.pdf) — kernel architecture deep-dive
- [docs/paper.pdf](docs/paper.pdf) — research paper writeup
- [docs/MEMORY_BUDGET.md](docs/MEMORY_BUDGET.md) — kernel static memory inventory
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SOT_SPEC.md](docs/SOT_SPEC.md), [docs/DECEPTION_MODEL.md](docs/DECEPTION_MODEL.md), [docs/FORMAL_MODEL.md](docs/FORMAL_MODEL.md), [docs/RUMP_ADAPTATION.md](docs/RUMP_ADAPTATION.md), [docs/ABI_v0.1.0.md](docs/ABI_v0.1.0.md)
- [docs/SPRINT1_STATUS.md](docs/SPRINT1_STATUS.md), [docs/SPRINT2_STATUS.md](docs/SPRINT2_STATUS.md), [docs/SPRINT3_STATUS.md](docs/SPRINT3_STATUS.md)

## Roadmap

See [TODO.md](TODO.md) for the full tier roadmap, finished items, the
v0.2.0+ "Illumos Heirlooms" wave (SMF / Crossbow / FMA / GUI renewal /
init splits / CI strict / hygiene), and parked follow-ups (real OpenZFS
link, `rump_init` scheduler bisect, multi-tx Atomicity fix, real-HW perf
comparison vs seL4/L4, LTP run).

## License

All rights reserved.
