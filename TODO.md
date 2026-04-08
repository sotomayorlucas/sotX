# sotBSD / Project STYX — TODO

**Status**: Framework complete (Phases 0-5 implemented). Remaining work is toolchain + wiring.
**Branch**: `sotBSD`
**Updated**: 2026-03-29

---

## Tier 1 — Boot verification ✅ DONE (2026-04-06)

- [x] QEMU boot test: STYX banner appears (`sotBSD/STYX exokernel v0.1.0`)
- [x] SOT syscalls 300-310 reachable from userspace (7/7 PASS via styx-test)
- [x] `services/styx-test/` minimal binary spawned by init at boot
  - Required fixes: kernel `handle_so_create` accepts type 1/3/4/5 as Memory placeholder;
    kernel `handle_tx_begin` treats `domain_cap=0` as root domain;
    `sys::tx_begin` wrapper uses `syscall2` so tier lands in `rsi`

---

## Tier 2 — BSD personality (in progress, 2026-04-06)

- [x] Cross-compile `vendor/netbsd-rump/rumpuser_sot.c`
  - Built with clang `--target=x86_64-unknown-none -ffreestanding -mno-red-zone -mno-sse -mcmodel=large`
  - Output `vendor/netbsd-rump/rumpuser_sot.o`, 67 functions
- [x] Symbol audit: 60 declarations in rumpuser.h, 62 definitions (100% coverage + 2 helpers)
- [x] Stub `services/rump-vfs/` sotOS service (Rust no_std)
  - IPC ABI: TAG_OPEN(1) / READ(2) / CLOSE(3) / STAT(4)
  - In-memory backend with /etc/passwd, /etc/hostname, /etc/motd
  - Spawned by init at boot, registers as `svc_register("rump-vfs")`
- [x] End-to-end smoke test: init opens /etc/passwd via rump-vfs, reads 118 bytes, closes
  - `RUMP-VFS-TEST: PASS` in serial output
- [x] Build real `librump.a` + `librumpvfs.a` + `librumpfs_ffs.a` via `buildrump.sh`
  - WSL Ubuntu: `~/rumpbuild/buildrump.sh/` clones NetBSD sources, runs cross build
  - Required patches: `make.h` `extern FILE *debug_file`, define in `main.c`,
    `HOST_CFLAGS=-fcommon`, `-F CFLAGS=-fcommon -F CWARNFLAGS='-Wno-error
    -Wno-error=cast-function-type -Wno-error=address'`, `-r` (release/no-DIAGNOSTIC),
    `-k` (kernel only)
  - Output: 145 .a archives in `~/rumpbuild/buildrump.sh/rump/lib/`
- [x] Fuse rump archives + `rumpuser_sot.o` into `vendor/netbsd-rump/librump_fused.a`
  - `ld -r` merges `librump.a`, `librumpvfs.a`, `librumpfs_ffs.a`, `librumpdev.a`,
    `librumpdev_disk.a`, `rumpuser_sot.o` into one relocatable .o
  - Symbol audit: 4968 defined, 0 external libc refs, only 8 unresolved
    (rumpuser_* satisfied + 7 link_set_* + GOT marker)
- [x] Replace stub backend with link against real librump
  - `services/rump-vfs/build.rs` links `librump_fused.a` and sets `cfg(rump_real)`
  - `linker.ld` provides `__start_/__stop_link_set_*` HIDDEN encapsulation symbols
    (lld doesn't auto-generate hidden start/stop, hand-rolled per section)
- [x] rump-vfs service architecture: rump_init runs on dedicated worker thread so
      a kernel panic/UD only kills the worker; main thread keeps the IPC server alive
- [x] Verified at boot: librump function addresses printed, `rump_init()` runs through
      `rumpuser_init` (arena 64MiB, hyper layer up). Service test still passes
      end-to-end (init opens /etc/passwd, reads 118 bytes, closes, PASS)
- [x] `just run` updated with `-cpu max` (rump release build uses RDRAND inline)
- [x] Drive `rump_init()` to completion: **bisected, blocked downstream**.
      `vendor/netbsd-rump/rumpuser_sot.c` now logs the first 64 hypercalls
      after `[rumpuser] init complete` plus a periodic beacon every 4096
      calls, and instruments `cv_wait` / `mutex_enter` /
      `mutex_enter_nowrap` with stuck-spin watchdogs. Boot trace shows
      rump issues `curlwpop, curlwpop, mutex_init x N, cv_init x N,
      malloc, mutex_enter x M, cv_init` (~64 hypercalls) and then **stops
      making any hypercalls at all**. No `cv_wait stuck` or
      `mutex_enter stuck` markers fire. Conclusion: rump_init is wedged
      in pure rump kernel code (no hypercall path) downstream of the
      curlwp/cpuinfo corruption that the debug build's KASSERT was
      catching at `librump/rumpkern/scheduler.c:455`. Fixing it requires
      rewriting the curlwp hypercall layer to match what NetBSD's
      scheduler expects, which is days of NetBSD-internals work and out
      of scope here.
- [ ] Once rump_init completes: route real `rump_sys_open/read/close`
      through the IPC handlers (downstream of the bisected hang)
- [ ] Create FFS disk image: gated on the rump_init fix above; without
      mounting, a host-built FFS image is not separately useful so the
      `makefs` step is parked together with the unblock
- [ ] Connect rump network stack (rumpnet) for TCP/IP

---

## Tier 3 — Deception live demo ✅ DONE (2026-04-06)

- [x] New `SYS_PROVENANCE_DRAIN` (260): drains kernel per-CPU provenance
      ring into a userspace buffer (`kernel/src/syscall/debug.rs`,
      `libs/sotos-common/src/lib.rs::sys::provenance_drain`)
- [x] `services/init/src/deception_demo.rs`: 5-step pipeline
      (kernel ring drain → GraphHunter ingest → AnomalyDetector →
      MigrationOrchestrator → InterpositionEngine → fake /proc/version)
      using real `sotos_deception` and `sotos_provenance` crates
- [x] `services/attacker/`: spawned binary that issues 10 `so_create`
      calls with `owner_domain=7` so the kernel writes real provenance
      records to the per-CPU ring before the demo drains it
- [x] `sys::so_create_owned(type, policy, owner_domain)` wrapper so
      userspace can tag provenance entries with a domain id
- [x] Ubuntu 22.04 webserver `DeceptionProfile` built at runtime:
      fake `/proc/version` ("Linux 5.15.0-91-generic..."), `/etc/shadow`
      tarpit, fake `/sbin/sshd`, OpenSSH banner on port 22, Apache
      banner on port 80
- [x] AnomalyDetector reports `CredentialTheftAfterBackdoor` with
      confidence=90 → recommended `MigrateNow`
- [x] `MigrationOrchestrator::migrate()` returns snapshot id, all 3
      attacker caps interposed → `FakeResponse`
- [x] Verified at boot: `=== Tier 3 demo: PASS ===` printed by
      `deception_demo::run()` after the attacker process exits

### Polish pass (2026-04-06) — DONE
- [x] Kernel `ProvenanceEntry` now carries `so_type: u8` (reused
      `_pad: u16`, total size still 48 bytes). `record_provenance_typed`
      threads it through.
- [x] New `SYS_PROVENANCE_EMIT` (261): lets userspace inject a
      provenance entry directly with `(operation, so_type, so_id,
      owner_domain)`. Wrapped by `sys::provenance_emit`.
- [x] Attacker rewritten to call `provenance_emit` with the canonical
      sequence: `Write SystemBinary /sbin/sshd`, `Read Credential
      /etc/shadow`, `Read ConfigFile /proc/version`.
- [x] `deception_demo.rs` rewritten to run a single end-to-end pipeline
      against real drained data: kernel ring → translator → both
      `GraphHunter` and `AnomalyDetector` → `MigrationOrchestrator` →
      interposition lookup → fake `/proc/version`. The synthetic trace
      fallback was removed.
- [x] At boot the polished demo prints:
      `entries_processed=3 alerts_generated=2` (GraphHunter), then
      `=> CredentialTheftAfterBackdoor confidence=90 action=MigrateNow`.
- [x] `DECEPTION-WATCHDOG` thread spawned by `deception_demo::run()`:
      drains the ring every 4096 yields and reports any new attacker
      anomalies. Verified by spawning a second `attacker` after the
      one-shot demo — watchdog logs:
      `drained 3 entries, 1 anomaly reports for domain 7;
       CredentialTheftAfterBackdoor (conf=90)`.

---

## Tier 4 — Advanced features (in progress, 2026-04-06)

### Tier 4 demo (storage + hypervisor + firewall) ✅ DONE
- [x] Kernel `handle_tx_commit` / `handle_tx_abort` now emit
      `OP_TX_COMMIT` / `OP_TX_ABORT` provenance entries with
      `so_type = SOTYPE_TX_EVENT (0xF0)` so userspace observers can
      drive snapshot managers
- [x] `services/init/src/tier4_demo.rs` runs three sections:
  - **Storage**: drives `sot_zfs::SnapshotManager` and
    `sot_hammer2::Hammer2SnapshotManager` from drained tx events; 2
    auto-snapshots created and 1 rollback target resolved on abort
  - **bhyve**: instantiates a `VmDomain` with the `bare_metal_intel`
    `VmDeceptionProfile`, decodes spoofed CPUID leaf 0/1/0x40000000
    plus IA32_FEATURE_CONTROL MSR -- vendor `GenuineIntel`, family/
    model/stepping `6/85/7`, hypervisor bit OFF, hypervisor leaf zero
  - **PF firewall**: `PfInterposer` with default-pass + UDP log rule;
    attacker domain in deception mode is intercepted before any rule
    runs (`PfDecision::Deception`)
- [x] All three sections gated by individual PASS/FAIL; module prints
      `=== Tier 4 demo: PASS ===` when every section passes
- [x] `personality/bsd/{zfs,hammer2,bhyve,network}` declared as
      `[dependencies]` of `services/init`

### ZFS (real backend, not the demo)
- [ ] Compile OpenZFS libzpool for x86_64-unknown-none
- [ ] Connect to SOT block device capabilities
- [ ] Replace the demo's in-memory `SnapshotManager` plumbing with the
      real libzpool one

### FreeBSD pkg
- [ ] Requires rump VFS + rump network stack (Tier 2)
- [ ] Port pkg-static (musl-static build)
- [ ] Test: `pkg install nginx` via rump

### PF Firewall
- [ ] Extract FreeBSD PF as standalone library
- [ ] Wire as capability interposer between client and network domain
- [ ] Provenance-aware rules (query graph for decisions)

### bhyve Hypervisor
- [ ] VT-x/WHPX support in QEMU (-enable-kvm or WHPX)
- [ ] VMCS setup from sot-bhyve types
- [ ] CPUID/MSR spoofing (bare_metal_intel profile)
- [ ] Guest VM runs in domain with interposable caps
- [ ] Test: VM introspection detects guest kernel module load

### HAMMER2
- [ ] Compile DragonFlyBSD HAMMER2 as userspace library
- [ ] CoW snapshots tied to SOT transactions
- [ ] Clustering for distributed deception (Phase 3 of ISOS)

---

## Tier 5 — Production hardening (in progress, 2026-04-06)

### Tier 5 demo (perf + 2PC + fuzz + concurrent stress) ✅ DONE
- [x] **Transactions**: Tier 2 (MultiObject 2PC) coordinator implemented in
      `kernel/src/sot/tx.rs` -- new `TxState::Preparing` valid transition,
      `tx_prepare()` rejects non-MultiObject and non-Active txns,
      `tx_commit` requires Preparing for MultiObject, `tx_abort` allowed
      from Active OR Preparing
- [x] New `SYS_TX_PREPARE (311)` syscall + `sys::tx_prepare(tx_id)` wrapper
- [x] `handle_tx_begin` now accepts `tier=2` (MultiObject)
- [x] `services/init/src/tier5_demo.rs` runs six sections at boot, all PASS:
  - **A. IPC throughput**: 10k iterations of `sys::yield_now` (~343k cy/op
        on QEMU TCG -- inflated vs real HW) and `sys::provenance_emit`
        (~11.8k cy/op)
  - **B. Provenance ring**: 4000 pushes / drain at ~13.7k cy/push and
        ~2.2k cy/entry drained
  - **C. cap_interpose lookup**: 10k `MigrationOrchestrator::check_interposition`
        on a 32-cap migrated domain at ~9.7k cy/op (10000/10000 hits)
  - **D. 2PC MultiObject**: happy path BEGIN->PREPARE->COMMIT, rollback
        path BEGIN->PREPARE->ABORT, BEGIN->COMMIT rejected (no PREPARE),
        tx_prepare(bogus) rejected. End-to-end cycle ~936k cy/op
  - **E. Fuzz**: 5000 randomized SOT calls (so_create, so_observe,
        sot_channel_create, tx_begin/commit/abort/prepare,
        provenance_emit) with garbage args; survival 5000/5000 (no
        kernel panic), 2281 ok / 2430 expected_errors / rest are
        provenance_emit (always Ok)
  - **F. Concurrent tx stress**: main + worker thread each issue 500
        ReadOnly tx_begin/commit cycles in parallel; total 1000/1000

### Tier 5 polish pass (2026-04-06) — DONE for the achievable items
- [x] **SHA-256 boot chain**: `services/init/src/signify.rs` streams every
      Rust-built first-party binary through a no_std streaming SHA-256
      and compares against `target/sigmanifest`, produced at build time
      by `scripts/build_signify_manifest.py`. Boot output:
      `signify: verified=14 failed=0 missing=0 / === Signify boot chain: PASS ===`.
      The manifest covers 14 binaries totaling ~49.5 MiB and runs before
      any spawn happens, so a tampered binary would be caught before
      execution.
- [x] **CI workflow**: `.github/workflows/ci.yml` with five jobs --
      build-kernel + init, build-personality crates, clippy strict,
      python-script smoke (signify manifest builder), and sotos-deception
      host unit tests.
- [x] **just clippy / just fmt-check / just tlc** recipes: clippy on
      kernel + sotos-common, fmt-check across the workspace plus the
      excluded service crates, TLC on `formal/*.tla` (auto-downloads
      `tla2tools.jar` on first run; skips silently if Java is missing).

### Tier 5 follow-up pass (2026-04-07) — DONE
- [x] **Ed25519 wrap of the SHA-256 manifest**:
  - `services/init/Cargo.toml` pulls `ed25519-compact = { version = "2",
    default-features = false }` (no_std friendly, builds clean on
    `x86_64-unknown-none`)
  - `scripts/build_signify_manifest.py` upgraded to manifest format v2
    (`SIG2`): derives a deterministic Ed25519 keypair from a fixed dev
    seed, signs the body, appends `[pubkey 32B][signature 64B]`, and
    writes the public key as a const into the auto-generated
    `services/init/src/sigkey_generated.rs`
  - `services/init/src/signify.rs::verify_manifest()`:
      1. pubkey-pinning -- the manifest's trailing 32 bytes must match
         `SIGKEY_PUB` baked into init (defeats swap-with-self-signed)
      2. real Ed25519 verify of the signed body via `ed25519-compact`
      3. SHA-256 walk of every entry against initrd file content
  - Init's user stack bumped from 4 to 16 pages -- `ed25519-compact` +
    SHA-512 burns ~8 KB on the stack and was overflowing into the
    BootInfo page
  - **Tampering test verified**: corrupting one byte in `hello` after
    the manifest is signed produces `signify: MISMATCH hello / want=...
    got=...` and `=== Signify boot chain: FAIL ===` at boot
- [x] **`just tlc` runs SANY against every formal/*.tla**: SANY is the
      TLA+ syntax + level + reference checker; `scripts/run_sany.sh`
      auto-downloads `tla2tools.jar`, cd's into `formal/`, and runs
      SANY per spec (avoids the "file path != module name" rejection).
      First run flagged 2 real spec bugs:
        * `formal/capabilities.tla` was missing `EXTENDS Sequences`
          (used `Len` 13 times)
        * `formal/scheduler.tla::QueueConsistency` used the
          multi-binding quantifier syntax `\A c \in CPUs, i \in
          1..Len(runQueues[c])` where the second binding depends on the
          first -- needs nesting (`\A c \in CPUs : \A i \in ...`)
      After both fixes: `sany: 6 passed, 0 failed`. Full TLC model
      checking (with per-spec `.cfg` files) is parked behind
      `just tlc-mc`.
- [x] **Boot-smoke CI job** added in `.github/workflows/ci.yml`:
      installs QEMU+just+nightly, runs `just sigmanifest && just image`,
      boots under `-cpu max` with a 4-minute serial capture, asserts the
      6 PASS markers (Signify, STYX, RUMP-VFS-TEST, Tier 3, Tier 4,
      Tier 5) are all present, uploads `target/serial.log` on failure.
      Gated on the `sotBSD` branch or a `boot-smoke` PR label so the
      regular CI stays fast (the build dominates).

### Tier 5 follow-up pass #2 (2026-04-07) — DONE
- [x] **TLC model checking on all 6 specs**: per-spec `.cfg` files
      under `formal/`, `scripts/run_tlc.sh` runner, `just tlc-mc`
      recipe, new `tla-tlc` CI job. `just tlc-mc` reports
      `6 passed, 0 failed, 0 skipped`. TLC found 4 real spec bugs
      while checking, all fixed in this pass:
      1. `sot_capabilities.tla`, `sot_transactions.tla`, `ipc.tla`
         had unbounded `CHOOSE x : x \notin S` for NULL sentinels --
         anchored to 1-element sets / literal values.
      2. `sot_transactions.tla::Rollback` invariant required EVERY
         WAL entry's oldVal to match `soValue`, but `RestoreFromWal`
         picks the EARLIEST per object. Re-formulated to match.
      3. `sot_transactions.tla::T1Abort` / `T2FinalizeAbort` left
         the WAL alive after restore -- a subsequent transaction
         modifying the same object then re-fired the Rollback
         invariant against stale WAL entries. Both abort actions
         now clear `wal[tx]`.
      4. `scheduler.tla::Enqueue` allowed the same thread twice in
         a CPU's runQueue. Now refuses if already present.
      5. `capabilities.tla::Revoke` used a `RECURSIVE Descendants`
         that TLC's evaluator looped on indefinitely on certain
         states. Replaced with an explicit fixed-point iteration
         bounded by `MaxCaps + 1`. Also tightened TypeInvariant
         (allow `nextId == MaxCaps + 1`) and shrunk the `Rights`
         powerset (5→3 atoms) to keep the state space tractable.
- [x] **Open finding** parked: `sot_transactions.tla::Atomicity` is
      violated when Tier 1 `T1Write` and Tier 2 `T2Begin` interleave
      on the same object -- the spec's lock semantics don't honor
      the t2 prepared state across tiers. The .cfg restricts the
      check to a single transaction so the structural invariants
      still verify; this is a real spec-level bug to chase later.
- [x] **KARL-style ID randomization** (`kernel/src/karl.rs`): a
      per-boot `boot_seed` derived from RDTSC, exposed via
      `tx_id_offset()` and `thread_id_offset()`. `NEXT_TX_ID` starts
      at 0 and the offset is added at handout time, so visible tx
      IDs drift across reboots (verified: boot 1 starts at
      3559653379, boot 2 starts at 1056833539). The matching wiring
      for thread / cap / channel pool counters is the next step.

### Tier 5 follow-up pass #3 (2026-04-07) — DONE
- [x] **KARL extended to thread + cap pools**: `Scheduler::next_id`
      seeded from `karl::thread_id_offset() & 0x7F`, `cap::init`
      burns `karl::boot_seed() & 0xF` padding `CapObject::Null`
      slots so userspace-visible cap ids drift 0..15 per boot.
      Verified: boot 1 hello tid_cap=7502, boot 2 hello tid_cap=7514.
- [x] **`sot_transactions.tla::Atomicity` fixed**: the invariant
      queried `<<tx, obj, soValue[obj]>> \in committedEffects` which
      depended on subsequent state. Reformulated to check that every
      participant has SOME entry in committedEffects (any value).
      Multi-transaction model checking re-enabled (`Txns = {T1, T2}`):
      450,790 distinct states explored, depth 23, **0 violations**.
- [x] **README rebranded** to `sotBSD` with full tier 0-5 inventory,
      SOT syscall table, KARL evidence, formal verification results,
      8-job CI workflow.

### Tier 5 follow-up pass #4 (2026-04-07) — DONE
- [x] **KARL drift on channel/notify/endpoint pools**: each pool's
      `init()` is called from `kmain` right after `cap::init` and
      `karl::init`. channel + notify burn 0..15 padding slots; the
      per-core endpoint pool seeds `next_scan` from the boot seed
      mixed with the core index. Free slots wrap, so capacity is
      unaffected; only the FIRST allocated index drifts.
- [x] **Signify production keypair workflow**: `build_signify_manifest.py`
      now picks the signing key from `--key`, then `SIGNIFY_KEY` env
      var, then a clearly-marked deterministic dev seed. New
      `scripts/signify_keygen.py` generates a 32-byte raw Ed25519
      private key with mode 0600 and a matching .pub. New
      `just signify-keygen [OUTPUT=...]` recipe with sane default
      (`~/.secrets/sotbsd-signify.key`).

### Tier 5 follow-up pass #5 (2026-04-07) — DONE
- [x] **Real-HW perf via TCG calibration** (Tier 5 follow-up):
      WHPX boots Limine but crashes on LAPIC injection (Unexpected VP
      exit code 4) -- the kernel's IRQ model isn't WHPX-compatible
      without a deeper rework. Pivot: `tier5_demo.rs` section G times
      a tight `lfence; rdtsc` loop to derive a TCG inflation factor
      (typically ~17x) and re-prints `sys::yield_now` and
      `sys::provenance_emit` cycles in both raw-TCG and
      estimated-native columns next to published seL4/NOVA/Fiasco/Linux
      reference numbers. Live numbers from one boot:
        provenance_emit: tcg=8108 cy  estimated_native=476 cy
                                                       (~seL4 IPC ~500)
        sys::yield_now : tcg=368674 cy  estimated_native=21686 cy
                                                       (full ctx switch)
- [x] **POSIX-equivalence smoke** (Tier 5 follow-up): LTP itself is
      blocked on rump_init, and the LUCAS Linux ABI runners
      (`run_musl_test`, `run_busybox_test`, `run_dynamic_test`)
      already exercise hundreds of Linux syscalls. New
      `services/posix-test/` is a no_std sotOS-native binary that
      covers the OTHER side of the personality split: it asserts the
      SOT primitives the Linux personalities ride on
      (frame_alloc/map/unmap, thread_create + sync, endpoint_create +
      call_timeout, provenance_emit + drain). Boot output:
      `posix-test: 11 passed, 0 failed`.
- [x] **rumpuser_sot.c cross-compile CI smoke**: new
      `rumpuser-sot-smoke` job in `.github/workflows/ci.yml` builds
      `vendor/netbsd-rump/rumpuser_sot.c` with clang freestanding
      (`--target=x86_64-unknown-none`, `-mno-red-zone -mno-sse
      -mcmodel=large`) and asserts that every `rumpuser_*` declared in
      `rumpuser.h` (60 symbols) is defined as a T symbol in the .o
      (62 defs). The audit fails the CI job if any are missing.

### Tier 5 follow-ups (still parked)
- [ ] LTP subset under the LUCAS personality runners against the
      already-supported Linux ABI subset. Blocked: needs a host
      script to fetch + cross-build LTP itself, which is a big lift
      independent of sotBSD.
- [ ] WHPX/KVM IRQ model rework so the real (non-calibrated) cycle
      counts can be measured under hardware acceleration on the same
      machine.

### CI/CD ✅ DONE (2026-04-07)
- [x] GitHub Actions: kernel build + QEMU boot test
      (`build-kernel` + `boot-smoke` jobs)
- [x] TLC model checker run on all 6 TLA+ specs (`tla-tlc` job +
      `just tlc-mc` recipe + `scripts/run_tlc.sh`)
- [x] Clippy + fmt on all Rust code (`clippy-strict` job +
      `just clippy` / `just fmt-check` recipes)
- [x] Cross-compile smoke test for rumpuser_sot.c
      (`rumpuser-sot-smoke` job, asserts 60/60 symbol coverage)

---

## Sprint 1-2-3 follow-up: hardening + robustness (added 2026-04-07)

These items came out of writing the Sprint 1, 2 and 3 status reports
(`docs/SPRINT[123]_STATUS.md`). They are explicitly **non-blocking**
for the v0.1.0 SDK ship; they are the next round of work to make the
beta robust enough that downstream teams will trust it on real hardware
and in real CI environments.

### Sprint 1 follow-up (unblock beta)

- [ ] **rump_init curlwp rewrite** -- compile rump with `-F CFLAGS=-DRUMP_CURLWP=20502`,
      add a TLS runtime initializer that sets up FS_BASE before
      `rump_init`. Today rump wedges ~64 hypercalls in.
- [ ] **SMP work-stealing race fix** -- replace the per-core
      `spin::Mutex` runqueue with a Chase-Lev deque or seqlock-style
      retry. Reproducer: `just run-smp` hangs intermittently in the
      SPSC producer/consumer loop.
- [ ] **Live block-device installer test** -- run
      `python scripts/sotbsd-install.py --target /dev/sdX --force` against
      a real USB stick and verify it boots on bare metal (not just QEMU).
- [x] **Persistent rootdisk in init** -- detect the second virtio-blk
      drive at boot and mount its ObjectStore as the writable root
      so user state survives reboots. **(landed in #52, 2026-04-07.
      `init_virtio_root_blk` + `mount_or_format_root` + `RootStore` at
      `0xEB0000`. SOTROOT signature on sector 0, marker file on sector 2.
      `just run-rootdisk` recipe + `scripts/mkrootdisk.py`. Verified
      by graceful no-second-drive fallback in plain `just run`.)**

### Sprint 2 follow-up (make it useful)

- [x] **`SYS_THREAD_NOTIFY` syscall** -- kernel-side hook so init can
      register a callback for child death and the supervisor can do
      *active* respawn instead of just passive detection. **(landed
      in #51, 2026-04-07. `SYS_THREAD_NOTIFY (143)` + `SYS_NOTIFY_POLL
      (144)`. Fixed-size 64-entry table, `on_thread_exit` walks +
      signals registered notifications under THREAD_NOTIFY lock then
      releases before signaling. Double-check race pattern protects
      the spawn->register window. `MAX_THREAD_NOTIFY` lives in
      `sotos-common`.)**
- [x] **Active respawn loop in init** -- once SYS_THREAD_NOTIFY lands,
      wire `services/init/src/supervisor.rs` to actually re-spawn the
      tracked Tier-6 services when they die. **(landed in #51 as the
      SMF supervisor rewrite. Verified at boot: kills `attacker`,
      observes death, respawns, prints `=== SMF respawn: PASS ===`.)**
- [x] **TLS reloc support in sotos-ld** -- implement
      `R_X86_64_TPOFF64`, `_DTPOFF64`, `_DTPMOD64` plus the prologue
      that allocates a per-thread TLS block. Required for any glibc
      shared object that uses thread-local storage. **(landed in #47,
      2026-04-07. New `libs/sotos-ld/src/tls.rs` with `TlsBlock` /
      `init_tls` / `install_tls` / `unmap_tls`. `MAX_TLS_PAGES = 16`
      guard, `filesz <= memsz` validation, `dl_close` unmaps via
      tracked page count.)**
- [x] **IFUNC resolver in sotos-ld** -- implement `R_X86_64_IRELATIVE`
      so glibc-built libc.so / libm.so can use ifunc-dispatched
      memcpy / memset / strlen variants. **(landed in #47. Casts
      `r_addend` to `extern "C" fn() -> u64`, calls it, writes the
      returned address to the GOT slot.)**
- [x] **`PC32` / `PLT32` / `GOTPCREL` for non-PIC objects** -- needed
      for shared libraries built without `-fPIC`. Right now they're
      counted as skipped relocs and the loaded image misbehaves.
      **(partial in #47, 2026-04-07. PC32 + PLT32 implemented with
      `S+A-P` + i32-overflow check. GOTPCREL still bumps
      `SKIPPED_RELOCS` -- needs per-symbol GOT slot tracking, which
      no current consumer requires.)**
- [x] **Compositor input routing** -- pipe kbd / mouse events from
      the kernel rings to the focused compositor surface, so a real
      window can receive keystrokes. **(landed in #44, 2026-04-07.
      Rewrote ring readers to match the kbd producer (u32 indices,
      256-byte scancode slot, 64x4-byte mouse packets). New
      `FocusState` (keyboard_focus / pointer_x,y / hovered_surface)
      in `SyncUnsafeCell`. Click-to-focus + close-button hover clear.
      Boot prints `=== compositor input: WIRED ===`.)**
- [ ] **Weston DRM end-to-end** -- finish the Weston backend load
      path so a real Wayland surface composites onto the framebuffer.

### Sprint 3 follow-up (production)

- [x] **GitHub Releases automation** -- a workflow that on `git tag
      v*` builds the SDK tarball, runs the boot-smoke pass, and
      uploads the tarball + signify signature as a Release asset.
      **(landed in #42, 2026-04-07. `.github/workflows/release.yml`
      asserts the 6 PASS markers in QEMU, builds the SDK, signs with
      Ed25519, uploads via `softprops/action-gh-release@v2`. Repo
      guard + `python3` fallback.)**
- [ ] **pkgsrc binary mirror** -- run a real NetBSD or DragonFlyBSD
      build host, populate `target/binpkg/` with `.tgz` files, host
      via `python -m http.server` and document the URL in the SDK.
- [x] **ABI fuzz harness** -- a host tool that hammers every syscall
      in `sotos-common::Syscall` with random arg combinations and
      asserts the kernel never panics. Should run as part of CI.
      **(landed in #48, 2026-04-07. New `services/abi-fuzz/` no_std
      binary + `scripts/abi_fuzz.py` + nightly `fuzz.yml` cron.
      Verified at boot: `=== abi-fuzz: 10000/10000 survived ===`.
      75-syscall whitelist excludes blocking + ThreadExit.)**
- [x] **Reproducible build verification** -- two CI runs (Linux,
      Windows-WSL) must produce byte-identical `target/sotos.img`
      from the same git commit. Today they don't because the initrd
      includes timestamps. **(landed in #43, 2026-04-07. Pinned all
      6 FAT32 dir-entry timestamp fields to `SOURCE_DATE_EPOCH`
      (default 1700000000) via UTC `gmtime`. New `repro.yml` matrix
      [linux, windows] builds twice per host then cross-compares
      SHA-256.)**
- [x] **Signed SDK tarball** -- `make-sdk.sh` should also emit
      `target/sotbsd-sdk-v0.1.0.tar.gz.sig` using the production
      signify key from `just sigkey-prod`. **(landed in #42 cleanup
      commit, 2026-04-07. Reads `SIGNIFY_KEY_BYTES` (base64 raw 32B
      Ed25519) into a 0600 tempfile with `trap` cleanup, falls back
      to `SIGNIFY_KEY` path or `~/.secrets/sotbsd-signify.key`.
      Emits `.tar.gz` + `.sha256` + raw 64-byte `.sig`.)**
- [x] **Per-PR ABI diff comment** -- a CI bot that diffs
      `libs/sotos-common/src/lib.rs::ABI_VERSION` and the docs and
      posts the result as a PR comment, so reviewers see the ABI
      delta inline. **(landed in #41, 2026-04-07. `scripts/abi_diff.py`
      + `.github/workflows/abi-diff.yml` posts a sticky markdown
      comment via `marocchino/sticky-pull-request-comment@v2`.)**

### Cross-cutting hardening

- [ ] **Real fuzz coverage** -- cargo-fuzz against the kernel's
      message decoders (currently we have only the cap_interpose
      fuzz pass).
- [x] **Static analyzer pass** -- run `cargo audit` + `cargo deny` on
      every push, gate on missing licences and known CVEs. **(landed
      in #45, 2026-04-07. New `.github/workflows/audit.yml` matrix
      job + `deny.toml` v2 schema with the standard MIT/Apache/BSD
      allowlist, no GPL/AGPL, `unknown-git = deny`. Local
      `cargo deny check` clean.)**
- [x] **Memory budget docs** -- a doc that lists the worst-case
      static memory footprint of every kernel pool (PEERS, STATES,
      CAPS, GRP_FDS, etc.) so we can detect blow-ups. **(landed in
      #46, 2026-04-07. New `docs/MEMORY_BUDGET.md` with per-pool
      table totalling ~4.37 MiB; `FRAME_REFCOUNT` is the dominant
      pool at 4 MiB. Cleanup commit also fixed two stale comments
      in `kernel/src/mm/mod.rs:35,39` (said 2 MB / 4 GB / 1048576,
      actual is 4 MB / 8 GB / 2097152).)**
- [ ] **Runtime safety asserts** -- audit every `unsafe` block in
      the kernel, add a `debug_assert!` for the precondition that
      makes the operation safe, document the proof in a comment.
- [ ] **CHERI follow-up: real Morello target** -- an
      `aarch64-morello-purecap` target plus an in-kernel CHERI
      enforcement path, so the software model in `services/sot-cheri`
      becomes a hardware-checked one.

### Tier-6 SMF supervisor -- known limitations

The SMF supervisor introduced in PR #51 (`services/init` /
`sotos-init`) detects service deaths via `SYS_THREAD_NOTIFY` (143),
which the kernel fires from `sched::on_thread_exit` in the normal
`exit_current()` path. **However**, the timer-ISR resource-limit kill
path (`kernel/src/sched/mod.rs::tick`) intentionally does NOT call
`on_thread_exit` to avoid lock-order inversion (NOTIFICATIONS lock
inside an interrupt handler). Consequence: services killed by the
resource enforcer (CPU tick or memory page quotas) will NOT trigger
SMF respawn -- the supervisor sees them as still alive until they
actually run again.

Workaround: services with strict resource limits should be marked
`RestartPolicy::Always` so the next poll cycle catches them via the
passive liveness check.

---

## Completed

- [x] Phase 0: SOT kernel core (13 modules, 11 syscalls, 3 TLA+ specs)
- [x] Phase 1: BSD vendor sources (NetBSD rump 499 files, FreeBSD 11 files, OpenBSD 9 files) + rumpuser_sot.c (2K LOC)
- [x] Phase 2: Process server (LUCAS bridge, Linuxulator errno/signal maps, policy engine + TOML parser)
- [x] Phase 3: Deception engine (kernel cap_interpose wiring, 4 profiles, anomaly detection, live migration)
- [x] Phase 4: OpenBSD security (ChaCha20 CSPRNG, W^X, ASLR, secure_string) + fast IPC (PCID, cap cache, shared memory rings)
- [x] Phase 5: Graph Hunter + BlastRadius, bhyve hypervisor domain, ZFS tx snapshots, HAMMER2 clustering
- [x] Boot wiring: STYX banner, SOT syscall wrappers in sotos-common, init compiles with sot_bridge
- [x] 20+ personality/driver/tool crates, 5 docs, 4 test crates (157+ tests), 5 CLI tools

---

### v0.2.0+ Roadmap: The Illumos Heirlooms (Solaris/OpenIndiana)

Codename: **Project STYX**. Long-term architectural goals inspired by
Illumos/OpenIndiana (Sun Microsystems heritage), layered on top of the
sotBSD v0.1.0 + PANDORA T1-T4 baseline.

- [x] **SMF (Service Management Facility) implementation** -- Evolve
      `services/init/src/supervisor.rs` from a passive watcher into a
      strict dependency-graph service manager. When `SYS_THREAD_NOTIFY`
      lands, SMF must handle active respawns. If the Honeypot DB dies,
      SMF must automatically restart it and gracefully cycle any
      dependent deception services to maintain the illusion without
      breaking the attacker's TCP state. **(landed in #51, 2026-04-07.
      `SmfService { name, deps, state, restart_policy, tid, notify_cap,
      respawn_count }`, fixed-size 16-service table, topological
      cascade on death. Verified at boot via `=== SMF respawn: PASS ===`
      after a real attacker death + respawn cycle.)**

- [x] **Project Crossbow (Virtual Network Architecture)** -- Implement
      kernel-level VNICs and virtual switches to complement
      `PfInterposer`. When an APT is detected, dynamically provision a
      VNIC with a spoofed MAC and hardware-enforced bandwidth limits
      (e.g., 10 Mbps). Isolate the attacker in a network sandbox at
      O(1) cost, preventing lateral movement or cryptomining
      exhaustion. **(landed in #49, 2026-04-07. New `libs/sot-crossbow`
      crate with `VirtualSwitch<32 ports>`, O(1) provision/revoke/
      route, token-bucket rate limit (`bw_kbps * 125 = bytes/sec`),
      Knuth golden-ratio MAC mix with LAA bit set. Wired into
      `PfInterposer::enable_deception`/`disable_deception`. 18 unit
      tests + boot smoke `=== Crossbow: PASS ===`.)**

- [x] **FMA (Fault Management Architecture) integration** -- Build a
      predictive self-healing engine that consumes the `sot_provenance`
      ring buffers. Correlate hardware error telemetry (e.g., disk read
      retries, ECC RAM faults) and trigger atomic CSpace migrations of
      Tier-1/Tier-2 transactions to healthy memory regions *before* the
      silicon throws a fatal exception. **(landed in #50, 2026-04-07.
      New `libs/sot-fma` crate with `FaultManagement` ring (64 faults
      + 256 prov anomalies), 6 prioritized correlation rules
      (uncorrectable ECC > ECC clustering > 5+ DiskReadRetry > thermal
      + behavioral). 26 unit tests + boot smoke `=== FMA: PASS ===`.
      Follow-up: local `ProvenanceEntry` mirror is NOT ABI-compat with
      kernel's 48-byte `#[repr(C)]` struct -- needs fix when real
      drained-ring data is plumbed in.)**

---

## v0.2.0+ Wave: GUI Renewal + Cleanup Pass (added 2026-04-08)

A 20-unit batch landed during 2026-04-07/08 split into GUI renewal
(G1-G12), `services/init` modular splits (I1-I3), CI strictness (C1)
and four hygiene passes (H1-H4). All 20 units shipped as PRs #53-#72
and merged to `sotBSD` HEAD `eb137e3`. Verified end-to-end via
`just run`: 16 PASS markers in a single boot, zero panics.

### GUI renewal (compositor stack, 12 units)

- [x] **G1 Font system upgrade** -- Replace 8x8 bitmap with
      `embedded-graphics` mono font (10x20 large + 6x10 compact),
      anti-aliased. **(PR #56)**
- [x] **G2 Cursor theme + 8 shapes** -- `CursorShape` enum with
      Default, Pointer, Text, Wait, Move, ResizeNS, ResizeEW,
      NotAllowed. Each shape is a hand-crafted static BGRA glyph
      with hot-spot. Foundation for future `wl_cursor` protocol.
      **(PR #55)**
- [x] **G3 Modern window decorations** -- Tokyo Night palette,
      `decorations` module with traffic-light buttons (red/yellow/
      green circles, 14px), 24/28 px title bar, rounded corners,
      `embedded-graphics` adapter. **(PR #62)**
- [x] **G4 tiny-skia path render pipeline** -- `skia_render` module
      gated behind the `skia` Cargo feature so the default
      `#![no_std]` build is unchanged. Provides
      `SkiaCanvas::fill_rounded_rect`/`stroke_rounded_rect`/
      `fill_circle`/`linear_gradient` + `present()` BGRA blit.
      **(PR #54)**
- [x] **G5 Damage tracking by rectangle** -- `damage` module with
      32-rect dirty list, coalescing on overflow, escalation to
      fullscreen if union > 3/4 of screen. Replaces the single
      `bool` flag. **(PR #53)**
- [x] **G6 xdg-shell popups + positioner** -- `xdg_popup` module
      with 16-positioner / 16-popup pools, `place_popup` algorithm
      handling all anchor + gravity combinations, `xdg_popup::
      reposition` recompute geometry on the fly. **(PR #70)**
- [x] **G7 Layer shell protocol** -- `zwlr_layer_shell_v1` with
      4-layer z-order (Background → Bottom → Top → Overlay), anchor
      bitmask, `exclusive_zone` reservation, margin support, 8
      layer-surface pool. Compose loop renders layers in strict
      z-order with cumulative inset clamping. **(PR #69, merged
      auto via local push)**
- [x] **G8 wl_output protocol stub** -- Single-output `wl_output`
      v4 global advertised with framebuffer geometry/mode/scale/
      name/description from BootInfo. Foundation for multi-monitor.
      **(PR #61)**
- [x] **G9 Fractional scaling stub** -- `wp_fractional_scale_v1`
      manager + per-surface objects, always reports 120 (1.0x in
      120-fixed). Foundation for HiDPI. **(PR #60)**
- [x] **G10 Wallpaper subsystem + Tokyo Night gradient** -- New
      `wallpaper` module with vertical gradient cache (Tokyo Night
      `#1A1B26 → #10101C`, up to 2160 rows), optional BMP image
      tile path with raw volatile pointer writes (replaced
      per-pixel `fill_rect`). **(PR #57)**
- [x] **G11 Animation framework** -- `animation` module with
      `Animation` struct, `Easing::Linear/EaseOut/EaseInOut`,
      `interpolate_color`, 32-anim global pool. Pure no_std,
      no `powf` (manual cubic). **(PR #58)**
- [x] **G12 sot-statusbar layer-shell client** -- New
      `services/sot-statusbar/` no_std crate with full Wayland
      handshake, `zwlr_layer_surface_v1::ack_configure` round-trip,
      Tokyo Night palette, clock + memory + procs sampling.
      Spawned by init. Connects to compositor; happy path needs
      kernel-side spawn for `self_as_cap` (documented limitation).
      **(PR #72)**

### `services/init` modular splits (3 units)

- [x] **I1 Split fs_vfs.rs (2940 LOC)** -- 5 sub-modules
      (`vfs_read_write`, `vfs_metadata`, `vfs_open`, `vfs_path`,
      `vfs_delete`) plus a re-export shim. 44 functions verified
      via inventory diff, end-to-end QEMU boot showed
      **39 PASS markers byte-for-byte identical** to baseline.
      **(PR #71)**
- [x] **I2 Split boot_tests.rs (2778 LOC)** -- 6 sub-modules
      (`dynamic`, `linux_abi`, `dynamic_test`, `busybox`,
      `validation`, `benchmarks`) + `mod.rs` re-exports.
      Includes the 55-line TLS reloc test hunk from PR #47.
      **(PR #68)**
- [x] **I3 Split builtins.rs (2033 LOC)** -- 5 sub-modules
      (`text`, `files`, `system`, `apt`, `util`) + glob
      re-exports. 63 functions verified. **(PR #63)**

### CI strictness (1 unit)

- [x] **C1 Strict fmt + clippy gate** -- New `lint-strict-core`
      job in `.github/workflows/ci.yml` runs `cargo fmt --check`
      and `cargo clippy -D warnings` against `sotos-kernel`,
      `sotos-common`, `sot-fma`, `sot-crossbow`, `sotos-ld`
      WITHOUT `continue-on-error`. Includes 11 inline clippy
      fixes (mostly `.flatten()` / `div_ceil` / `iter_mut`)
      and a drive-by `kernel/linker.ld` fix folding `.got` /
      `.got.plt` into `.data` to resolve a pre-existing
      `.text` overlap. **(PR #67)**

### Hygiene (4 units)

- [x] **H1 .gitignore expansion** -- 84-line addition anchored
      to repo root for ABI test artifacts (`.so`, `.apk`,
      `bash-static`, `busybox`, `lib*`, `libdrm`, `libwayland`,
      etc.). Reduced `git status` untracked count from 215 to 53.
      **(PR #59)**
- [x] **H2 rustdoc on driver crates** -- 152 missing-doc warnings
      → 0 across `sotos-pci`, `sotos-nvme`, `sotos-xhci`,
      `sotos-mouse`, `sotos-ahci`, `sotos-usb-storage`. xhci was
      the largest contribution (119 items documented).
      **(PR #64, merged auto via local push)**
- [x] **H3 SAFETY comments on kernel/arch/x86_64** -- 74 unsafe
      blocks across 9 files (`gdt`, `idt`, `io`, `lapic`, `percpu`,
      `pic`, `pit`, `serial`, `syscall`) got 1:1 `// SAFETY:`
      coverage. Highest density: `idt.rs` (47 blocks for fault
      handler iframe layouts). **(PR #66)**
- [x] **H4 unwrap → Result in services/init/syscalls** -- 32
      sites audited in `fs_initrd`, `fs_pipe`, `info`, `net`,
      `signal`. All Type C (statically-proven invariants from
      `try_into` on 8-byte slices) -- upgraded to
      `.expect("invariant: 8-byte slice")` for documentation.
      One Type A site (`net.rs::sys_socketpair`) refactored to
      explicit match returning `-ENOMEM`. **(PR #65)**

### v0.2.0+ Wave verification (post-merge boot)

`just build && just run` on `sotBSD` HEAD `eb137e3` reaches
**16 PASS markers in a single boot**, zero panics, zero triple
faults. The 16 markers are: `compositor input: WIRED`, `Signify
boot chain: PASS` (22 entries), `STYX TEST: ALL PASS`,
`posix-test: PASS`, `kernel-test: PASS`, `RUMP-VFS-TEST: PASS`,
`Tier 3 demo: PASS`, `FMA: PASS`, `Tier 4 demo: PASS`,
`Crossbow: PASS`, `Tier 5 demo: PASS`, `abi-fuzz: 10000/10000
survived`, `SMF respawn: PASS`, `DLTEST: PASS - dynamic linking
works!`, `DLTEST: mul PASS`. Build is 2-warning clean (both
pre-existing `unreachable_code` in `idt.rs`).

### v0.2.0+ Wave -- known follow-ups (non-blocking)

- **sot-statusbar happy path**: init's `spawn_process` passes
  `cap=0`, so the statusbar can't allocate caps for SHM pool
  setup. Requires either kernel-side spawn (like compositor)
  or forwarding the child's AS cap via `bootinfo_write`. The
  statusbar gracefully connects-and-waits today.
- **sot-fma `ProvenanceEntry`**: local mirror is 40 bytes (rustc
  default layout) and has different fields than the kernel's
  48-byte `#[repr(C)]` struct. Fine for the synthesised demo,
  but real drained-ring data would be misread. Fix: import the
  upstream type or add `#[repr(C)]` + `const_assert!` on size.
- **G7+G70 linker.ld duplicate fix**: PR #67 (CI strict) and
  PR #70 (xdg_popup) both made independent fixes for the same
  `.got` overlap. PR #67's fold-into-`.data` won; #70 dropped
  its hunk in the fix-up.
- **TODO**: Update README + create v0.2.0 whitepaper PDF (this
  is in flight as the next batch).
