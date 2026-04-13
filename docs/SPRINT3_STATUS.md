# Sprint 3 — "Production"

Goal: third parties can build on top of sotX without needing
write access to the repo. The system ships a frozen ABI, a
reproducible SDK, a CI gate that enforces both, and an on-ramp for
production signify keys.

## Status

| Item                          | State   | Notes                                                                 |
|-------------------------------|---------|-----------------------------------------------------------------------|
| Exportable SDK tarball        | Done    | `just sdk` → `target/sotx-sdk-v<ABI_VERSION>.tar.gz` (~117 MB)       |
| ABI freeze document           | Done    | `docs/ABI_v0.1.0.md` — syscalls, struct layouts, compat contract       |
| `ABI_VERSION` constant        | Done    | `libs/sotos-common/src/lib.rs::ABI_VERSION = "0.1.0"`                 |
| CI ABI gate                   | Done    | `.github/workflows/ci.yml::abi-freeze` job cross-checks constant vs doc |
| CI boot-smoke T1–T4 markers   | Done    | 12 PASS markers enforced, was 8 before                                |
| Production signify key recipe | Done    | `just sigkey-prod` → `~/.secrets/sotx-signify-prod.key` (0600)       |
| pkgsrc mirror bootstrap       | Partial | `vendor/pkgsrc` sparse tree in place, HTTP mirror parked               |
| pkgsrc binary package cache   | **Parked** | Needs a real pkgsrc build host first                                 |
| Release branch automation     | **Parked** | One-shot tag → github release workflow not yet wired                 |

## SDK layout

```
sotx-sdk-v0.1.0/
├── VERSION              # "0.1.0"
├── README
├── sotx.img            # 512 MiB bootable QEMU image
├── kernel/
│   └── sotos-kernel.elf # raw kernel ELF for gdb
├── abi/
│   ├── ABI_v0.1.0.md
│   └── sotos-common/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── elf.rs
│           ├── linux_abi.rs
│           ├── spsc.rs
│           ├── trace.rs
│           └── typed_channel.rs
└── docs/
    ├── ABI_v0.1.0.md
    ├── ARCHITECTURE.md
    ├── SOT_SPEC.md
    ├── SPRINT1_STATUS.md
    ├── SPRINT2_STATUS.md
    └── SPRINT3_STATUS.md
```

The consumer workflow:

```sh
tar xf sotx-sdk-v0.1.0.tar.gz
cd sotx-sdk-v0.1.0
# boot
qemu-system-x86_64 -cpu max -drive format=raw,file=sotx.img \
    -serial stdio -display none -m 2048M
# link your own crate against the ABI
cd ../my-service
cargo add --path ../sotx-sdk-v0.1.0/abi/sotos-common
```

## ABI freeze contract

- `libs/sotos-common/src/lib.rs::ABI_VERSION` is the single source of
  truth.
- `docs/ABI_v<version>.md` must exist with a matching version string.
- The `abi-freeze` CI job fails any push that bumps one without the other.
- Minor bumps are additive. Major bumps require a fresh document.

## Production signify keys

`just sigkey-prod` wraps the existing `scripts/signify_keygen.py` with
the convention-path `~/.secrets/sotx-signify-prod.key` (mode 0600).
To actually use it, export `SIGNIFY_KEY=$HOME/.secrets/sotx-signify-prod.key`
before running `just sigmanifest`, so the manifest gets signed with
the production key instead of the deterministic dev seed embedded in
`scripts/build_signify_manifest.py`.

## What this unlocks

- Downstream crates can `cargo add --path .../abi/sotos-common` and get
  a stable, documented, CI-enforced ABI surface.
- Bumping the ABI is now a two-file review: code + doc.
- Every push to `sotX` asserts all 12 Tier-6 PANDORA PASS markers
  before merging; no more silent regression in any tier.
- A single `just sdk` command produces a reproducible tarball third
  parties can host on GitHub Releases.

## Parked items

### pkgsrc binary cache / mirror

`vendor/pkgsrc` ships the sparse source tree (bootstrap, pkg_install,
mk/defaults, www/nginx) as the canonical reference for future
`pkg_add` / `bmake install` work. A binary package cache that third
parties can pull from needs a real build host running NetBSD or
DragonFlyBSD — parked until we have one, because clean-room
cross-building pkgsrc from Windows is not realistic.

### Release branch automation

Tagging a commit → GitHub Release workflow is not wired. For now, cut
a release by hand: `git tag v0.1.0 && git push --tags`, then upload
the SDK tarball manually.
