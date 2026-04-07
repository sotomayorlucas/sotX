# Sprint 2 — "Make it useful"

Goal: the system can be used for something beyond a boot demo.
Three critical pillars: panic / respawn, robust dynamic linker, and
one complete display story.

## Status

| Item                          | State       | Notes                                                                                |
|-------------------------------|-------------|--------------------------------------------------------------------------------------|
| Service supervisor scaffold   | Done        | `services/init/src/supervisor.rs` tracks live thread count, reports dead tracked svc |
| Actual respawn                | **Parked**  | Needs `SYS_THREAD_NOTIFY` in the kernel (see TODO.md)                                |
| Dynamic linker skipped-reloc audit | Done  | `SKIPPED_RELOCS` counter + named known-unimplemented types in `libs/sotos-ld/src/reloc.rs` |
| TLS reloc support (`TPOFF64` et al) | **Parked** | Needs a TLS runtime before `_start` — scheduler + loader work              |
| `IRELATIVE` / IFUNC resolver   | **Parked** | Needs kernel-side resolver callback path                                            |
| Native compositor input routing | **Parked** | Compositor exists, needs kbd→focused-window dispatch                               |
| Weston DRM path end-to-end    | **Parked**  | Runs as far as DRM backend load; needs real EGL stack                               |

## Supervisor model

`services/init/src/supervisor.rs` is **passive** — it captures the
`thread_count()` after every `spawn_process()` and a later
`check_all()` complains to the serial console if the count has
dropped below the recorded baseline minus a slack window (4 threads,
accommodating transient worker churn). It does **not** respawn
anything today.

Why passive: an active respawn loop would need the kernel to notify
init when a child dies asynchronously. That hook doesn't exist yet —
the kernel's `ThreadInfo` syscall returns a stub tuple and has no
"watch this tid for exit" variant. Adding it correctly is
non-trivial: the same notification channel needs to handle signal
delivery to a parent waitpid(), and that path already touches the
scheduler, the CoW fork trampoline, and the signal frame layout. A
full implementation is tracked as TODO.md Sprint-2-Followup-1.

What Sprint 2 ships today:

```text
SUPERVISOR: 4/4 tracked services healthy (live tids=123)
```

...appearing at the end of the Tier 6 demo phase. If any Tier 6
service crashes mid-demo, this line will flag it loud before the
LUCAS shell takes over, turning silent regressions into visible ones.

## Dynamic linker audit

Previous state of `libs/sotos-ld/src/reloc.rs`:

| type                 | state        |
|----------------------|--------------|
| R_X86_64_RELATIVE(8) | implemented  |
| R_X86_64_64(1)       | implemented  |
| R_X86_64_GLOB_DAT(6) | implemented  |
| R_X86_64_JUMP_SLOT(7)| implemented  |
| anything else        | silently skipped (NO counter, NO log) |

Post-Sprint-2 state:

| type                 | state                                  |
|----------------------|----------------------------------------|
| R_X86_64_RELATIVE(8) | implemented                            |
| R_X86_64_64(1)       | implemented                            |
| R_X86_64_GLOB_DAT(6) | implemented                            |
| R_X86_64_JUMP_SLOT(7)| implemented                            |
| R_X86_64_PC32(2)     | named, skipped, bumps `SKIPPED_RELOCS` |
| R_X86_64_PLT32(4)    | named, skipped, bumps `SKIPPED_RELOCS` |
| R_X86_64_GOTPCREL(9) | named, skipped, bumps `SKIPPED_RELOCS` |
| R_X86_64_DTPMOD64(16)| named, skipped, bumps `SKIPPED_RELOCS` |
| R_X86_64_DTPOFF64(17)| named, skipped, bumps `SKIPPED_RELOCS` |
| R_X86_64_TPOFF64(18) | named, skipped, bumps `SKIPPED_RELOCS` |
| R_X86_64_IRELATIVE(37)| named, skipped, bumps `SKIPPED_RELOCS`|
| unknown              | bumps `SKIPPED_RELOCS`                 |

Callers can now do:

```rust
sotos_ld::reset_skipped();
apply_relocations(base, elf_data, &dyn_info)?;
let dropped = sotos_ld::skipped_count();
if dropped > 0 {
    // The shared object relies on reloc types the loader can't
    // handle -- fail loud instead of silently loading broken code.
    return Err("unsupported relocation types");
}
```

...which gives us a 5-minute failure mode for the next shared object
that reaches for TLS or IFUNC, instead of the current "load succeeds,
program segfaults in libc" behavior.

## What this unlocks

- Any Tier 6 service crashing during its demo phase gets reported
  loudly instead of being hidden by later output.
- The loader stops silently miscompiling shared objects that rely on
  TLS or IFUNC — the call site can detect and reject them.
- A future `services/init/src/respawn.rs` has a well-defined interface
  (`supervisor::record(name)` / `supervisor::check_all()`) to drop its
  logic into without having to touch every spawn site in `_start()`.
