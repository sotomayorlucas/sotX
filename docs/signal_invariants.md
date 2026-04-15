# Signal async invariants — regression reference

**Purpose**: document the three historical bugs in async signal delivery
(Phase 12 CoW fork bring-up) so that Fase 7 (migrating signal/task
syscalls to LKL) does not silently regress. Each section below names
the invariant, the bug that violated it, the fix, and a recipe for
repro testing when Fase 7 lands.

---

## Invariant 1 — `#PF` must not use IST

When multiple user-mode threads page-fault concurrently (normal under
CoW fork — every write-to-read-only page faults independently), the
kernel must save each faulting thread's trapframe on that thread's
**own** kernel stack. Using a shared IST stack causes the second
concurrent fault to overwrite the first thread's saved RIP/RSP, and
when the first `#PF` returns it jumps into garbage.

**Bug**: `#PF` vector pointed at IST entry in the IDT. Any two threads
faulting simultaneously (two CoW children writing) corrupted each other.

**Fix** (Phase 12): `#PF` no longer uses IST. User-mode page faults
land on the thread's kernel stack (TSS RSP0). `#DF`, `#GP`, and one
misc vector still use IST (for stacks that the scheduler guarantees
are single-use: double-fault handlers cannot recurse).

**Repro for Fase 7**: `busybox sh -c 'echo a | cat | cat'` — nested
pipes + two forks + CoW trigger a burst of concurrent `#PF`s. If any
child crashes with a garbage RIP, Invariant 1 broke.

---

## Invariant 2 — VMM sees child-AS page faults via the global fallback

The VMM userspace server handles `#PF` for every address space in the
system, not just its own. When a CoW-forked child faults, the kernel
must route the fault to VMM even though VMM's CR3 is different from
the faulting thread's CR3.

**Bug**: `SYS_FAULT_REGISTER` with `rsi=0` was interpreted as
"register for caller's AS (cr3=current)", so VMM's registration only
covered init's AS. CoW child page faults went unhandled → triple-fault.

**Fix** (Phase 12): `SYS_FAULT_REGISTER(rsi=0)` now means "global
fallback (cr3=0, match any)". Per-AS handlers still work via
`rsi=as_cap`.

**Repro for Fase 7**: `kill -SEGV <cow-forked-child>` — the child's
SIGSEGV handler must run. If VMM doesn't see the fault, the child
triple-faults and the test kernel panics.

---

## Invariant 3 — `rt_sigreturn` restores RSP from the frame, not from the handler's return address

When a signal handler returns, the handler's epilogue pops callee-saved
regs and then `ret`s to an address on the user stack. That return
address is **separate** from the `SignalFrame` the kernel injected
earlier. `rt_sigreturn` must load the pre-signal RSP from the
`SignalFrame`, not from wherever the handler happened to finish up
the stack.

**Bug**: kernel computed `frame_rsp = entry_rsp - SIZE_OF_SIGNAL_FRAME`
and read RSP back from that location. That address actually held the
handler's return address (8 bytes before the real frame), so
`rt_sigreturn` restored RSP to a bogus value and the child crashed.

**Fix** (Phase 12): `entry_rsp - 8` holds the handler return address,
`frame_rsp = entry_rsp - 8 - SIGNAL_FRAME_SIZE` holds the actual
`SignalFrame`. `rt_sigreturn` reads rip/rsp/fs_base from `frame_rsp`.

**Repro for Fase 7**: any syscall inside a `SIGALRM` handler.
`alarm(1); sleep(5);` — if `rt_sigreturn` lands on the wrong stack,
the `sleep()` never resumes and the process hangs.

---

## Hard markers to watch in the boot log

If Fase 7 accidentally removes any of these emitters, the regression
harness fails. These are the canonical signs that signal plumbing
came up correctly:

| Marker                                | Meaning                                       |
|---------------------------------------|-----------------------------------------------|
| `vDSO forged at 0xB80000`             | Signal trampoline page published.             |
| `INIT: self_as_cap=`                  | CoW fork source AS registered.                |
| `LinuxBackend: LucasBackend + HybridBackend registered` | Backend surface up (fase 3). |
| *(absence of)* `STACK.SMASH`          | No canary tripped by rt_sigreturn or #PF.     |
| *(absence of)* `VMM: unhandled PF`    | Invariant 2 still holds.                      |
| *(absence of)* `GP: rip=?`            | No garbage RIP from Invariant 1 regression.   |

The test harness in `scripts/test_signal_regression.py` checks all of
these after a WHPX boot. Signal-specific runtime tests (pipe+fork,
alarm-inside-handler, kill -SEGV cow-child) are scaffolded but need
`busybox` or a purpose-built Linux binary in the initrd to exercise
them; they are gated on the LKL-rootfs work of Fase 5–6.

---

## Runtime plan for Fase 7

Before starting signal/task migration:

1. Land a purpose-built Rust binary `services/signal-test/` that
   exercises each invariant (SIGCHLD ordering, sigreturn stack,
   concurrent signal under CoW). Built as musl-static so it runs under
   LUCAS today.
2. Extend `scripts/test_signal_regression.py` to run that binary and
   check exit code.
3. Only after the harness is green on the pre-migration branch,
   migrate `rt_sigaction` / `rt_sigprocmask` to LKL with the whitelist
   switch.
4. Re-run the harness after each LKL whitelist addition. Any failure
   → rollback the whitelist entry, not the kernel migration.

---

## Fase 7 outcome (2026-04-15) — DEFERRED INDEFINITELY

After landing the LKL proxy worker architecture (Phase 5/6), the
case for migrating signal/task syscalls to LKL evaporated:

1. **Proxy worker breaks signal semantics**. All foreign LKL calls
   marshal through one worker thread. A `rt_sigaction(SIGUSR1, h)`
   from process X, if forwarded to LKL, would install handler `h`
   on the WORKER's task, not X's. Signal delivery to X would never
   fire X's handler. This is fundamentally incompatible with how
   POSIX signals work.

2. **LUCAS already covers the 3 historical bugs**. Invariants 1-3
   are kernel + VMM concerns (#PF IST, fault routing, sigreturn
   frame layout). Migrating the userspace `rt_sig*` syscalls to LKL
   doesn't change any of them.

3. **The harness passes in the LUCAS-only configuration**. As of
   commit 68e4a83 the smoke-tier harness reports 3/3 markers
   present, 5/5 regression indicators clean. No reason to disturb a
   working signal subsystem.

**Decision**: signal + task syscalls stay in LUCAS permanently.
Phase 7 is closed without a whitelist addition. The signal regression
harness remains in CI as a safety net against future regressions in
the kernel/VMM signal plumbing.
