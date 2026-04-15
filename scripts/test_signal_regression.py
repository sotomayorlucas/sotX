#!/usr/bin/env python3
"""
Signal async regression harness — smoke-test tier.

Boots sotOS under WHPX, greps the serial log for the three
"signal plumbing healthy" markers documented in
`docs/signal_invariants.md`, and fails loudly if any regression
indicator shows up.

This is the Fase 7 pre-flight gate. It does NOT yet exercise
runtime signal scenarios (SIGCHLD ordering, sigreturn stack,
alarm-inside-handler) — those need a purpose-built signal-test
binary in the initrd, gated on Fase 5-6's LKL-rootfs work. For
now this harness catches the structural regressions that killed
signal delivery during Phase 12 bring-up.

Usage:
    python scripts/test_signal_regression.py                # auto build + boot
    python scripts/test_signal_regression.py --no-build     # reuse target/sotos.img
    python scripts/test_signal_regression.py --timeout 120  # boot timeout sec

Exit codes:
    0 — all required markers present, no regression indicators seen
    1 — missing required marker or regression indicator found
    2 — boot timed out before any marker appeared
"""

import argparse
import os
import subprocess
import sys
import time


QEMU = os.environ.get("QEMU", r"C:\Program Files\qemu\qemu-system-x86_64.exe")
PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IMAGE = os.path.join(PROJ, "target", "sotx.img")
DISK = os.path.join(PROJ, "target", "disk.img")
LOGFILE = os.path.join(PROJ, "target", "bootlog_signal.txt")

# Markers that MUST appear for signal plumbing to be healthy.
# Missing any of these = regression. Each marker is an unconditional
# `print(b"...")` in the init crate, NOT a `trace!(...)` call (traces
# can be filtered by feature/category — don't trust them as gates).
REQUIRED_MARKERS = [
    ("LinuxBackend: LucasBackend + HybridBackend registered",
     "Backend surface did not link (fase 3 regression)."),
    ("LUCAS-DBG: guest_entry=",
     "PID-1 lucas_shell::shell_main never reached the shell entry — "
     "vDSO forge + VFS mount + make_ctx setup must have failed."),
    ("vfs-keeper: ObjectStore mounted",
     "Shared VFS (SHARED_STORE_PTR) not published — child handler "
     "filesystem access would be broken, including signal-delivery "
     "sequences that touch /proc or /dev/null."),
]

# Indicators that MUST NOT appear. Their presence = regression.
REGRESSION_INDICATORS = [
    ("STACK.SMASH",
     "Stack canary tripped — Invariant 3 (rt_sigreturn) likely broken."),
    ("VMM: unhandled PF",
     "VMM missed a #PF — Invariant 2 (global fallback) broken."),
    ("PANIC",
     "Kernel panic during signal-relevant boot path."),
    ("GP: rip=0x0",
     "Garbage RIP after signal return — Invariant 1 (#PF IST) broken."),
    ("UNHANDLED syscall=15",  # SYS_rt_sigreturn
     "rt_sigreturn routed outside signal context."),
]


def boot_and_capture(timeout: int) -> bool:
    """Boot QEMU with serial→file. Returns True if QEMU exited cleanly,
    False if it had to be killed on timeout."""
    for p in (LOGFILE,):
        try: os.remove(p)
        except FileNotFoundError: pass

    cmd = [
        QEMU,
        "-accel", "whpx", "-machine", "q35",
        "-drive", f"format=raw,file={IMAGE}",
        "-drive", f"if=none,format=raw,file={DISK},id=disk0",
        "-device", "virtio-blk-pci,drive=disk0,disable-modern=on",
        "-serial", f"file:{LOGFILE}",
        "-display", "none",
        "-no-reboot",
        "-m", "2048M",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        proc.kill()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: pass
        return False


def read_log() -> str:
    try:
        with open(LOGFILE, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def check(log: str) -> int:
    """Evaluate markers against the boot log. Returns exit code."""
    problems = []

    for marker, why in REQUIRED_MARKERS:
        if marker not in log:
            problems.append(f"  MISSING required marker: {marker!r}\n    -> {why}")

    for indicator, why in REGRESSION_INDICATORS:
        if indicator in log:
            problems.append(f"  FORBIDDEN indicator present: {indicator!r}\n    -> {why}")

    if problems:
        print("SIGNAL REGRESSION HARNESS — FAIL")
        print("See docs/signal_invariants.md for context.")
        print()
        for p in problems:
            print(p)
        return 1

    print("SIGNAL REGRESSION HARNESS — OK")
    print(f"  {len(REQUIRED_MARKERS)} required markers present.")
    print(f"  {len(REGRESSION_INDICATORS)} regression indicators clean.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-build", action="store_true",
                    help="Skip `just image`; reuse target/sotx.img.")
    ap.add_argument("--timeout", type=int, default=90,
                    help="QEMU wall-clock timeout in seconds (default 90).")
    args = ap.parse_args()

    if not args.no_build:
        print("Building image (just image)...")
        r = subprocess.run(["just", "image"], cwd=PROJ,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"just image failed:\n{r.stderr}")
            return 1
    elif not os.path.exists(IMAGE):
        print(f"ERROR: {IMAGE} not found; run without --no-build first.")
        return 1

    if not os.path.exists(DISK):
        print(f"ERROR: test disk {DISK} not found; run `just create-test-disk`.")
        return 1

    print(f"Booting under WHPX (timeout {args.timeout}s)...")
    clean = boot_and_capture(args.timeout)
    log = read_log()

    if not log:
        print("ERROR: serial log empty — QEMU never emitted output.")
        return 2
    if not clean:
        # Not fatal by itself — WHPX boots often need SIGKILL to exit
        # since the loop inside LUCAS never terminates. What matters is
        # whether the markers appeared before the timeout.
        print("(QEMU killed on timeout — this is expected under WHPX.)")

    return check(log)


if __name__ == "__main__":
    sys.exit(main())
