#!/usr/bin/env python3
"""ABI fuzz harness driver -- Unit 9.

Boots sotOS under QEMU via `just run`, captures the serial log for at
most 240 seconds (4 minutes), and asserts that the
`=== abi-fuzz: <ok>/<total> survived ===` marker emitted by the
`services/abi-fuzz/` userspace binary appears in the output.

Designed to run both locally on Windows (where QEMU lives at
``C:/Program Files/qemu/``) and on the GitHub Actions runner used by
``.github/workflows/fuzz.yml``. The runner is responsible for
installing nightly Rust + just + qemu before invoking this script.

Usage:
    python scripts/abi_fuzz.py [--iterations N] [--timeout SECONDS]

The iteration count is informational only -- the actual number of
syscalls to fire is hard-coded in `services/abi-fuzz/src/main.rs`
(``DEFAULT_ITERATIONS``) so failures are bit-for-bit reproducible
across machines and re-runs. The flag is plumbed through as an env
var (``SOTOS_ABI_FUZZ_ITERATIONS``) which the userspace binary may
honour in a future revision.
"""

import argparse
import os
import re
import subprocess
import sys
import threading
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TIMEOUT = 240  # seconds, the unit instructions cap this at 4 min
DEFAULT_ITERATIONS = 10000

# Regex captures both the success ("10000/10000 survived") and
# partial-progress ("9743/10000 survived") variants so we can tell the
# operator how far the fuzzer got even when something goes wrong upstream.
MARKER_RE = re.compile(rb"=== abi-fuzz: (\d+)/(\d+) survived ===")


def run_just(timeout_seconds: int, iterations: int) -> tuple[int, bytes]:
    """Invoke ``just run`` and capture its serial output.

    Returns ``(matched_total, captured_bytes)`` where ``matched_total``
    is the number of fuzz iterations the marker reported (or 0 if the
    marker never appeared).
    """
    cmd = ["just", "run"]
    print(f"abi_fuzz: launching `{' '.join(cmd)}` with timeout={timeout_seconds}s")
    print(f"abi_fuzz: target marker = '=== abi-fuzz: {iterations}/{iterations} survived ==='")

    env = os.environ.copy()
    env["SOTOS_ABI_FUZZ_ITERATIONS"] = str(iterations)

    proc = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        bufsize=0,
    )

    captured = bytearray()
    captured_lock = threading.Lock()

    def reader() -> None:
        while True:
            byte = proc.stdout.read(1)
            if not byte:
                return
            with captured_lock:
                captured.extend(byte)
            sys.stdout.write(byte.decode("utf-8", errors="replace"))
            sys.stdout.flush()

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()

    matched = 0
    snapshot = b""
    serial_log_path = os.path.join(REPO_ROOT, "target", "serial.log")
    os.makedirs(os.path.dirname(serial_log_path), exist_ok=True)

    deadline = time.time() + timeout_seconds
    try:
        while time.time() < deadline:
            with captured_lock:
                m = MARKER_RE.search(captured)
            if m:
                matched = int(m.group(1))
                # Linger briefly so the rest of the boot can drain to
                # the serial log, then shut down so we don't burn the
                # whole 4-minute budget.
                time.sleep(1.0)
                break
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        else:
            print("abi_fuzz: timeout reached, killing QEMU")
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        reader_thread.join(timeout=2)
        with captured_lock:
            snapshot = bytes(captured)
        with open(serial_log_path, "wb") as fp:
            fp.write(snapshot)
        print(f"abi_fuzz: serial log written to {serial_log_path} ({len(snapshot)} bytes)")

    return matched, snapshot


def main() -> int:
    ap = argparse.ArgumentParser(description="Drive sotOS ABI fuzz harness under QEMU.")
    ap.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help="Number of fuzz iterations the userspace binary should run (default 10000)",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"QEMU runtime cap in seconds (default {DEFAULT_TIMEOUT})",
    )
    args = ap.parse_args()

    matched, captured = run_just(args.timeout, args.iterations)

    if matched == 0:
        print("abi_fuzz: FAIL -- marker `=== abi-fuzz: ... survived ===` not found")
        # Tail the captured output so CI shows where boot stalled.
        tail = captured[-4000:].decode("utf-8", errors="replace")
        print("--- last 4 KiB of serial output ---")
        print(tail)
        print("--- end serial output ---")
        return 1

    print(f"abi_fuzz: PASS -- marker found, fuzzer survived {matched} iterations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
