#!/usr/bin/env python3
"""
sotOS Boot TDD Verification Suite
===================================
Builds the OS image, boots QEMU headless, captures serial output, and verifies
that every expected boot stage appears (in order) and no regression markers
are present.

Usage:
    python scripts/test_boot.py              # full build + boot + verify
    python scripts/test_boot.py --no-build   # skip build, use existing image
    python scripts/test_boot.py --transcript FILE  # parse an existing transcript (no QEMU)
    python scripts/test_boot.py --verbose    # print full serial transcript on completion

Exit code: 0 if all stages pass and no regressions, 1 otherwise.
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

QEMU = os.environ.get("QEMU", r"C:\Program Files\qemu\qemu-system-x86_64.exe")
IMAGE = os.path.join("target", "sotos.img")
DISK = os.path.join("target", "disk.img")
TRANSCRIPT = os.path.join("target", "boot_transcript.txt")
SCREENDUMP = os.path.join("target", "boot_screendump.ppm")
BOOT_TIMEOUT = 180  # seconds
MONITOR_PORT = 45455  # QMP/HMP monitor TCP port

# ---------------------------------------------------------------------------
# Required boot stages — must appear in order in the serial transcript
# ---------------------------------------------------------------------------

REQUIRED_STAGES = [
    ("limine_load",         r"limine: Loading executable"),
    ("initrd_load",         r"limine: Loading module.*initrd"),
    ("splash_shown",        r"v0\.1\.0 microkernel"),
    ("progress_cpu",        r"CPU \+ memory"),
    ("progress_sched",      r"Scheduler \+ IPC"),
    ("progress_caps",       r"Capabilities"),
    ("progress_drivers",    r"Drivers"),
    ("progress_userspace",  r"Userspace"),
    ("progress_ready",      r"ready"),
    ("kernel_ready",        r"Kernel ready"),
    ("vmm_registered",      r"VMM: registered"),
    ("kbd_mouse",           r"KB\+MOUSE"),
    ("compositor_start",    r"compositor: starting"),
    ("compositor_fb",       r"compositor: fb"),
    ("compositor_service",  r"compositor: registered service"),
    ("compositor_input",    r"compositor input: WIRED"),
    ("compositor_clients",  r"compositor: waiting for clients"),
    ("hello_gui_start",     r"hello-gui: starting"),
    ("sotos_term_start",    r"sotos-term: starting"),
    ("wallpaper_loaded",    r"wallpaper: loaded BMP"),
    ("hello_gui_connected", r"hello-gui: connected"),
    ("init_complete",       r"INIT: boot complete"),
    ("signify_ok",          r"Ed25519 signature OK"),
]

# ---------------------------------------------------------------------------
# Must NOT appear (regressions)
# ---------------------------------------------------------------------------

MUST_NOT_APPEAR = [
    ("kernel_panic",     r"KERNEL PANIC"),
    ("page_fault",       r"#PF\(kernel\)"),
    ("double_fault",     r"DOUBLE FAULT"),
    ("exit_t_spew",      r"EXIT-T.*\n.*EXIT-T.*\n.*EXIT-T.*\n.*EXIT-T.*\n.*EXIT-T"),
    ("pci_zero",         r"PCI: 0 devices"),
    ("blk_not_found",    r"BLK: virtio-blk not found"),
    ("net_not_found",    r"NET: virtio-net device not found"),
    ("lkl_disabled_msg", r"LKL: disabled"),
    ("vmm_segv_flood",   r"VMM: SEGV.*\n.*VMM: SEGV.*\n.*VMM: SEGV.*\n.*VMM: SEGV.*\n.*VMM: SEGV.*\n.*VMM: SEGV"),
]

# ---------------------------------------------------------------------------
# QEMU process wrapper
# ---------------------------------------------------------------------------

class QemuBoot:
    """Boot QEMU headless, capture serial output, optional monitor."""

    def __init__(self):
        self.proc = None
        self.buf = bytearray()
        self.lock = threading.Lock()
        self._reader = None
        self._done = threading.Event()

    def start(self, use_whpx=True):
        """Launch QEMU. Try WHPX first, fall back to TCG."""
        # Ensure disk.img exists (some boot paths need virtio-blk)
        if not os.path.isfile(DISK):
            subprocess.run(
                ["python", "scripts/mkdisk.py", "--size", "256"],
                check=False,
                capture_output=True,
            )

        cmd = [QEMU]

        # Acceleration
        if use_whpx:
            cmd += ["-accel", "whpx", "-machine", "q35"]
        else:
            cmd += ["-cpu", "max"]

        cmd += [
            "-drive", f"format=raw,file={IMAGE}",
            "-drive", f"if=none,format=raw,file={DISK},id=disk0",
            "-device", "virtio-blk-pci,drive=disk0,disable-modern=on",
            "-serial", "stdio",
            "-display", "none",
            "-no-reboot",
            "-m", "2048M",
        ]

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                cwd=os.getcwd(),
            )
        except Exception as e:
            if use_whpx:
                print(f"  WHPX launch failed ({e}), trying TCG...")
                return self.start(use_whpx=False)
            raise

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

        # Quick check: if QEMU dies immediately (bad accel), retry with TCG
        time.sleep(1.0)
        if self.proc.poll() is not None and use_whpx:
            print("  WHPX not available, falling back to TCG...")
            self.buf.clear()
            return self.start(use_whpx=False)

        accel = "WHPX" if use_whpx else "TCG"
        print(f"  QEMU started (PID {self.proc.pid}, accel={accel})")
        return True

    def _read_loop(self):
        while not self._done.is_set():
            try:
                b = self.proc.stdout.read(1)
            except Exception:
                break
            if not b:
                break
            with self.lock:
                self.buf.extend(b)

    def get_transcript(self):
        with self.lock:
            return self.buf.decode("utf-8", errors="replace")

    def wait_for(self, pattern, timeout=BOOT_TIMEOUT):
        """Wait until regex pattern appears in accumulated output."""
        pat = re.compile(pattern)
        deadline = time.time() + timeout
        while time.time() < deadline:
            transcript = self.get_transcript()
            if pat.search(transcript):
                return True
            # Check if QEMU exited
            if self.proc and self.proc.poll() is not None:
                return pat.search(self.get_transcript()) is not None
            time.sleep(0.2)
        return False

    def stop(self):
        self._done.set()
        if self.proc:
            try:
                self.proc.kill()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=5)
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def check_stages(transcript):
    """Check required stages appear in order. Returns (results, pass_count, fail_count)."""
    results = []
    search_from = 0
    for name, pattern in REQUIRED_STAGES:
        m = re.search(pattern, transcript[search_from:])
        if m:
            # Record absolute position for ordering
            abs_pos = search_from + m.start()
            results.append((name, pattern, True, None))
            # Advance search_from so next stage must come after this one
            search_from = abs_pos + len(m.group(0))
        else:
            # Try searching entire transcript (out of order?)
            m_any = re.search(pattern, transcript)
            if m_any:
                results.append((name, pattern, False, "FOUND BUT OUT OF ORDER"))
            else:
                results.append((name, pattern, False, "NOT FOUND"))

    pass_count = sum(1 for _, _, ok, _ in results if ok)
    fail_count = len(results) - pass_count
    return results, pass_count, fail_count


def check_regressions(transcript):
    """Check that no regression markers appear. Returns (results, regression_count)."""
    results = []
    for name, pattern in MUST_NOT_APPEAR:
        flags = re.DOTALL if r"\n" in pattern else 0
        m = re.search(pattern, transcript, flags)
        if m:
            results.append((name, pattern, True))  # True = found = BAD
        else:
            results.append((name, pattern, False))  # False = not found = GOOD

    regression_count = sum(1 for _, _, found in results if found)
    return results, regression_count


def print_results(stage_results, regression_results, pass_count, fail_count, regression_count):
    """Print the summary table."""
    print()
    print("=" * 60)
    print("  sotOS Boot TDD Results")
    print("=" * 60)
    print()

    # Stage results
    for name, pattern, ok, reason in stage_results:
        if ok:
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name} -- {reason}")

    print()

    # Regression results
    if regression_count > 0:
        print("  --- Regressions detected ---")
        for name, pattern, found in regression_results:
            if found:
                print(f"  [REGR] {name}: pattern matched in transcript!")
        print()

    # Summary line
    total = len(stage_results)
    print(f"  {pass_count}/{total} stages passed, {regression_count} regressions")
    print()

    if fail_count == 0 and regression_count == 0:
        print("  RESULT: PASS")
    else:
        print("  RESULT: FAIL")

    print("=" * 60)


def save_transcript(transcript, path):
    """Save transcript to file."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(transcript)
        print(f"  Transcript saved to {path}")
    except Exception as e:
        print(f"  Warning: could not save transcript: {e}")


def main():
    parser = argparse.ArgumentParser(description="sotOS Boot TDD Verification Suite")
    parser.add_argument("--no-build", action="store_true",
                        help="Skip building image (use existing target/sotos.img)")
    parser.add_argument("--transcript", metavar="FILE",
                        help="Parse an existing transcript file (skip QEMU boot)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full serial transcript")
    parser.add_argument("--timeout", type=int, default=BOOT_TIMEOUT,
                        help=f"Boot timeout in seconds (default: {BOOT_TIMEOUT})")
    args = parser.parse_args()

    # ── Mode 1: parse existing transcript ──
    if args.transcript:
        print(f"[*] Parsing existing transcript: {args.transcript}")
        with open(args.transcript, "r", encoding="utf-8", errors="replace") as f:
            transcript = f.read()
        stage_results, pass_count, fail_count = check_stages(transcript)
        regression_results, regression_count = check_regressions(transcript)
        print_results(stage_results, regression_results, pass_count, fail_count, regression_count)
        sys.exit(0 if (fail_count == 0 and regression_count == 0) else 1)

    # ── Mode 2: build + boot + verify ──

    # Step 1: Build
    if not args.no_build:
        print("[*] Building image (just image)...")
        build = subprocess.run(
            ["just", "image"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if build.returncode != 0:
            print(f"[FAIL] Build failed (exit {build.returncode})")
            # Show last 800 chars of stderr/stdout for diagnosis
            output = (build.stdout or "") + (build.stderr or "")
            print(output[-800:])
            sys.exit(1)
        print("[OK] Build succeeded")
    else:
        if not os.path.isfile(IMAGE):
            print(f"[FAIL] Image not found: {IMAGE}")
            sys.exit(1)
        print("[*] Skipping build (--no-build)")

    # Step 2: Boot QEMU
    print(f"[*] Booting QEMU (timeout={args.timeout}s)...")
    qemu = QemuBoot()

    # Register cleanup for Ctrl+C
    def cleanup(*_a):
        print("\n[*] Interrupted, killing QEMU...")
        qemu.stop()
        sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)
    try:
        signal.signal(signal.SIGBREAK, cleanup)
    except AttributeError:
        pass  # SIGBREAK is Windows-only

    try:
        qemu.start(use_whpx=True)
    except Exception as e:
        print(f"[FAIL] Could not start QEMU: {e}")
        sys.exit(1)

    # Step 3: Wait for boot completion
    # We wait for the last expected marker: "INIT: boot complete"
    # or "Ed25519 signature OK" (whichever is the final stage)
    print("[*] Waiting for boot to complete...")
    boot_complete = qemu.wait_for(
        r"Ed25519 signature OK|INIT: boot complete",
        timeout=args.timeout,
    )

    # Give a small grace period for any trailing output
    if boot_complete:
        time.sleep(2.0)
    else:
        print(f"[!] Boot did not complete within {args.timeout}s timeout")
        # Still collect what we have

    # Step 4: Collect transcript
    transcript = qemu.get_transcript()
    qemu.stop()

    save_transcript(transcript, TRANSCRIPT)

    if args.verbose:
        print()
        print("=" * 60)
        print("  FULL SERIAL TRANSCRIPT")
        print("=" * 60)
        print(transcript)
        print("=" * 60)

    # Step 5: Run assertions
    print(f"[*] Analyzing transcript ({len(transcript)} bytes)...")
    stage_results, pass_count, fail_count = check_stages(transcript)
    regression_results, regression_count = check_regressions(transcript)

    # Step 6: Print results
    print_results(stage_results, regression_results, pass_count, fail_count, regression_count)

    # Step 7: Exit code
    if fail_count == 0 and regression_count == 0:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
