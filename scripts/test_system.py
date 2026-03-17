#!/usr/bin/env python3
"""
sotOS Interactive Test System
=============================
Boots QEMU once, runs a comprehensive test suite over serial, reports results.

Usage:
    python scripts/test_system.py              # run all tests
    python scripts/test_system.py --list       # list available tests
    python scripts/test_system.py --filter net  # run only tests matching "net"
    python scripts/test_system.py --verbose     # show full serial output per test
    python scripts/test_system.py --no-build    # skip build step (use existing image)

Requires: QEMU, just (for building)
"""

import argparse
import os
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

QEMU = os.environ.get("QEMU", r"C:\Program Files\qemu\qemu-system-x86_64.exe")
IMAGE = os.path.join("target", "sotos.img")
BOOT_TIMEOUT = 50       # seconds to wait for shell prompt
CMD_CHAR_DELAY = 0.012  # seconds between serial characters
DEFAULT_WAIT = 6         # seconds to wait after sending command


# ---------------------------------------------------------------------------
# QEMU Serial Driver
# ---------------------------------------------------------------------------

class QemuSerial:
    """Manages a QEMU instance with serial stdio I/O."""

    def __init__(self):
        self.proc = None
        self.buf = bytearray()
        self.lock = threading.Lock()
        self._reader = None

    def start(self):
        self.proc = subprocess.Popen(
            [QEMU,
             "-drive", f"format=raw,file={IMAGE}",
             "-serial", "stdio",
             "-display", "none",
             "-no-reboot",
             "-m", "512M",
             "-device", "virtio-net-pci,netdev=n0",
             "-netdev", "user,id=n0"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.getcwd(),
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        while True:
            b = self.proc.stdout.read(1)
            if not b:
                break
            with self.lock:
                self.buf.extend(b)

    def wait_for(self, pattern: str, timeout: float = BOOT_TIMEOUT) -> bool:
        """Wait until pattern appears in accumulated serial output."""
        start = time.time()
        pat = pattern.encode()
        while time.time() - start < timeout:
            with self.lock:
                if pat in self.buf:
                    return True
            time.sleep(0.1)
        return False

    def send(self, cmd: str, wait: float = DEFAULT_WAIT):
        """Send a command character-by-character, then newline."""
        for c in cmd:
            self.proc.stdin.write(c.encode())
            self.proc.stdin.flush()
            time.sleep(CMD_CHAR_DELAY)
        self.proc.stdin.write(b"\n")
        self.proc.stdin.flush()
        time.sleep(wait)

    def output_since(self, marker: int) -> str:
        """Return text accumulated since byte offset `marker`."""
        with self.lock:
            return self.buf[marker:].decode("utf-8", errors="replace")

    def mark(self) -> int:
        """Return current buffer length as a marker."""
        with self.lock:
            return len(self.buf)

    def stop(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait()


# ---------------------------------------------------------------------------
# Test Framework
# ---------------------------------------------------------------------------

class TestResult:
    def __init__(self, name: str, passed: bool, detail: str, output: str = ""):
        self.name = name
        self.passed = passed
        self.detail = detail
        self.output = output


def check_output(output: str, expected: list[str], forbidden: list[str] = None) -> tuple[bool, str]:
    """Check that all expected strings appear and no forbidden strings appear."""
    for exp in expected:
        if exp not in output:
            return False, f"missing: '{exp}'"
    if forbidden:
        for fb in forbidden:
            if fb in output:
                return False, f"unexpected: '{fb}'"
    return True, "ok"


# ---------------------------------------------------------------------------
# Test Definitions
# ---------------------------------------------------------------------------

TESTS = []

def test(name: str, category: str = "general"):
    """Decorator to register a test function."""
    def decorator(fn):
        fn.test_name = f"{category}/{name}"
        TESTS.append(fn)
        return fn
    return decorator


# ── Boot ──────────────────────────────────────────────────────────────────

@test("kernel_boot", "boot")
def test_kernel_boot(q: QemuSerial) -> TestResult:
    """Verify kernel boots and all subsystems initialize."""
    m = q.mark()
    # Boot output is already in buffer from startup
    out = q.output_since(0)
    expected = [
        "[ok] GDT", "[ok] SSE", "[ok] IDT",
        "[ok] Frame allocator", "[ok] Slab allocator",
        "[ok] Capabilities", "[ok] Scheduler",
        "[ok] SYSCALL/SYSRET", "[ok] LAPIC",
        "[ok] Init process", "[ok] Initrd",
        "Kernel ready",
    ]
    ok, detail = check_output(out, expected, ["PANIC", "panic", "triple fault"])
    return TestResult("boot/kernel_boot", ok, detail)


@test("services_start", "boot")
def test_services_start(q: QemuSerial) -> TestResult:
    """Verify all userspace services start."""
    out = q.output_since(0)
    expected = [
        "VMM: registered",
        "KB+MOUSE",
        "NET: MAC=",
        "NET: registered as 'net' service",
        "INIT: boot complete",
        "LUCAS shell v0.2",
    ]
    ok, detail = check_output(out, expected)
    return TestResult("boot/services_start", ok, detail)


@test("network_init", "boot")
def test_network_init(q: QemuSerial) -> TestResult:
    """Verify DHCP and network ping succeed."""
    out = q.output_since(0)
    expected = ["DHCP: IP=10.0.2.15", "PONG from 8.8.8.8"]
    ok, detail = check_output(out, expected)
    return TestResult("boot/network_init", ok, detail)


@test("dynamic_linking", "boot")
def test_dynamic_linking(q: QemuSerial) -> TestResult:
    """Verify dynamic linking test passes at boot."""
    out = q.output_since(0)
    expected = ["DLTEST: PASS", "DLTEST: mul PASS", "HELLO: exiting cleanly"]
    ok, detail = check_output(out, expected)
    return TestResult("boot/dynamic_linking", ok, detail)


# ── Shell Builtins ────────────────────────────────────────────────────────

@test("echo", "shell")
def test_echo(q: QemuSerial) -> TestResult:
    m = q.mark()
    q.send("echo hello-from-sotos", 3)
    out = q.output_since(m)
    ok, detail = check_output(out, ["hello-from-sotos"])
    return TestResult("shell/echo", ok, detail, out)


@test("ls", "shell")
def test_ls(q: QemuSerial) -> TestResult:
    """Verify ls command works."""
    m = q.mark()
    q.send("ls /tmp", 3)
    out = q.output_since(m)
    # ls /tmp should complete without errors
    ok = "PANIC" not in out and "$" in out
    detail = "ok" if ok else "ls failed"
    return TestResult("shell/ls", ok, detail, out)


@test("cat_etc", "shell")
def test_cat_etc(q: QemuSerial) -> TestResult:
    """Read a virtual /etc file."""
    m = q.mark()
    q.send("cat /etc/hostname", 3)
    out = q.output_since(m)
    # hostname file should exist and produce output
    ok = len(out.strip().split("\n")) >= 2  # echo + content
    detail = "ok" if ok else "no content from /etc/hostname"
    return TestResult("shell/cat_etc", ok, detail, out)


@test("cat_resolv", "shell")
def test_cat_resolv(q: QemuSerial) -> TestResult:
    """Read /etc/resolv.conf (virtual file)."""
    m = q.mark()
    q.send("cat /etc/resolv.conf", 4)
    out = q.output_since(m)
    ok, detail = check_output(out, ["nameserver"])
    return TestResult("shell/cat_resolv", ok, detail, out)


@test("env_var", "shell")
def test_env_var(q: QemuSerial) -> TestResult:
    """Set and read environment variable."""
    m = q.mark()
    q.send("export TESTVAR=sotos42", 3)
    q.send("echo $TESTVAR", 3)
    out = q.output_since(m)
    ok, detail = check_output(out, ["sotos42"])
    return TestResult("shell/env_var", ok, detail, out)


# ── Pipes ─────────────────────────────────────────────────────────────────

@test("echo_grep", "pipe")
def test_echo_grep(q: QemuSerial) -> TestResult:
    m = q.mark()
    q.send("echo needle-in-haystack | grep needle", 4)
    out = q.output_since(m)
    ok, detail = check_output(out, ["needle-in-haystack"],
                               ["cannot create temp"])
    return TestResult("pipe/echo_grep", ok, detail, out)


@test("echo_wc", "pipe")
def test_echo_wc(q: QemuSerial) -> TestResult:
    m = q.mark()
    q.send("echo one two three | wc", 4)
    out = q.output_since(m)
    # wc should show 1 line, 3 words
    ok, detail = check_output(out, ["1", "3"])
    return TestResult("pipe/echo_wc", ok, detail, out)


@test("quote_passthrough", "pipe")
def test_quote_passthrough(q: QemuSerial) -> TestResult:
    """Pipe inside quotes should NOT be split by LUCAS."""
    m = q.mark()
    q.send('busybox sh -c "echo quote-pipe-ok"', 8)
    out = q.output_since(m)
    ok, detail = check_output(out, ["quote-pipe-ok"],
                               ["cannot create temp"])
    return TestResult("pipe/quote_passthrough", ok, detail, out)


@test("busybox_pipe", "pipe")
def test_busybox_pipe(q: QemuSerial) -> TestResult:
    """Real busybox pipe: echo | cat with fork+exec."""
    m = q.mark()
    q.send('busybox sh -c "echo real-pipe-ok | busybox cat"', 20)
    out = q.output_since(m)
    ok, detail = check_output(out, ["real-pipe-ok", "exit_code=0"])
    return TestResult("pipe/busybox_pipe", ok, detail, out)


# ── Process Management (fork/exec) ───────────────────────────────────────

@test("busybox_echo", "process")
def test_busybox_echo(q: QemuSerial) -> TestResult:
    m = q.mark()
    q.send("busybox echo process-ok-42", 6)
    out = q.output_since(m)
    ok, detail = check_output(out, ["process-ok-42", "exit_code=0"])
    return TestResult("process/busybox_echo", ok, detail, out)


@test("busybox_multi_cmd", "process")
def test_busybox_multi_cmd(q: QemuSerial) -> TestResult:
    m = q.mark()
    q.send('busybox sh -c "echo AAA && echo BBB && echo CCC"', 10)
    out = q.output_since(m)
    ok, detail = check_output(out, ["AAA", "BBB", "CCC", "exit_code=0"])
    return TestResult("process/busybox_multi_cmd", ok, detail, out)


@test("proc_death_logging", "process")
def test_proc_death_logging(q: QemuSerial) -> TestResult:
    """Verify PROC-DEATH alarm fires for all PIDs (Fix 3)."""
    m = q.mark()
    q.send("busybox echo death-log-test", 6)
    out = q.output_since(m)
    ok, detail = check_output(out, ["PROC-DEATH P"])
    return TestResult("process/proc_death_logging", ok, detail, out)


# ── Networking ────────────────────────────────────────────────────────────

@test("wget_http", "net")
def test_wget_http(q: QemuSerial) -> TestResult:
    m = q.mark()
    q.send("busybox wget http://example.com/ -O /dev/null", 18)
    out = q.output_since(m)
    ok, detail = check_output(out, ["saved", "exit_code=0"],
                               ["bad address", "network unreachable"])
    return TestResult("net/wget_http", ok, detail, out)


@test("ping", "net")
def test_ping(q: QemuSerial) -> TestResult:
    """Verify ICMP ping sends request."""
    m = q.mark()
    q.send("ping 10.0.2.2", 6)
    out = q.output_since(m)
    ok, detail = check_output(out, ["PING", "data bytes"])
    return TestResult("net/ping", ok, detail, out)


# ── File System ───────────────────────────────────────────────────────────

@test("rm_file", "fs")
def test_rm_file(q: QemuSerial) -> TestResult:
    m = q.mark()
    q.send("write /tmp/rmtest.txt deleteme", 3)
    q.send("rm /tmp/rmtest.txt", 3)
    q.send("cat /tmp/rmtest.txt", 3)
    out = q.output_since(m)
    # After rm, cat should fail or show nothing meaningful
    # The key check is that rm didn't crash
    ok = "PANIC" not in out and "PROC-DEATH" not in out.split("rm /tmp")[0]
    detail = "ok" if ok else "crash during rm"
    return TestResult("fs/rm_file", ok, detail, out)



# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def filter_noise(output: str) -> str:
    """Remove noisy kernel debug lines for cleaner display."""
    lines = output.split("\n")
    return "\n".join(
        l for l in lines
        if "SIG_REDIRECT" not in l
        and "rt_sigreturn" not in l
        and "CHILD-HANDLER" not in l
    )


def run_tests(q: QemuSerial, filter_str: str = None, verbose: bool = False):
    """Run all registered tests (or filtered subset) and print results."""
    selected = TESTS
    if filter_str:
        selected = [t for t in TESTS if filter_str in t.test_name]

    if not selected:
        print(f"No tests match filter '{filter_str}'")
        return 1

    results: list[TestResult] = []
    total = len(selected)

    print(f"\n{'='*60}")
    print(f"  sotOS Test System — {total} tests")
    print(f"{'='*60}\n")

    for i, test_fn in enumerate(selected, 1):
        name = test_fn.test_name
        sys.stdout.write(f"  [{i:2}/{total}] {name:40s} ")
        sys.stdout.flush()

        try:
            result = test_fn(q)
        except Exception as e:
            result = TestResult(name, False, f"exception: {e}")

        results.append(result)

        if result.passed:
            print(f"\033[32mPASS\033[0m")
        else:
            print(f"\033[31mFAIL\033[0m  ({result.detail})")

        if verbose and result.output:
            print(f"    --- output ---")
            for line in filter_noise(result.output).strip().split("\n")[:15]:
                print(f"    | {line}")
            print()

    # Summary
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    print(f"\n{'='*60}")
    if failed == 0:
        print(f"  \033[32mALL {passed} TESTS PASSED\033[0m")
    else:
        print(f"  \033[32m{passed} passed\033[0m, \033[31m{failed} failed\033[0m")
        print()
        for r in results:
            if not r.passed:
                print(f"  FAIL: {r.name} — {r.detail}")
    print(f"{'='*60}\n")

    return 0 if failed == 0 else 1


def list_tests(filter_str: str = None):
    """Print available tests."""
    selected = TESTS
    if filter_str:
        selected = [t for t in TESTS if filter_str in t.test_name]
    print(f"\nAvailable tests ({len(selected)}):\n")
    for t in selected:
        print(f"  {t.test_name:40s}  {t.__doc__ or ''}")
    print()


def main():
    parser = argparse.ArgumentParser(description="sotOS Interactive Test System")
    parser.add_argument("--list", action="store_true", help="List available tests")
    parser.add_argument("--filter", type=str, default=None, help="Run tests matching pattern")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show command output")
    parser.add_argument("--no-build", action="store_true", help="Skip image build")
    parser.add_argument("--timeout", type=int, default=BOOT_TIMEOUT, help="Boot timeout (seconds)")
    args = parser.parse_args()

    if args.list:
        list_tests(args.filter)
        return 0

    # Build image
    if not args.no_build:
        print("Building image...")
        r = subprocess.run(["just", "image"], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stderr}")
            return 1
        print("Build OK.\n")
    elif not os.path.exists(IMAGE):
        print(f"Error: {IMAGE} not found. Run without --no-build or run 'just image' first.")
        return 1

    # Boot QEMU
    print("Booting sotOS in QEMU...")
    q = QemuSerial()
    q.start()

    if not q.wait_for("$ ", timeout=args.timeout):
        print("TIMEOUT: Shell prompt not reached.")
        q.stop()
        # Dump what we got
        print(q.output_since(0)[-500:])
        return 1

    print("Shell ready.\n")
    time.sleep(2)  # let boot settle

    try:
        rc = run_tests(q, filter_str=args.filter, verbose=args.verbose)
    finally:
        q.stop()

    return rc


if __name__ == "__main__":
    sys.exit(main())
