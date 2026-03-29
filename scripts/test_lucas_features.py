#!/usr/bin/env python3
"""Test LUCAS shell v0.3 features.

Boots QEMU, waits for LUCAS shell, sends commands, validates output.

Usage:
  python scripts/test_lucas_features.py
"""

import sys
import time
import subprocess
import threading

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
IMAGE = "target/sotos.img"
DISK = "target/disk.img"
TIMEOUT_BOOT = 90
TIMEOUT_CMD = 15


class QemuSession:
    def __init__(self):
        self.proc = None
        self.output = bytearray()
        self.lock = threading.Lock()
        self._reader = None
        self._done = threading.Event()

    def start(self):
        self.proc = subprocess.Popen(
            [QEMU,
             "-drive", f"format=raw,file={IMAGE}",
             "-drive", f"if=none,format=raw,file={DISK},id=disk0",
             "-device", "virtio-blk-pci,drive=disk0,disable-modern=on",
             "-serial", "stdio",
             "-display", "none",
             "-no-reboot",
             "-m", "512M"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        while not self._done.is_set():
            b = self.proc.stdout.read(1)
            if not b:
                break
            with self.lock:
                self.output.extend(b)

    def wait_for(self, pattern, timeout=TIMEOUT_BOOT, after=0):
        pat = pattern.encode() if isinstance(pattern, str) else pattern
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if pat in self.output[after:]:
                    return True
            time.sleep(0.1)
        return False

    def send(self, cmd):
        for ch in cmd:
            self.proc.stdin.write(ch.encode() if isinstance(ch, str) else bytes([ch]))
            self.proc.stdin.flush()
            time.sleep(0.08)
        time.sleep(0.1)
        self.proc.stdin.write(b"\r\n")
        self.proc.stdin.flush()
        time.sleep(0.2)

    def snapshot(self):
        with self.lock:
            return len(self.output)

    def output_after(self, pos):
        with self.lock:
            return self.output[pos:].decode("utf-8", errors="replace")

    def send_and_wait(self, cmd, timeout=TIMEOUT_CMD):
        pos = self.snapshot()
        self.send(cmd)
        self.wait_for("$ ", timeout=timeout, after=pos)
        time.sleep(0.3)
        return self.output_after(pos)

    def boot_to_shell(self):
        self.start()
        if not self.wait_for("$ ", timeout=TIMEOUT_BOOT):
            return False
        time.sleep(1.0)
        return True

    def stop(self):
        self._done.set()
        if self.proc:
            self.proc.kill()
            self.proc.wait()


def run_tests():
    print("=" * 60)
    print("LUCAS Shell v0.3 Feature Tests")
    print("=" * 60)

    # Build image first
    print("\n[*] Building image...")
    r = subprocess.run(["just", "image"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"FAIL: Build failed\n{r.stderr[-500:]}")
        return False

    print("[*] Booting QEMU...")
    s = QemuSession()
    try:
        if not s.boot_to_shell():
            print("FAIL: Shell did not start within timeout")
            print(f"  Output: {s.output_after(0)[:500]}")
            return False

        print("[OK] Shell booted (LUCAS v0.3)")
        results = []

        # ── Test 1: $? exit status ──
        print("\n--- Test: $? exit status ---")
        out = s.send_and_wait("echo $?")
        ok = "0" in out
        results.append(("$? after echo", ok))
        print(f"  echo $? -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 2: true/false + $? ──
        print("\n--- Test: true/false ---")
        out = s.send_and_wait("true")
        out2 = s.send_and_wait("echo $?")
        ok1 = "0" in out2
        results.append(("true sets $?=0", ok1))
        print(f"  true; echo $? -> {'PASS' if ok1 else 'FAIL'}: {repr(out2.strip()[:80])}")

        out = s.send_and_wait("false")
        out2 = s.send_and_wait("echo $?")
        ok2 = "1" in out2
        results.append(("false sets $?=1", ok2))
        print(f"  false; echo $? -> {'PASS' if ok2 else 'FAIL'}: {repr(out2.strip()[:80])}")

        # ── Test 3: && operator ──
        print("\n--- Test: && operator ---")
        out = s.send_and_wait("true && echo and-ok")
        ok = "and-ok" in out
        results.append(("&& on success", ok))
        print(f"  true && echo and-ok -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        out = s.send_and_wait("false && echo skipped-yes")
        # "skipped-yes" appears in the echoed command; check it does NOT appear on its own line
        lines = [l.strip() for l in out.split('\n')]
        ok = not any(l == "skipped-yes" for l in lines)
        results.append(("&& on failure skips", ok))
        print(f"  false && echo skipped-yes -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 4: || operator ──
        print("\n--- Test: || operator ---")
        out = s.send_and_wait("false || echo or-ok")
        ok = "or-ok" in out
        results.append(("|| on failure", ok))
        print(f"  false || echo or-ok -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 5: Semicolons ──
        print("\n--- Test: semicolons ---")
        out = s.send_and_wait("echo aaa; echo bbb")
        ok = "aaa" in out and "bbb" in out
        results.append(("semicolons", ok))
        print(f"  echo aaa; echo bbb -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 6: Arithmetic $(()) ──
        print("\n--- Test: arithmetic ---")
        out = s.send_and_wait("echo $((2+3))")
        ok = "5" in out
        results.append(("$((2+3))", ok))
        print(f"  echo $((2+3)) -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        out = s.send_and_wait("echo $((10*3+1))")
        ok = "31" in out
        results.append(("$((10*3+1))", ok))
        print(f"  echo $((10*3+1)) -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 7: Special variables ──
        print("\n--- Test: special variables ---")
        out = s.send_and_wait("echo $$")
        ok = out.strip() and any(c.isdigit() for c in out)
        results.append(("$$ returns PID", ok))
        print(f"  echo $$ -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        out = s.send_and_wait("echo $0")
        ok = "lucas" in out
        results.append(("$0 is lucas", ok))
        print(f"  echo $0 -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 8: Command substitution ──
        print("\n--- Test: command substitution ---")
        out = s.send_and_wait("echo $(uname)")
        ok = "sotOS" in out
        results.append(("$(uname)", ok))
        print(f"  echo $(uname) -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 9: Extended test conditions ──
        print("\n--- Test: extended test ---")
        out = s.send_and_wait("if [ 5 -gt 3 ]; then echo gt-ok; fi")
        ok = "gt-ok" in out
        results.append(("[ 5 -gt 3 ]", ok))
        print(f"  [ 5 -gt 3 ] -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        out = s.send_and_wait("if test -n hello; then echo nonempty; fi")
        ok = "nonempty" in out
        results.append(("test -n", ok))
        print(f"  test -n hello -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 10: type command ──
        print("\n--- Test: type ---")
        out = s.send_and_wait("type echo")
        ok = "builtin" in out
        results.append(("type echo", ok))
        print(f"  type echo -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:80])}")

        # ── Test 11: sleep ──
        print("\n--- Test: sleep ---")
        out = s.send_and_wait("sleep 1")
        ok = "PANIC" not in out
        results.append(("sleep 1", ok))
        print(f"  sleep 1 -> {'PASS' if ok else 'FAIL'}")

        # ── Test 12: Environment inheritance ──
        print("\n--- Test: env inheritance ---")
        out = s.send_and_wait("echo $PATH")
        ok = "/bin" in out
        results.append(("$PATH set", ok))
        print(f"  echo $PATH -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:120])}")

        # ── Test 13: while loop ──
        print("\n--- Test: while loop ---")
        s.send_and_wait("export i=0")
        out = s.send_and_wait("while test $i -lt 3; do echo iter-$i; export i=$(($i+1)); done", timeout=30)
        ok = "iter-0" in out and "iter-1" in out and "iter-2" in out
        results.append(("while loop", ok))
        print(f"  while loop -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:120])}")

        # ── Test 14: pkg command (may trigger init #UD, run last) ──
        print("\n--- Test: pkg ---")
        out = s.send_and_wait("pkg help")
        ok = "pkg" in out and ("list" in out or "info" in out)
        results.append(("pkg help", ok))
        print(f"  pkg help -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:120])}")

        # ── Test 15: apt command ──
        print("\n--- Test: apt ---")
        out = s.send_and_wait("apt help")
        ok = "apt" in out and "install" in out
        results.append(("apt help", ok))
        print(f"  apt help -> {'PASS' if ok else 'FAIL'}: {repr(out.strip()[:120])}")

        # ── Summary ──
        print("\n" + "=" * 60)
        passed = sum(1 for _, ok in results if ok)
        total = len(results)
        print(f"Results: {passed}/{total} passed")
        for name, ok in results:
            print(f"  {'PASS' if ok else 'FAIL'}: {name}")
        print("=" * 60)
        return passed == total

    finally:
        s.stop()


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
