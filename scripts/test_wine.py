#!/usr/bin/env python3
"""Test wine64 --version on sotOS.

Boots sotOS with the Wine sysroot disk, runs 'wine64 --version',
and checks for the version string in the output.

Usage:
  python scripts/test_wine.py
"""

import sys, os, time, subprocess, threading

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
IMAGE = "target/sotos.img"
DISK = "target/disk.img"

BOOT_TIMEOUT = 60
CMD_TIMEOUT = 300


class Session:
    def __init__(self):
        self.output = bytearray()
        self.lock = threading.Lock()

    def start(self):
        self.proc = subprocess.Popen(
            [QEMU,
             "-drive", f"format=raw,file={IMAGE}",
             "-drive", f"if=none,format=raw,file={DISK},id=disk0",
             "-device", "virtio-blk-pci,drive=disk0,disable-modern=on",
             "-serial", "stdio", "-display", "none", "-no-reboot", "-m", "1024M"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        while True:
            b = self.proc.stdout.read(1)
            if not b:
                break
            with self.lock:
                self.output.extend(b)

    def wait_for(self, text, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            with self.lock:
                if text.encode() in self.output:
                    return True
            time.sleep(0.1)
        return False

    def get_output(self):
        with self.lock:
            return self.output.decode('utf-8', errors='replace')

    def get_output_after(self, marker):
        out = self.get_output()
        idx = out.rfind(marker)
        if idx >= 0:
            return out[idx:]
        return out[-2000:]

    def send(self, cmd):
        for ch in cmd:
            self.proc.stdin.write(ch.encode())
            self.proc.stdin.flush()
            time.sleep(0.05)
        self.proc.stdin.write(b'\n')
        self.proc.stdin.flush()

    def clear(self):
        with self.lock:
            self.output.clear()

    def stop(self):
        try:
            self.proc.kill()
        except:
            pass


def main():
    print("=== Wine64 on sotOS ===\n")

    if not os.path.isfile(IMAGE):
        print(f"FAIL: {IMAGE} not found. Run 'just image'.")
        return 1
    if not os.path.isfile(DISK):
        print(f"FAIL: {DISK} not found. Run 'python scripts/fetch_wine.py --disk'.")
        return 1

    s = Session()
    s.start()

    print("  Booting sotOS...")
    if not s.wait_for("$", BOOT_TIMEOUT):
        print("  FAIL: shell not ready")
        print(s.get_output()[-3000:])
        s.stop()
        return 1
    print("  Shell ready!")

    # First, let's see what's on disk
    time.sleep(0.5)
    s.clear()
    print("\n  Running: ls /bin")
    s.send("ls /bin")
    time.sleep(2)
    out = s.get_output()
    print(f"  Output: {out.strip()}")

    # Check Wine PE DLL directory
    s.clear()
    print("\n  Running: ls /x86_64-linux-gnu/wine/x86_64-windows")
    s.send("ls /x86_64-linux-gnu/wine/x86_64-windows")
    time.sleep(2)
    out = s.get_output()
    print(f"  Output: {out.strip()}")

    # Try running wine64
    s.clear()
    print("\n  Running: /bin/wine64 --version")
    s.send("/bin/wine64 --version")

    # Wait for result
    found_version = s.wait_for("wine-", CMD_TIMEOUT)
    found_prompt = s.wait_for("$", CMD_TIMEOUT)

    out = s.get_output()
    print(f"\n  === Output ===")
    print(out)
    print(f"  === End ===")

    if found_version:
        for line in out.split('\n'):
            if 'wine-' in line:
                print(f"\n  PASS --version: {line.strip()}")
                break
    else:
        print("\n  FAIL: wine64 --version did not print version string")
        print(s.get_output()[-2000:])
        s.stop()
        return 1

    # Now try running a PE executable
    time.sleep(1)
    s.clear()
    print("\n  Running: /bin/wine64 /bin/hello.exe")
    s.send("/bin/wine64 /bin/hello.exe")

    # Wait longer — PE loading is more complex.
    # Wine's ntdll does thousands of MAP_FIXED_NOREPLACE probes (VA reservation),
    # each one going through IPC. Give it plenty of time.
    found_hello = s.wait_for("Hello", CMD_TIMEOUT)
    found_prompt2 = s.wait_for("$", 30)

    out2 = s.get_output()
    print(f"\n  === hello.exe Output ===")
    print(out2)
    print(f"  === End ===")

    s.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
