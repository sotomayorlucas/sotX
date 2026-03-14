#!/usr/bin/env python3
"""Enhanced Wine hello.exe test — staged execution with categorized diagnostics.

Boots sotOS with Wine disk, verifies Wine files exist, runs wine64 --version,
then runs wine64 /bin/hello.exe. Categorizes all serial output and prints
a diagnostic summary.
"""
import sys, os, time, subprocess, threading, re
from collections import Counter

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
IMAGE = "target/sotos.img"
DISK = "target/disk.img"
OUTPUT = "target/wine_hello_diag.txt"

# ---------------------------------------------------------------------------
# Output categories
# ---------------------------------------------------------------------------
CATEGORIES = {
    "SYSCALL_MISSING": ["unimpl", "STUB", "unhandled syscall"],
    "MEMORY_ISSUE":    ["VMA-FULL", "MFIX-CLOB", "MUNM-CLOB", "OOM", "frame_alloc"],
    "PAGE_FAULT":      ["VF t=", "SEGV", "#PF", "fault"],
    "WINE_PROGRESS":   ["wine-", "ntdll", "PE", "start.exe", "conhost"],
    "FORK_EXEC":       ["FK1", "FK2", "AS-SYS", "EXEC P", "fork", "exec"],
    "IPC":             ["LOOP-KILL", "KERN-ADDR", "IPC"],
    "MMAP":            ["MM3 base", "MMAP", "mmap", "MAP_FIXED"],
    "SUCCESS":         ["Hello from Wine"],
}

# ---------------------------------------------------------------------------
# Session — QEMU serial I/O
# ---------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.output = bytearray()
        self.lock = threading.Lock()

    def start(self):
        self.proc = subprocess.Popen(
            [QEMU, "-drive", f"format=raw,file={IMAGE}",
             "-drive", f"if=none,format=raw,file={DISK},id=disk0",
             "-device", "virtio-blk-pci,drive=disk0,disable-modern=on",
             "-serial", "stdio", "-display", "none", "-no-reboot", "-m", "1024M"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0)
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

    def wait_for_prompt(self, timeout=30):
        return self.wait_for("$ ", timeout)

    def get_output(self):
        with self.lock:
            return self.output.decode('utf-8', errors='replace')

    def output_size(self):
        with self.lock:
            return len(self.output)

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

# ---------------------------------------------------------------------------
# Categorize output lines
# ---------------------------------------------------------------------------
def categorize_lines(text):
    """Categorize each line into zero or more categories. Returns dict of category -> [lines]."""
    result = {cat: [] for cat in CATEGORIES}
    for line in text.split('\n'):
        stripped = line.rstrip()
        if not stripped:
            continue
        for cat, markers in CATEGORIES.items():
            for marker in markers:
                if marker in stripped:
                    result[cat].append(stripped)
                    break  # one category match per line per category
    return result

def extract_unhandled_syscalls(text):
    """Extract syscall numbers from unhandled/unimpl lines."""
    syscalls = Counter()
    for line in text.split('\n'):
        # Match patterns like "unimpl 123" or "unhandled syscall 45" or "STUB: sys_123"
        m = re.search(r'(?:unimpl|unhandled\s+syscall)\s+(\d+)', line, re.IGNORECASE)
        if m:
            syscalls[int(m.group(1))] += 1
        m = re.search(r'STUB[:\s]+(?:sys[_]?)?(\d+)', line)
        if m:
            syscalls[int(m.group(1))] += 1
    return syscalls

def wait_with_stall_detection(session, marker, timeout, stall_timeout=30):
    """Wait for marker with stall detection.
    Returns (found_marker, stalled, timed_out)."""
    t0 = time.time()
    last_size = session.output_size()
    stall_start = None

    while time.time() - t0 < timeout:
        out = session.get_output()

        if marker and marker in out:
            return (True, False, False)

        cur_size = session.output_size()
        if cur_size == last_size:
            if stall_start is None:
                stall_start = time.time()
            elif time.time() - stall_start >= stall_timeout:
                return (False, True, False)
        else:
            stall_start = None
            last_size = cur_size

        time.sleep(1)

    return (False, False, True)

# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------
def main():
    s = Session()
    s.start()

    wine_version_ok = False
    hello_exe_ok = False
    termination = "completed"  # or "stalled" or "timed_out" or "crashed"

    # -----------------------------------------------------------------------
    # Stage 1: Boot and wait for shell prompt
    # -----------------------------------------------------------------------
    print("=== Stage 1: Boot ===", flush=True)
    if not s.wait_for("$", 60):
        print("  FAIL: no shell prompt within 60s", flush=True)
        out = s.get_output()
        with open(OUTPUT, 'w') as f:
            f.write(out)
        print(f"  Output saved to {OUTPUT} ({len(out)} bytes)", flush=True)
        s.stop()
        return 1
    print("  Shell ready.", flush=True)
    time.sleep(0.5)

    # -----------------------------------------------------------------------
    # Stage 2: Verify Wine files on disk
    # -----------------------------------------------------------------------
    print("\n=== Stage 2: Verify Wine files ===", flush=True)

    s.clear()
    s.send("ls /bin")
    s.wait_for_prompt(timeout=15)
    ls_bin = s.get_output()

    has_wine64 = "wine64" in ls_bin
    print(f"  /bin/wine64 present: {'YES' if has_wine64 else 'NO'}", flush=True)

    s.clear()
    s.send("ls /x86_64-linux-gnu/wine/x86_64-windows")
    s.wait_for_prompt(timeout=15)
    ls_wine = s.get_output()

    has_ntdll = "ntdll" in ls_wine
    has_start = "start.exe" in ls_wine
    print(f"  ntdll.dll present : {'YES' if has_ntdll else 'NO'}", flush=True)
    print(f"  start.exe present : {'YES' if has_start else 'NO'}", flush=True)

    if not has_wine64:
        print("  FAIL: wine64 not found in /bin", flush=True)
        out = s.get_output()
        with open(OUTPUT, 'w') as f:
            f.write(out)
        s.stop()
        return 1

    # -----------------------------------------------------------------------
    # Stage 3: wine64 --version
    # -----------------------------------------------------------------------
    print("\n=== Stage 3: wine64 --version ===", flush=True)
    s.clear()
    s.send("/bin/wine64 --version")

    found, stalled, timed_out = wait_with_stall_detection(s, "wine-", 300)
    stage3_out = s.get_output()

    if found:
        # Extract the version line
        for line in stage3_out.split('\n'):
            if 'wine-' in line:
                version_line = line.strip()
                print(f"  Version: {version_line}", flush=True)
                break
        wine_version_ok = True
        print("  [OK] wine64 --version succeeded.", flush=True)
        # Wait for prompt to return
        s.wait_for_prompt(timeout=30)
    else:
        reason = "stalled (30s no output)" if stalled else "timed out (300s)"
        print(f"  [FAIL] wine64 --version {reason}", flush=True)
        if "PANIC" in stage3_out or "SEGV" in stage3_out:
            termination = "crashed"

    time.sleep(1)

    # -----------------------------------------------------------------------
    # Stage 4: wine64 /bin/hello.exe
    # -----------------------------------------------------------------------
    print("\n=== Stage 4: wine64 /bin/hello.exe ===", flush=True)
    s.clear()
    s.send("/bin/wine64 /bin/hello.exe")

    found, stalled, timed_out = wait_with_stall_detection(s, "Hello from Wine", 300)
    stage4_out = s.get_output()

    if found:
        hello_exe_ok = True
        print("  [OK] 'Hello from Wine' detected!", flush=True)
        time.sleep(2)
    else:
        if stalled:
            termination = "stalled"
            print("  Output stalled for 30s, stopping.", flush=True)
        elif timed_out:
            termination = "timed_out"
            print("  Timed out after 300s.", flush=True)

        if "PANIC" in stage4_out or "SEGV" in stage4_out:
            termination = "crashed"
            print("  Process appears to have crashed.", flush=True)

    # -----------------------------------------------------------------------
    # Save full output
    # -----------------------------------------------------------------------
    full_output = s.get_output()
    s.stop()

    with open(OUTPUT, 'w') as f:
        f.write(full_output)
    line_count = full_output.count('\n')
    print(f"\nFull output saved to {OUTPUT} ({len(full_output)} bytes, {line_count} lines)", flush=True)

    # -----------------------------------------------------------------------
    # Diagnostic summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60, flush=True)
    print("DIAGNOSTIC SUMMARY", flush=True)
    print("=" * 60, flush=True)

    # Categorize
    cats = categorize_lines(full_output)
    print("\nCategory counts:", flush=True)
    for cat in CATEGORIES:
        count = len(cats[cat])
        if count > 0:
            print(f"  {cat:20s}: {count}", flush=True)

    # Wine version
    print(f"\n  wine64 --version   : {'PASS' if wine_version_ok else 'FAIL'}", flush=True)
    print(f"  hello.exe message  : {'PASS' if hello_exe_ok else 'FAIL'}", flush=True)
    print(f"  Termination        : {termination}", flush=True)

    # Top 5 unhandled syscalls
    unhandled = extract_unhandled_syscalls(full_output)
    if unhandled:
        print("\n  Top unhandled syscalls:", flush=True)
        for num, count in unhandled.most_common(5):
            print(f"    syscall {num:4d}: {count}x", flush=True)

    # Key diagnostic lines (sample from interesting categories)
    interesting = ["SYSCALL_MISSING", "MEMORY_ISSUE", "PAGE_FAULT", "SUCCESS"]
    sample_lines = []
    for cat in interesting:
        for line in cats[cat][:3]:
            sample_lines.append((cat, line))
    if sample_lines:
        print("\n  Sample diagnostic lines:", flush=True)
        for cat, line in sample_lines:
            print(f"    [{cat}] {line[:150]}", flush=True)

    print("\n" + "=" * 60, flush=True)
    if hello_exe_ok:
        print("RESULT: PASS", flush=True)
    else:
        print("RESULT: FAIL", flush=True)
    print("=" * 60, flush=True)

    return 0 if hello_exe_ok else 1

if __name__ == '__main__':
    sys.exit(main())
