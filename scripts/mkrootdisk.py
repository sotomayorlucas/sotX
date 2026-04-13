#!/usr/bin/env python
"""Create a 64 MiB raw image for the persistent rootdisk (Unit 3).

The rootdisk is consumed by services/init/src/main.rs `init_virtio_root_blk()`,
which probes for a `b"SOTROOT\\0"` magic header at offset 0 of sector 0. If the
signature is absent, init formats the disk on first boot. So this script
defaults to producing a zero-filled image: first boot will format it, second
boot will mount it.

Pass --pre-format to write the SOTROOT signature so init takes the mount path
on the very first boot (useful for tests that want to skip the format step).

Usage:
    python scripts/mkrootdisk.py [output] [--pre-format]
    python scripts/mkrootdisk.py target/sotx-rootdisk.img
"""

import os
import sys

DEFAULT_OUTPUT = os.path.join("target", "sotx-rootdisk.img")
DISK_SIZE = 64 * 1024 * 1024  # 64 MiB
SECTOR_SIZE = 512
SIGNATURE = b"SOTROOT\0"


def main():
    args = sys.argv[1:]
    pre_format = False
    output = DEFAULT_OUTPUT
    for a in args:
        if a == "--pre-format":
            pre_format = True
        elif not a.startswith("--"):
            output = a

    out_dir = os.path.dirname(output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output, "wb") as f:
        sector0 = bytearray(SECTOR_SIZE)
        if pre_format:
            sector0[: len(SIGNATURE)] = SIGNATURE
        f.write(sector0)

        remaining = DISK_SIZE - SECTOR_SIZE
        chunk = b"\x00" * (1024 * 1024)
        while remaining > 0:
            n = min(len(chunk), remaining)
            f.write(chunk[:n])
            remaining -= n

    state = "pre-formatted" if pre_format else "zero-filled (init will format on first boot)"
    print(f"Created rootdisk: {output} ({DISK_SIZE // (1024*1024)} MiB, {state})")


if __name__ == "__main__":
    main()
