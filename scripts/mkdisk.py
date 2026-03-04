#!/usr/bin/env python3
"""Create a 1 MiB test disk for virtio-blk testing.

Sector 0 contains "SOTOS DISK TEST\0" followed by sequential bytes.
All other sectors are zeroed.

Usage: python scripts/mkdisk.py [--output target/disk.img]
"""

import argparse
import os

SECTOR_SIZE = 512
DISK_SIZE = 1024 * 1024  # 1 MiB

def main():
    parser = argparse.ArgumentParser(description="Create a test disk image")
    parser.add_argument("--output", default="target/disk.img",
                        help="Output disk image path")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    data = bytearray(DISK_SIZE)

    # Write test pattern to sector 0
    marker = b"SOTOS DISK TEST\x00"
    data[:len(marker)] = marker
    # Fill rest of sector 0 with sequential bytes
    for i in range(len(marker), SECTOR_SIZE):
        data[i] = i & 0xFF

    with open(args.output, "wb") as f:
        f.write(data)

    sectors = DISK_SIZE // SECTOR_SIZE
    print(f"Created {args.output}: {DISK_SIZE} bytes ({sectors} sectors)")

if __name__ == "__main__":
    main()
