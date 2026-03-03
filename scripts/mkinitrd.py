#!/usr/bin/env python3
"""
Build a CPIO newc archive (initramfs) from a list of files.

Usage:
    python scripts/mkinitrd.py --output target/initrd.img --file init=path/to/elf
"""

import argparse
import struct
import sys
from pathlib import Path


def align4(n: int) -> int:
    """Round up to the next 4-byte boundary."""
    return (n + 3) & ~3


def cpio_header(namesize: int, filesize: int, ino: int) -> bytes:
    """Build a 110-byte CPIO newc header."""
    # All fields are 8-char zero-padded hex strings, except magic (6 chars).
    hdr = "070701"                  # magic
    hdr += f"{ino:08X}"             # inode
    hdr += f"{0o100644:08X}"        # mode: regular file
    hdr += f"{0:08X}"               # uid
    hdr += f"{0:08X}"               # gid
    hdr += f"{1:08X}"               # nlink
    hdr += f"{0:08X}"               # mtime
    hdr += f"{filesize:08X}"        # filesize
    hdr += f"{0:08X}"               # devmajor
    hdr += f"{0:08X}"               # devminor
    hdr += f"{0:08X}"               # rdevmajor
    hdr += f"{0:08X}"               # rdevminor
    hdr += f"{namesize:08X}"        # namesize (includes NUL)
    hdr += f"{0:08X}"               # checksum (unused in newc)
    assert len(hdr) == 110
    return hdr.encode("ascii")


def make_entry(name: str, data: bytes, ino: int) -> bytes:
    """Create one CPIO newc entry (header + name + padding + data + padding)."""
    name_bytes = name.encode("ascii") + b"\x00"
    namesize = len(name_bytes)
    filesize = len(data)

    out = bytearray()
    out += cpio_header(namesize, filesize, ino)
    out += name_bytes
    # Pad name to 4-byte boundary (offset from start of header)
    header_plus_name = 110 + namesize
    pad_name = align4(header_plus_name) - header_plus_name
    out += b"\x00" * pad_name
    # File data
    out += data
    # Pad data to 4-byte boundary
    pad_data = align4(filesize) - filesize
    out += b"\x00" * pad_data
    return bytes(out)


def make_trailer() -> bytes:
    """Create the TRAILER!!! sentinel entry."""
    return make_entry("TRAILER!!!", b"", 0)


def main():
    p = argparse.ArgumentParser(description="Build CPIO newc initramfs archive")
    p.add_argument("--output", "-o", required=True, help="Output archive path")
    p.add_argument("--file", "-f", action="append", default=[],
                   help="name=path pairs to include (e.g., init=path/to/elf)")
    args = p.parse_args()

    archive = bytearray()
    ino = 1

    for spec in args.file:
        if "=" not in spec:
            print(f"Error: --file must be name=path, got: {spec}", file=sys.stderr)
            return 1
        name, path = spec.split("=", 1)
        data = Path(path).read_bytes()
        archive += make_entry(name, data, ino)
        print(f"  {name}: {len(data):,} bytes")
        ino += 1

    archive += make_trailer()

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_bytes(archive)
    print(f"  Initrd: {args.output} ({len(archive):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
