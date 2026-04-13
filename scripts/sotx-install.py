#!/usr/bin/env python3
"""sotX installer.

Writes the bootable disk image (kernel + initrd + Limine) to a target
path, optionally alongside a persistent ObjectStore data disk that
survives reboots. The installer is intentionally minimalist: it does
not partition, format, or touch any block device that wasn't named on
the command line. It refuses to overwrite anything unless `--force`
is passed.

Usage:
  python scripts/sotx-install.py --target /path/to/sotx.img
  python scripts/sotx-install.py --target /dev/sdX --force          # raw block device
  python scripts/sotx-install.py --target out.img --with-rootdisk   # also stage rootdisk.img next to it

The script is the host-side bootstrap of "Sprint 1" -- the goal is
that a third party with nothing more than this repo, just, python,
and qemu can get a sotX image onto a USB stick or hypervisor
without reading the rest of the build system.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = REPO_ROOT / "target" / "sotx.img"
DEFAULT_ROOTDISK = REPO_ROOT / "target" / "rootdisk.img"


def die(msg: str) -> None:
    print(f"sotx-install: error: {msg}", file=sys.stderr)
    sys.exit(1)


def info(msg: str) -> None:
    print(f"sotx-install: {msg}")


def ensure_image_built(force_rebuild: bool) -> Path:
    """Make sure target/sotx.img exists, optionally re-running `just image`."""
    if not DEFAULT_IMAGE.exists() or force_rebuild:
        info("running 'just image' to (re)build the bootable disk image...")
        rc = subprocess.call(["just", "image"], cwd=REPO_ROOT)
        if rc != 0:
            die("'just image' failed -- check the build first")
    if not DEFAULT_IMAGE.exists():
        die(f"{DEFAULT_IMAGE} still missing after 'just image'")
    return DEFAULT_IMAGE


def ensure_rootdisk(size_mb: int) -> Path:
    """Build target/rootdisk.img via the existing mkdisk.py if missing."""
    if DEFAULT_ROOTDISK.exists():
        info(f"reusing existing rootdisk: {DEFAULT_ROOTDISK}")
        return DEFAULT_ROOTDISK
    info(f"running mkdisk.py to create a {size_mb}M rootdisk...")
    rc = subprocess.call(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "mkdisk.py"),
            "--output", str(DEFAULT_ROOTDISK),
            "--size", str(size_mb),
        ],
        cwd=REPO_ROOT,
    )
    if rc != 0:
        die("mkdisk.py failed -- could not stage rootdisk")
    return DEFAULT_ROOTDISK


def install_image(src: Path, dst: Path, force: bool) -> None:
    """Copy the disk image to the target path/device."""
    if dst.exists() and not force:
        die(f"{dst} already exists; pass --force to overwrite")
    info(f"writing {src} ({src.stat().st_size:,} bytes) -> {dst}")

    # On Linux you can dd directly to /dev/sdX. On Windows we just copy.
    # We don't try to be cute about block alignment -- the image is
    # already a sector-aligned GPT layout from scripts/mkimage.py.
    if os.name == "posix" and dst.is_block_device() if dst.exists() else False:
        rc = subprocess.call(["dd", f"if={src}", f"of={dst}", "bs=4M", "status=progress"])
        if rc != 0:
            die("dd failed")
    else:
        shutil.copyfile(src, dst)
    info("install complete")


def main() -> int:
    p = argparse.ArgumentParser(description="Install sotX to a target image / device")
    p.add_argument("--target", required=True,
                   help="output path (file or block device)")
    p.add_argument("--force", action="store_true",
                   help="overwrite an existing target without prompting")
    p.add_argument("--rebuild", action="store_true",
                   help="rerun 'just image' even if target/sotx.img exists")
    p.add_argument("--with-rootdisk", action="store_true",
                   help="also create target/rootdisk.img alongside the boot image")
    p.add_argument("--rootdisk-size", type=int, default=64,
                   help="rootdisk size in MiB (default 64)")
    args = p.parse_args()

    src = ensure_image_built(args.rebuild)
    install_image(src, Path(args.target), args.force)

    if args.with_rootdisk:
        rd = ensure_rootdisk(args.rootdisk_size)
        info(f"rootdisk staged at {rd} -- attach with -drive in QEMU or copy to a second LUN")

    info("done. Boot with:")
    info(f"  qemu-system-x86_64 -drive format=raw,file={args.target} -serial stdio -m 2048M")
    return 0


if __name__ == "__main__":
    sys.exit(main())
