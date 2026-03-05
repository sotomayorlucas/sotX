#!/usr/bin/env python3
"""Build a shared library (.so) from a Rust staticlib (.a).

Extracts only the library's own object file (not core/compiler_builtins)
and links it into an ET_DYN shared object with proper .dynsym/.dynamic.
"""

import argparse
import subprocess
import tempfile
import os
import shutil


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, help="Path to .a file")
    parser.add_argument("--linker-script", required=True, help="Linker script for .so")
    parser.add_argument("--output", required=True, help="Output .so path")
    args = parser.parse_args()

    # List objects in archive.
    result = subprocess.run(
        ["llvm-ar", "t", args.archive],
        capture_output=True, text=True, check=True
    )
    objects = result.stdout.strip().split("\n")

    # Find the library's own object (not core-* or compiler_builtins-*).
    lib_objects = [
        o for o in objects
        if not o.startswith("core-") and not o.startswith("compiler_builtins-")
        and not o.startswith("alloc-")
    ]

    if not lib_objects:
        print("ERROR: no library objects found in archive")
        return 1

    # Extract the objects to a temp dir and link.
    with tempfile.TemporaryDirectory() as tmpdir:
        for obj in lib_objects:
            subprocess.run(
                ["llvm-ar", "x", os.path.abspath(args.archive), obj],
                cwd=tmpdir, check=True
            )

        obj_paths = [os.path.join(tmpdir, o) for o in lib_objects]

        # Ensure output directory exists.
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

        subprocess.run(
            ["lld", "-flavor", "gnu",
             "-shared", "-nostdlib",
             "--strip-debug",
             "-T", os.path.abspath(args.linker_script),
             ] + obj_paths + [
             "-o", os.path.abspath(args.output),
            ],
            check=True
        )

    size = os.path.getsize(args.output)
    print(f"Created {args.output} ({size} bytes)")


if __name__ == "__main__":
    main()
