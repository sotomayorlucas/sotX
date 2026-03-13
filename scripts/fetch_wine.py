#!/usr/bin/env python3
"""Download Wine64 minimal files for running 'wine64 --version' on sotOS.

Only 5 files needed:
  /bin/wine64          - ELF loader (dynamically linked)
  /bin/ntdll.so        - Wine ntdll Unix-side library (loaded via dlopen)
  /lib/ld-linux-x86-64.so.2  - glibc dynamic linker
  /lib/libc.so.6       - glibc
  /lib/libunwind.so.8  - required by ntdll.so

Flow: wine64 -> dlopen("ntdll.so") -> __wine_main() -> check_command_line()
      -> printf(wine_build) -> exit(0)

No wineserver, no PE DLLs, no Windows environment needed for --version.

Usage:
  python scripts/fetch_wine.py              # download wine + deps
  python scripts/fetch_wine.py --disk       # download + create disk image
"""

import argparse
import os
import struct
import sys
import tarfile
import urllib.request

CACHE_DIR = "target/wine-cache"
SYSROOT = "target/wine-sysroot"

# Debian Bookworm (glibc 2.36, Wine 8.0 — stable, well-tested)
WINE_DEB_URL = "http://deb.debian.org/debian/pool/main/w/wine/"
LIBUNWIND_DEB_URL = "http://deb.debian.org/debian/pool/main/libu/libunwind/"

# We'll fetch package listings to find exact filenames
PACKAGES_URL = "http://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.gz"


def download(url, output_path):
    """Download a file if not cached."""
    if os.path.isfile(output_path):
        sz = os.path.getsize(output_path)
        print(f"  Cached: {os.path.basename(output_path)} ({sz:,} bytes)")
        return True

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    print(f"  Downloading: {url}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sotOS-fetch/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = resp.headers.get('Content-Length')
            total = int(total) if total else None
            with open(output_path + ".tmp", 'wb') as f:
                downloaded = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded * 100 // total
                        sys.stdout.write(f"\r  {downloaded / (1024*1024):.1f} MiB ({pct}%)")
                        sys.stdout.flush()

            if total:
                print()
            print(f"  Downloaded: {downloaded:,} bytes")

        os.replace(output_path + ".tmp", output_path)
        return True
    except Exception as e:
        print(f"\n  Error: {e}")
        tmp = output_path + ".tmp"
        if os.path.exists(tmp):
            os.remove(tmp)
        return False


def extract_deb_data(deb_path):
    """Extract data.tar from a .deb file (ar archive format)."""
    with open(deb_path, 'rb') as f:
        # ar header: "!<arch>\n" (8 bytes)
        magic = f.read(8)
        if magic != b'!<arch>\n':
            print(f"  Error: {deb_path} is not an ar archive")
            return None

        while True:
            # ar entry header: 60 bytes
            header = f.read(60)
            if len(header) < 60:
                break

            name = header[0:16].strip()
            size = int(header[48:58].strip())

            # Look for data.tar*
            name_str = name.decode('ascii', errors='replace').rstrip('/')
            if name_str.startswith('data.tar'):
                data = f.read(size)
                return data, name_str

            # Skip this entry (+ padding to even boundary)
            f.seek(size + (size % 2), 1)

    return None


def extract_files_from_deb(deb_path, file_patterns, output_dir):
    """Extract specific files from a .deb package."""
    result = extract_deb_data(deb_path)
    if result is None:
        print(f"  Error: no data.tar found in {deb_path}")
        return {}

    data, tar_name = result
    extracted = {}

    # Determine compression
    if tar_name.endswith('.xz'):
        import lzma
        data = lzma.decompress(data)
    elif tar_name.endswith('.gz'):
        import gzip
        data = gzip.decompress(data)
    elif tar_name.endswith('.zst'):
        print(f"  Error: zstd compression not supported by stdlib")
        return {}

    tf = tarfile.open(fileobj=__import__('io').BytesIO(data), mode='r:')

    for member in tf.getmembers():
        path = member.name.lstrip('./')
        if not path:
            continue

        for pattern, out_name in file_patterns:
            if path == pattern or path.endswith('/' + pattern.split('/')[-1]):
                if member.isfile() or member.issym():
                    # For symlinks, try to get the target
                    if member.issym():
                        target = member.linkname
                        if not target.startswith('/'):
                            resolved = os.path.normpath(
                                os.path.join(os.path.dirname(path), target))
                        else:
                            resolved = target.lstrip('/')
                        # Try to extract the target
                        for try_path in [resolved, './' + resolved]:
                            try:
                                tm = tf.getmember(try_path)
                                if tm.isfile():
                                    fobj = tf.extractfile(tm)
                                    if fobj:
                                        out_path = os.path.join(output_dir, out_name)
                                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                                        file_data = fobj.read()
                                        with open(out_path, 'wb') as out:
                                            out.write(file_data)
                                        extracted[out_name] = len(file_data)
                                        break
                            except KeyError:
                                continue
                    else:
                        fobj = tf.extractfile(member)
                        if fobj:
                            out_path = os.path.join(output_dir, out_name)
                            os.makedirs(os.path.dirname(out_path), exist_ok=True)
                            file_data = fobj.read()
                            with open(out_path, 'wb') as out:
                                out.write(file_data)
                            extracted[out_name] = len(file_data)

    tf.close()
    return extracted


def find_deb_url(packages_data, pkg_name):
    """Find the download URL for a package from Packages index."""
    current_pkg = None
    filename = None
    for line in packages_data.split('\n'):
        if line.startswith('Package: '):
            current_pkg = line[9:].strip()
            filename = None
        elif line.startswith('Filename: '):
            filename = line[10:].strip()
        elif line == '' and current_pkg == pkg_name and filename:
            return f"http://deb.debian.org/debian/{filename}"
    return None


def main():
    parser = argparse.ArgumentParser(description="Fetch Wine64 for sotOS")
    parser.add_argument("--disk", action="store_true",
                        help="Also create disk image with Wine sysroot")
    parser.add_argument("--disk-size", type=int, default=512,
                        help="Disk size in MiB (default: 512)")
    args = parser.parse_args()

    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(SYSROOT, exist_ok=True)

    print("=== sotOS Wine64 Sysroot Builder ===\n")

    # Step 1: Download Packages index to find exact .deb URLs
    print("[1/4] Fetching Debian package index...")
    packages_gz_path = os.path.join(CACHE_DIR, "Packages.gz")
    if not download(PACKAGES_URL, packages_gz_path):
        print("  Error: could not download package index")
        return 1

    import gzip
    with gzip.open(packages_gz_path, 'rt', encoding='utf-8', errors='replace') as f:
        packages_data = f.read()

    # Find URLs for our packages
    needed_pkgs = {
        'wine64': 'wine64',
        'libwine': 'libwine',
        'libunwind8': 'libunwind8',
    }

    deb_paths = {}
    for pkg_name, label in needed_pkgs.items():
        url = find_deb_url(packages_data, pkg_name)
        if not url:
            print(f"  Warning: {pkg_name} not found in Packages index")
            # Try direct URLs as fallback
            continue
        deb_file = os.path.join(CACHE_DIR, os.path.basename(url))
        deb_paths[label] = (url, deb_file)

    # Step 2: Download .deb packages
    print("\n[2/4] Downloading Wine packages...")
    for label, (url, deb_file) in deb_paths.items():
        print(f"  [{label}]")
        if not download(url, deb_file):
            print(f"  Error downloading {label}")
            return 1

    # Step 3: Extract needed files
    print("\n[3/4] Extracting Wine binaries...")

    all_extracted = {}

    # From wine64 package: the wine64 loader binary
    if 'wine64' in deb_paths:
        print("  Extracting wine64 loader...")
        files = extract_files_from_deb(deb_paths['wine64'][1], [
            ("usr/lib/wine/wine64", "bin/wine64"),
        ], SYSROOT)
        all_extracted.update(files)

    # From libwine package: ntdll.so
    if 'libwine' in deb_paths:
        print("  Extracting ntdll.so...")
        files = extract_files_from_deb(deb_paths['libwine'][1], [
            ("usr/lib/x86_64-linux-gnu/wine/x86_64-unix/ntdll.so", "bin/ntdll.so"),
            # Also try alternative paths
            ("x86_64-unix/ntdll.so", "bin/ntdll.so"),
        ], SYSROOT)
        all_extracted.update(files)

    # From libunwind8 package: libunwind.so.8
    if 'libunwind8' in deb_paths:
        print("  Extracting libunwind.so.8...")
        files = extract_files_from_deb(deb_paths['libunwind8'][1], [
            ("usr/lib/x86_64-linux-gnu/libunwind.so.8", "lib/libunwind.so.8"),
            ("usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8", "lib/libunwind-x86_64.so.8"),
        ], SYSROOT)
        all_extracted.update(files)

    # Copy existing glibc files from project root
    import shutil
    for fname, dest in [
        ("ld-linux-x86-64.so.2", "lib/ld-linux-x86-64.so.2"),
        ("libc.so.6", "lib/libc.so.6"),
        ("libgcc_s.so.1", "lib/libgcc_s.so.1"),
    ]:
        src = os.path.join(".", fname)
        if os.path.isfile(src):
            dst = os.path.join(SYSROOT, dest)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            all_extracted[dest] = os.path.getsize(src)
            print(f"  Copied {fname} -> {dest} ({os.path.getsize(src):,} bytes)")

    # Also ensure lib64 symlink equivalent
    lib64_dir = os.path.join(SYSROOT, "lib64")
    os.makedirs(lib64_dir, exist_ok=True)
    ld_src = os.path.join(SYSROOT, "lib/ld-linux-x86-64.so.2")
    ld_dst = os.path.join(lib64_dir, "ld-linux-x86-64.so.2")
    if os.path.isfile(ld_src) and not os.path.isfile(ld_dst):
        shutil.copy2(ld_src, ld_dst)

    # Summary
    print(f"\n  Sysroot contents ({SYSROOT}):")
    for root, dirs, files in os.walk(SYSROOT):
        for fname in sorted(files):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, SYSROOT).replace('\\', '/')
            sz = os.path.getsize(full)
            print(f"    /{rel}: {sz:,} bytes")

    # Verify we have the critical files
    critical = ["bin/wine64", "bin/ntdll.so", "lib/ld-linux-x86-64.so.2", "lib/libc.so.6"]
    missing = [f for f in critical if not os.path.isfile(os.path.join(SYSROOT, f))]
    if missing:
        print(f"\n  WARNING: Missing critical files: {missing}")
        print("  wine64 --version will not work without these.")
    else:
        print(f"\n  All critical files present!")

    # Step 4: Create disk image
    if args.disk:
        print(f"\n[4/4] Creating disk image...")
        import subprocess

        # Create tarball from sysroot
        sysroot_tar = "target/wine-sysroot.tar.gz"
        print(f"  Creating tarball: {sysroot_tar}")
        with tarfile.open(sysroot_tar, 'w:gz') as tf:
            for root, dirs, files in os.walk(SYSROOT):
                for d in sorted(dirs):
                    full = os.path.join(root, d)
                    arcname = os.path.relpath(full, SYSROOT).replace('\\', '/')
                    tf.add(full, arcname=arcname, recursive=False)
                for f in sorted(files):
                    full = os.path.join(root, f)
                    arcname = os.path.relpath(full, SYSROOT).replace('\\', '/')
                    tf.add(full, arcname=arcname)

        cmd = [
            sys.executable, "scripts/mkdisk.py",
            "--size", str(args.disk_size),
            "--tarball", sysroot_tar,
        ]
        print(f"  Running: {' '.join(cmd)}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print("  Disk creation failed.")
            return 1

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
