#!/usr/bin/env python3
"""Download Alpine Mini RootFS and extract shared libraries for sotX sysroot.

Downloads the Alpine minirootfs tarball and extracts .so files into
target/sysroot/{lib,usr/lib}. Also supports creating a disk image with
the sysroot injected via mkdisk.py --tarball.

Can also download and extract Alpine APK packages (e.g. Python 3):
  python scripts/fetch_rootfs.py --python --disk

Uses only Python stdlib (urllib, tarfile).

Usage:
  python scripts/fetch_rootfs.py                  # download + extract sysroot
  python scripts/fetch_rootfs.py --extract-only    # extract from cached tarball
  python scripts/fetch_rootfs.py --disk            # download + extract + create disk
  python scripts/fetch_rootfs.py --python --disk   # + Python 3 APK packages
  python scripts/fetch_rootfs.py --apk python3 --apk libffi --disk
"""

import argparse
import os
import sys
import tarfile
import urllib.request

# Alpine Mini RootFS (musl, ~3MB)
ALPINE_VERSION = "3.21"
ALPINE_RELEASE = "3.21.3"
ALPINE_MIRROR = f"https://dl-cdn.alpinelinux.org/alpine/v{ALPINE_VERSION}"
ALPINE_URL = (
    f"{ALPINE_MIRROR}/releases/x86_64/"
    f"alpine-minirootfs-{ALPINE_RELEASE}-x86_64.tar.gz"
)
ALPINE_OUT = "target/alpine.tar.gz"
SYSROOT = "target/sysroot"
APK_CACHE = "target/apk-cache"

# Ubuntu Base RootFS (glibc, ~30MB compressed)
UBUNTU_CODENAME = "noble"  # 24.04 LTS
UBUNTU_URL = (
    f"http://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/"
    f"ubuntu-base-24.04.2-base-amd64.tar.gz"
)
UBUNTU_OUT = "target/ubuntu-base.tar.gz"

# Packages needed for Python 3 interpreter
PYTHON_APKS = [
    "python3",
    "libffi",
    "gdbm",
    "xz-libs",
    "mpdecimal",
    "readline",
    "sqlite-libs",
    "libbz2",
    "expat",
    "ncurses-libs",
    "ncurses-terminfo-base",
    "libuuid",
]

# Patterns for files to extract from the rootfs
EXTRACT_PATTERNS = (
    "lib/",        # /lib/*.so* (musl libc, ld-musl)
    "usr/lib/",    # /usr/lib/*.so*
    "etc/",        # /etc/resolv.conf, passwd, group, etc.
)

# File extensions to extract (shared libs + key config)
SO_EXTENSIONS = (".so", ".so.", ".conf", ".cfg")


def download(url, output_path):
    """Download a file with progress indication."""
    if os.path.isfile(output_path):
        size = os.path.getsize(output_path)
        print(f"  Already exists: {output_path} ({size:,} bytes) -- skipping")
        return True

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    print(f"  Downloading: {url}")
    print(f"  Target: {output_path}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sotX-fetch/1.0"})
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
                        mb = downloaded / (1024 * 1024)
                        sys.stdout.write(f"\r  {mb:.1f} MiB ({pct}%)")
                        sys.stdout.flush()

            print(f"\r  Downloaded: {downloaded:,} bytes")

        os.replace(output_path + ".tmp", output_path)
        return True

    except Exception as e:
        print(f"\n  Error: {e}")
        tmp = output_path + ".tmp"
        if os.path.exists(tmp):
            os.remove(tmp)
        return False


def is_shared_lib(name):
    """Check if a filename looks like a shared library."""
    base = os.path.basename(name)
    return ".so" in base


def extract_sysroot(tarball_path, sysroot_dir):
    """Extract shared libraries and key files from Alpine rootfs tarball."""
    if not os.path.isfile(tarball_path):
        print(f"  Error: {tarball_path} not found")
        return False

    print(f"  Extracting from: {tarball_path}")
    print(f"  Sysroot: {sysroot_dir}")

    total_files = 0
    total_bytes = 0
    total_libs = 0

    with tarfile.open(tarball_path, 'r:gz') as tf:
        for member in tf.getmembers():
            path = member.name.lstrip('./')
            if not path:
                continue

            # Extract shared libraries from lib/ and usr/lib/
            extract = False
            if path.startswith("lib/") or path.startswith("usr/lib/"):
                if member.isdir():
                    extract = True
                elif is_shared_lib(path):
                    extract = True
            # Extract /etc config files
            elif path.startswith("etc/"):
                if member.isfile() and member.size < 4096:
                    extract = True
                elif member.isdir():
                    extract = True

            if not extract:
                continue

            out_path = os.path.join(sysroot_dir, path)

            if member.isdir():
                os.makedirs(out_path, exist_ok=True)
                continue

            if member.issym():
                # Resolve symlink: try to extract target from tarball
                target = member.linkname
                if not target.startswith('/'):
                    link_dir = os.path.dirname(path)
                    resolved = os.path.normpath(os.path.join(link_dir, target))
                else:
                    resolved = target.lstrip('/')

                # Try to extract the target file
                try:
                    for try_name in [resolved, './' + resolved]:
                        try:
                            target_member = tf.getmember(try_name)
                            if target_member.isfile():
                                f = tf.extractfile(target_member)
                                if f:
                                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                                    data = f.read()
                                    with open(out_path, 'wb') as out:
                                        out.write(data)
                                    total_files += 1
                                    total_bytes += len(data)
                                    if is_shared_lib(path):
                                        total_libs += 1
                                    break
                        except KeyError:
                            continue
                except Exception:
                    pass
                continue

            if not member.isfile():
                continue

            f = tf.extractfile(member)
            if f is None:
                continue

            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            data = f.read()
            with open(out_path, 'wb') as out:
                out.write(data)
            total_files += 1
            total_bytes += len(data)
            if is_shared_lib(path):
                total_libs += 1

    print(f"  Extracted: {total_files} files ({total_libs} shared libs), "
          f"{total_bytes:,} bytes")

    # List shared libs
    print(f"\n  Shared libraries in sysroot:")
    for root, dirs, files in os.walk(sysroot_dir):
        for fname in sorted(files):
            if is_shared_lib(fname):
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, sysroot_dir)
                sz = os.path.getsize(full)
                print(f"    /{rel.replace(os.sep, '/')}: {sz:,} bytes")

    return True


def parse_apkindex(index_path):
    """Parse APKINDEX to map package name -> version.

    APKINDEX is a tar.gz containing an APKINDEX file with blocks like:
      C:Q1...
      P:python3
      V:3.12.9-r0
      D:libffi gdbm ...
      (blank line)
    Returns dict: {name: version}
    """
    pkgs = {}
    with tarfile.open(index_path, 'r:gz') as tf:
        for member in tf.getmembers():
            if member.name == 'APKINDEX':
                f = tf.extractfile(member)
                if not f:
                    continue
                text = f.read().decode('utf-8', errors='replace')
                name = None
                version = None
                for line in text.split('\n'):
                    if line.startswith('P:'):
                        name = line[2:].strip()
                    elif line.startswith('V:'):
                        version = line[2:].strip()
                    elif line == '':
                        if name and version:
                            pkgs[name] = version
                        name = None
                        version = None
                # Last block
                if name and version:
                    pkgs[name] = version
    return pkgs


def download_apkindex(repo="main"):
    """Download APKINDEX.tar.gz for a repo, return parsed package map."""
    url = f"{ALPINE_MIRROR}/{repo}/x86_64/APKINDEX.tar.gz"
    out = os.path.join(APK_CACHE, f"APKINDEX-{repo}.tar.gz")
    os.makedirs(APK_CACHE, exist_ok=True)

    # Always re-download APKINDEX (it's small, ~200KB)
    print(f"  Fetching APKINDEX for {repo}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sotX-fetch/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        with open(out, 'wb') as f:
            f.write(data)
        print(f"  Downloaded APKINDEX: {len(data):,} bytes")
    except Exception as e:
        # Use cached if available
        if os.path.isfile(out):
            print(f"  Warning: fresh download failed ({e}), using cached APKINDEX")
        else:
            print(f"  Error downloading APKINDEX: {e}")
            return {}

    return parse_apkindex(out)


def download_apk(pkg_name, version, repo="main"):
    """Download a single APK package. Returns path to downloaded file or None."""
    filename = f"{pkg_name}-{version}.apk"
    url = f"{ALPINE_MIRROR}/{repo}/x86_64/{filename}"
    out = os.path.join(APK_CACHE, filename)

    if os.path.isfile(out):
        sz = os.path.getsize(out)
        print(f"    Cached: {filename} ({sz:,} bytes)")
        return out

    if not download(url, out):
        return None
    return out


def extract_apk(apk_path, sysroot_dir):
    """Extract an APK package into the sysroot.

    APK files are .tar.gz archives. We skip Alpine metadata files
    (.PKGINFO, .SIGN.*, .pre-install, .post-install, .trigger).
    """
    total_files = 0
    total_bytes = 0

    with tarfile.open(apk_path, 'r:gz') as tf:
        for member in tf.getmembers():
            path = member.name.lstrip('./')
            if not path:
                continue

            # Skip APK metadata
            base = os.path.basename(path)
            if base.startswith('.PKGINFO') or base.startswith('.SIGN') \
               or base.startswith('.pre-') or base.startswith('.post-') \
               or base.startswith('.trigger'):
                continue

            out_path = os.path.join(sysroot_dir, path)

            if member.isdir():
                os.makedirs(out_path, exist_ok=True)
                continue

            if member.issym():
                # Resolve symlink — copy target data if available
                target = member.linkname
                if not target.startswith('/'):
                    link_dir = os.path.dirname(path)
                    resolved = os.path.normpath(os.path.join(link_dir, target))
                else:
                    resolved = target.lstrip('/')
                resolved = resolved.replace('\\', '/')

                # Try to find target in this APK
                target_data = None
                for try_path in [resolved, './' + resolved]:
                    try:
                        tm = tf.getmember(try_path)
                        if tm.isfile():
                            fobj = tf.extractfile(tm)
                            if fobj:
                                target_data = fobj.read()
                                break
                    except KeyError:
                        continue

                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                if target_data is not None:
                    with open(out_path, 'wb') as out:
                        out.write(target_data)
                    total_files += 1
                    total_bytes += len(target_data)
                else:
                    # Store symlink target as file content (will be resolved on disk)
                    with open(out_path, 'wb') as out:
                        out.write(target.encode('utf-8'))
                    total_files += 1
                continue

            if member.islnk():
                # Hard link — resolve target
                target = member.linkname.lstrip('./')
                for try_path in [target, './' + target]:
                    try:
                        tm = tf.getmember(try_path)
                        if tm.isfile():
                            fobj = tf.extractfile(tm)
                            if fobj:
                                data = fobj.read()
                                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                                with open(out_path, 'wb') as out:
                                    out.write(data)
                                total_files += 1
                                total_bytes += len(data)
                                break
                    except KeyError:
                        continue
                continue

            if not member.isfile():
                continue

            fobj = tf.extractfile(member)
            if fobj is None:
                continue

            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            data = fobj.read()
            with open(out_path, 'wb') as out:
                out.write(data)
            total_files += 1
            total_bytes += len(data)

    return total_files, total_bytes


def extract_ubuntu(tarball_path, sysroot_dir):
    """Extract glibc dynamic linker, core libs, and test binaries from Ubuntu rootfs."""
    if not os.path.isfile(tarball_path):
        print(f"  Error: {tarball_path} not found")
        return False

    print(f"  Extracting Ubuntu glibc sysroot from: {tarball_path}")

    # Files/dirs we want from Ubuntu
    UBUNTU_EXTRACT = {
        # Dynamic linker (Ubuntu 24.04 uses usr/lib paths)
        "usr/lib64/ld-linux-x86-64.so.2",
        "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "lib64/ld-linux-x86-64.so.2",
        "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        # Core glibc libs
        "usr/lib/x86_64-linux-gnu/libc.so.6",
        "usr/lib/x86_64-linux-gnu/libm.so.6",
        "usr/lib/x86_64-linux-gnu/libdl.so.2",
        "usr/lib/x86_64-linux-gnu/libpthread.so.0",
        "usr/lib/x86_64-linux-gnu/librt.so.1",
        "usr/lib/x86_64-linux-gnu/libresolv.so.2",
        "usr/lib/x86_64-linux-gnu/libnss_dns.so.2",
        "usr/lib/x86_64-linux-gnu/libnss_files.so.2",
        "usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
        "lib/x86_64-linux-gnu/libc.so.6",
        "lib/x86_64-linux-gnu/libm.so.6",
    }
    # Also extract any .so* from these dirs
    UBUNTU_PREFIXES = (
        "usr/lib/x86_64-linux-gnu/",
        "lib/x86_64-linux-gnu/",
        "usr/lib64/",
        "lib64/",
    )
    # Test binaries (save with _ubuntu suffix to avoid collisions)
    UBUNTU_BINS = {
        "usr/bin/ls": "usr/bin/ls_ubuntu",
        "bin/ls": "usr/bin/ls_ubuntu",
        "usr/bin/echo": "usr/bin/echo_ubuntu",
        "bin/echo": "usr/bin/echo_ubuntu",
        "usr/bin/cat": "usr/bin/cat_ubuntu",
        "bin/cat": "usr/bin/cat_ubuntu",
    }

    total_files = 0
    total_bytes = 0

    with tarfile.open(tarball_path, 'r:gz') as tf:
        members = tf.getmembers()

        # First pass: collect all member names for symlink resolution
        member_map = {m.name.lstrip('./'): m for m in members}

        for member in members:
            path = member.name.lstrip('./')
            if not path:
                continue

            # Determine output path and whether to extract
            out_rel = None

            # Check for test binaries (renamed)
            if path in UBUNTU_BINS:
                out_rel = UBUNTU_BINS[path]
            # Check for exact match files
            elif path in UBUNTU_EXTRACT:
                out_rel = path
            # Check for shared libs under lib/x86_64-linux-gnu/
            elif any(path.startswith(p) for p in UBUNTU_PREFIXES):
                if member.isdir():
                    os.makedirs(os.path.join(sysroot_dir, path), exist_ok=True)
                    continue
                if '.so' in os.path.basename(path):
                    out_rel = path

            if out_rel is None:
                continue

            out_path = os.path.join(sysroot_dir, out_rel)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            if member.issym():
                # Resolve symlink
                target = member.linkname
                if not target.startswith('/'):
                    resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
                else:
                    resolved = target.lstrip('/')

                target_member = member_map.get(resolved)
                if target_member and target_member.isfile():
                    fobj = tf.extractfile(target_member)
                    if fobj:
                        data = fobj.read()
                        with open(out_path, 'wb') as out:
                            out.write(data)
                        total_files += 1
                        total_bytes += len(data)
                        continue

                # If target is also a symlink, chase one more level
                if target_member and target_member.issym():
                    t2 = target_member.linkname
                    if not t2.startswith('/'):
                        resolved2 = os.path.normpath(os.path.join(os.path.dirname(resolved), t2))
                    else:
                        resolved2 = t2.lstrip('/')
                    tm2 = member_map.get(resolved2)
                    if tm2 and tm2.isfile():
                        fobj = tf.extractfile(tm2)
                        if fobj:
                            data = fobj.read()
                            with open(out_path, 'wb') as out:
                                out.write(data)
                            total_files += 1
                            total_bytes += len(data)
                            continue

                # Fallback: store symlink target as content
                with open(out_path, 'wb') as out:
                    out.write(target.encode('utf-8'))
                total_files += 1
                continue

            if member.islnk():
                # Hard link
                target = member.linkname.lstrip('./')
                tm = member_map.get(target)
                if tm and tm.isfile():
                    fobj = tf.extractfile(tm)
                    if fobj:
                        data = fobj.read()
                        with open(out_path, 'wb') as out:
                            out.write(data)
                        total_files += 1
                        total_bytes += len(data)
                continue

            if not member.isfile():
                continue

            fobj = tf.extractfile(member)
            if fobj is None:
                continue

            data = fobj.read()
            with open(out_path, 'wb') as out:
                out.write(data)
            total_files += 1
            total_bytes += len(data)

    print(f"  Ubuntu extracted: {total_files} files, {total_bytes:,} bytes")

    # Post-extraction fixup: ensure /lib64/ld-linux-x86-64.so.2 is the real binary
    # (Ubuntu stores it under usr/lib/x86_64-linux-gnu/ and /lib64/ is a symlink)
    import shutil
    real_ld = os.path.join(sysroot_dir, "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    for link_path in [
        os.path.join(sysroot_dir, "lib64/ld-linux-x86-64.so.2"),
        os.path.join(sysroot_dir, "usr/lib64/ld-linux-x86-64.so.2"),
        os.path.join(sysroot_dir, "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    ]:
        if os.path.isfile(real_ld):
            needs_fix = False
            if not os.path.isfile(link_path):
                needs_fix = True
            elif os.path.getsize(link_path) < 1024:
                needs_fix = True
            if needs_fix:
                os.makedirs(os.path.dirname(link_path), exist_ok=True)
                shutil.copy2(real_ld, link_path)
                print(f"  Fixed ld-linux: /{os.path.relpath(link_path, sysroot_dir).replace(chr(92), '/')} -> real ELF ({os.path.getsize(link_path):,} bytes)")

    # Also ensure /lib/x86_64-linux-gnu/libc.so.6 exists (glibc RPATH)
    real_libc = os.path.join(sysroot_dir, "usr/lib/x86_64-linux-gnu/libc.so.6")
    compat_libc = os.path.join(sysroot_dir, "lib/x86_64-linux-gnu/libc.so.6")
    if os.path.isfile(real_libc) and not os.path.isfile(compat_libc):
        os.makedirs(os.path.dirname(compat_libc), exist_ok=True)
        shutil.copy2(real_libc, compat_libc)
        print(f"  Copied libc.so.6 to /lib/x86_64-linux-gnu/ ({os.path.getsize(compat_libc):,} bytes)")

    # Fix broken symlinks: .so files < 256 bytes are text symlink targets
    # Replace them with the actual target file from the same directory
    fixed_count = 0
    for lib_dir in UBUNTU_PREFIXES:
        dir_path = os.path.join(sysroot_dir, lib_dir)
        if not os.path.isdir(dir_path):
            continue
        for root, dirs, files in os.walk(dir_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                if '.so' not in fname:
                    continue
                sz = os.path.getsize(fpath)
                if sz >= 256:
                    continue
                # Read symlink target text
                try:
                    with open(fpath, 'r') as f:
                        target = f.read().strip()
                except Exception:
                    continue
                if not target or '/' in target or not target.endswith('.so') and '.so.' not in target:
                    continue
                # Look for target in same directory
                real_path = os.path.join(root, target)
                if os.path.isfile(real_path) and os.path.getsize(real_path) > 256:
                    shutil.copy2(real_path, fpath)
                    fixed_count += 1
    if fixed_count:
        print(f"  Fixed {fixed_count} broken .so symlinks")

    # List what we got
    for root, dirs, files in os.walk(sysroot_dir):
        for fname in sorted(files):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, sysroot_dir).replace('\\', '/')
            if 'x86_64-linux-gnu' in rel or 'lib64' in rel or '_ubuntu' in rel:
                sz = os.path.getsize(full)
                print(f"    /{rel}: {sz:,} bytes")

    return True


def fetch_apk_packages(pkg_names, sysroot_dir):
    """Download and extract a list of APK packages into sysroot."""
    # Parse APKINDEX to resolve versions
    print("\n  Resolving APK package versions...")
    pkg_map = download_apkindex("main")
    if not pkg_map:
        print("  Error: could not download/parse APKINDEX")
        return False

    # Also check community repo for some packages
    community_map = {}

    grand_files = 0
    grand_bytes = 0
    missing = []

    for name in pkg_names:
        version = pkg_map.get(name)
        repo = "main"
        if not version:
            # Try community repo
            if not community_map:
                community_map = download_apkindex("community")
            version = community_map.get(name)
            repo = "community"

        if not version:
            missing.append(name)
            print(f"    [SKIP] {name} — not found in APKINDEX")
            continue

        print(f"  [{repo}] {name}-{version}")
        apk_path = download_apk(name, version, repo)
        if not apk_path:
            print(f"    [FAIL] Could not download {name}")
            continue

        nfiles, nbytes = extract_apk(apk_path, sysroot_dir)
        grand_files += nfiles
        grand_bytes += nbytes
        print(f"    Extracted: {nfiles} files, {nbytes:,} bytes")

    print(f"\n  APK total: {grand_files} files, {grand_bytes:,} bytes")
    if missing:
        print(f"  Missing packages: {', '.join(missing)}")
    return len(missing) == 0


def main():
    parser = argparse.ArgumentParser(
        description="Download Alpine Mini RootFS and extract sysroot for sotX")
    parser.add_argument("--extract-only", action="store_true",
                        help="Only extract from cached tarball (skip download)")
    parser.add_argument("--disk", action="store_true",
                        help="Also create disk image with sysroot injected")
    parser.add_argument("--disk-size", type=int, default=512,
                        help="Disk size in MiB when --disk is used (default: 512)")
    parser.add_argument("--python", action="store_true",
                        help="Download Python 3 APK packages and dependencies")
    parser.add_argument("--apk", action="append", default=[],
                        help="Additional APK package to download (repeatable)")
    parser.add_argument("--ubuntu", action="store_true",
                        help="Download Ubuntu Base rootfs and extract glibc + test binaries")
    args = parser.parse_args()

    print("=== sotX Sysroot Builder ===\n")

    # Collect APK packages to download
    apk_list = list(args.apk)
    if args.python:
        for pkg in PYTHON_APKS:
            if pkg not in apk_list:
                apk_list.append(pkg)

    steps = 2 + (1 if apk_list else 0) + (1 if args.ubuntu else 0) + (1 if args.disk else 0)
    step = 0

    # Step 1: Download Alpine rootfs
    step += 1
    if not args.extract_only:
        print(f"[{step}/{steps}] Downloading Alpine Mini RootFS...")
        if not download(ALPINE_URL, ALPINE_OUT):
            print("Download failed.")
            return 1
    else:
        if not os.path.isfile(ALPINE_OUT):
            print(f"Error: {ALPINE_OUT} not found. Run without --extract-only first.")
            return 1
        print(f"[{step}/{steps}] Using cached tarball")

    # Step 2: Extract shared libraries
    step += 1
    print(f"\n[{step}/{steps}] Extracting sysroot...")
    if not extract_sysroot(ALPINE_OUT, SYSROOT):
        return 1

    # Step 3 (optional): Download and extract APK packages
    if apk_list:
        step += 1
        print(f"\n[{step}/{steps}] Downloading APK packages: {', '.join(apk_list)}")
        fetch_apk_packages(apk_list, SYSROOT)

    # Step (optional): Download and extract Ubuntu glibc
    if args.ubuntu:
        step += 1
        print(f"\n[{step}/{steps}] Downloading Ubuntu Base rootfs...")
        if not download(UBUNTU_URL, UBUNTU_OUT):
            print("  Ubuntu download failed. Continuing without glibc.")
        else:
            extract_ubuntu(UBUNTU_OUT, SYSROOT)

    # Step (optional): Create disk image
    if args.disk:
        step += 1
        import subprocess
        print(f"\n[{step}/{steps}] Creating disk image with sysroot...")
        # Build tarball from sysroot so mkdisk injects everything
        sysroot_tar = "target/sysroot.tar.gz"
        print(f"  Creating tarball from sysroot: {sysroot_tar}")
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
            "--tarball", ALPINE_OUT,
            "--tarball", sysroot_tar,
        ]
        print(f"  Running: {' '.join(cmd)}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print("  Disk creation failed.")
            return 1

    print(f"\nDone. Sysroot at: {SYSROOT}/")
    if apk_list:
        print(f"APK packages extracted into sysroot.")
    print(f"To create a disk with full rootfs:")
    print(f"  python scripts/mkdisk.py --size 512 --tarball {ALPINE_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
