#!/usr/bin/env python3
"""Download Alpine APKs for git with SSL/TLS support and build a sysroot disk for sotOS.

Downloads all Alpine packages needed for `git clone https://...` to work:
git, libcurl, openssl, ca-certificates, and all transitive dependencies.

Uses only Python stdlib (urllib, tarfile, argparse, os, sys).

Usage:
  python scripts/fetch_git_ssl.py                          # download + extract
  python scripts/fetch_git_ssl.py --disk                   # download + extract + create disk
  python scripts/fetch_git_ssl.py --disk-size 1024 --disk  # larger disk
"""

import argparse
import os
import sys
import tarfile
import urllib.request

# Alpine configuration
ALPINE_VERSION = "3.21"
ALPINE_RELEASE = "3.21.3"
ALPINE_MIRROR = f"https://dl-cdn.alpinelinux.org/alpine/v{ALPINE_VERSION}"
ALPINE_ROOTFS_URL = (
    f"{ALPINE_MIRROR}/releases/x86_64/"
    f"alpine-minirootfs-{ALPINE_RELEASE}-x86_64.tar.gz"
)

# Paths
APK_CACHE = "target/apk-cache"
SYSROOT = "target/git-ssl-sysroot"
ALPINE_OUT = "target/alpine.tar.gz"

# All APK packages needed for git with SSL/TLS
GIT_SSL_APKS = [
    # Core
    "git",
    "curl",
    "libcurl",
    # TLS
    "libssl3",
    "libcrypto3",
    "ca-certificates-bundle",
    # libcurl dependencies
    "nghttp2-libs",
    "brotli-libs",
    "c-ares",
    "libidn2",
    "libunistring",
    "zstd-libs",
    "libpsl",
    # Common dependencies
    "pcre2",
    "zlib",
    # musl libc (needed for dynamic linking)
    "musl",
]

# Critical files that must exist after extraction
CRITICAL_FILES = [
    ("usr/bin/git", "usr/libexec/git-core/git"),
    ("usr/lib/libcurl.so.4",),
    ("usr/lib/libssl.so.3", "lib/libssl.so.3"),
    ("usr/lib/libcrypto.so.3", "lib/libcrypto.so.3"),
    ("etc/ssl/certs/ca-certificates.crt",),
]


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
        req = urllib.request.Request(url, headers={"User-Agent": "sotOS-fetch/1.0"})
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
    Symlinks are resolved by copying target data (sotOS VFS doesn't
    support symlinks).
    """
    total_files = 0
    total_bytes = 0

    with tarfile.open(apk_path, 'r:gz') as tf:
        # Build member map for symlink resolution
        member_map = {}
        for m in tf.getmembers():
            key = m.name.lstrip('./')
            if key:
                member_map[key] = m

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
                # Resolve symlink -- copy target data if available
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
                    # Target not in this APK -- check if already extracted
                    # to sysroot (from a previously extracted APK)
                    resolved_sysroot = os.path.join(sysroot_dir, resolved)
                    if os.path.isfile(resolved_sysroot):
                        import shutil
                        shutil.copy2(resolved_sysroot, out_path)
                        total_files += 1
                        total_bytes += os.path.getsize(out_path)
                    else:
                        # Store symlink target as text for later resolution
                        with open(out_path, 'wb') as out:
                            out.write(target.encode('utf-8'))
                        total_files += 1
                continue

            if member.islnk():
                # Hard link -- resolve target
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


def extract_musl_from_rootfs(tarball_path, sysroot_dir):
    """Extract musl dynamic linker and libc from Alpine minirootfs.

    We need ld-musl-x86_64.so.1 and libc.musl-x86_64.so.1 for
    dynamically-linked Alpine binaries.
    """
    if not os.path.isfile(tarball_path):
        print(f"  Error: {tarball_path} not found")
        return False

    print(f"  Extracting musl dynamic linker from: {tarball_path}")

    wanted_prefixes = ("lib/ld-musl", "lib/libc.musl")
    total_files = 0

    with tarfile.open(tarball_path, 'r:gz') as tf:
        member_map = {m.name.lstrip('./'): m for m in tf.getmembers()}

        for member in tf.getmembers():
            path = member.name.lstrip('./')
            if not path:
                continue

            if not any(path.startswith(p) for p in wanted_prefixes):
                continue

            out_path = os.path.join(sysroot_dir, path)

            if member.issym():
                # Resolve symlink
                target = member.linkname
                if not target.startswith('/'):
                    resolved = os.path.normpath(
                        os.path.join(os.path.dirname(path), target))
                else:
                    resolved = target.lstrip('/')

                tm = member_map.get(resolved)
                if tm and tm.isfile():
                    fobj = tf.extractfile(tm)
                    if fobj:
                        data = fobj.read()
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        with open(out_path, 'wb') as fout:
                            fout.write(data)
                        total_files += 1
                        sz = len(data)
                        print(f"    /{path}: {sz:,} bytes (resolved symlink -> {target})")
                        continue

            if member.isfile():
                fobj = tf.extractfile(member)
                if fobj:
                    data = fobj.read()
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, 'wb') as fout:
                        fout.write(data)
                    total_files += 1
                    print(f"    /{path}: {len(data):,} bytes")

    print(f"  Extracted {total_files} musl files")
    return True


def resolve_broken_symlinks(sysroot_dir):
    """Post-extraction pass: fix symlink files that were stored as text.

    When extracting APKs, if a symlink target wasn't in the same APK,
    we stored the target path as text content. Now that all APKs are
    extracted, we can resolve these by copying the real target file.
    """
    import shutil
    fixed = 0

    for root, dirs, files in os.walk(sysroot_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            sz = os.path.getsize(fpath)
            # Symlink text files are small (just a relative path)
            if sz > 256 or sz == 0:
                continue
            # Only fix .so files and binaries
            if '.so' not in fname and '/bin/' not in fpath.replace('\\', '/'):
                continue

            try:
                with open(fpath, 'r') as f:
                    target = f.read().strip()
            except Exception:
                continue

            # Looks like a symlink target? (relative path, no spaces, short)
            if not target or ' ' in target or len(target) > 200:
                continue
            if '\x00' in target:
                continue

            # Resolve relative to file's directory
            if not target.startswith('/'):
                resolved = os.path.normpath(os.path.join(
                    os.path.dirname(fpath), target))
            else:
                resolved = os.path.join(sysroot_dir, target.lstrip('/'))

            if os.path.isfile(resolved) and os.path.getsize(resolved) > 256:
                shutil.copy2(resolved, fpath)
                fixed += 1

    if fixed:
        print(f"  Resolved {fixed} broken symlinks (cross-APK references)")


def setup_etc(sysroot_dir):
    """Create /etc configuration files needed for git + TLS."""
    # /etc/resolv.conf for QEMU SLIRP DNS
    etc_dir = os.path.join(sysroot_dir, "etc")
    os.makedirs(etc_dir, exist_ok=True)

    resolv_path = os.path.join(etc_dir, "resolv.conf")
    with open(resolv_path, 'w') as f:
        f.write("nameserver 10.0.2.3\n")
    print(f"  Created /etc/resolv.conf (QEMU SLIRP DNS)")

    # Ensure /etc/ssl/certs/ directory exists for CA certificates
    ssl_certs_dir = os.path.join(sysroot_dir, "etc", "ssl", "certs")
    os.makedirs(ssl_certs_dir, exist_ok=True)

    # Also create /etc/ssl pointing structure
    ssl_dir = os.path.join(sysroot_dir, "etc", "ssl")
    os.makedirs(ssl_dir, exist_ok=True)

    # Git needs these
    passwd_path = os.path.join(etc_dir, "passwd")
    if not os.path.exists(passwd_path):
        with open(passwd_path, 'w') as f:
            f.write("root:x:0:0:root:/root:/bin/sh\n")
        print(f"  Created /etc/passwd")

    group_path = os.path.join(etc_dir, "group")
    if not os.path.exists(group_path):
        with open(group_path, 'w') as f:
            f.write("root:x:0:\n")
        print(f"  Created /etc/group")


def verify_critical_files(sysroot_dir):
    """Verify that critical files exist in the sysroot. Return True if all found."""
    print("\n  Verifying critical files:")
    all_ok = True

    for alternatives in CRITICAL_FILES:
        found = False
        for path in alternatives:
            # Also check with glob-like matching for versioned .so files
            full = os.path.join(sysroot_dir, path)
            if os.path.isfile(full):
                sz = os.path.getsize(full)
                print(f"    OK  /{path} ({sz:,} bytes)")
                found = True
                break
            # Try glob for wildcard paths like libssl.so.*
            if '*' not in path:
                parent = os.path.dirname(full)
                base = os.path.basename(full)
                if os.path.isdir(parent):
                    for f in os.listdir(parent):
                        if f.startswith(base.rstrip('*')):
                            real = os.path.join(parent, f)
                            sz = os.path.getsize(real)
                            print(f"    OK  /{os.path.relpath(real, sysroot_dir).replace(chr(92), '/')} ({sz:,} bytes)")
                            found = True
                            break
            if found:
                break

        if not found:
            print(f"    MISSING  {' or '.join(alternatives)}")
            all_ok = False

    return all_ok


def print_summary(sysroot_dir):
    """Print summary of extracted sysroot contents."""
    print("\n  Sysroot contents summary:")

    categories = {
        "Binaries": [],
        "Shared libraries": [],
        "CA certificates": [],
        "Config files": [],
    }

    for root, dirs, files in os.walk(sysroot_dir):
        for fname in sorted(files):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, sysroot_dir).replace('\\', '/')
            sz = os.path.getsize(full)

            if '/bin/' in rel or '/libexec/' in rel:
                categories["Binaries"].append((rel, sz))
            elif '.so' in fname:
                categories["Shared libraries"].append((rel, sz))
            elif 'ssl' in rel or 'cert' in rel:
                categories["CA certificates"].append((rel, sz))
            elif rel.startswith('etc/'):
                categories["Config files"].append((rel, sz))

    for cat, items in categories.items():
        if not items:
            continue
        print(f"\n  {cat} ({len(items)} files):")
        # Show up to 30 items per category, summarize rest
        show = items[:30]
        for rel, sz in show:
            print(f"    /{rel}: {sz:,} bytes")
        if len(items) > 30:
            print(f"    ... and {len(items) - 30} more")

    # Total size
    total_size = 0
    total_count = 0
    for root, dirs, files in os.walk(sysroot_dir):
        for f in files:
            total_size += os.path.getsize(os.path.join(root, f))
            total_count += 1
    print(f"\n  Total: {total_count} files, {total_size / (1024*1024):.1f} MiB")


def fetch_apk_packages(pkg_names, sysroot_dir):
    """Download and extract a list of APK packages into sysroot."""
    print("\n  Resolving APK package versions...")
    pkg_map = download_apkindex("main")
    if not pkg_map:
        print("  Error: could not download/parse APKINDEX")
        return False

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
            print(f"    [SKIP] {name} -- not found in APKINDEX")
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
        description="Download Alpine APKs for git with SSL/TLS and build sysroot for sotOS")
    parser.add_argument("--disk", action="store_true",
                        help="Also create disk image via mkdisk.py")
    parser.add_argument("--disk-size", type=int, default=512,
                        help="Disk size in MiB when --disk is used (default: 512)")
    args = parser.parse_args()

    print("=== sotOS Git+SSL Sysroot Builder ===\n")

    steps = 5 + (1 if args.disk else 0)
    step = 0

    # Step 1: Download Alpine minirootfs (for musl dynamic linker)
    step += 1
    print(f"[{step}/{steps}] Downloading Alpine Mini RootFS (musl dynamic linker)...")
    if not download(ALPINE_ROOTFS_URL, ALPINE_OUT):
        print("  Failed to download Alpine rootfs.")
        return 1

    # Step 2: Download and extract APK packages
    step += 1
    print(f"\n[{step}/{steps}] Downloading APK packages for git+SSL...")
    print(f"  Packages: {', '.join(GIT_SSL_APKS)}")
    if not fetch_apk_packages(GIT_SSL_APKS, SYSROOT):
        print("  Warning: some packages were not found (continuing anyway)")

    # Step 3: Extract musl dynamic linker from rootfs
    step += 1
    print(f"\n[{step}/{steps}] Extracting musl dynamic linker from rootfs...")
    extract_musl_from_rootfs(ALPINE_OUT, SYSROOT)

    # Step 4: Resolve broken symlinks and set up /etc
    step += 1
    print(f"\n[{step}/{steps}] Post-extraction fixups...")
    resolve_broken_symlinks(SYSROOT)
    setup_etc(SYSROOT)

    # Step 5: Verify and summarize
    step += 1
    print(f"\n[{step}/{steps}] Verification...")
    ok = verify_critical_files(SYSROOT)
    print_summary(SYSROOT)

    if not ok:
        print("\n  WARNING: Some critical files are missing!")
        print("  git clone https:// may not work correctly.")

    # Step 6 (optional): Create disk image
    if args.disk:
        step += 1
        import subprocess
        print(f"\n[{step}/{steps}] Creating disk image...")

        # Build tarball from sysroot
        sysroot_tar = "target/git-ssl-sysroot.tar.gz"
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

        tar_sz = os.path.getsize(sysroot_tar)
        print(f"  Tarball: {tar_sz / (1024*1024):.1f} MiB")

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
        print(f"  Disk image created: target/disk.img ({args.disk_size} MiB)")

    print(f"\nDone. Sysroot at: {SYSROOT}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
