#!/usr/bin/env python3
"""Download Alpine Mini RootFS and Ubuntu Base RootFS for sotOS sysroot injection.

Downloads to target/ directory. Uses only Python stdlib (urllib).

Usage:
  python scripts/fetch_rootfs.py
"""

import os
import sys
import urllib.request

# Alpine Mini RootFS (musl, ~3MB)
ALPINE_VERSION = "3.21"
ALPINE_RELEASE = "3.21.3"
ALPINE_URL = (
    f"https://dl-cdn.alpinelinux.org/alpine/v{ALPINE_VERSION}/releases/x86_64/"
    f"alpine-minirootfs-{ALPINE_RELEASE}-x86_64.tar.gz"
)
ALPINE_OUT = "target/alpine.tar.gz"

# Ubuntu Base RootFS (glibc, ~30MB)
UBUNTU_CODENAME = "noble"  # 24.04 LTS
UBUNTU_URL = (
    f"http://cdimage.ubuntu.com/ubuntu-base/releases/{UBUNTU_CODENAME}/release/"
    f"ubuntu-base-24.04.2-base-amd64.tar.gz"
)
UBUNTU_OUT = "target/ubuntu-base.tar.gz"


def download(url, output_path):
    """Download a file with progress indication."""
    if os.path.isfile(output_path):
        size = os.path.getsize(output_path)
        print(f"  Already exists: {output_path} ({size:,} bytes) — skipping")
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
        # Clean up partial download
        tmp = output_path + ".tmp"
        if os.path.exists(tmp):
            os.remove(tmp)
        return False


def main():
    print("=== sotOS RootFS Downloader ===")

    print("\n[1/2] Alpine Mini RootFS (musl)")
    ok_alpine = download(ALPINE_URL, ALPINE_OUT)

    print("\n[2/2] Ubuntu Base RootFS (glibc)")
    ok_ubuntu = download(UBUNTU_URL, UBUNTU_OUT)

    print()
    if ok_alpine and ok_ubuntu:
        print("All rootfs downloaded successfully.")
        return 0
    else:
        print("Some downloads failed. Check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
