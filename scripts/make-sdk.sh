#!/usr/bin/env bash
# Sprint 3 -- build an exportable sotBSD SDK tarball.
#
# The SDK lets a third party link their own component against the
# frozen sotBSD ABI (see docs/ABI_v0.1.0.md) without needing to clone
# the whole repo. It contains:
#
#   - target/sotos.img          bootable 512 MiB QEMU image
#   - kernel/sotos-kernel.elf   raw kernel ELF for gdb
#   - abi/sotos-common/         frozen ABI crate (source)
#   - abi/ABI_v0.1.0.md         frozen ABI reference document
#   - docs/                     architecture + SOT spec + sprint status
#   - VERSION                   the ABI version string
#   - README                    quick start
#
# Output: target/sotbsd-sdk-v<ABI_VERSION>.tar.gz

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

ABI_VERSION=$(grep -E 'pub const ABI_VERSION' libs/sotos-common/src/lib.rs \
              | head -1 \
              | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$ABI_VERSION" ]; then
    echo "make-sdk: could not parse ABI_VERSION from sotos-common/src/lib.rs" >&2
    exit 1
fi

SDK_NAME="sotbsd-sdk-v${ABI_VERSION}"
SDK_DIR="target/${SDK_NAME}"
SDK_TAR="target/${SDK_NAME}.tar.gz"

rm -rf "$SDK_DIR" "$SDK_TAR"
mkdir -p "$SDK_DIR/kernel" "$SDK_DIR/abi/sotos-common" "$SDK_DIR/docs"

# -- bootable image --------------------------------------------------------
if [ ! -f target/sotos.img ]; then
    echo "make-sdk: target/sotos.img missing -- run 'just image' first" >&2
    exit 1
fi
cp target/sotos.img "$SDK_DIR/"

# -- raw kernel ELF (for gdb) ---------------------------------------------
if [ -f target/x86_64-unknown-none/debug/sotos-kernel ]; then
    cp target/x86_64-unknown-none/debug/sotos-kernel "$SDK_DIR/kernel/sotos-kernel.elf"
fi

# -- ABI crate: source + Cargo.toml ----------------------------------------
cp -r libs/sotos-common/src "$SDK_DIR/abi/sotos-common/"
cp    libs/sotos-common/Cargo.toml "$SDK_DIR/abi/sotos-common/"

# -- docs ------------------------------------------------------------------
for d in ABI_v0.1.0.md ARCHITECTURE.md SOT_SPEC.md SPRINT1_STATUS.md SPRINT2_STATUS.md SPRINT3_STATUS.md; do
    if [ -f "docs/$d" ]; then
        cp "docs/$d" "$SDK_DIR/docs/"
    fi
done
if [ -f docs/ABI_v0.1.0.md ]; then
    cp docs/ABI_v0.1.0.md "$SDK_DIR/abi/ABI_v0.1.0.md"
fi

# -- version + readme ------------------------------------------------------
echo "$ABI_VERSION" > "$SDK_DIR/VERSION"
cat > "$SDK_DIR/README" <<EOF
sotBSD SDK v${ABI_VERSION}
==========================

This tarball bundles the frozen sotBSD ABI plus a bootable image.
It is produced by \`just sdk\` / \`scripts/make-sdk.sh\` from the
public sotBSD source tree.

Contents:

  sotos.img              -- 512 MiB bootable disk image
  kernel/                -- raw kernel ELF (sotos-kernel.elf) for gdb
  abi/sotos-common/      -- the frozen ABI Rust crate you link against
  abi/ABI_v0.1.0.md      -- authoritative ABI reference document
  docs/                  -- architecture + sprint status reports
  VERSION                -- the ABI version string

Quick start:

  1. Boot the image:
       qemu-system-x86_64 -cpu max -drive format=raw,file=sotos.img \\
           -serial stdio -display none -no-reboot -m 2048M

  2. Build your own component against the frozen ABI:
       cd your-service
       cargo add --path ../abi/sotos-common
       # see abi/ABI_v0.1.0.md for the syscall + struct contract

ABI stability:

  * Minor bumps (0.1.0 -> 0.2.0) are additive.
  * Major bumps (0.1.0 -> 1.0.0) are breaking.
  * The CI gate at .github/workflows/ci.yml enforces ABI_VERSION
    matching docs/ABI_v0.1.0.md at every push.
EOF

# -- tarball ---------------------------------------------------------------
tar -czf "$SDK_TAR" -C target "$SDK_NAME"
rm -rf "$SDK_DIR"

size=$(wc -c < "$SDK_TAR")
printf "make-sdk: wrote %s (%s bytes)\n" "$SDK_TAR" "$size"
