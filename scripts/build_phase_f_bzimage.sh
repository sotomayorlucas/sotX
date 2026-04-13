#!/bin/bash
# build_phase_f_bzimage.sh — compile a tiny Linux bzImage for Phase F
#
# Run this ONCE from WSL Ubuntu. Output: target/bzImage in the sotX
# tree, ready to be baked into the initrd by `just initrd`.
#
# Usage (from Windows or WSL):
#   wsl -e bash /mnt/c/Users/sotom/sotX/scripts/build_phase_f_bzimage.sh
#
# What it does:
#   1. Apt-installs libssl-dev (the only missing build dep on WSL Ubuntu)
#   2. git clone --depth 1 the latest stable Linux from kernel.org
#      into /tmp/sotos-linux (skipped if already present)
#   3. Runs `make tinyconfig` then enables CONFIG_64BIT, CONFIG_PRINTK,
#      and CONFIG_SERIAL_8250_CONSOLE — the minimum to print "Linux
#      version" via the COM1 emulation we built in Phase F.2
#   4. Builds the bzImage with all CPU cores
#   5. Copies it to <sotos-tree>/target/bzImage
#
# After this script finishes, Phase F.4's loader can pick the file up.

set -euo pipefail

# Resolve sotX tree root from this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOTOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LINUX_DIR="/tmp/sotos-linux"
# Mainline-only tag (torvalds/linux only carries vX.Y tags, not the
# vX.Y.Z stable point releases — those live in the linux-stable tree).
# v6.6 is the LTS release from October 2023, well-tested for our
# tinyconfig + serial-only path.
LINUX_TAG="v6.6"
JOBS="$(nproc)"

echo "==> sotX root: $SOTOS_ROOT"
echo "==> Linux dir:  $LINUX_DIR"
echo "==> Linux tag:  $LINUX_TAG"
echo "==> Build jobs: $JOBS"
echo

# Step 1 — install missing build deps. libelf-dev is already there.
if ! dpkg -l libssl-dev 2>/dev/null | grep -q '^ii'; then
    echo "==> Installing libssl-dev (sudo password may be required)"
    sudo apt-get update -qq
    sudo apt-get install -y libssl-dev
else
    echo "==> libssl-dev already installed"
fi

# Step 2 — shallow clone Linux at the chosen tag.
if [ ! -d "$LINUX_DIR" ]; then
    echo "==> Cloning Linux $LINUX_TAG (shallow, this is the slow step)"
    git clone --depth 1 --branch "$LINUX_TAG" \
        https://github.com/torvalds/linux.git "$LINUX_DIR"
else
    echo "==> $LINUX_DIR already exists, reusing"
fi

cd "$LINUX_DIR"

# Step 3 — minimal config.
echo "==> make tinyconfig"
make ARCH=x86_64 tinyconfig

echo "==> Enabling COM1 console + printk"
./scripts/config \
    --enable  CONFIG_64BIT \
    --enable  CONFIG_PRINTK \
    --enable  CONFIG_PRINTK_TIME \
    --enable  CONFIG_TTY \
    --enable  CONFIG_SERIAL_8250 \
    --enable  CONFIG_SERIAL_8250_CONSOLE \
    --enable  CONFIG_SERIAL_8250_PCI \
    --enable  CONFIG_EARLY_PRINTK \
    --set-str CONFIG_CMDLINE "console=ttyS0,38400 earlyprintk=serial,ttyS0,38400 panic=1"
make ARCH=x86_64 olddefconfig

# Step 4 — build.
echo "==> make -j$JOBS bzImage"
make ARCH=x86_64 -j"$JOBS" bzImage

# Step 5 — copy result.
SRC="$LINUX_DIR/arch/x86/boot/bzImage"
DST="$SOTOS_ROOT/target/bzImage"
mkdir -p "$SOTOS_ROOT/target"
cp -f "$SRC" "$DST"

SIZE_BYTES="$(stat -c '%s' "$DST")"
SIZE_KB="$(( SIZE_BYTES / 1024 ))"

echo
echo "===================================================================="
echo "  Phase F bzImage ready"
echo "===================================================================="
echo "  Source:  $SRC"
echo "  Dest:    $DST"
echo "  Size:    $SIZE_BYTES bytes (~$SIZE_KB KiB)"
echo "  Linux:   $LINUX_TAG"
echo
echo "  Next: Phase F.4 (bzImage loader) will pick this file up"
echo "  during 'just initrd' and bake it into the initrd archive."
echo "===================================================================="
