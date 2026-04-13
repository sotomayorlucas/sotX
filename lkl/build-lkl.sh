#!/usr/bin/env bash
# Build LKL (Linux Kernel Library) as a static library for sotX.
# Runs inside WSL2 on Windows 11.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LKL_REPO="https://github.com/lkl/linux.git"
LKL_SRC="$SCRIPT_DIR/linux"
OUTPUT_DIR="$SCRIPT_DIR/output"

# ---------------------------------------------------------------------------
# 1. Check required build dependencies
# ---------------------------------------------------------------------------
MISSING=()
for cmd in gcc make flex bison bc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING+=("$cmd")
    fi
done
if ! pkg-config --exists libelf 2>/dev/null && [ ! -f /usr/include/libelf.h ]; then
    MISSING+=("libelf-dev")
fi

if [ ${#MISSING[@]} -ne 0 ]; then
    echo "ERROR: missing packages: ${MISSING[*]}"
    echo "Install with:  sudo apt-get install -y gcc make flex bison bc libelf-dev"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Clone LKL source (once)
# ---------------------------------------------------------------------------
if [ ! -d "$LKL_SRC" ]; then
    echo "Cloning LKL master branch ..."
    git clone --depth 1 "$LKL_REPO" "$LKL_SRC"
else
    echo "LKL source already present at $LKL_SRC"
fi

# ---------------------------------------------------------------------------
# 3. Apply defconfig
# ---------------------------------------------------------------------------
DEFCONFIG="$SCRIPT_DIR/lkl_defconfig"
if [ ! -f "$DEFCONFIG" ]; then
    echo "ERROR: $DEFCONFIG not found"
    exit 1
fi

echo "Applying lkl_defconfig ..."
cp "$DEFCONFIG" "$LKL_SRC/arch/lkl/configs/lkl_defconfig"
make -C "$LKL_SRC" ARCH=lkl lkl_defconfig

# ---------------------------------------------------------------------------
# 4. Build liblkl.a
# ---------------------------------------------------------------------------
echo "Building LKL (ARCH=lkl) with $(nproc) jobs ..."
make -C "$LKL_SRC" ARCH=lkl -j"$(nproc)" tools/lkl/

# ---------------------------------------------------------------------------
# 5. Copy output artifacts
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR/include"

cp "$LKL_SRC/tools/lkl/liblkl.a" "$OUTPUT_DIR/liblkl.a"

# Install headers into output/include/
if [ -d "$LKL_SRC/tools/lkl/include" ]; then
    cp -r "$LKL_SRC/tools/lkl/include/"* "$OUTPUT_DIR/include/"
fi

echo ""
echo "=== LKL build complete ==="
echo "  Static library : $OUTPUT_DIR/liblkl.a"
echo "  Headers        : $OUTPUT_DIR/include/"
