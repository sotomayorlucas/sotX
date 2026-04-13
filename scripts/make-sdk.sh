#!/usr/bin/env bash
# Sprint 3 -- build an exportable sotX SDK tarball.
#
# The SDK lets a third party link their own component against the
# frozen sotX ABI (see docs/ABI_v0.1.0.md) without needing to clone
# the whole repo. It contains:
#
#   - target/sotx.img          bootable 512 MiB QEMU image
#   - kernel/sotos-kernel.elf   raw kernel ELF for gdb
#   - abi/sotos-common/         frozen ABI crate (source)
#   - abi/ABI_v0.1.0.md         frozen ABI reference document
#   - docs/                     architecture + SOT spec + sprint status
#   - VERSION                   the ABI version string
#   - README                    quick start
#
# Output:
#   target/sotx-sdk-<VERSION>.tar.gz
#   target/sotx-sdk-<VERSION>.tar.gz.sha256
#   target/sotx-sdk-<VERSION>.tar.gz.sig    (only when a signing key is available)
#
# Versioning
# ----------
# By default the version string is taken from the ABI constant in
# `libs/sotos-common/src/lib.rs` (e.g. `0.1.0` -> `v0.1.0`). Pass
# `--version <tag>` to override -- this is what the GitHub Releases
# workflow does so the tarball name lines up with the pushed git tag.
#
# Signing
# -------
# Signing key sources, in priority order:
#   1. `SIGNIFY_KEY_BYTES` env var: base64-encoded 32-byte raw Ed25519
#      private key. Decoded into a 0600 tempfile (cleaned up on exit).
#      This is what the GitHub Releases workflow uses so the secret
#      can be stored as raw bytes rather than a filesystem path.
#   2. `SIGNIFY_KEY` env var: absolute path to a 32-byte raw Ed25519
#      private key file already on disk.
#   3. `~/.secrets/sotx-signify.key`: the per-developer fallback.
# If none of these exists the script logs a warning and does NOT fail
# -- unsigned dev builds are still valid SDK artifacts. The signature
# itself is byte-compatible with the format consumed by
# `services/init/src/signify.rs::verify_manifest()` (raw 64-byte
# Ed25519 over the tarball bytes; the matching public key lives in
# `services/init/src/sigkey_generated.rs`).
#
# Python interpreter
# ------------------
# The signing block runs a small Python helper that uses
# `cryptography.hazmat.primitives.asymmetric.ed25519`. Fresh Ubuntu CI
# runners ship `python3` but not `python`, so this script picks
# whichever exists at startup and stores it in `$PY`.

set -euo pipefail

# Pick a Python interpreter once. Prefer python3 (Ubuntu CI default),
# fall back to python (older distros / dev workstations). Signing is
# optional, so leaving $PY empty just disables the .sig step rather
# than hard-failing the SDK build.
PY="$(command -v python3 || command -v python || true)"
if [ -z "${PY}" ]; then
    echo "make-sdk.sh: python3 (or python) not found on PATH -- signing disabled" >&2
fi

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

# -- argument parsing ------------------------------------------------------
VERSION_OVERRIDE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION_OVERRIDE="$2"
            shift 2
            ;;
        --version=*)
            VERSION_OVERRIDE="${1#--version=}"
            shift
            ;;
        -h|--help)
            cat <<'USAGE'
make-sdk.sh -- build the sotX SDK tarball.

Usage:
    bash scripts/make-sdk.sh [--version <tag>]

Options:
    --version <tag>   Override the version string baked into the SDK
                      name and VERSION file. A leading 'v' is stripped.
                      Default: nearest git tag, falling back to the
                      ABI_VERSION constant in libs/sotos-common.

Outputs (under target/):
    sotx-sdk-v<VERSION>.tar.gz
    sotx-sdk-v<VERSION>.tar.gz.sha256
    sotx-sdk-v<VERSION>.tar.gz.sig    (only if SIGNIFY_KEY_BYTES,
                                         SIGNIFY_KEY is set, or
                                         ~/.secrets/sotx-signify.key
                                         exists)

See the comment block at the top of this file for full details.
USAGE
            exit 0
            ;;
        *)
            echo "make-sdk: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

# -- version derivation ----------------------------------------------------
if [ -n "$VERSION_OVERRIDE" ]; then
    # Strip a leading 'v' so the SDK_NAME we produce is consistent with
    # the unprefixed ABI version case below.
    SDK_VERSION="${VERSION_OVERRIDE#v}"
elif command -v git >/dev/null 2>&1 && git describe --tags --abbrev=0 >/dev/null 2>&1; then
    GIT_TAG=$(git describe --tags --abbrev=0)
    SDK_VERSION="${GIT_TAG#v}"
else
    SDK_VERSION=$(grep -E 'pub const ABI_VERSION' libs/sotos-common/src/lib.rs \
                  | head -1 \
                  | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$SDK_VERSION" ]; then
        echo "make-sdk: could not parse ABI_VERSION from sotos-common/src/lib.rs" >&2
        exit 1
    fi
fi

SDK_NAME="sotx-sdk-v${SDK_VERSION}"
SDK_DIR="target/${SDK_NAME}"
SDK_TAR="target/${SDK_NAME}.tar.gz"
SDK_SHA="${SDK_TAR}.sha256"
SDK_SIG="${SDK_TAR}.sig"

rm -rf "$SDK_DIR" "$SDK_TAR" "$SDK_SHA" "$SDK_SIG"
mkdir -p "$SDK_DIR/kernel" "$SDK_DIR/abi/sotos-common" "$SDK_DIR/docs"

# -- bootable image --------------------------------------------------------
if [ -f target/sotx.img ]; then
    cp target/sotx.img "$SDK_DIR/"
else
    echo "make-sdk: target/sotx.img missing -- continuing without bootable image (run 'just image' first for a complete SDK)" >&2
fi

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
echo "$SDK_VERSION" > "$SDK_DIR/VERSION"
cat > "$SDK_DIR/README" <<EOF
sotX SDK v${SDK_VERSION}
==========================

This tarball bundles the frozen sotX ABI plus a bootable image.
It is produced by \`just sdk\` / \`scripts/make-sdk.sh\` from the
public sotX source tree.

Contents:

  sotx.img              -- 512 MiB bootable disk image
  kernel/                -- raw kernel ELF (sotos-kernel.elf) for gdb
  abi/sotos-common/      -- the frozen ABI Rust crate you link against
  abi/ABI_v0.1.0.md      -- authoritative ABI reference document
  docs/                  -- architecture + sprint status reports
  VERSION                -- the ABI version string

Quick start:

  1. Boot the image:
       qemu-system-x86_64 -cpu max -drive format=raw,file=sotx.img \\
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

Verifying this tarball:

  sha256sum -c ${SDK_NAME}.tar.gz.sha256
  # Optional Ed25519 signature: matches the public key in
  # services/init/src/sigkey_generated.rs (raw 64-byte signature
  # over the tarball bytes).
EOF

# -- tarball ---------------------------------------------------------------
tar -czf "$SDK_TAR" -C target "$SDK_NAME"
rm -rf "$SDK_DIR"

size=$(wc -c < "$SDK_TAR")
printf "make-sdk: wrote %s (%s bytes)\n" "$SDK_TAR" "$size"

# -- SHA-256 ---------------------------------------------------------------
# Standard `sha256sum` format: "<hex>  <relative path>". The relative
# path uses the basename so the .sha256 file is portable.
(
    cd target
    sha256sum "${SDK_NAME}.tar.gz" > "${SDK_NAME}.tar.gz.sha256"
)
printf "make-sdk: wrote %s\n" "$SDK_SHA"

# -- Ed25519 signature -----------------------------------------------------
# Pick the signing key in this order:
#   1. SIGNIFY_KEY_BYTES env var (base64-encoded 32-byte raw private
#      key). Decoded to a 0600 tempfile that is removed on exit. This
#      is what the GitHub Releases workflow passes from the
#      SIGNIFY_KEY_B64 secret.
#   2. SIGNIFY_KEY env var (absolute path to a 32-byte raw private key)
#   3. ~/.secrets/sotx-signify.key (the workflow Lucas documents)
# If none exist, log a warning and skip -- unsigned dev tarballs
# are still valid SDK artifacts.
SIGN_KEY_PATH=""
SIGN_KEY_TMP=""
cleanup_sign_key() {
    if [ -n "$SIGN_KEY_TMP" ] && [ -f "$SIGN_KEY_TMP" ]; then
        rm -f "$SIGN_KEY_TMP"
    fi
}
trap cleanup_sign_key EXIT

if [ -n "${SIGNIFY_KEY_BYTES:-}" ]; then
    if [ -z "$PY" ]; then
        echo "make-sdk: SIGNIFY_KEY_BYTES set but no python interpreter found -- skipping .sig" >&2
    else
        SIGN_KEY_TMP="$(mktemp)"
        chmod 600 "$SIGN_KEY_TMP"
        # Decode base64 -> raw bytes via python (portable: no `base64`
        # binary needed). Strips whitespace so heredoc/secret blobs
        # with trailing newlines decode cleanly.
        if SIGNIFY_KEY_BYTES="$SIGNIFY_KEY_BYTES" "$PY" - "$SIGN_KEY_TMP" <<'PY'
import base64, os, sys
out_path = sys.argv[1]
b64 = os.environ.get("SIGNIFY_KEY_BYTES", "")
raw = base64.b64decode("".join(b64.split()))
if len(raw) != 32:
    sys.stderr.write(f"make-sdk: SIGNIFY_KEY_BYTES must decode to 32 bytes (got {len(raw)})\n")
    sys.exit(3)
with open(out_path, "wb") as f:
    f.write(raw)
PY
        then
            SIGN_KEY_PATH="$SIGN_KEY_TMP"
        else
            echo "make-sdk: failed to decode SIGNIFY_KEY_BYTES -- skipping .sig" >&2
            rm -f "$SIGN_KEY_TMP"
            SIGN_KEY_TMP=""
        fi
    fi
elif [ -n "${SIGNIFY_KEY:-}" ] && [ -f "${SIGNIFY_KEY}" ]; then
    SIGN_KEY_PATH="${SIGNIFY_KEY}"
elif [ -f "${HOME:-/nonexistent}/.secrets/sotx-signify.key" ]; then
    SIGN_KEY_PATH="${HOME}/.secrets/sotx-signify.key"
fi

if [ -n "$SIGN_KEY_PATH" ]; then
    if [ -z "$PY" ]; then
        echo "make-sdk: python not found, cannot sign tarball" >&2
    else
        "$PY" - "$SIGN_KEY_PATH" "$SDK_TAR" "$SDK_SIG" <<'PY'
import sys

key_path, tar_path, sig_path = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("make-sdk: install `cryptography` to sign (pip install cryptography)",
          file=sys.stderr)
    sys.exit(2)

with open(key_path, "rb") as f:
    priv = f.read()
if len(priv) != 32:
    print(f"make-sdk: key {key_path} must be 32 bytes (got {len(priv)})",
          file=sys.stderr)
    sys.exit(3)

sk = Ed25519PrivateKey.from_private_bytes(priv)

with open(tar_path, "rb") as f:
    body = f.read()

sig = sk.sign(body)
assert len(sig) == 64, f"unexpected sig length: {len(sig)}"

with open(sig_path, "wb") as f:
    f.write(sig)

print(f"make-sdk: signed {tar_path} -> {sig_path} (Ed25519, 64 bytes)")
PY
        printf "make-sdk: wrote %s\n" "$SDK_SIG"
    fi
else
    echo "make-sdk: no signing key found (set SIGNIFY_KEY_BYTES, SIGNIFY_KEY, or place one at ~/.secrets/sotx-signify.key) -- skipping .sig"
fi

printf "make-sdk: done -- artifacts in target/\n"
