#!/usr/bin/env bash
#
# bootstrap-sotx.sh — PANDORA Task 2 pkgsrc bootstrap for sotX.
#
# Creates a sotX-flavored pkgsrc environment on the HOST (not inside
# the running sotX image). Output is a directory skeleton that
# mirrors the layout the sot-pkg service expects to see inside
# initrd:
#
#     target/pkg-root/
#         etc/mk.conf           -- sotX-specific pkgsrc defaults
#         etc/sotx.conf       -- shim config (fetch routing, paths)
#         var/db/pkg/           -- installed package database
#         var/db/pkg.refcount   -- opaque counter file
#         bin/                  -- binary install prefix
#         lib/                  -- library install prefix
#         share/                -- shared data prefix
#         include/              -- headers
#
# The host-side prep stages the skeleton, generates a default
# pkgsrc `mk.conf` that points at the sotX layout, and prepares
# a sample "hello-1.0" package blob the sot-pkg service can register
# on first boot to demonstrate the install flow end-to-end.
#
# The actual bmake-driven compile of nginx et al. is deferred: it
# requires a musl-static gcc + bmake inside the initrd, plus the
# rump network stack to be fully booting (parked behind the
# rump_init bisect). This script sets up EVERYTHING upstream of
# that final step so the integration is ready to plug in the
# toolchain when it lands.
#
# Usage:
#     bash scripts/bootstrap-sotx.sh
#     bash scripts/bootstrap-sotx.sh --root target/pkg-root

set -euo pipefail

ROOT="target/pkg-root"
FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --root)   ROOT="$2"; shift 2 ;;
        --force)  FORCE=1;   shift   ;;
        -h|--help)
            sed -n '3,28p' "$0"
            exit 0
            ;;
        *) echo "bootstrap-sotx: unknown arg: $1"; exit 2 ;;
    esac
done

echo "bootstrap-sotx: staging pkg-root at $ROOT"
if [ -d "$ROOT" ] && [ "$FORCE" -eq 0 ]; then
    echo "bootstrap-sotx: $ROOT already exists (pass --force to rebuild)"
else
    rm -rf "$ROOT"
    mkdir -p "$ROOT"/{etc,var/db/pkg,bin,lib,share,include}
fi

# -----------------------------------------------------------------------
# mk.conf — the canonical sotX pkgsrc defaults
# -----------------------------------------------------------------------
cat > "$ROOT/etc/mk.conf" <<'MKCONF'
# sotX pkgsrc defaults -- PANDORA Task 2 bootstrap output
#
# Minimal overrides pointing pkgsrc at the sotX install hierarchy.
# Anything the vendor bootstrap would put into mk.conf goes here with
# sotX-flavored paths.

LOCALBASE=            /pkg
VARBASE=              /pkg/var
PKG_DBDIR=            /pkg/var/db/pkg
PKG_SYSCONFDIR=       /pkg/etc
PREFIX=               /pkg

# Use the sotX fetch shim (routes HTTP/HTTPS through the sot-net
# service's socket API rather than the host's libfetch/curl).
FETCH_CMD=            /pkg/bin/sot-fetch
FETCH_USING=          custom

# Use the LUCAS musl toolchain installed into initrd.
CC=                   /pkg/bin/cc-musl
CXX=                  /pkg/bin/cxx-musl
MAKE=                 /pkg/bin/bmake

# Disable every feature that requires ports we don't yet have.
PKG_RESUME_TRANSFERS=    no
FETCH_USE_IPV6=         yes
MKCONF

# -----------------------------------------------------------------------
# sotx.conf — the shim routing config consumed by sot-pkg
# -----------------------------------------------------------------------
cat > "$ROOT/etc/sotx.conf" <<'SHIMCONF'
# sotX pkgsrc shim config
# Consumed by services/sot-pkg at runtime to route pkg_add / pkg_info
# / pkg_delete operations.

[paths]
pkg_dbdir = /pkg/var/db/pkg
localbase = /pkg
binprefix = /pkg/bin
libprefix = /pkg/lib

[fetch]
# Route fetch calls through the sot-net service via the sot-fetch
# wrapper. The wrapper uses the socket proxy (AF_INET TCP connect +
# HTTP/1.1 GET) already validated by busybox wget.
scheme_http_handler  = sot-fetch
scheme_https_handler = sot-fetch

[registry]
# sot-pkg registers installed packages in VFS-backed files:
#     /pkg/var/db/pkg/<name>/+CONTENTS
#     /pkg/var/db/pkg/<name>/+DESC
#     /pkg/var/db/pkg/<name>/+BUILD_INFO
format = pkgng-compatible
SHIMCONF

# -----------------------------------------------------------------------
# Sample "hello-1.0" package payload for the demo
# -----------------------------------------------------------------------
HELLO="$ROOT/var/db/pkg/hello-1.0"
mkdir -p "$HELLO"

cat > "$HELLO/+CONTENTS" <<'CONTENTS'
@name hello-1.0
@comment Sample pkgsrc package demonstrating sot-pkg registration
@cwd /pkg
bin/hello
share/doc/hello/README
CONTENTS

cat > "$HELLO/+DESC" <<'DESC'
Sample PANDORA Task 2 package -- demonstrates the sot-pkg registration
flow end-to-end without requiring a full bmake compile of an upstream
package. Installs one placeholder binary + one README.
DESC

cat > "$HELLO/+BUILD_INFO" <<'BI'
OPSYS=sotX
OS_VERSION=0.1
MACHINE_ARCH=x86_64
PKGTOOLS_VERSION=20260407
CC=cc-musl
BI

# Also stage the fake binary and doc so their install is observable.
echo '#!/pkg/bin/sh' > "$ROOT/bin/hello"
echo 'echo hello from pkgsrc under sotX' >> "$ROOT/bin/hello"
chmod 0755 "$ROOT/bin/hello"

mkdir -p "$ROOT/share/doc/hello"
cat > "$ROOT/share/doc/hello/README" <<'RM'
hello — sotX pkgsrc demo package
PANDORA Task 2 deliverable: demonstrates sot-pkg register/info/list/remove
against a VFS-backed package database.
RM

echo "bootstrap-sotx: wrote pkg-root skeleton ($(find "$ROOT" -type f | wc -l) files)"
echo "bootstrap-sotx: sample package: hello-1.0"
echo "bootstrap-sotx: mk.conf at $ROOT/etc/mk.conf"
echo "bootstrap-sotx: sotx.conf at $ROOT/etc/sotx.conf"
echo
echo "Next:"
echo "  just build-sot-pkg && just image && just run"
echo "  (watch for '=== Tier 6 PANDORA T2 pkgsrc demo: PASS ===' in serial)"
