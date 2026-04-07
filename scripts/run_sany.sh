#!/usr/bin/env bash
# Tier 5: run SANY (the TLA+ syntax + level checker) on every .tla file
# under the given directory. Downloads tla2tools.jar if missing.
#
# Usage: scripts/run_sany.sh formal
#
# Exits 0 if every spec parses cleanly, 1 if any spec fails.

set -u

if ! command -v java >/dev/null 2>&1; then
    echo "sany: java not installed, skipping"
    exit 0
fi

DIR="${1:-formal}"
TOOLS_DIR="tools"
JAR="${TOOLS_DIR}/tlc.jar"
TLA_TOOLS_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"

if [ ! -f "$JAR" ]; then
    mkdir -p "$TOOLS_DIR"
    echo "sany: downloading tla2tools.jar..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$JAR" "$TLA_TOOLS_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$JAR" "$TLA_TOOLS_URL"
    else
        echo "sany: neither curl nor wget available; cannot download $JAR"
        exit 1
    fi
fi

PASS=0
FAIL=0
FAILED_SPECS=()

JAR_ABS="$(pwd)/$JAR"

for spec in "$DIR"/*.tla; do
    [ -f "$spec" ] || continue
    base=$(basename "$spec")
    # SANY requires the file to be invoked from the directory that
    # contains it, otherwise the "file path != module name" check
    # rejects every spec. cd in, run, cd back.
    out=$(cd "$DIR" && java -cp "$JAR_ABS" tla2sany.SANY "$base" 2>&1)
    if echo "$out" | grep -qE '(Parsing or semantic analysis failed|Could not.*locate|^\*\*\* Error|^\*\*\* Errors)'; then
        echo "==> SANY FAIL $base"
        echo "$out" | sed 's/^/    /'
        FAIL=$((FAIL+1))
        FAILED_SPECS+=("$base")
    else
        echo "==> SANY  ok  $base"
        PASS=$((PASS+1))
    fi
done

echo
echo "sany: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    printf 'failed: %s\n' "${FAILED_SPECS[@]}"
    exit 1
fi
exit 0
