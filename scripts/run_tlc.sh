#!/usr/bin/env bash
# Tier 5: run TLC model checking on every .tla file under formal/ that
# has a sibling .cfg. Each spec is exhaustively explored within its
# state-space bound (defined inside the spec via state constraints).
#
# Usage: scripts/run_tlc.sh formal
#
# Exits 0 if every spec model-checks cleanly, 1 if any spec found a
# property violation.

set -u

if ! command -v java >/dev/null 2>&1; then
    echo "tlc: java not installed, skipping"
    exit 0
fi

DIR="${1:-formal}"
TOOLS_DIR="tools"
JAR="${TOOLS_DIR}/tlc.jar"
TLA_TOOLS_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"

if [ ! -f "$JAR" ]; then
    mkdir -p "$TOOLS_DIR"
    echo "tlc: downloading tla2tools.jar..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$JAR" "$TLA_TOOLS_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$JAR" "$TLA_TOOLS_URL"
    else
        echo "tlc: neither curl nor wget available; cannot download $JAR"
        exit 1
    fi
fi

JAR_ABS="$(pwd)/$JAR"
PASS=0
FAIL=0
SKIP=0
FAILED_SPECS=()

for spec in "$DIR"/*.tla; do
    [ -f "$spec" ] || continue
    base=$(basename "$spec" .tla)
    cfg="$DIR/${base}.cfg"
    if [ ! -f "$cfg" ]; then
        echo "==> SKIP $base (no .cfg)"
        SKIP=$((SKIP+1))
        continue
    fi

    # TLC requires CWD to contain the spec; otherwise the "file path !=
    # module name" check rejects it.
    out=$(cd "$DIR" && java -Xss64m -cp "$JAR_ABS" tlc2.TLC -workers auto "$base" 2>&1)
    if echo "$out" | grep -qE 'Model checking completed\. No error has been found\.'; then
        states=$(echo "$out" | grep -oE '[0-9]+ distinct states found' | tail -1)
        depth=$(echo "$out"  | grep -oE 'depth of the complete state graph search is [0-9]+' | tail -1)
        echo "==> TLC  ok  $base ($states, $depth)"
        PASS=$((PASS+1))
    else
        echo "==> TLC FAIL $base"
        echo "$out" | grep -E 'Error|violated|Invariant' | sed 's/^/    /' | head -10
        FAIL=$((FAIL+1))
        FAILED_SPECS+=("$base")
    fi

    # Clean up TLC trace artifacts so the working tree stays tidy.
    rm -f "$DIR"/${base}_TTrace_*.tla "$DIR"/${base}_TTrace_*.bin
    rm -rf "$DIR"/states 2>/dev/null
done

echo
echo "tlc: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -gt 0 ]; then
    printf 'failed: %s\n' "${FAILED_SPECS[@]}"
    exit 1
fi
exit 0
