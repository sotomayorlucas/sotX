#!/usr/bin/env bash
# ============================================================================
# run_tlc.sh — Run TLC model checker on all sotFS specs at multiple bound sizes
#
# Usage:
#   ./run_tlc.sh              # run all specs, all sizes
#   ./run_tlc.sh small        # run only small configs
#   ./run_tlc.sh medium       # run only medium configs
#   ./run_tlc.sh large        # run only large configs
#   ./run_tlc.sh graph        # run only sotfs_graph (all sizes)
#
# Requirements:
#   - Java 11+ on PATH
#   - TLC jar: set TLC_JAR env var, or place tla2tools.jar in this directory
#
# Output:
#   - Per-run logs in formal/tlc_output/
#   - Summary table printed to stdout and saved to formal/tlc_output/summary.txt
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --------------------------------------------------------------------------
# Locate TLC jar
# --------------------------------------------------------------------------
if [[ -n "${TLC_JAR:-}" ]] && [[ -f "$TLC_JAR" ]]; then
    TLC="$TLC_JAR"
elif [[ -f "$SCRIPT_DIR/tla2tools.jar" ]]; then
    TLC="$SCRIPT_DIR/tla2tools.jar"
elif [[ -f "$HOME/tla2tools.jar" ]]; then
    TLC="$HOME/tla2tools.jar"
else
    echo "ERROR: Cannot find tla2tools.jar."
    echo "Set TLC_JAR env var or place tla2tools.jar in $SCRIPT_DIR"
    exit 1
fi

echo "Using TLC jar: $TLC"

# --------------------------------------------------------------------------
# JVM options — increase heap for large configs
# --------------------------------------------------------------------------
JVM_OPTS="${TLC_JVM_OPTS:--Xmx4g -Xms1g}"
TLC_WORKERS="${TLC_WORKERS:-auto}"

# --------------------------------------------------------------------------
# Output directory
# --------------------------------------------------------------------------
OUT_DIR="$SCRIPT_DIR/tlc_output"
mkdir -p "$OUT_DIR"

# --------------------------------------------------------------------------
# Spec definitions: spec_name tla_file cfg_suffix
# --------------------------------------------------------------------------
SPECS=(
    "sotfs_graph"
    "sotfs_transactions"
    "sotfs_capabilities"
    "sotfs_crash"
)

SIZES=("small" "medium" "large")

# Map size to cfg suffix (small = original file, no suffix)
cfg_for() {
    local spec="$1" size="$2"
    case "$size" in
        small)  echo "${spec}.cfg" ;;
        medium) echo "${spec}_medium.cfg" ;;
        large)  echo "${spec}_large.cfg" ;;
    esac
}

# --------------------------------------------------------------------------
# Filter by CLI arguments
# --------------------------------------------------------------------------
FILTER_SIZE=""
FILTER_SPEC=""

for arg in "$@"; do
    case "$arg" in
        small|medium|large) FILTER_SIZE="$arg" ;;
        graph)              FILTER_SPEC="sotfs_graph" ;;
        transactions)       FILTER_SPEC="sotfs_transactions" ;;
        capabilities)       FILTER_SPEC="sotfs_capabilities" ;;
        crash)              FILTER_SPEC="sotfs_crash" ;;
        sotfs_*)            FILTER_SPEC="$arg" ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [small|medium|large] [graph|transactions|capabilities|crash]"
            exit 1
            ;;
    esac
done

# --------------------------------------------------------------------------
# Summary table header
# --------------------------------------------------------------------------
SUMMARY="$OUT_DIR/summary.txt"
{
    printf "%-28s %-8s %12s %12s %8s %s\n" \
        "SPEC" "SIZE" "STATES" "DISTINCT" "TIME(s)" "RESULT"
    printf "%-28s %-8s %12s %12s %8s %s\n" \
        "----------------------------" "--------" "------------" "------------" "--------" "------"
} | tee "$SUMMARY"

# --------------------------------------------------------------------------
# Run TLC on one (spec, size) pair
# --------------------------------------------------------------------------
run_one() {
    local spec="$1" size="$2"
    local tla_file="${spec}.tla"
    local cfg_file
    cfg_file="$(cfg_for "$spec" "$size")"

    if [[ ! -f "$SCRIPT_DIR/$cfg_file" ]]; then
        printf "%-28s %-8s %12s %12s %8s %s\n" \
            "$spec" "$size" "-" "-" "-" "SKIP (no cfg)" | tee -a "$SUMMARY"
        return
    fi

    local log_file="$OUT_DIR/${spec}_${size}.log"
    local label="${spec} (${size})"

    echo ">>> Running: $label"
    echo "    TLA: $tla_file  CFG: $cfg_file"

    local start_time
    start_time=$(date +%s)

    # Run TLC; capture output, don't fail script on violation
    set +e
    java $JVM_OPTS \
        -cp "$TLC" tlc2.TLC \
        -config "$cfg_file" \
        -workers "$TLC_WORKERS" \
        -noGenerateSpecTE \
        "$tla_file" \
        > "$log_file" 2>&1
    local exit_code=$?
    set -e

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    # Parse results from TLC output
    local states="-"
    local distinct="-"
    local result="UNKNOWN"

    if grep -q "Model checking completed. No error has been found." "$log_file"; then
        result="PASS"
    elif grep -q "Error:" "$log_file"; then
        result="VIOLATION"
    elif grep -q "Finished in" "$log_file"; then
        result="PASS"
    elif [[ $exit_code -ne 0 ]]; then
        result="ERROR(rc=$exit_code)"
    fi

    # Extract state counts
    local states_line
    states_line=$(grep -oP '\d+ states generated' "$log_file" | tail -1 | grep -oP '^\d+' || true)
    if [[ -n "$states_line" ]]; then
        states="$states_line"
    fi

    local distinct_line
    distinct_line=$(grep -oP '\d+ distinct states found' "$log_file" | tail -1 | grep -oP '^\d+' || true)
    if [[ -n "$distinct_line" ]]; then
        distinct="$distinct_line"
    fi

    printf "%-28s %-8s %12s %12s %8s %s\n" \
        "$spec" "$size" "$states" "$distinct" "$elapsed" "$result" | tee -a "$SUMMARY"

    if [[ "$result" == "VIOLATION" ]]; then
        echo "    !!! VIOLATION found — see $log_file"
    fi
}

# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------
echo ""
echo "============================================"
echo " sotFS TLC Model Checking Suite"
echo " $(date)"
echo "============================================"
echo ""

total_start=$(date +%s)

for spec in "${SPECS[@]}"; do
    if [[ -n "$FILTER_SPEC" ]] && [[ "$spec" != "$FILTER_SPEC" ]]; then
        continue
    fi
    for size in "${SIZES[@]}"; do
        if [[ -n "$FILTER_SIZE" ]] && [[ "$size" != "$FILTER_SIZE" ]]; then
            continue
        fi
        run_one "$spec" "$size"
    done
done

total_end=$(date +%s)
total_elapsed=$(( total_end - total_start ))

echo ""
echo "============================================"
echo " Total wall-clock time: ${total_elapsed}s"
echo " Logs: $OUT_DIR/"
echo " Summary: $SUMMARY"
echo "============================================"
