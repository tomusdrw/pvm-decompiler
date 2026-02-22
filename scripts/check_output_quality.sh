#!/usr/bin/env bash
set -euo pipefail

# Default thresholds can be overridden by environment variables.
max_if_placeholders="${MAX_IF_PLACEHOLDERS:-0}"
max_empty_if="${MAX_EMPTY_IF:-0}"
max_empty_while="${MAX_EMPTY_WHILE:-0}"
max_false_main="${MAX_FALSE_MAIN:-0}"
max_raw_jump="${MAX_RAW_JUMP:-0}"

if [[ "$#" -eq 0 ]]; then
    set -- examples/output/*.diss
fi

metrics="$(./scripts/output_metrics.sh "$@")"
echo "$metrics"

total_line="$(printf "%s\n" "$metrics" | awk '$1=="TOTAL"{print}')"
if [[ -z "$total_line" ]]; then
    echo "error: failed to parse TOTAL line from output metrics" >&2
    exit 1
fi

read -r _ if_placeholders empty_if empty_while false_main raw_jump <<<"$total_line"

fail=0

check_threshold() {
    local label="$1"
    local value="$2"
    local max="$3"
    if (( value > max )); then
        echo "error: ${label}=${value} exceeds threshold ${max}" >&2
        fail=1
    fi
}

check_threshold "if(...)" "$if_placeholders" "$max_if_placeholders"
check_threshold "empty_if" "$empty_if" "$max_empty_if"
check_threshold "empty_while" "$empty_while" "$max_empty_while"
check_threshold "false_main" "$false_main" "$max_false_main"
check_threshold "jump_offset" "$raw_jump" "$max_raw_jump"

if (( fail != 0 )); then
    exit 1
fi

echo "Output quality checks passed."
