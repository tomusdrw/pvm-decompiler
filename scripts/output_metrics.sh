#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/output_metrics.sh [FILE_OR_GLOB ...]

Reports per-file metrics:
  - placeholder conditions: if (...)
  - empty if blocks
  - empty while blocks
  - main() calls (excluding fn main(...) definitions)
  - raw jump <offset> text

If no arguments are provided, defaults to:
  examples/output/*.diss
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

declare -a files=()

if [[ "$#" -eq 0 ]]; then
    while IFS= read -r file; do
        files+=("$file")
    done < <(find examples/output -maxdepth 1 -type f -name '*.diss' | sort)
else
    for arg in "$@"; do
        matched=0
        for file in $arg; do
            if [[ -f "$file" ]]; then
                files+=("$file")
                matched=1
            fi
        done
        if [[ "$matched" -eq 0 ]]; then
            echo "warning: no files matched '$arg'" >&2
        fi
    done
    if [[ "${#files[@]}" -gt 0 ]]; then
        IFS=$'\n' files=($(printf "%s\n" "${files[@]}" | sort -u))
        unset IFS
    fi
fi

if [[ "${#files[@]}" -eq 0 ]]; then
    echo "error: no .diss files found" >&2
    exit 1
fi

printf "%-34s %12s %10s %13s %10s %14s\n" \
    "file" "if(...)" "empty_if" "empty_while" "main()" "jump <offset>"
printf "%-34s %12s %10s %13s %10s %14s\n" \
    "----------------------------------" "------------" "----------" "-------------" "----------" "--------------"

total_placeholders=0
total_empty_if=0
total_empty_while=0
total_main_calls=0
total_raw_jump=0

count="${#files[@]}"
index=0

for file in "${files[@]}"; do
    index=$((index + 1))
    if [[ -t 2 ]]; then
        printf "\r[%d/%d] scanning %s" "$index" "$count" "$file" >&2
    else
        printf "[%d/%d] scanning %s\n" "$index" "$count" "$file" >&2
    fi

    metrics="$(
        awk '
            BEGIN {
                placeholder_if = 0
                empty_if = 0
                empty_while = 0
                main_calls = 0
                raw_jump = 0
                pending_block = ""
            }
            {
                line = $0

                tail = line
                while (match(tail, /if \(\.\.\.\)/)) {
                    placeholder_if++
                    tail = substr(tail, RSTART + RLENGTH)
                }

                if (line !~ /^[[:space:]]*fn[[:space:]]+main[[:space:]]*\(/) {
                    tail = line
                    while (match(tail, /main\(\)/)) {
                        main_calls++
                        tail = substr(tail, RSTART + RLENGTH)
                    }
                }

                tail = line
                while (match(tail, /jump <[^>]+>/)) {
                    raw_jump++
                    tail = substr(tail, RSTART + RLENGTH)
                }

                if (pending_block != "") {
                    if (line ~ /^[[:space:]]*$/) {
                        next
                    }
                    if (line ~ /^[[:space:]]*}[[:space:]]*$/) {
                        if (pending_block == "if") {
                            empty_if++
                        } else if (pending_block == "while") {
                            empty_while++
                        }
                        pending_block = ""
                        next
                    }
                    pending_block = ""
                }

                if (line ~ /^[[:space:]]*if[[:space:]]*\(.*\)[[:space:]]*{[[:space:]]*$/) {
                    pending_block = "if"
                    next
                }

                if (line ~ /^[[:space:]]*while[[:space:]]*\(.*\)[[:space:]]*{[[:space:]]*$/) {
                    pending_block = "while"
                    next
                }
            }
            END {
                printf "%d %d %d %d %d\n", placeholder_if, empty_if, empty_while, main_calls, raw_jump
            }
        ' "$file"
    )"

    read -r placeholder_if empty_if empty_while main_calls raw_jump <<<"$metrics"

    total_placeholders=$((total_placeholders + placeholder_if))
    total_empty_if=$((total_empty_if + empty_if))
    total_empty_while=$((total_empty_while + empty_while))
    total_main_calls=$((total_main_calls + main_calls))
    total_raw_jump=$((total_raw_jump + raw_jump))

    printf "%-34s %12d %10d %13d %10d %14d\n" \
        "$file" "$placeholder_if" "$empty_if" "$empty_while" "$main_calls" "$raw_jump"
done

if [[ -t 2 ]]; then
    printf "\r\033[K" >&2
fi

printf "%-34s %12s %10s %13s %10s %14s\n" \
    "----------------------------------" "------------" "----------" "-------------" "----------" "--------------"
printf "%-34s %12d %10d %13d %10d %14d\n" \
    "TOTAL" "$total_placeholders" "$total_empty_if" "$total_empty_while" "$total_main_calls" "$total_raw_jump"
