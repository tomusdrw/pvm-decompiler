#!/bin/sh
# Entrypoint for Rellic Docker container.
# Supports both .ll (LLVM IR text) and .bc (bitcode) input.
# Usage:
#   docker run --rm -v /tmp/pvm-decompile:/work rellic-decomp /work/input.ll /work/output.c
#   docker run --rm -v /tmp/pvm-decompile:/work rellic-decomp /work/input.bc /work/output.c

set -e

INPUT="$1"
OUTPUT="$2"

if [ -z "$INPUT" ] || [ -z "$OUTPUT" ]; then
    echo "Usage: rellic-decomp <input.ll|input.bc> <output.c>" >&2
    exit 1
fi

# If input is .ll, assemble to .bc first using the container's LLVM 16 llvm-as
case "$INPUT" in
    *.ll)
        BC_FILE="${INPUT%.ll}.bc"
        echo "[rellic-docker] Assembling $INPUT -> $BC_FILE" >&2
        /opt/trailofbits/llvm/bin/llvm-as "$INPUT" -o "$BC_FILE"
        INPUT="$BC_FILE"
        ;;
esac

echo "[rellic-docker] Decompiling $INPUT -> $OUTPUT" >&2
exec /opt/trailofbits/bin/rellic-decomp --input "$INPUT" --output "$OUTPUT"
