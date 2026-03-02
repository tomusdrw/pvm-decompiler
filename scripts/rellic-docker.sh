#!/bin/bash
# Wrapper script for Docker-based Rellic decompiler.
# Usage: scripts/rellic-docker.sh <input.ll|input.bc> <output.c>
#
# Automatically builds the Docker image if not present.
# Input/output files are bind-mounted into the container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="pvm-rellic-decomp"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <input.ll|input.bc> <output.c>" >&2
    exit 1
fi

INPUT_FILE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUTPUT_FILE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
WORK_DIR="$(dirname "$INPUT_FILE")"

# Ensure output directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Build Docker image if not present
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[rellic-docker] Building Docker image '$IMAGE_NAME' (this may take 15-30 minutes)..." >&2
    docker build -t "$IMAGE_NAME" "$PROJECT_DIR/docker/rellic/"
    echo "[rellic-docker] Image built successfully." >&2
fi

# Determine container paths
INPUT_BASENAME="$(basename "$INPUT_FILE")"
OUTPUT_BASENAME="$(basename "$OUTPUT_FILE")"

# If input and output are in different directories, mount both
INPUT_DIR="$(dirname "$INPUT_FILE")"
OUTPUT_DIR="$(dirname "$OUTPUT_FILE")"

if [ "$INPUT_DIR" = "$OUTPUT_DIR" ]; then
    docker run --rm \
        -v "$INPUT_DIR:/work" \
        "$IMAGE_NAME" \
        "/work/$INPUT_BASENAME" "/work/$OUTPUT_BASENAME"
else
    docker run --rm \
        -v "$INPUT_DIR:/input" \
        -v "$OUTPUT_DIR:/output" \
        "$IMAGE_NAME" \
        "/input/$INPUT_BASENAME" "/output/$OUTPUT_BASENAME"
fi

echo "[rellic-docker] Done: $OUTPUT_FILE" >&2
