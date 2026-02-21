#!/bin/bash
set -e

# Compile the decompiler
cargo build --release

TOOLS="./target/release/pvm-decompiler"

for file in examples/compiled/*.pvm; do
    filename=$(basename "$file" .pvm)
    echo "Decompiling $filename..."
    $TOOLS "$file" > "examples/output/$filename.diss"
done

echo "Done! Check examples/output/"
