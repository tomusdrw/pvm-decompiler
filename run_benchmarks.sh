#!/bin/bash
set -e

# Compile the disassembler
cargo build --release

TOOLS="./target/release/pvm-diss"

for file in benchmarks/compiled/*.pvm; do
    filename=$(basename "$file" .pvm)
    echo "Disassembling $filename..."
    $TOOLS "$file" > "benchmarks/output/$filename.diss"
done

echo "Done! Check benchmarks/output/"
