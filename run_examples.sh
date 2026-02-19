#!/bin/bash

# Compile the disassembler
cargo build --release

TOOLS="./target/release/pvm-diss"

mkdir -p benchmarks/output

for file in benchmarks/compiled/*.pvm; do
    filename=$(basename "$file" .pvm)
    echo "Disassembling $filename..."
    if $TOOLS "$file" > "benchmarks/output/$filename.diss"; then
        echo "✅ $filename success"
    else
        echo "❌ $filename failed"
    fi
done

echo "Done! Check benchmarks/output/"
