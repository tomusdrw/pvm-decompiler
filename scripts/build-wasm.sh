#!/usr/bin/env bash
set -euo pipefail

# Build the WASM package using wasm-pack
wasm-pack build --target bundler --no-default-features --features wasm

# Patch package.json with the scoped npm name
node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('pkg/package.json', 'utf8'));
  pkg.name = '@fluffylabs/pvm-decompiler';
  fs.writeFileSync('pkg/package.json', JSON.stringify(pkg, null, 2) + '\n');
"

echo "WASM package built successfully in pkg/"
echo "Package name: $(node -e "console.log(JSON.parse(require('fs').readFileSync('pkg/package.json','utf8')).name)")"
