# PVM Decompiler

## Design Principles

- **High-level intent over low-level detail**: The output should focus on understanding decompiled code intent, not on debugging memory layout or runtime internals. Prefer collapsing boilerplate (heap headers, pointer arithmetic) even at the cost of hiding implementation details.

## Performance

- **NEVER disable or skip optimizations for large programs.** All programs, regardless of size, must receive the same optimization passes. If a pass is too slow, fix the algorithmic complexity (e.g., build indexes, use better data structures) instead of skipping the pass.
- When fixing performance issues, prefer building precomputed indexes (e.g., `HashMap` lookups) over scanning all data structures repeatedly. Convert O(n^2) algorithms to O(n log n) or O(n) using proper indexing.
- Add progress reporting (stderr) for long-running operations so users can see that something is happening. Use `\r` overwriting for TTY output.

## Commits

- **Always regenerate examples before each commit.** Run `./run_examples.sh` to update all example outputs so they reflect the latest changes.

## Architecture

- **Library + binary crate.** `src/lib.rs` exposes the public API (`decompile_to_pseudocode`). `src/main.rs` is the CLI binary.
- **Feature flags:** `native` (default) enables CLI deps (atty, reqwest, tempfile, wait-timeout) and the `decompile`, `llm_refine` modules. `wasm` enables wasm-bindgen bindings in `src/wasm.rs`.
- **WASM target:** `@fluffylabs/pvm-decompiler` npm package. Build with `./scripts/build-wasm.sh` or `wasm-pack build --target bundler --no-default-features --features wasm`. The `pkg/` directory is gitignored build output.
- **CI:** The `wasm` job in `ci.yml` checks WASM compilation and builds the package. `publish-npm.yml` publishes to npm on GitHub release (requires `NPM_TOKEN` secret).

## Testing

- **Bug fixes must include a regression test.** When the user reports something broken and asks for a fix, implement the fix and add/adjust a unit or integration test in the same change so the issue is covered and prevented from regressing. If a test is not feasible, explicitly explain why.
- **WASM bindings cannot be tested natively** — `JsValue` types abort on non-wasm targets. The underlying logic is covered by `lib_tests`. For actual WASM integration tests, use `wasm-pack test`.
