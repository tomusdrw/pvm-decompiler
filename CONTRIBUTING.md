# Contributing Guide

Thanks for contributing to `pvm-decompiler`.

## Development setup

1. Install stable Rust (edition 2024-compatible toolchain).
2. Clone the repository.
3. (Optional) enable local hooks:

```bash
git config core.hooksPath .githooks
```

## Build and test

Run the full local validation before opening a PR:

```bash
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test
./run_examples.sh
./scripts/check_output_quality.sh
```

`./run_examples.sh` must be run before every commit so fixture outputs remain current.

## Coding expectations

- Preserve optimization passes for all program sizes; do not disable passes for large inputs.
- When fixing performance issues, prefer algorithmic improvements (indexes/maps/sets) over pass skipping.
- Add stderr progress reporting for long-running operations; use TTY-friendly `\r` updates where appropriate.
- Keep behavior deterministic where possible (stable ordering for emitted output).
- Add or update tests with functional changes.

## Pull request checklist

- Changes are focused and documented.
- New behavior is covered by tests.
- Example outputs were regenerated if output-affecting code changed.
- Documentation was updated if user-facing behavior changed.

## Reporting issues

Use the issue templates in GitHub for bug reports and feature requests.
