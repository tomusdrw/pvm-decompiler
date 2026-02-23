## Summary

Describe what changed and why.

## Validation

- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy -- -D warnings`
- [ ] `cargo test`
- [ ] `./run_examples.sh` (if output-affecting changes)
- [ ] `./scripts/check_output_quality.sh` (if output-affecting changes)

## Checklist

- [ ] Tests updated/added for new behavior
- [ ] Documentation updated (`README.md`, docs, or changelog)
- [ ] No optimization passes were removed or disabled for large programs
- [ ] Performance-sensitive logic uses indexed lookups where appropriate
