# Public Release Checklist

Use this checklist before tagging a release or publishing major changes.

## Code quality

- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy -- -D warnings`
- [ ] `cargo test`
- [ ] `./run_examples.sh`
- [ ] `./scripts/check_output_quality.sh`

## Documentation

- [ ] `README.md` reflects current CLI and behavior
- [ ] `CHANGELOG.md` updated
- [ ] Any new flags/features documented
- [ ] `docs/output-baseline.md` refreshed if quality thresholds changed

## Repository hygiene

- [ ] License file present and correct (`LICENSE`)
- [ ] Governance docs are up to date (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`)
- [ ] Issue and PR templates still match workflow

## Release artifacts

- [ ] Version bumped in `Cargo.toml`
- [ ] Tag created with release notes
- [ ] (Optional) binary artifacts attached to release
