# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) while in 0.x development.

## [Unreleased]

### Added

- Public project governance and safety docs:
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
  - `CHANGELOG.md`
- GitHub collaboration templates:
  - issue templates (`bug report`, `feature request`)
  - pull request template
- MIT licensing (`LICENSE`)
- Expanded package metadata in `Cargo.toml`
- CLI `-V`/`--version` support

### Changed

- CLI now exits with status code `2` for invalid usage (unknown option, missing input file, or multiple input files).
- README expanded with install, usage, limitations, and documentation index.
- `docs/output-baseline.md` refreshed from regenerated examples.
