# Changelog

## 0.1.0

Initial release.

- Added a bounded reader with checked arithmetic, endian-aware integer operations, bounded strings, slices, and parser budgets.
- Added typed parse trees with exact byte spans, stable semantic paths, metadata, and structured diagnostics.
- Added core ELF32, ELF64, PE32, PE32+, iNES, NES 2.0, Game Boy, Game Boy Color, and Game Boy Advance header inspection.
- Added automatic detection, text inspection, versioned JSON, validation, structural diff, and an interactive synchronized hexadecimal view.
- Added generated fixtures, unit tests, every-prefix truncation tests, randomized properties, CLI integration tests, TUI model tests, and a benchmark harness.
- Added CI for OCaml 5.1.1 and 5.5.0 on Ubuntu, macOS, and Windows, plus coverage, scheduled parser hardening, documentation, and tag-release workflows.

Known format limits are recorded in [docs/FORMAT_COVERAGE.md](docs/FORMAT_COVERAGE.md).
