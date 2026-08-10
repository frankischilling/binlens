# Changelog

## Unreleased

- Add registration API version 1 for immutable custom parser registries.
- Validate duplicate and malformed parser identifiers and file extensions.
- Apply the built-in detector and parser exception boundaries to custom registries.
- Add a compiled custom-registry example while keeping runtime library loading disabled.
- Validate all 156 Game Boy Advance Nintendo logo bytes with documented flag masks and attach exact mismatch diagnostics.
- Detect Game Boy Advance save-memory SDK strings under the parser work budget.
- Add NES trainer, PRG ROM, and CHR ROM spans plus PRG and CHR bank counts.
- Add Game Boy ROM and external RAM bank counts and a checked ROM-image span.
- Mark truncated declared ROM payloads partial and report trailing bytes separately.

## 0.1.0

Initial release.

- Added a bounded reader with checked arithmetic, endian-aware integer operations, bounded strings, slices, and parser budgets.
- Added typed parse trees with exact byte spans, stable semantic paths, metadata, and structured diagnostics.
- Added core ELF32, ELF64, PE32, PE32+, iNES, NES 2.0, Game Boy, Game Boy Color, and Game Boy Advance header inspection.
- Added automatic detection, text inspection, versioned JSON, validation, structural diff, and an interactive synchronized hexadecimal view.
- Added generated fixtures, unit tests, every-prefix truncation tests, randomized properties, CLI integration tests, TUI model tests, and a benchmark harness.
- Added CI for OCaml 5.1.1 and 5.5.0 on Ubuntu, macOS, and Windows, plus coverage, scheduled parser hardening, documentation, and tag-release workflows.

Known format limits are recorded in [docs/FORMAT_COVERAGE.md](docs/FORMAT_COVERAGE.md).
