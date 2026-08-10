# Changelog

## Unreleased

- Resolve ELF extended numbering through section header zero before table iteration.
- Decode bounded ELF symbol, dynamic, REL, RELA, and note records with exact spans.
- Identify common DWARF section names and selected MIPS, ARM, and RISC-V header flags.
- Map PE header and section RVAs to checked file ranges and reject ambiguous overlaps.
- Parse PE export names and ordinals plus PE32 and PE32+ import thunks.
- Walk PE resource metadata with cycle, depth, string, entry, and work limits.
- Parse PE base-relocation blocks, debug directory records, and certificate records.
- Add registration API version 1 for immutable custom parser registries.
- Validate duplicate and malformed parser identifiers and file extensions.
- Apply the built-in detector and parser exception boundaries to custom registries.
- Add a compiled custom-registry example while keeping runtime library loading disabled.
- Validate all 156 Game Boy Advance Nintendo logo bytes with documented flag masks and attach exact mismatch diagnostics.
- Detect Game Boy Advance save-memory SDK strings under the parser work budget.
- Add NES trainer, PRG ROM, and CHR ROM spans plus PRG and CHR bank counts.
- Add Game Boy ROM and external RAM bank counts and a checked ROM-image span.
- Mark truncated declared ROM payloads partial and report trailing bytes separately.
- Add a bounded 64 KiB paged file backend for inputs above the 512 MiB byte-snapshot limit.
- Keep reader slices as shared windows over either backend and preserve structured setup, read, change-detection, and close failures.
- Add `--backend auto|bytes|paged` to file commands and record the selected backend in JSON schema 1.1.
- Exercise both input backends with unit, property, CLI, sparse-file, cleanup, and random-read benchmark coverage.

## 0.1.0

Initial release.

- Added a bounded reader with checked arithmetic, endian-aware integer operations, bounded strings, slices, and parser budgets.
- Added typed parse trees with exact byte spans, stable semantic paths, metadata, and structured diagnostics.
- Added core ELF32, ELF64, PE32, PE32+, iNES, NES 2.0, Game Boy, Game Boy Color, and Game Boy Advance header inspection.
- Added automatic detection, text inspection, versioned JSON, validation, structural diff, and an interactive synchronized hexadecimal view.
- Added generated fixtures, unit tests, every-prefix truncation tests, randomized properties, CLI integration tests, TUI model tests, and a benchmark harness.
- Added CI for OCaml 5.1.1 and 5.5.0 on Ubuntu, macOS, and Windows, plus coverage, scheduled parser hardening, documentation, and tag-release workflows.

Known format limits are recorded in [docs/FORMAT_COVERAGE.md](docs/FORMAT_COVERAGE.md).
