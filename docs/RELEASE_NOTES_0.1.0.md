# BinLens 0.1.0

BinLens 0.1.0 is the first public release of the OCaml parsing library and terminal explorer.

The release can inspect ELF32 and ELF64 files in either byte order, PE32 and PE32+ headers, iNES and NES 2.0 headers, Game Boy and Game Boy Color headers, and Game Boy Advance headers. Parsed fields carry exact byte spans shared by the text renderer, versioned JSON output, structural diff, and interactive hexadecimal view.

The parser treats input as untrusted. Checked arithmetic, bounded reads, table and work budgets, string limits, deterministic rendering, property tests, and every-prefix truncation tests guard the public parsing boundary. Recognized but damaged files return typed diagnostics and safe partial output when possible.

This release does not claim complete ELF or PE support. Dynamic linking details, relocations, symbols, DWARF, PE imports and resources, executable payload analysis, and emulation remain outside the documented v0.1.0 scope. See `docs/FORMAT_COVERAGE.md` for the field-level contract.

Release downloads include source, native command-line binaries for the supported workflow runners, and `SHA256SUMS`.
