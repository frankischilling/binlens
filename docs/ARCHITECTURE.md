# Architecture

BinLens has four layers: checked byte access, a render-independent parse model, first-party format parsers, and user interfaces.

## Checked byte access

`Reader.t` is an `int64` base-and-length window over `Reader_backend.t`. The memory backend owns an immutable byte snapshot. The paged backend owns a read-only file descriptor and one 64 KiB cache page. Reads validate the complete relative range and add the base with checked arithmetic before asking the backend for data.

`Reader.slice` creates another window over the same backend. It does not copy bytes or open another descriptor. The paged backend checks the file size when filling a page, uses checked conversion before seeking, and returns structured setup, read, change-detection, and close failures.

`Input` selects and owns the backend. `Auto` snapshots files up to 512 MiB and uses paged reads above that threshold. `Bytes` and `Paged` force one policy. CLI and TUI commands keep the input open through detection, parsing, rendering, and hexadecimal access, then close it through `Fun.protect`.

`Span.t` stores an `int64` start and length. Construction rejects negative values and an end offset that exceeds signed 64-bit range. A node span must fit inside the input before `Parse_context` accepts it.

`Limits.tracker` counts nodes, table entries, copied bytes, diagnostics, and work. Parsers check declared tables as a complete range before entering a loop.

## Parse model

`Value.t` distinguishes unsigned and signed integers, booleans, enumerations, bitfields, strings, byte summaries, addresses, offsets, collections, absent values, and invalid values. Unsigned values retain their original width and bit pattern.

`Node.t` stores a stable identifier, semantic path, display label, optional description, span, typed value, ordered children, diagnostics, source format, and rendering metadata. Paths such as `pe.coff.timestamp` and `elf.section_headers[2].offset` do not depend on translated or decorated labels.

Diagnostics carry severity, code, message, optional span, component, expected and actual conditions, recoverability, and an optional hint. A parse result can contain a useful tree and still be marked partial.

## Parsers and registry

Each format exports a `Format.parser` record with identity, extensions, coverage, detection, and parsing functions. `Registry.builtins` contains the first-party parsers used by the CLI. The CLI does not switch on file formats itself.

`Registry.create` and `Registry.with_parser` build immutable custom registries. Registration API version 1 accepts lowercase parser identifiers and lowercase file extensions, rejects duplicates, and returns structured errors. Custom registry order is deterministic. Existing calls without `~registry` use `Registry.builtins`.

Registry parsing contains the public exception boundary. Parser code uses `result` values internally. If an unexpected exception reaches the boundary, the registry converts it into `parser.internal_exception` and a partial result. The test suite also calls parser functions directly so this boundary cannot hide parser defects.

A custom parser is ordinary OCaml code linked by the host application and runs with that application's authority. BinLens does not use `Dynlink`, search the inspected file's directory, download packages, or execute plugin commands. A stable native plugin ABI across OCaml compiler versions is not claimed.

## Rendering and comparison

`Render_text` and `Render_json` consume `Node.t`; they do not read format fields. JSON object construction uses fixed association-list order. Unsigned values are strings in both decimal and hexadecimal form.

`Diff` flattens trees into maps keyed by semantic path. It compares format, partial state, value type, value, span, diagnostic signature, and optional bounded raw ranges. Display labels are not match keys.

## Command and TUI layers

Cmdliner owns argument parsing and maps command failures to the documented statuses. JSON commands keep operational messages on stderr. Every file command accepts the same backend policy.

The TUI parses once. `Model` stores expansion, selection, pane, search, display toggles, and terminal dimensions. `Hex_view` builds only the visible byte window. `terml` handles input and terminal commands, while `terminal_size` provides portable resize polling. Cleanup restores raw mode, cursor visibility, line wrapping, and the primary screen through `Fun.protect`.
