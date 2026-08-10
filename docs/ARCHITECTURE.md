# Architecture

BinLens has four layers: checked byte access, a render-independent parse model, first-party format parsers, and user interfaces.

## Checked byte access

`Reader.t` is a window over immutable bytes. A window stores an `int64` base and length. Reads validate the complete relative range, add the base with checked arithmetic, and only then convert the absolute offset to OCaml `int` for byte indexing.

`Span.t` stores an `int64` start and length. Construction rejects negative values and an end offset that exceeds signed 64-bit range. A node span must fit inside the input before `Parse_context` accepts it.

`Limits.tracker` counts nodes, table entries, copied bytes, diagnostics, and work. Parsers check declared tables as a complete range before entering a loop.

## Parse model

`Value.t` distinguishes unsigned and signed integers, booleans, enumerations, bitfields, strings, byte summaries, addresses, offsets, collections, absent values, and invalid values. Unsigned values retain their original width and bit pattern.

`Node.t` stores a stable identifier, semantic path, display label, optional description, span, typed value, ordered children, diagnostics, source format, and rendering metadata. Paths such as `pe.coff.timestamp` and `elf.section_headers[2].offset` do not depend on translated or decorated labels.

Diagnostics carry severity, code, message, optional span, component, expected and actual conditions, recoverability, and an optional hint. A parse result can contain a useful tree and still be marked partial.

## Parsers and registry

Each format exports a `Format.parser` record with identity, extensions, coverage, detection, and parsing functions. `Registry.all` is the first-party registry. The CLI does not switch on file formats itself.

`Registry.safe_parse` is the public exception boundary. Parser code uses `result` values internally. If an unexpected exception reaches the boundary, the registry converts it into `parser.internal_exception` and a partial result. The test suite also calls parser functions directly so this boundary cannot hide parser defects.

Dynamic third-party loading is outside v0.1.0. A future plugin interface would need versioned types, explicit trust rules, and isolation from the inspected file's directory.

## Rendering and comparison

`Render_text` and `Render_json` consume `Node.t`; they do not read format fields. JSON object construction uses fixed association-list order. Unsigned values are strings in both decimal and hexadecimal form.

`Diff` flattens trees into maps keyed by semantic path. It compares format, partial state, value type, value, span, diagnostic signature, and optional bounded raw ranges. Display labels are not match keys.

## Command and TUI layers

Cmdliner owns argument parsing and maps command failures to the documented statuses. JSON commands keep operational messages on stderr.

The TUI parses once. `Model` stores expansion, selection, pane, search, display toggles, and terminal dimensions. `Hex_view` builds only the visible byte window. `terml` handles input and terminal commands, while `terminal_size` provides portable resize polling. Cleanup restores raw mode, cursor visibility, line wrapping, and the primary screen through `Fun.protect`.
