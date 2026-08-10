# Parser safety

BinLens treats the entire file as hostile. A matching magic value raises detection confidence; it does not make later counts, sizes, offsets, or strings trustworthy.

## Read invariants

Every file read goes through `Reader`. A read succeeds only when all of these conditions hold:

1. The relative offset and length are nonnegative.
2. Offset plus length fits in signed 64-bit range.
3. The complete range fits in the reader window.
4. Window base plus relative offset fits in signed 64-bit range.
5. The absolute byte index fits in the OCaml runtime's `int`.

Integer reads check the complete width before reading the first byte. Slices share input. Byte and string copies consume the copy budget when a parser tracker is supplied.

## Arithmetic and table rules

`Reader.checked_add` and `Reader.checked_mul` reject negative operands and overflow. `Reader.table_range` checks entry size times count, then validates the full range. A parser checks the table-entry budget before iterating.

ELF and PE offsets whose unsigned bit pattern exceeds signed 64-bit range are rejected as invalid ranges. BinLens can display those values exactly, but the byte backend cannot address them.

## Strings and terminal output

C strings scan at most the configured limit and use an iterative loop. Fixed strings copy a declared constant length or a previously checked bounded length.

`Sanitize.text` preserves printable ASCII, doubles backslashes, and writes every control or non-ASCII byte as `\xNN`. Parser labels derived from section names or cartridge headers use this function before text or terminal rendering. Raw bytes remain available through typed metadata or hexadecimal summaries.

## Budgets

The default budgets are:

- 20,000 parse-tree nodes
- 4,096 table entries
- 4,096 bytes in one string
- depth 64
- 16 MiB copied by parser string and byte operations
- 1,000 diagnostics
- 2,000,000 work units
- 512 MiB input for the normal byte backend

The CLI accepts lower or higher nonnegative node, table, string, and depth values. A reached budget sets `limit_reached`, marks the parse partial, and returns status 5. Raising a limit can increase time and memory use.

## Termination

Format loops use validated, budgeted counts. ELF extended counts are read from a complete section-zero entry and checked before conversion to an OCaml integer. ELF symbol, dynamic, relocation, and note records consume both table entries and work units. A zero metadata entry size is rejected before division or iteration. Linked string tables must fit in the input, and string offsets are checked against the linked table.

Null-terminated strings have a maximum. The Game Boy global checksum runs only when the file length fits the work budget. Game Boy Advance save-signature detection consumes one work unit for each candidate byte offset and stops when the budget is exhausted. Tree depth is fixed by the current parsers and bounded by the model limit.

ROM payload nodes hold spans and lengths. They do not copy trainer, PRG ROM, CHR ROM, or Game Boy ROM bytes into the tree.

The hardening suite calls every parser with arbitrary byte strings, validates every returned node span, checks deterministic output, and parses every prefix of each generated fixture. The scheduled workflow raises QCheck counts to 10,000.

## Input and file changes

The v0.1 byte backend reads a file once and parses that snapshot. It rejects files larger than 512 MiB before allocation. If a file becomes shorter during the read, BinLens returns `input.changed_during_read`. Appends after the initial stat are not included.

Memory mapping and streaming input are deferred. Neither parsing nor detection performs network access, decompression, external commands, dynamic library loading, or code execution.

## Remaining risks

The registry catches unexpected exceptions at the public boundary, but such a diagnostic is still a parser defect. Please report a reproducible `parser.internal_exception` through the security process if it has denial-of-service or memory-safety impact.

OCaml memory allocation can still fail if the host has less memory than a permitted input and configured budgets require. The 512 MiB byte-backend cap limits the request but does not measure current free memory.
