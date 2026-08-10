# Parser safety

BinLens treats the entire file as hostile. A matching magic value raises detection confidence; it does not make later counts, sizes, offsets, or strings trustworthy.

## Read invariants

Every file read goes through `Reader`. A read succeeds only when all of these conditions hold:

1. The relative offset and length are nonnegative.
2. Offset plus length fits in signed 64-bit range.
3. The complete range fits in the reader window.
4. Window base plus relative offset fits in signed 64-bit range.
5. The absolute offset fits the selected backend's addressing range. Memory indexes and paged seeks use checked conversion to the OCaml runtime's `int`.

Integer reads check the complete width before reading the first byte. Slices share input. Byte and string copies consume the copy budget when a parser tracker is supplied.

## Arithmetic and table rules

`Reader.checked_add` and `Reader.checked_mul` reject negative operands and overflow. `Reader.table_range` checks entry size times count, then validates the full range. A parser checks the table-entry budget before iterating.

ELF and PE offsets whose unsigned bit pattern exceeds signed 64-bit range are rejected as invalid ranges. BinLens can display those values exactly, but neither input backend can address them. The paged backend also rejects an offset that does not fit the runtime's `int` seek range.

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
- 512 MiB for one byte-backend snapshot
- one 64 KiB cache page for each paged input

The CLI accepts lower or higher nonnegative node, table, string, and depth values. A reached budget sets `limit_reached`, marks the parse partial, and returns status 5. Raising a limit can increase time and memory use.

## Termination

Format loops use validated, budgeted counts. ELF extended counts are read from a complete section-zero entry and checked before conversion to an OCaml integer. ELF symbol, dynamic, relocation, and note records consume both table entries and work units. A zero metadata entry size is rejected before division or iteration. Linked string tables must fit in the input, and string offsets are checked against the linked table.

PE RVA mapping checks the header range and every candidate section. A mapped range must fit the section's virtual and raw extents, and overlapping matches are rejected. Export arrays, import descriptors and thunks, relocation blocks, debug records, and certificates consume shared table and work budgets. Import strings stop at the mapped section boundary or the string limit.

PE resource offsets stay inside the declared directory span. Traversal records visited directory offsets to stop cycles and checks `max_depth` before recursion. UTF-16LE resource names must pass both directory bounds and the string-length budget. Resource payload nodes retain spans without copying payload bytes.

Null-terminated strings have a maximum. The Game Boy global checksum runs only when the file length fits the work budget. Game Boy Advance save-signature detection consumes one work unit for each candidate byte offset and stops when the budget is exhausted. Nonrecursive parsers have a fixed structural depth; PE resource traversal checks the configured depth limit.

ROM payload nodes hold spans and lengths. They do not copy trainer, PRG ROM, CHR ROM, or Game Boy ROM bytes into the tree.

The hardening suite calls every parser with arbitrary byte strings, validates every returned node span, checks deterministic output, and parses every prefix of each generated fixture. The scheduled workflow raises QCheck counts to 10,000.

## Input backends and file changes

The byte backend reads a file once and parses that snapshot. It rejects files larger than 512 MiB before allocation. If the size changes while the snapshot is being read, BinLens returns `input.changed_during_read`.

The paged backend holds a read-only descriptor and allocates one 64 KiB page, regardless of file size. It checks the observed size before and after setup and around each page fill. A detected change or short read becomes a structured I/O error. Slices share the same descriptor and cache, so a deeply sliced tree does not increase cache memory.

This is not a transactional file snapshot. An overwrite that preserves file size cannot be detected portably, and a previously cached page can represent an earlier version than a later page. Do not modify a file while BinLens is inspecting it. Windows commonly prevents truncation or removal while the read handle is open; Unix tests exercise active truncation detection, while Windows tests verify initialization and cleanup without depending on pathname mutation.

The paged descriptor and cache are intended for one inspection flow, not concurrent reader calls from several threads. Network, archive, compressed, device, writable, and streaming input remain unsupported. Neither parsing nor detection performs network access, decompression, external commands, dynamic library loading, or code execution.

## Remaining risks

The registry catches unexpected exceptions at the public boundary, but such a diagnostic is still a parser defect. Please report a reproducible `parser.internal_exception` through the security process if it has denial-of-service or memory-safety impact.

OCaml memory allocation can still fail if the host has less memory than a requested byte snapshot or parser allocation. The 512 MiB byte-backend cap limits one snapshot but does not measure current free memory. The paged backend avoids a full-file copy, but parser budgets still govern copied strings, tree nodes, diagnostics, and work.
