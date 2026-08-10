# BinLens

BinLens is an OCaml library and terminal program for examining binary files. It turns supported headers and tables into a typed tree. Every field carries the exact byte offset and length that produced it, so the text view, JSON document, structural diff, and interactive hexadecimal panel refer to the same source range.

The v0.1 parser covers selected ELF, PE, NES, Game Boy, and Game Boy Advance structures. This is deliberately partial format support. BinLens reports malformed offsets and unsupported structures instead of treating a recognized file as fully understood.

## Install

BinLens requires OCaml 5.1.1 through 5.5.x and opam 2.2 or newer.

Install the tagged release through opam:

```console
opam pin add binlens https://github.com/frankischilling/binlens.git#v0.1.0
```

The package has not yet been submitted to the central opam repository, so `opam install binlens` without a pin is not available for this release.

To build a checkout:

```console
opam switch create . 5.3.0
opam install . --deps-only --with-test --with-doc
opam exec -- dune build
opam exec -- dune runtest
opam install .
```

## Commands

```console
binlens detect program.exe
binlens inspect program.exe
binlens json --output program.json program.exe
binlens validate --strict program.exe
binlens diff --check old.exe new.exe
binlens tui program.exe
binlens formats
binlens version
```

Use `--format elf`, `--format pe`, `--format nes`, `--format gameboy`, or `--format gba` to bypass automatic detection. Parser limits can be changed with `--max-nodes`, `--max-string-bytes`, `--max-table-entries`, and `--max-depth`.

## Text inspection

The synthetic examples contain no third-party executables or commercial ROM data.

```console
$ dune exec examples/generate_fixtures.exe -- examples/generated
Wrote 9 synthetic fixtures to examples/generated

$ dune exec binlens -- inspect examples/generated/minimal-elf64-le.elf --max-depth 1
ELF [0x00000000..0x00000040) = 18 items
  Magic [0x00000000..0x00000004) = 7F 45 4C 46
  Class [0x00000004..0x00000005) = ELF64 (0x02)
  Endianness [0x00000005..0x00000006) = Little endian (0x01)
  Entry point [0x00000018..0x00000020) = 0x0000000000401000
  Program header table [0x00000040..0x00000078) = 1 items
  Section header table [0x00000078..0x00000138) = 3 items
```

The interval `[0x18..0x20)` means the entry point came from eight bytes beginning at file offset `0x18`. The TUI uses that same span to mark bytes in the hexadecimal panel.

## Interactive view

```text
BinLens  minimal-elf64-le.elf  format: ELF  pane: tree
>- ELF                                      |00000000 [7F][45][4C][46] 02  01  01  00
   Magic                                    |00000008  00  00  00  00  00  00  00  00
   Class                                    |00000010  02  00  3E  00  01  00  00  00
   Entry point                              |00000018 [00][10][40][00][00][00][00][00]
elf.entry_point  offset 0x18  size 8
No diagnostics for the selected node.
```

Arrow keys or `j` and `k` move through the tree. `h` and `l` collapse or expand nodes. Press `g` for an offset, `/` to search, `d` for diagnostics, `r` for raw details, `x` to change numeric display, `?` for help, and `q` to quit. [The TUI guide](docs/TUI.md) lists every key.

## JSON export

Unsigned values use decimal and hexadecimal strings, so a 64-bit value never passes through a lossy JSON number.

```json
{
  "schema_version": "1.0",
  "binlens_version": "0.1.0",
  "input": { "filename": "minimal-elf64-le.elf", "size": "329" },
  "detected_format": {
    "format": "elf",
    "confidence": 100,
    "definitive": true
  },
  "partial": false,
  "tree": {
    "path": "elf",
    "span": { "offset": "0", "length": "64", "end": "64" }
  }
}
```

See [the JSON schema notes](docs/JSON_SCHEMA.md) for the complete versioned shape.

## Format coverage

| Format | Implemented in v0.1.0 | Not parsed in v0.1.0 |
| --- | --- | --- |
| ELF | ELF32 and ELF64 identification and main headers, both byte orders, program headers, section headers, section names, file-range checks | Extended numbering, dynamic linking semantics, relocations, symbols, DWARF |
| PE | DOS and PE signatures, COFF, PE32 and PE32+ core fields, basic data directories, sections, alignment and raw-range checks | Imports, resources, relocations, debug contents, complete RVA mapping |
| NES | iNES and NES 2.0 sizes, mapper, submapper, console and storage flags | Payload banks and emulation |
| Game Boy | Title, CGB flag, cartridge metadata, declared sizes, destination, version, header and global checksums | Mapper behavior and payload banks |
| Game Boy Advance | Title and identity fields, unit and device fields, fixed byte, software version, header checksum | Payload structures and save-memory detection |

[Format coverage](docs/FORMAT_COVERAGE.md) records field-level details. Separate notes cover [ELF](docs/ELF.md), [PE](docs/PE.md), and [ROM headers](docs/ROM_HEADERS.md).

## Parser limits and hostile input

BinLens checks every read and offset calculation. Declared counts are capped before allocation or iteration. C strings have an explicit maximum, parser work is budgeted, and byte-derived terminal text escapes control characters.

| Limit | Default |
| --- | ---: |
| Parse-tree nodes | 20,000 |
| Table entries | 4,096 |
| Bytes in one parsed string | 4,096 |
| Tree depth | 64 |
| Total copied bytes | 16 MiB |
| Diagnostics | 1,000 |
| Work units | 2,000,000 |
| Input for the byte backend | 512 MiB |

A limit failure returns status 5. [Parser safety](docs/PARSER_SAFETY.md) describes the trust boundary and remaining risks.

## Exit statuses

| Status | Meaning |
| ---: | --- |
| 0 | The command completed successfully. |
| 1 | A file, output, or other operational failure occurred. |
| 2 | Command syntax or an option value was invalid. |
| 3 | No supported format matched the input. |
| 4 | A format was recognized or forced, but the input was malformed. Partial output may already have been written. |
| 5 | A parser resource limit was reached. |
| 6 | `diff --check` found structural differences. |

## Library

The `binlens` library exposes `Reader`, `Span`, `Node`, `Diagnostic`, `Registry`, `Render_json`, `Render_text`, and `Diff` under the `Binlens` module. Parser entry points return `result` values or `Format.parse_result`; the registry contains the only exception-catching boundary.

`Registry.builtins` is the registry used by the command-line application. An OCaml application can link its own `Format.parser`, then create an immutable registry without editing BinLens source:

```ocaml
let registry =
  match Binlens.Registry.with_parser Binlens.Registry.builtins My_format.parser with
  | Ok registry -> registry
  | Error error -> failwith (Binlens.Error.to_string error)

let result =
  Binlens.Registry.parse ~registry Binlens.Limits.default input_reader
```

Registration API version 1 validates parser identifiers and extensions. BinLens does not discover or load libraries at runtime. A complete compiled example is in [`examples/custom_registry.ml`](examples/custom_registry.ml).

[Architecture](docs/ARCHITECTURE.md) explains module ownership. [Development](docs/DEVELOPMENT.md) covers tests, generated fixtures, documentation, and benchmarks.

## Roadmap

The [v0.1.0 milestone](https://github.com/frankischilling/binlens/milestone/1) tracks the release. Current work is split across [bootstrap](https://github.com/frankischilling/binlens/issues/1), [reader safety](https://github.com/frankischilling/binlens/issues/2), [the tree model](https://github.com/frankischilling/binlens/issues/3), [ELF](https://github.com/frankischilling/binlens/issues/4), [PE](https://github.com/frankischilling/binlens/issues/5), [ROM headers](https://github.com/frankischilling/binlens/issues/6), [CLI and JSON](https://github.com/frankischilling/binlens/issues/7), [TUI](https://github.com/frankischilling/binlens/issues/8), [diff](https://github.com/frankischilling/binlens/issues/9), [hardening](https://github.com/frankischilling/binlens/issues/10), and [release preparation](https://github.com/frankischilling/binlens/issues/11).

BinLens is available under the MIT license. See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change and [SECURITY.md](SECURITY.md) for private vulnerability reports.
