# Development

## Toolchain

The supported OCaml range is 5.1.1 through 5.5.x. The local release build uses 5.3.0. CI also checks the minimum and latest supported versions.

```console
opam switch create . 5.3.0
opam install . --deps-only --with-test --with-doc --with-dev-setup
```

`terml` supplies terminal input and commands. `terminal_size` supplies portable dimensions. Both build on the native Windows opam switch used for local testing.

## Common checks

```console
opam exec -- dune fmt --check
opam exec -- dune build @all
opam exec -- dune runtest
opam exec -- dune build @doc
opam lint .
python scripts/check_markdown_links.py
```

The test executables can run separately:

```console
dune exec test/test_reader.exe
dune exec test/test_tree.exe
dune exec test/test_formats.exe
dune exec test/test_diff.exe
dune exec test/test_arbitrary.exe
dune exec test/test_tui.exe
dune exec test/test_cli.exe
```

Set `BINLENS_QCHECK_COUNT=10000` for the scheduled hardening count.

## Fixtures

`test/fixture_builder.ml` writes integers in either byte order and creates minimal headers for each supported format. Tests mutate magic, class, offsets, counts, sizes, indexes, alignments, and checksums through the same builder.

Every prefix from zero bytes through full fixture length is parsed. A truncation case may return a full result, partial result, or typed error. It must not raise.

Generate manual files with:

```console
dune exec examples/generate_fixtures.exe -- examples/generated
```

The output directory is ignored by Git.

## Coverage

```console
mkdir _coverage
BISECT_FILE=$PWD/_coverage/bisect dune runtest --instrument-with bisect_ppx --force
bisect-ppx-report summary --coverage-path _coverage
bisect-ppx-report html --coverage-path _coverage --output _coverage/html
```

On PowerShell, set `$env:BISECT_FILE` to an absolute prefix before `dune runtest`.

## Benchmarks

```console
dune exec bench/bench.exe
```

The harness measures sequential reads, ELF and PE parsing, text and JSON rendering, structural diff, and hex-window rendering. Results are local measurements. Do not put a performance claim in the README without recording the compiler, operating system, hardware, command, iteration count, and output.

## Adding a parser

1. Add a module under `lib/formats` that exports a `Format.parser` record.
2. Read file data only through `Reader`.
3. Check table count, multiplication, and the full range before iteration.
4. Build stable paths from format fields, not labels.
5. Add the parser to `Registry.parsers` in deterministic order.
6. Add generated valid and malformed fixtures, every-prefix truncation coverage, and arbitrary-input execution.
7. Update format coverage and schema examples if new value types or metadata are needed.

Keep exceptions inside a helper only when the helper catches and converts them before returning. Public parser calls must return structured results.
