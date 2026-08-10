# Contributing

BinLens accepts focused bug fixes, parser tests, documentation corrections, and format coverage that includes a clear safety argument.

## Before coding

Search existing issues and pull requests. Open or claim an issue when the change affects a parser, public JSON, command behavior, or the TUI. A format request needs a public specification and synthetic or freely licensed test data.

Do not add commercial ROMs, downloaded executables with unclear licenses, or fixtures that cannot be regenerated.

## Build and test

```console
opam install . --deps-only --with-test --with-doc --with-dev-setup
opam exec -- dune fmt
opam exec -- dune build @all
opam exec -- dune runtest
opam exec -- dune build @doc
python scripts/check_markdown_links.py
```

Parser changes need valid, malformed, boundary, and truncation cases. If the format uses file-declared counts or offsets, include cases that exceed the input and configured limits. A parser must not index file bytes outside `Reader`.

## Pull requests

Keep one issue or tightly related group in each pull request. Explain the format subset, checked arithmetic, recovery behavior, and tests. Include `Closes #N` only after every acceptance criterion is met. TUI changes should include a terminal capture when practical.

Run ocamlformat before pushing. Do not mix parser behavior with unrelated renaming or refactoring.
