# Synthetic examples

BinLens does not ship third-party executables or commercial ROM images. The fixture generator writes small binaries from source code in `test/fixture_builder.ml`.

```console
dune exec examples/generate_fixtures.exe -- examples/generated
dune exec binlens -- inspect examples/generated/minimal-elf64-le.elf
dune exec binlens -- inspect examples/generated/directories-pe32.exe
dune exec binlens -- tui examples/generated/directories-pe32-plus.exe
```

The generated files are test data, not runnable programs or games. You can delete `examples/generated` at any time and recreate it with the same command.
