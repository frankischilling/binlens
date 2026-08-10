# ROM header coverage

ROM support is limited to cartridge headers. BinLens neither downloads ROMs nor interprets game code.

## NES

The parser recognizes `NES 1A`, distinguishes iNES from NES 2.0, and reports PRG and CHR sizes, mapper, submapper for NES 2.0, mirroring, battery-backed memory, trainer presence, and console type.

Linear NES 2.0 sizes combine the lower and upper size bits with checked multiplication. Exponent and multiplier sizes reject values that cannot fit safely. The declared header, optional trainer, PRG, and CHR total is compared with the file length without allocating the payload.

## Game Boy and Game Boy Color

Detection uses the 48 Nintendo logo bytes. The parser reads the title length appropriate to the CGB flag, cartridge type, ROM and RAM size codes, destination, version, stored header checksum, and stored global checksum.

The header checksum covers `0134..014C`. The global checksum sums the file except `014E..014F`. BinLens skips the global pass and reports a warning when the file length exceeds the work budget.

Declared ROM size codes include the standard powers of two and codes `52`, `53`, and `54`. A mismatch with the inspected snapshot is a warning.

## Game Boy Advance

Detection uses the opening Nintendo logo bytes and fixed byte `96` at `00B2`. The parser reads the title, game code, maker code, unit code, device type, software version, and header checksum. It validates the fixed byte and complement checksum over `00A0..00BC`.

Full logo comparison, save-memory type detection, payload structures, and executable analysis are deferred.

## Test data

`test/fixture_builder.ml` creates every ROM fixture from byte assignments and checksum calculations. The generated files contain no game payload. Run the generator described in [examples](../examples/README.md) when you need files for manual inspection.
