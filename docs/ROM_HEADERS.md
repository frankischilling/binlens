# ROM header coverage

ROM support is limited to cartridge headers. BinLens neither downloads ROMs nor interprets game code.

## NES

The parser recognizes `NES 1A`, distinguishes iNES from NES 2.0, and reports PRG and CHR sizes, bank counts, mapper, submapper for NES 2.0, mirroring, battery-backed memory, trainer presence, and console type.

Linear NES 2.0 sizes combine the lower and upper size bits with checked multiplication. Exponent and multiplier sizes reject values that cannot fit safely. The parser creates `nes.payload.trainer`, `nes.payload.prg_rom`, and `nes.payload.chr_rom` only when each complete range fits inside the file. These nodes refer to source spans and do not copy payload bytes.

A declared payload larger than the file marks the parse partial. Extra bytes after the declared payload produce a warning because some tools and containers append data intentionally.

## Game Boy and Game Boy Color

Detection uses the 48 Nintendo logo bytes. The parser reads the title length appropriate to the CGB flag, cartridge type, ROM and RAM size codes, destination, version, stored header checksum, and stored global checksum.

The header checksum covers `0134..014C`. The global checksum sums the file except `014E..014F`. BinLens skips the global pass and reports a warning when the file length exceeds the work budget.

Declared ROM size codes include the standard powers of two and codes `52`, `53`, and `54`. BinLens reports ROM and external RAM bank counts. It creates `gameboy.rom_payload` only when the complete declared ROM fits in the inspected snapshot. A truncated declaration marks the parse partial, while trailing bytes produce a warning.

## Game Boy Advance

Detection validates all 156 Nintendo logo bytes at `0004..009F` and checks fixed byte `96` at `00B2`. The comparison permits documented flag bits 2 and 7 at `009C` and key bits 0 and 1 at `009E`. The parser reads the title, game code, maker code, unit code, device type, software version, and header checksum. It validates the fixed byte and complement checksum over `00A0..00BC`. A logo mismatch diagnostic points to the first bad byte.

The GBA header has no save-memory field. BinLens scans the ROM for the SDK strings `EEPROM_V`, `SRAM_V`, `FLASH_V`, `FLASH512_V`, and `FLASH1M_V`. The scan consumes one work unit per candidate offset and stops at the configured work limit. A match is a heuristic because unused library code can leave more than one signature in a ROM.

Payload decoding, save-data decoding, and executable analysis remain outside the parser.

## Test data

`test/fixture_builder.ml` creates every ROM fixture from byte assignments and checksum calculations. NES and Game Boy fixtures use zero-filled synthetic payloads sized from their headers. They contain no game code or commercial data. Run the generator described in [examples](../examples/README.md) when you need files for manual inspection.
