# ELF coverage

BinLens reads ELF32 and ELF64 files in little-endian or big-endian form.

## Main header

The parser exposes magic, class, byte order, object type, machine, version, entry point, program-header offset, section-header offset, flags, header size, table entry sizes and counts, and the section-name string-table index.

Object and machine names cover common values. Unknown values remain exact unsigned integers.

## Program headers

ELF32 entries expose type, file offset, virtual and physical addresses, file and memory sizes, flags, and alignment. ELF64 uses the format's different field order and widths. A nonempty file range must fit inside the input.

The declared entry size must be at least 32 bytes for ELF32 or 56 bytes for ELF64. Larger entries remain represented by their full declared span, while known child fields use their specification widths.

## Section headers and names

ELF32 and ELF64 section entries expose name offset, type, flags, address, file offset, size, link, information, alignment, and element size. `SHT_NOBITS` sections do not require file-backed contents. Other nonempty ranges are checked against the input.

If `e_shstrndx` names a valid, in-file string table, section names are read with the configured string limit. Invalid indexes and name offsets produce warnings. Names are escaped before display.

## Not implemented

Extended section numbering is not interpreted in v0.1.0. The parser also stops at table structure: it does not interpret dynamic linking, relocation semantics, symbol tables, DWARF, or architecture-specific flags.
