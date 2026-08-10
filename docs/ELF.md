# ELF coverage

BinLens reads ELF32 and ELF64 files in little-endian or big-endian form.

## Main header

The parser exposes magic, class, byte order, object type, machine, version, entry point, program-header offset, section-header offset, flags, header size, table entry sizes and counts, and the section-name string-table index.

Object and machine names cover common values. Unknown values remain exact unsigned integers.

For MIPS files, BinLens names the no-reorder, PIC, CPIC, XGOT, obsolete microcode, ABI2, options-first, 32-bit-mode, FP64, and NaN-2008 bits. For ARM, it names relocation-executable, entry-present, interworking, APCS, PIC, alignment, ABI, floating-point, and EABI-version fields. For RISC-V, it names compressed instructions, the floating-point ABI, embedded ABI, total-store-ordering, and RV64ILP32 fields.

The original 32-bit value remains in the typed bitfield, so unknown bits are not discarded. Other machine flag fields stay as exact unsigned values.

## Program headers

ELF32 entries expose type, file offset, virtual and physical addresses, file and memory sizes, flags, and alignment. ELF64 uses the format's different field order and widths. A nonempty file range must fit inside the input.

The declared entry size must be at least 32 bytes for ELF32 or 56 bytes for ELF64. Larger entries remain represented by their full declared span, while known child fields use their specification widths.

## Section headers and names

ELF32 and ELF64 section entries expose name offset, type, flags, address, file offset, size, link, information, alignment, and element size. `SHT_NOBITS` sections do not require file-backed contents. Other nonempty ranges are checked against the input.

If `e_shstrndx` names a valid, in-file string table, section names are read with the configured string limit. Invalid indexes and name offsets produce warnings. Names are escaped before display.

## Extended numbering

BinLens resolves the three standard extended-numbering markers through section header zero:

- `e_phnum == PN_XNUM` uses `sh_info`.
- `e_shnum == 0` with a nonzero section-table offset uses `sh_size`.
- `e_shstrndx == SHN_XINDEX` uses `sh_link`.

The complete section-zero entry must fit in the file before any of these values are read. Resolved counts pass the same table-entry budget as ordinary counts before conversion or iteration. A zero section count paired with a zero section-table offset still means that no section table is present.

## Section metadata

`SHT_SYMTAB` and `SHT_DYNSYM` entries expose the name offset, resolved name, value, size, binding, symbol type, visibility, and section index. Names are accepted only from the complete `SHT_STRTAB` section selected by `sh_link`.

`SHT_DYNAMIC` entries expose the signed tag and unsigned value. Common string tags, including `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and `DT_RUNPATH`, also expose their bounded string value when the linked string table is valid.

`SHT_REL` and `SHT_RELA` entries expose the relocation offset, raw information, symbol index, relocation type, and addend where present. BinLens checks the linked symbol-table index and target section index. It does not apply relocations.

`SHT_NOTE` records expose name size, descriptor size, type, sanitized name, and a short descriptor summary. Four-byte padding is included in each record span. Note counts share the table budget, note names share the string and copy budgets, and descriptor summaries read at most 16 bytes.

The `.debug_abbrev`, `.debug_addr`, `.debug_aranges`, `.debug_frame`, `.debug_info`, `.debug_line`, `.debug_line_str`, `.debug_loc`, `.debug_loclists`, `.debug_names`, `.debug_pubnames`, `.debug_pubtypes`, `.debug_ranges`, `.debug_rnglists`, `.debug_str`, `.debug_str_offsets`, `.debug_types`, `.eh_frame`, and `.zdebug_*` names receive a `dwarf_section` marker. Their payloads remain opaque.

## Validation

Metadata entry sizes must be nonzero and at least as large as the class-specific structure. The parser validates each complete table range before iterating. Remainder bytes, invalid links, out-of-table strings, oversized counts, malformed note sizes, and unrepresentable offsets produce stable diagnostics and partial output where appropriate.

## Not implemented

BinLens does not perform dynamic loading, apply relocations, decode DWARF payloads, interpret symbol versioning or hash tables, or decode every architecture-specific flag.
