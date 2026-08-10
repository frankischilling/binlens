# PE coverage

BinLens follows `e_lfanew` only after reading a complete 64-byte DOS header and validating the target range. MZ without a PE signature remains a heuristic detection, not a definitive match.

## COFF and optional headers

The COFF tree includes machine, section count, timestamp, optional-header size, and characteristics.

PE32 and PE32+ parsing covers optional-header magic, entry point RVA, image base, section and file alignment, image size, header size, subsystem, DLL characteristics, and data-directory count. Image base uses 32 bits for PE32 and 64 bits for PE32+.

The declared optional-header size bounds every optional field. It must be at least 96 bytes for PE32 or 112 bytes for PE32+ before data directories are considered.

## Data directories

Each available directory has an RVA and size. The parser caps the declared count by the optional-header bytes, the standard 16 directory names, and the configured table budget. Nonempty ranges are checked against `SizeOfImage`.

The certificate table uses a file offset rather than an RVA in the PE specification. BinLens v0.1.0 records the numeric pair but does not apply certificate-specific mapping.

## Sections

Section nodes include the eight-byte escaped name, virtual size and address, raw-data size and offset, and characteristics. Nonempty raw ranges must fit inside the input.

File and section alignments must be nonzero powers of two, and section alignment should not be smaller than file alignment. BinLens reports warnings for inconsistent values rather than trying to load the image.

## Not implemented

The parser does not walk imports, exports, resources, relocations, debug data, or certificates. It does not provide complete RVA to file-offset mapping and never loads or executes a PE image.
