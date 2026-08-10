# PE coverage

BinLens follows `e_lfanew` only after reading a complete 64-byte DOS header and validating the target range. MZ without a PE signature remains a heuristic detection, not a definitive match.

## COFF and optional headers

The COFF tree includes machine, section count, timestamp, optional-header size, and characteristics.

PE32 and PE32+ parsing covers optional-header magic, entry point RVA, image base, section and file alignment, image size, header size, subsystem, DLL characteristics, and data-directory count. Image base uses 32 bits for PE32 and 64 bits for PE32+.

The declared optional-header size bounds every optional field. It must be at least 96 bytes for PE32 or 112 bytes for PE32+ before data directories are considered.

## RVA mapping

BinLens builds an internal map from `SizeOfHeaders` and the section table. A section-backed range must fit both the section's virtual extent and its raw-data range. It must also fit the input snapshot. A range that maps through two overlapping sections is rejected as ambiguous.

The certificate directory is the PE exception: its address is a file offset, not an RVA. BinLens applies that rule before parsing certificate records.

Mapped content appears under `pe.directory_mappings[index]`. The data-directory pair keeps its original eight-byte span, while the mapped node uses the exact file-backed span.

## Exports and imports

The export parser reads the 40-byte export directory, module name, function table, name pointer table, and ordinal table. Named exports expose their name RVA, name, ordinal index, public ordinal, and function RVA. Counts must pass the shared table and work budgets before iteration.

Import descriptors are 20 bytes and must end with a complete null descriptor inside the declared directory. The parser reads library names and the lookup thunk table. PE32 uses four-byte thunks and PE32+ uses eight-byte thunks. Each nonzero thunk exposes either an ordinal or a hint and bounded import name.

BinLens does not resolve forwarded exports, delay imports, bound imports, or import-address-table state after loading.

## Resources

Resource parsing covers directory headers, named and numeric entries, UTF-16LE names, subdirectories, data entries, code pages, and mapped payload spans. Payload bytes are not decoded or copied into the tree.

Relative offsets must remain inside the declared resource directory. A visited-offset set stops cycles and repeated directory references. `max_depth` stops nested directory traversal, while entry and work budgets bound each level.

## Relocations, debug records, and certificates

Base-relocation blocks expose page RVAs, block sizes, relocation types, and page offsets. Blocks smaller than eight bytes, entries with incomplete two-byte values, and blocks that cross the declared table are rejected.

Debug directory records use the fixed 28-byte layout. BinLens exposes the core fields and checks nonempty file pointers, but it does not follow PDB paths or interpret CodeView payloads.

Certificate records expose `dwLength`, revision, type, and a short byte summary. Record lengths must be at least eight bytes, remain inside the directory, and advance on an eight-byte boundary. BinLens does not verify Authenticode signatures.

## Sections and alignment

Section nodes include the eight-byte escaped name, virtual size and address, raw-data size and offset, and characteristics. Nonempty raw ranges must fit inside the input.

File and section alignments must be nonzero powers of two, and section alignment should not be smaller than file alignment. BinLens reports warnings for inconsistent values rather than trying to load the image.

## Not implemented

BinLens does not load or execute images, decode resource payloads, follow external debug files, verify Authenticode, interpret CLR metadata, or parse architecture-specific directory payloads. TLS, exception, load-configuration, bound-import, delay-import, and CLR directories remain numeric directory records unless covered above.
