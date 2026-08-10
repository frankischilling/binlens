# Format coverage

The word "supported" below means BinLens parses the named structure, attaches exact spans, and applies the listed basic validations. It does not mean that BinLens implements the complete format specification.

| Format | Detection | Parsed structures | Validation | Deferred |
| --- | --- | --- | --- | --- |
| ELF | `7F 45 4C 46` | `e_ident`, ELF32 and ELF64 headers, program headers, section headers, section names | Class, byte order, header length, entry size, table range, count budget, segment and section file ranges, string-table index and name offsets | Extended numbering, dynamic entries, relocations, symbols, notes beyond table fields, DWARF, architecture flags |
| PE | MZ plus PE signature at `e_lfanew`; MZ alone is heuristic | DOS magic and `e_lfanew`, signature, COFF, PE32 and PE32+ core optional fields, basic data directories, sections | Header ranges, optional magic and size, count budgets, powers-of-two alignment, image directory ranges, section raw ranges | Imports, exports beyond directory fields, resources, relocations, debug contents, certificates, complete RVA mapping |
| NES | `NES 1A` | iNES and NES 2.0 header version, PRG and CHR sizes and bank counts, mapper, submapper, mirroring, battery, trainer, console, trainer and ROM payload spans | Header length, size arithmetic, each payload range, truncated declarations, trailing data | Mapper behavior, archive containers, emulation |
| Game Boy | Nintendo logo bytes at `0104..0134` | Title, CGB flag, cartridge type, ROM and RAM sizes and bank counts, ROM span, destination, version, checksums | Header length, known size codes, declared ROM range, trailing data, header checksum, global checksum under budget | Bank-switch behavior, save-data decoding, code analysis, emulation |
| Game Boy Advance | All 156 Nintendo logo bytes with documented flag masks, plus fixed byte `96` | Logo validity, title, game and maker codes, fixed value, unit, device, software version, header checksum, bounded save-memory signatures | Header length, exact logo mismatch, allowed bits at `009C` and `009E`, fixed value, header checksum, save scan work budget | Payload structures, save-data decoding, code analysis, emulation |

## Partial results

A recognized file can produce a root and early fields even when a later table is outside the file. Such a result sets `partial` and includes diagnostics. `validate` returns status 4 for error diagnostics. Warnings fail only with `--strict`.

## Detection scores

A definitive format signature receives confidence 100. PE files with MZ but no valid PE signature receive a lower heuristic score and a contradiction. Candidates with confidence zero remain in `detect` output so callers can see the complete registry and required minimum lengths.
