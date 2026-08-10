# JSON schema notes

`binlens json FILE` writes one UTF-8 JSON document to stdout. Operational errors go to stderr. `--output FILE` redirects the document and leaves stdout empty.

## Versioning

The top-level `schema_version` is `1.0` for BinLens v0.1.0. A new incompatible shape will change the major schema component. New optional fields may appear in a compatible minor schema revision.

## Top-level object

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | JSON contract version. |
| `binlens_version` | string | Program or library version that produced the document. |
| `input` | object | Filename and decimal byte size string. |
| `detected_format` | detection or null | Detection record for the selected parser. |
| `detections` | array | Every registry candidate in confidence and format-ID order. |
| `limits` | object | Effective parser budgets. |
| `partial` | boolean | At least one requested structure could not be parsed safely. |
| `limit_reached` | boolean | A parser budget stopped work. |
| `diagnostics` | array | Parse-level diagnostics. |
| `tree` | node or null | Parsed tree. |

## Detection

A detection record contains `format`, `display_name`, integer `confidence`, boolean `definitive`, decimal string `required_minimum_length`, ordered `evidence`, and ordered `contradictions`.

## Node

Nodes use this fixed field order:

1. `id`
2. `path`
3. `label`
4. `span`
5. `value`
6. `source_format`
7. `metadata`
8. `diagnostics`
9. `children`
10. optional `description`

`id` is stable within its parent. `path` is the structural diff key. Labels and descriptions are for display.

## Spans

```json
{
  "offset": "24",
  "offset_hex": "0x18",
  "length": "8",
  "end": "32"
}
```

Offsets, lengths, and ends are decimal strings. This avoids runtime-specific JSON integer limits. `end` is null only if an invalid internal span reached rendering, which parser context rejects in normal results.

## Typed values

Each value has a `type`. Numeric records include `width`, exact decimal text, and hexadecimal text.

```json
{
  "type": "address",
  "number": {
    "width": 64,
    "decimal": "18446744073709551615",
    "hex": "0xffffffffffffffff"
  }
}
```

Other types are `signed`, `boolean`, `enumeration`, `bitfield`, `string`, `bytes`, `offset`, `collection`, `null`, and `invalid`. Enumeration names are optional because specifications permit unknown numeric values.

String text is terminal-safe escaped text. `raw_hex` is optional. `valid_utf8` describes the parser's current interpretation and does not change the stored source bytes.

## Diagnostics

Diagnostics contain `severity`, `code`, `message`, `component`, and `recoverable`. Optional fields are `span`, `expected`, `actual`, and `hint`. Codes such as `reader.out_of_bounds`, `limit.table_entries`, and `pe.missing_signature` are the stable machine keys.

## Determinism

Registry order, child order, diagnostic order, object field order, and diff order are deterministic for the same input, parser version, options, and limits. BinLens does not include timestamps in JSON output.
