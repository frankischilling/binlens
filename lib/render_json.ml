let option field convert = function
  | None -> []
  | Some value -> [ (field, convert value) ]

let span span =
  `Assoc
    [ ("offset", `String (Int64.to_string (Span.start span)));
      ("offset_hex", `String (Printf.sprintf "0x%Lx" (Span.start span)));
      ("length", `String (Int64.to_string (Span.length span)));
      ( "end",
        match Span.end_offset span with
        | Ok value -> `String (Int64.to_string value)
        | Error _ -> `Null )
    ]

let numeric numeric =
  `Assoc
    [ ("width", `Int numeric.Value.width);
      ("decimal", `String (Unsigned.to_decimal numeric.value));
      ("hex", `String (Unsigned.to_hex numeric.value))
    ]

let value = function
  | Value.Unsigned number ->
      `Assoc [ ("type", `String "unsigned"); ("number", numeric number) ]
  | Signed { width; value } ->
      `Assoc
        [ ("type", `String "signed");
          ("width", `Int width);
          ("decimal", `String (Int64.to_string value))
        ]
  | Boolean value ->
      `Assoc [ ("type", `String "boolean"); ("value", `Bool value) ]
  | Enumeration { raw; name } ->
      `Assoc
        ([ ("type", `String "enumeration"); ("raw", numeric raw) ]
        @ option "name" (fun name -> `String name) name)
  | Bitfield { raw; flags } ->
      `Assoc
        [ ("type", `String "bitfield");
          ("raw", numeric raw);
          ( "flags",
            `List
              (List.map
                 (fun (name, set) ->
                   `Assoc [ ("name", `String name); ("set", `Bool set) ])
                 flags) )
        ]
  | String { text; raw_hex; valid_utf8 } ->
      `Assoc
        ([ ("type", `String "string");
           ("text", `String text);
           ("valid_utf8", `Bool valid_utf8)
         ]
        @ option "raw_hex" (fun raw -> `String raw) raw_hex)
  | Bytes { summary; length } ->
      `Assoc
        [ ("type", `String "bytes");
          ("summary", `String summary);
          ("length", `String (Int64.to_string length))
        ]
  | Address number ->
      `Assoc [ ("type", `String "address"); ("number", numeric number) ]
  | Offset number ->
      `Assoc [ ("type", `String "offset"); ("number", numeric number) ]
  | Collection count ->
      `Assoc [ ("type", `String "collection"); ("count", `Int count) ]
  | Null -> `Assoc [ ("type", `String "null") ]
  | Invalid message ->
      `Assoc [ ("type", `String "invalid"); ("message", `String message) ]

let diagnostic diagnostic =
  `Assoc
    ([ ( "severity",
         `String (Diagnostic.severity_to_string diagnostic.Diagnostic.severity)
       );
       ("code", `String diagnostic.code);
       ("message", `String diagnostic.message);
       ("component", `String diagnostic.component);
       ("recoverable", `Bool diagnostic.recoverable)
     ]
    @ option "span" span diagnostic.span
    @ option "expected" (fun value -> `String value) diagnostic.expected
    @ option "actual" (fun value -> `String value) diagnostic.actual
    @ option "hint" (fun value -> `String value) diagnostic.hint)

let metadata metadata =
  `Assoc
    (option "endian"
       (fun endian -> `String (Endian.to_string endian))
       metadata.Node.endian
    @ option "numeric_base"
        (fun base ->
          `String
            (match base with
            | `Decimal -> "decimal"
            | `Hexadecimal -> "hexadecimal"))
        metadata.numeric_base
    @ option "raw" (fun value -> `String value) metadata.raw)

let rec node current =
  `Assoc
    ([ ("id", `String current.Node.id);
       ("path", `String current.path);
       ("label", `String current.label);
       ("span", span current.span);
       ("value", value current.value);
       ("source_format", `String current.source_format);
       ("metadata", metadata current.metadata);
       ("diagnostics", `List (List.map diagnostic current.diagnostics));
       ("children", `List (List.map node current.children))
     ]
    @ option "description" (fun value -> `String value) current.description)

let detection (detection : Format.detection) =
  `Assoc
    [ ("format", `String detection.Format.format_id);
      ("display_name", `String detection.display_name);
      ("confidence", `Int detection.confidence);
      ("definitive", `Bool detection.definitive);
      ( "required_minimum_length",
        `String (Int64.to_string detection.required_minimum_length) );
      ( "evidence",
        `List (List.map (fun value -> `String value) detection.evidence) );
      ( "contradictions",
        `List (List.map (fun value -> `String value) detection.contradictions)
      )
    ]

let limits limits =
  `Assoc
    [ ("max_nodes", `Int limits.Limits.max_nodes);
      ("max_table_entries", `Int limits.max_table_entries);
      ("max_string_bytes", `Int limits.max_string_bytes);
      ("max_depth", `Int limits.max_depth);
      ("max_total_bytes_copied", `Int limits.max_total_bytes_copied);
      ("max_diagnostics", `Int limits.max_diagnostics);
      ("max_work_units", `Int limits.max_work_units)
    ]

let document ~filename ~input_size ~detections ~selected_detection
    ~limits:limits_value parse_result =
  `Assoc
    [ ("schema_version", `String Version.schema_version);
      ("binlens_version", `String Version.version);
      ( "input",
        `Assoc
          [ ("filename", `String filename);
            ("size", `String (Int64.to_string input_size))
          ] );
      ( "detected_format",
        match selected_detection with
        | None -> `Null
        | Some value -> detection value );
      ("detections", `List (List.map detection detections));
      ("limits", limits limits_value);
      ("partial", `Bool parse_result.Format.partial);
      ("limit_reached", `Bool parse_result.limit_reached);
      ("diagnostics", `List (List.map diagnostic parse_result.diagnostics));
      ( "tree",
        match parse_result.root with None -> `Null | Some root -> node root )
    ]

let to_string json = Yojson.Safe.pretty_to_string ~std:true json ^ "\n"
