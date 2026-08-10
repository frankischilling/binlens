open Cmdliner
open Binlens

let exit_operational = 1
let exit_invalid_arguments = 2
let exit_unrecognized = 3
let exit_malformed = 4
let exit_limit = 5
let exit_different = 6
let stop code = Stdlib.exit code

let print_error error =
  prerr_endline (Sanitize.text (Error.to_string error));
  flush stderr

let output_text destination contents =
  match destination with
  | None ->
      print_string contents;
      flush stdout;
      Ok ()
  | Some filename -> Input.output filename contents

let make_limits max_nodes max_string_bytes max_table_entries max_depth =
  { Limits.default with
    max_nodes;
    max_string_bytes;
    max_table_entries;
    max_depth
  }

let load filename =
  match Input.read filename with
  | Ok input -> input
  | Error error ->
      print_error error;
      stop exit_operational

let parse_input ~format ~limits input =
  match Registry.parse ~format limits input.Input.reader with
  | Ok value -> value
  | Error error ->
      print_error error;
      stop
        (if String.equal error.Error.code "format.unrecognized" then
           exit_unrecognized
         else exit_operational)

let detection_for format_id (detections : Format.detection list) =
  List.find_opt
    (fun (detection : Format.detection) ->
      String.equal detection.Format.format_id format_id)
    detections

let render_json_document input limits parser parse_result =
  let detections = Registry.detect limits input.Input.reader in
  let selected_detection = detection_for parser.Format.id detections in
  Render_json.document ~filename:input.filename ~input_size:input.size
    ~detections ~selected_detection ~limits parse_result
  |> Render_json.to_string

let result_has_error result =
  List.exists
    (fun diagnostic -> diagnostic.Diagnostic.severity = Diagnostic.Error)
    result.Format.diagnostics

let select_subtree root path offset =
  match path with
  | Some path -> Node.find_by_path root path
  | None -> (
      match offset with
      | None -> Some root
      | Some offset -> (
          let point = Span.unsafe ~start:offset ~length:0L in
          let candidates =
            Node.flatten root
            |> List.filter (fun node -> Span.contains node.Node.span point)
            |> List.sort (fun left right ->
                Int64.compare
                  (Span.length left.Node.span)
                  (Span.length right.Node.span))
          in
          match candidates with [] -> None | first :: _ -> Some first))

let run_inspect filename format max_nodes max_string_bytes max_table_entries
    max_depth show_descriptions show_diagnostics show_raw decimal_offsets path
    offset json _no_color output =
  let limits =
    make_limits max_nodes max_string_bytes max_table_entries max_depth
  in
  let input = load filename in
  let parser, result = parse_input ~format ~limits input in
  let contents =
    if json then render_json_document input limits parser result
    else
      match result.Format.root with
      | None -> "No parse tree was produced.\n"
      | Some root -> (
          match select_subtree root path offset with
          | None ->
              prerr_endline
                "The requested semantic path or offset was not found.";
              stop exit_invalid_arguments
          | Some root ->
              Render_text.render root
                ~options:
                  { Render_text.max_depth;
                    show_descriptions;
                    show_diagnostics;
                    show_raw;
                    decimal_offsets
                  })
  in
  (match output_text output contents with
  | Ok () -> ()
  | Error error ->
      print_error error;
      stop exit_operational);
  if result.limit_reached then stop exit_limit;
  if result.root = None || result_has_error result then stop exit_malformed

let run_json filename format max_nodes max_string_bytes max_table_entries
    max_depth output =
  let limits =
    make_limits max_nodes max_string_bytes max_table_entries max_depth
  in
  let input = load filename in
  let parser, result = parse_input ~format ~limits input in
  let contents = render_json_document input limits parser result in
  (match output_text output contents with
  | Ok () -> ()
  | Error error ->
      print_error error;
      stop exit_operational);
  if result.limit_reached then stop exit_limit
  else if result.root = None || result_has_error result then stop exit_malformed

let run_validate filename format strict max_nodes max_string_bytes
    max_table_entries max_depth =
  let limits =
    make_limits max_nodes max_string_bytes max_table_entries max_depth
  in
  let input = load filename in
  let _, result = parse_input ~format ~limits input in
  List.iter
    (fun diagnostic -> prerr_endline (Diagnostic.to_string diagnostic))
    result.Format.diagnostics;
  flush stderr;
  if result.limit_reached then stop exit_limit;
  let has_error =
    List.exists
      (fun diagnostic -> diagnostic.Diagnostic.severity = Diagnostic.Error)
      result.diagnostics
  in
  let has_warning =
    List.exists
      (fun diagnostic -> diagnostic.Diagnostic.severity = Diagnostic.Warning)
      result.diagnostics
  in
  if has_error || (strict && has_warning) || result.root = None then
    stop exit_malformed

let run_detect filename json max_nodes max_string_bytes max_table_entries
    max_depth =
  let limits =
    make_limits max_nodes max_string_bytes max_table_entries max_depth
  in
  let input = load filename in
  let detections = Registry.detect limits input.Input.reader in
  if json then
    `Assoc
      [ ("schema_version", `String Version.schema_version);
        ("input", `String input.filename);
        ("candidates", `List (List.map Render_json.detection detections))
      ]
    |> Render_json.to_string |> print_string
  else
    List.iter
      (fun (detection : Format.detection) ->
        Printf.printf "%s (%s): %d%%\n" detection.Format.format_id
          detection.display_name detection.confidence;
        List.iter
          (fun evidence -> Printf.printf "  evidence: %s\n" evidence)
          detection.evidence;
        List.iter
          (fun contradiction ->
            Printf.printf "  contradiction: %s\n" contradiction)
          detection.contradictions)
      detections;
  flush stdout;
  match detections with
  | best :: _ when best.Format.confidence > 0 -> ()
  | _ -> stop exit_unrecognized

let run_formats json =
  let parsers = Registry.all () in
  if json then
    let coverage parser =
      `Assoc
        [ ("id", `String parser.Format.id);
          ("display_name", `String parser.display_name);
          ( "extensions",
            `List (List.map (fun value -> `String value) parser.extensions) );
          ("summary", `String parser.coverage.summary);
          ( "supported",
            `List
              (List.map (fun value -> `String value) parser.coverage.supported)
          );
          ( "unsupported",
            `List
              (List.map
                 (fun value -> `String value)
                 parser.coverage.unsupported) )
        ]
    in
    `Assoc
      [ ("schema_version", `String Version.schema_version);
        ("formats", `List (List.map coverage parsers))
      ]
    |> Render_json.to_string |> print_string
  else
    List.iter
      (fun parser ->
        Printf.printf "%s: %s\n  %s\n" parser.Format.id parser.display_name
          parser.coverage.summary;
        Printf.printf "  Supported: %s\n"
          (String.concat "; " parser.coverage.supported);
        Printf.printf "  Not parsed: %s\n"
          (String.concat "; " parser.coverage.unsupported))
      parsers;
  flush stdout

let run_diff left_filename right_filename format json check compare_raw
    ignore_paths max_nodes max_string_bytes max_table_entries max_depth output =
  let limits =
    make_limits max_nodes max_string_bytes max_table_entries max_depth
  in
  let left_input = load left_filename and right_input = load right_filename in
  let _, left = parse_input ~format ~limits left_input in
  let _, right = parse_input ~format ~limits right_input in
  let options = { Diff.ignore_paths; compare_raw; max_raw_bytes = 65_536 } in
  let differences =
    Diff.compare ~options ~left_reader:left_input.reader
      ~right_reader:right_input.reader left right
  in
  let contents =
    if json then Diff.to_yojson differences |> Render_json.to_string
    else Diff.render_text differences
  in
  (match output_text output contents with
  | Ok () -> ()
  | Error error ->
      print_error error;
      stop exit_operational);
  if left.limit_reached || right.limit_reached then stop exit_limit;
  if check && differences <> [] then stop exit_different

let run_tui filename format max_nodes max_string_bytes max_table_entries
    max_depth =
  let limits =
    make_limits max_nodes max_string_bytes max_table_entries max_depth
  in
  let input = load filename in
  let parser, result = parse_input ~format ~limits input in
  if result.limit_reached then stop exit_limit;
  match result.Format.root with
  | None ->
      prerr_endline "The parser could not build a tree for this input.";
      stop exit_malformed
  | Some root ->
      Binlens_tui.App.run ~filename ~format:parser.Format.display_name
        ~reader:input.reader ~root

let run_version () =
  Printf.printf "binlens %s (%s)\n" Version.version Version.build_metadata

let formats = [ "auto"; "elf"; "pe"; "nes"; "gameboy"; "gba" ]

let format_arg =
  let values = List.map (fun value -> (value, value)) formats in
  Arg.(
    value
    & opt (enum values) "auto"
    & info [ "format" ] ~docv:"FORMAT"
        ~doc:"Select FORMAT or use automatic detection.")

let file position doc =
  Arg.(required & pos position (some file) None & info [] ~docv:"FILE" ~doc)

let nonnegative_int =
  let parse value =
    match int_of_string_opt value with
    | Some value when value >= 0 -> Ok value
    | _ -> Error (`Msg "expected a nonnegative integer")
  in
  let print formatter value = Stdlib.Format.fprintf formatter "%d" value in
  Arg.conv (parse, print)

let max_nodes =
  Arg.(
    value
    & opt nonnegative_int Limits.default.max_nodes
    & info [ "max-nodes" ] ~docv:"N" ~doc:"Stop after N parse-tree nodes.")

let max_string_bytes =
  Arg.(
    value
    & opt nonnegative_int Limits.default.max_string_bytes
    & info [ "max-string-bytes" ] ~docv:"N"
        ~doc:"Copy at most N bytes for one parsed string.")

let max_table_entries =
  Arg.(
    value
    & opt nonnegative_int Limits.default.max_table_entries
    & info [ "max-table-entries" ] ~docv:"N"
        ~doc:"Visit at most N declared table entries.")

let max_depth =
  Arg.(
    value
    & opt nonnegative_int Limits.default.max_depth
    & info [ "max-depth" ] ~docv:"N"
        ~doc:"Render and construct trees with at most N levels.")

let output =
  Arg.(
    value
    & opt (some string) None
    & info [ "o"; "output" ] ~docv:"FILE" ~doc:"Write command output to FILE.")

let offset_conv =
  let parse value =
    try Ok (Int64.of_string value)
    with Failure _ -> Error (`Msg "expected a decimal or 0x-prefixed offset")
  in
  let print formatter value = Stdlib.Format.fprintf formatter "%Ld" value in
  Arg.conv (parse, print)

let inspect_cmd =
  let filename = file 0 "Binary file to inspect." in
  let descriptions =
    Arg.(value & flag & info [ "descriptions" ] ~doc:"Show field descriptions.")
  in
  let no_diagnostics =
    Arg.(
      value & flag & info [ "no-diagnostics" ] ~doc:"Hide inline diagnostics.")
  in
  let raw =
    Arg.(
      value & flag & info [ "raw" ] ~doc:"Show available raw-byte summaries.")
  in
  let decimal =
    Arg.(
      value & flag
      & info [ "decimal-offsets" ] ~doc:"Print byte offsets in decimal.")
  in
  let path =
    Arg.(
      value
      & opt (some string) None
      & info [ "path" ] ~docv:"PATH"
          ~doc:"Render only the node at semantic PATH.")
  in
  let offset =
    Arg.(
      value
      & opt (some offset_conv) None
      & info [ "offset" ] ~docv:"OFFSET"
          ~doc:"Render the smallest node containing OFFSET.")
  in
  let json =
    Arg.(
      value & flag
      & info [ "json" ] ~doc:"Use the versioned JSON document instead of text.")
  in
  let no_color =
    Arg.(
      value & flag
      & info [ "no-color" ]
          ~doc:"Disable color. Text output is colorless in v0.1.0.")
  in
  let term =
    Term.(
      const
        (fun
          filename
          format
          max_nodes
          max_string_bytes
          max_table_entries
          max_depth
          descriptions
          no_diagnostics
          raw
          decimal
          path
          offset
          json
          no_color
          output
        ->
          run_inspect filename format max_nodes max_string_bytes
            max_table_entries max_depth descriptions (not no_diagnostics) raw
            decimal path offset json no_color output)
      $ filename $ format_arg $ max_nodes $ max_string_bytes $ max_table_entries
      $ max_depth $ descriptions $ no_diagnostics $ raw $ decimal $ path
      $ offset $ json $ no_color $ output)
  in
  Cmd.v
    (Cmd.info "inspect"
       ~doc:"Print a structured tree tied to exact byte ranges.")
    term

let json_cmd =
  let filename = file 0 "Binary file to export." in
  let term =
    Term.(
      const run_json $ filename $ format_arg $ max_nodes $ max_string_bytes
      $ max_table_entries $ max_depth $ output)
  in
  Cmd.v (Cmd.info "json" ~doc:"Export a versioned JSON parse document.") term

let validate_cmd =
  let filename = file 0 "Binary file to validate." in
  let strict =
    Arg.(
      value & flag
      & info [ "strict" ] ~doc:"Treat warnings as validation failures.")
  in
  let term =
    Term.(
      const run_validate $ filename $ format_arg $ strict $ max_nodes
      $ max_string_bytes $ max_table_entries $ max_depth)
  in
  Cmd.v
    (Cmd.info "validate" ~doc:"Parse a file and report warnings and errors.")
    term

let detect_cmd =
  let filename = file 0 "Binary file to detect." in
  let json =
    Arg.(
      value & flag & info [ "json" ] ~doc:"Write detection candidates as JSON.")
  in
  let term =
    Term.(
      const run_detect $ filename $ json $ max_nodes $ max_string_bytes
      $ max_table_entries $ max_depth)
  in
  Cmd.v
    (Cmd.info "detect" ~doc:"List candidate formats, confidence, and evidence.")
    term

let formats_cmd =
  let json =
    Arg.(value & flag & info [ "json" ] ~doc:"Write the coverage list as JSON.")
  in
  Cmd.v
    (Cmd.info "formats" ~doc:"List supported formats and exact parser coverage.")
    Term.(const run_formats $ json)

let diff_cmd =
  let left = file 0 "First binary file."
  and right = file 1 "Second binary file." in
  let json =
    Arg.(value & flag & info [ "json" ] ~doc:"Write differences as JSON.")
  in
  let check =
    Arg.(
      value & flag
      & info [ "check" ] ~doc:"Exit with status 6 when differences exist.")
  in
  let raw =
    Arg.(
      value & flag
      & info [ "raw" ] ~doc:"Compare matched raw byte ranges up to 65536 bytes.")
  in
  let ignore =
    Arg.(
      value & opt_all string []
      & info [ "ignore" ] ~docv:"PATH"
          ~doc:"Ignore semantic PATH. Repeat this option for more paths.")
  in
  let term =
    Term.(
      const run_diff $ left $ right $ format_arg $ json $ check $ raw $ ignore
      $ max_nodes $ max_string_bytes $ max_table_entries $ max_depth $ output)
  in
  Cmd.v
    (Cmd.info "diff"
       ~doc:"Compare two binaries by semantic paths and byte spans.")
    term

let tui_cmd =
  let filename = file 0 "Binary file to explore." in
  let term =
    Term.(
      const run_tui $ filename $ format_arg $ max_nodes $ max_string_bytes
      $ max_table_entries $ max_depth)
  in
  Cmd.v
    (Cmd.info "tui"
       ~doc:"Open the synchronized parse-tree and hexadecimal explorer.")
    term

let version_cmd =
  Cmd.v
    (Cmd.info "version" ~doc:"Print version and build metadata.")
    Term.(const run_version $ const ())

let command =
  let info =
    Cmd.info "binlens" ~version:Version.version
      ~doc:
        "Inspect binary formats as structured fields tied to exact byte ranges."
      ~man:
        [ `S Manpage.s_description;
          `P
            "BinLens detects and parses selected ELF, PE, NES, Game Boy, and \
             Game Boy Advance structures. Parsers apply explicit bounds and \
             resource limits to hostile input.";
          `S "EXIT STATUS";
          `P
            "0 means success. 1 is an operational failure. 2 is invalid \
             command syntax. 3 means no supported format matched. 4 means the \
             format was recognized but malformed. 5 means a parser resource \
             limit was reached. 6 means diff --check found differences."
        ]
  in
  Cmd.group info
    [ inspect_cmd;
      tui_cmd;
      json_cmd;
      validate_cmd;
      detect_cmd;
      diff_cmd;
      formats_cmd;
      version_cmd
    ]

let () =
  let status = Cmd.eval command in
  Stdlib.exit
    (if status = Cmd.Exit.cli_error then exit_invalid_arguments else status)
