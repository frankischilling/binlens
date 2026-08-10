open Binlens

let safe_parse bytes =
  let limits =
    { Limits.default with
      max_nodes = 256;
      max_table_entries = 64;
      max_string_bytes = 128;
      max_diagnostics = 64;
      max_work_units = 2_048
    }
  in
  let reader = Reader.of_string bytes in
  Registry.all ()
  |> List.for_all (fun parser ->
      try
        let result = parser.Format.parse limits reader in
        match result.Format.root with
        | None -> true
        | Some root ->
            Node.flatten root
            |> List.for_all (fun node ->
                Span.within ~input_length:(Reader.length reader) node.Node.span)
      with _ -> false)

let deterministic_json bytes =
  let reader = Reader.of_string bytes in
  match Registry.parse ~format:"elf" Limits.default reader with
  | Error _ -> true
  | Ok (_, result) ->
      let render () =
        match result.Format.root with
        | None -> "null"
        | Some root -> Yojson.Safe.to_string (Render_json.node root)
      in
      String.equal (render ()) (render ())

let reader_never_overreturns (bytes, offset, length) =
  let reader = Reader.of_string bytes in
  match
    Reader.bytes reader
      ~offset:(Int64.of_int (abs offset mod 1024))
      ~length:(Int64.of_int (abs length mod 1024))
  with
  | Error _ -> true
  | Ok result -> Bytes.length result <= abs length mod 1024

let diff_self_empty bytes =
  let reader = Reader.of_string bytes in
  match Registry.parse ~format:"elf" Limits.default reader with
  | Error _ -> true
  | Ok (_, result) ->
      Diff.compare ~left_reader:reader ~right_reader:reader result result = []

let file_backend_matches bytes =
  let filename = Filename.temp_file "binlens-property-" ".bin" in
  let channel = open_out_bin filename in
  output_string channel bytes;
  close_out channel;
  Fun.protect
    ~finally:(fun () -> if Sys.file_exists filename then Sys.remove filename)
    (fun () ->
      let memory = Reader.of_string bytes in
      match
        Input.with_open ~backend:Input.Paged filename (fun input ->
            let length = Int64.of_int (String.length bytes) in
            match
              ( Reader.bytes memory ~offset:0L ~length,
                Reader.bytes input.Input.reader ~offset:0L ~length )
            with
            | Ok left, Ok right -> Bytes.equal left right
            | Error _, Error _ -> true
            | _ -> false)
      with
      | Ok matches -> matches
      | Error _ -> false)

let qcheck_tests =
  let configured_count fallback =
    match Sys.getenv_opt "BINLENS_QCHECK_COUNT" with
    | Some value -> Option.value (int_of_string_opt value) ~default:fallback
    | None -> fallback
  in
  let long_count = configured_count 1_000
  and short_count = configured_count 500 in
  let strings =
    QCheck.Gen.string_size (QCheck.Gen.int_range 0 512) |> QCheck.make
  in
  [ QCheck.Test.make ~count:long_count
      ~name:"arbitrary input stays inside parser boundary" strings safe_parse;
    QCheck.Test.make ~count:short_count ~name:"JSON rendering is deterministic"
      strings deterministic_json;
    QCheck.Test.make ~count:short_count ~name:"diff with self is empty" strings
      diff_self_empty;
    QCheck.Test.make ~count:long_count
      ~name:"reader copies no more than requested"
      QCheck.(triple string nat_small nat_small)
      reader_never_overreturns;
    QCheck.Test.make ~count:(min short_count 250)
      ~name:"byte and paged readers return identical data" strings
      file_backend_matches
  ]

let () =
  Alcotest.run "arbitrary"
    [ ("properties", List.map QCheck_alcotest.to_alcotest qcheck_tests) ]
