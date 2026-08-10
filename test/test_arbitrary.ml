open Binlens

let safe_parse bytes =
  let limits =
    {
      Limits.default with
      max_nodes = 256;
      max_table_entries = 64;
      max_string_bytes = 128;
      max_diagnostics = 64;
      max_work_units = 2_048;
    }
  in
  let reader = Reader.of_string bytes in
  Registry.all ()
  |> List.for_all (fun parser ->
         let result = Registry.safe_parse parser limits reader in
         match result.Format.root with
         | None -> true
         | Some root ->
             Node.flatten root
             |> List.for_all (fun node ->
                    Span.within ~input_length:(Reader.length reader) node.Node.span))

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
    Reader.bytes reader ~offset:(Int64.of_int (abs offset mod 1024))
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

let qcheck_tests =
  let strings = QCheck.Gen.string_size (QCheck.Gen.int_range 0 512) |> QCheck.make in
  [
    QCheck.Test.make ~count:1_000 ~name:"arbitrary input stays inside parser boundary"
      strings safe_parse;
    QCheck.Test.make ~count:500 ~name:"JSON rendering is deterministic" strings
      deterministic_json;
    QCheck.Test.make ~count:500 ~name:"diff with self is empty" strings
      diff_self_empty;
    QCheck.Test.make ~count:1_000 ~name:"reader copies no more than requested"
      QCheck.(triple string nat_small nat_small)
      reader_never_overreturns;
  ]

let () =
  Alcotest.run "arbitrary"
    [
      ( "properties",
        List.map QCheck_alcotest.to_alcotest qcheck_tests );
    ]
