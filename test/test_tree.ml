open Binlens

let span start length =
  match Span.create ~start ~length with Ok value -> value | Error error -> failwith (Error.to_string error)

let sample_tree () =
  let child =
    Node.make ~id:"field" ~path:"sample.field" ~label:"Field"
      ~span:(span 1L 1L) ~value:(Value.unsigned 8 42L) ~source_format:"sample" ()
  in
  Node.make ~id:"sample" ~path:"sample" ~label:"Sample"
    ~span:(span 0L 2L) ~value:(Value.Collection 1) ~children:[ child ]
    ~source_format:"sample" ()

let test_paths_and_order () =
  let root = sample_tree () in
  Alcotest.(check (list string)) "paths" [ "sample"; "sample.field" ]
    (Node.flatten root |> List.map (fun node -> node.Node.path));
  Alcotest.(check bool) "find" true (Option.is_some (Node.find_by_path root "sample.field"))

let test_json_determinism () =
  let root = sample_tree () in
  let json = Render_json.node root |> Yojson.Safe.to_string in
  let again = Render_json.node root |> Yojson.Safe.to_string in
  Alcotest.(check string) "same output" json again;
  Alcotest.(check bool) "contains path" true (String.contains json 'p')

let test_sanitize () =
  let escaped = Sanitize.text "ok\x1b[31m\n" in
  Alcotest.(check string) "control bytes escaped" "ok\\x1B[31m\\x0A" escaped;
  Alcotest.(check bool) "no escape byte" false (String.contains escaped '\x1b');
  let rendered = Render_text.render (sample_tree ()) in
  Alcotest.(check bool) "renderer no escape byte" false (String.contains rendered '\x1b')

let test_node_limit () =
  let limits = { Limits.default with max_nodes = 1 } in
  let reader = Reader.of_bytes (Fixture_builder.nes ()) in
  match Registry.parse ~format:"nes" limits reader with
  | Error error -> Alcotest.fail (Error.to_string error)
  | Ok (_, result) ->
      Alcotest.(check bool) "limit reached" true result.Format.limit_reached;
      Alcotest.(check bool) "partial" true result.partial

let () =
  Alcotest.run "tree"
    [
      ( "tree",
        [
          Alcotest.test_case "paths and order" `Quick test_paths_and_order;
          Alcotest.test_case "JSON deterministic" `Quick test_json_determinism;
          Alcotest.test_case "sanitization" `Quick test_sanitize;
          Alcotest.test_case "node limit" `Quick test_node_limit;
        ] );
    ]
