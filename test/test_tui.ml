open Binlens
module Model = Binlens_tui.Model
module Hex_view = Binlens_tui.Hex_view

let parsed_nes () =
  let reader = Reader.of_bytes (Fixture_builder.nes ()) in
  match Registry.parse ~format:"nes" Limits.default reader with
  | Ok (_, { Format.root = Some root; _ }) -> (reader, root)
  | Ok _ -> Alcotest.fail "missing root"
  | Error error -> Alcotest.fail (Error.to_string error)

let test_navigation () =
  let reader, root = parsed_nes () in
  let model = Model.create ~reader ~root ~rows:24 ~cols:100 in
  Alcotest.(check bool) "children visible" true (Array.length model.visible > 1);
  let moved = Model.move model 1 in
  Alcotest.(check int) "move" 1 moved.selected;
  let top = Model.move moved (-10) in
  Alcotest.(check int) "clamped" 0 top.selected;
  let collapsed = Model.collapse model in
  Alcotest.(check int) "collapsed root" 1 (Array.length collapsed.visible);
  let expanded = Model.expand collapsed in
  Alcotest.(check bool) "expanded root" true (Array.length expanded.visible > 1)

let test_search_and_offset () =
  let reader, root = parsed_nes () in
  let model = Model.create ~reader ~root ~rows:24 ~cols:100 in
  let searched = Model.search model "mapper" in
  Alcotest.(check bool)
    "search result" true
    (Array.length searched.search_matches > 0);
  let selected = Option.get (Model.selected_node searched) in
  Alcotest.(check string) "selected mapper" "nes.mapper" selected.Node.path;
  let at_magic = Model.goto_offset model 0L in
  let node = Option.get (Model.selected_node at_magic) in
  Alcotest.(check string) "smallest containing node" "nes.magic" node.path;
  let next = Model.next_match searched 1 in
  Alcotest.(check bool)
    "next remains valid" true
    (Option.is_some (Model.selected_node next))

let test_resize_and_hex_window () =
  let reader, root = parsed_nes () in
  let model = Model.create ~reader ~root ~rows:24 ~cols:100 in
  let resized = Model.resize model ~rows:2 ~cols:3 in
  Alcotest.(check int) "rows" 2 resized.rows;
  Alcotest.(check int) "cols" 3 resized.cols;
  let bounded = Model.resize model ~rows:max_int ~cols:max_int in
  Alcotest.(check int) "bounded rows" Model.max_rows bounded.rows;
  Alcotest.(check int) "bounded columns" Model.max_cols bounded.cols;
  let selected = Span.unsafe ~start:2L ~length:100L in
  let window =
    Hex_view.calculate ~input_length:1_000L ~selected ~rows:2 ~bytes_per_line:8
  in
  Alcotest.(check bool) "large range continues" true window.selected_after;
  let lines = Hex_view.render reader root.Node.span window in
  Alcotest.(check bool) "window renders" true (lines <> [])

let () =
  Alcotest.run "tui"
    [ ( "model",
        [ Alcotest.test_case "navigation and expansion" `Quick test_navigation;
          Alcotest.test_case "search and offset" `Quick test_search_and_offset;
          Alcotest.test_case "resize and hex window" `Quick
            test_resize_and_hex_window
        ] )
    ]
