open Binlens

let parse format bytes =
  match Registry.parse ~format Limits.default (Reader.of_bytes bytes) with
  | Ok (_, result) -> result
  | Error error -> failwith (Error.to_string error)

let compare ?(options = Diff.default_options) left_bytes right_bytes left right =
  Diff.compare ~options ~left_reader:(Reader.of_bytes left_bytes)
    ~right_reader:(Reader.of_bytes right_bytes) left right

let has_kind kind differences =
  List.exists (fun difference -> difference.Diff.kind = kind) differences

let test_identical () =
  let bytes = Fixture_builder.pe32 () in
  let tree = parse "pe" bytes in
  Alcotest.(check int) "empty" 0 (List.length (compare bytes bytes tree tree))

let test_changed_value_and_ignore () =
  let left_bytes = Fixture_builder.pe32 () in
  let right_bytes = Bytes.copy left_bytes in
  Fixture_builder.set_u32 right_bytes Endian.Little (0x84 + 4) 0x66_000_000L;
  let left = parse "pe" left_bytes and right = parse "pe" right_bytes in
  let differences = compare left_bytes right_bytes left right in
  Alcotest.(check bool) "changed value" true (has_kind Diff.Changed_value differences);
  let options = { Diff.default_options with ignore_paths = [ "pe.coff.timestamp" ] } in
  let ignored = compare ~options left_bytes right_bytes left right in
  Alcotest.(check bool) "timestamp ignored" false
    (List.exists (fun difference -> String.equal difference.Diff.path "pe.coff.timestamp") ignored)

let test_added_removed () =
  let left_bytes = Fixture_builder.pe32 () in
  let right_bytes = Bytes.copy left_bytes in
  Fixture_builder.set_u16 right_bytes Endian.Little (0x84 + 2) 0;
  let left = parse "pe" left_bytes and right = parse "pe" right_bytes in
  let differences = compare left_bytes right_bytes left right in
  Alcotest.(check bool) "removed node" true (has_kind Diff.Removed_node differences)

let test_raw_and_format () =
  let left_bytes = Fixture_builder.nes () in
  let right_bytes = Fixture_builder.corrupt_u8 left_bytes 6 2 in
  let left = parse "nes" left_bytes and right = parse "nes" right_bytes in
  let options = { Diff.default_options with compare_raw = true } in
  Alcotest.(check bool) "raw changed" true
    (has_kind Diff.Changed_raw (compare ~options left_bytes right_bytes left right));
  let elf_bytes = Fixture_builder.elf32_little () in
  let elf = parse "elf" elf_bytes in
  Alcotest.(check bool) "format changed" true
    (has_kind Diff.Format_changed (compare left_bytes elf_bytes left elf))

let test_determinism () =
  let left_bytes = Fixture_builder.pe32 () in
  let right_bytes = Fixture_builder.pe32_plus () in
  let left = parse "pe" left_bytes and right = parse "pe" right_bytes in
  let first = compare left_bytes right_bytes left right
  and second = compare left_bytes right_bytes left right in
  Alcotest.(check string) "stable JSON"
    (Yojson.Safe.to_string (Diff.to_yojson first))
    (Yojson.Safe.to_string (Diff.to_yojson second))

let () =
  Alcotest.run "diff"
    [
      ( "diff",
        [
          Alcotest.test_case "identical" `Quick test_identical;
          Alcotest.test_case "changed and ignored" `Quick test_changed_value_and_ignore;
          Alcotest.test_case "added or removed" `Quick test_added_removed;
          Alcotest.test_case "raw and format" `Quick test_raw_and_format;
          Alcotest.test_case "deterministic" `Quick test_determinism;
        ] );
    ]
