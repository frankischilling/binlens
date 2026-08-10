open Binlens

let parse format bytes =
  match Registry.parse ~format Limits.default (Reader.of_bytes bytes) with
  | Ok (_, result) -> result
  | Error error -> Alcotest.fail (Error.to_string error)

let require_root result =
  match result.Format.root with
  | Some root -> root
  | None -> Alcotest.fail "missing root"

let assert_path result path =
  let root = require_root result in
  Alcotest.(check bool) path true (Option.is_some (Node.find_by_path root path))

let assert_no_errors result =
  let errors =
    List.filter
      (fun diagnostic -> diagnostic.Diagnostic.severity = Diagnostic.Error)
      result.Format.diagnostics
  in
  if errors <> [] then
    Alcotest.fail (String.concat "\n" (List.map Diagnostic.to_string errors))

let test_elf_variants () =
  List.iter
    (fun bytes ->
      let result = parse "elf" bytes in
      assert_no_errors result;
      assert_path result "elf.entry_point";
      assert_path result "elf.program_headers[0].offset";
      assert_path result "elf.section_headers[1].name")
    [ Fixture_builder.elf32_little ();
      Fixture_builder.elf32_big ();
      Fixture_builder.elf64_little ();
      Fixture_builder.elf64_big ()
    ]

let test_elf_malformed () =
  let invalid_class =
    Fixture_builder.corrupt_u8 (Fixture_builder.elf32_little ()) 4 9
  in
  let result = parse "elf" invalid_class in
  Alcotest.(check bool) "partial" true result.Format.partial;
  let truncated =
    parse "elf" (Fixture_builder.truncate (Fixture_builder.elf64_little ()) 40)
  in
  Alcotest.(check bool) "truncated partial" true truncated.partial;
  let outside = Bytes.copy (Fixture_builder.elf32_little ()) in
  Fixture_builder.set_u32 outside Endian.Little 32 Int64.max_int;
  let result = parse "elf" outside in
  Alcotest.(check bool) "outside table partial" true result.partial

let test_pe_variants () =
  List.iter
    (fun bytes ->
      let result = parse "pe" bytes in
      assert_no_errors result;
      assert_path result "pe.optional_header.entry_point";
      assert_path result "pe.sections[0].name")
    [ Fixture_builder.pe32 (); Fixture_builder.pe32_plus () ]

let test_pe_malformed () =
  let invalid_mz = Fixture_builder.corrupt_u8 (Fixture_builder.pe32 ()) 0 0 in
  Alcotest.(check bool) "bad MZ partial" true (parse "pe" invalid_mz).partial;
  let invalid_offset = Bytes.copy (Fixture_builder.pe32 ()) in
  Fixture_builder.set_u32 invalid_offset Endian.Little 0x3c 0xfffffff0L;
  Alcotest.(check bool)
    "bad e_lfanew partial" true (parse "pe" invalid_offset).partial;
  let missing_signature =
    Fixture_builder.corrupt_u8 (Fixture_builder.pe32 ()) 0x80 0
  in
  Alcotest.(check bool)
    "missing signature partial" true (parse "pe" missing_signature).partial;
  let bad_alignment = Bytes.copy (Fixture_builder.pe32 ()) in
  Fixture_builder.set_u32 bad_alignment Endian.Little (0x98 + 36) 3L;
  let result = parse "pe" bad_alignment in
  Alcotest.(check bool)
    "alignment warning" true
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code "pe.invalid_alignment")
       result.diagnostics)

let test_parser_limits_and_ranges () =
  let elf = Bytes.copy (Fixture_builder.elf32_little ()) in
  Fixture_builder.set_u16 elf Endian.Little 44 0xffff;
  let result = parse "elf" elf in
  Alcotest.(check bool) "ELF table limit" true result.limit_reached;
  let pe = Bytes.copy (Fixture_builder.pe32 ()) in
  Fixture_builder.set_u16 pe Endian.Little 0x86 0xffff;
  let result = parse "pe" pe in
  Alcotest.(check bool) "PE table limit" true result.limit_reached;
  let pe = Bytes.copy (Fixture_builder.pe32 ()) in
  Fixture_builder.set_u32 pe Endian.Little 0x188 0x200L;
  Fixture_builder.set_u32 pe Endian.Little 0x18c 0xfffffff0L;
  let result = parse "pe" pe in
  Alcotest.(check bool)
    "PE raw range" true
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code
           "pe.section_raw_data_out_of_file")
       result.diagnostics)

let test_rom_headers () =
  let nes = parse "nes" (Fixture_builder.nes ()) in
  assert_no_errors nes;
  assert_path nes "nes.mapper";
  let nes2 = parse "nes" (Fixture_builder.nes ~nes2:true ()) in
  assert_path nes2 "nes.submapper";
  let gb = parse "gameboy" (Fixture_builder.gameboy ()) in
  assert_no_errors gb;
  assert_path gb "gameboy.header_checksum";
  let gba = parse "gba" (Fixture_builder.gba ()) in
  assert_no_errors gba;
  assert_path gba "gba.header_checksum"

let test_rom_malformed () =
  let gb = Fixture_builder.corrupt_u8 (Fixture_builder.gameboy ()) 0x14d 0 in
  let result = parse "gameboy" gb in
  Alcotest.(check bool)
    "GB checksum warning" true
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code
           "gameboy.header_checksum_mismatch")
       result.diagnostics);
  let gba = Fixture_builder.corrupt_u8 (Fixture_builder.gba ()) 0xb2 0 in
  let result = parse "gba" gba in
  Alcotest.(check bool)
    "GBA fixed warning" true
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code "gba.invalid_fixed_value")
       result.diagnostics);
  Alcotest.(check bool)
    "truncated NES" true
    (parse "nes" (Fixture_builder.truncate (Fixture_builder.nes ()) 8)).partial

let test_detection () =
  let cases =
    [ ("elf", Fixture_builder.elf64_little ());
      ("pe", Fixture_builder.pe32 ());
      ("nes", Fixture_builder.nes ());
      ("gameboy", Fixture_builder.gameboy ());
      ("gba", Fixture_builder.gba ())
    ]
  in
  List.iter
    (fun (expected, bytes) ->
      match Registry.detect Limits.default (Reader.of_bytes bytes) with
      | best :: _ ->
          Alcotest.(check string) "detected" expected best.Format.format_id
      | [] -> Alcotest.fail "no detections")
    cases

let test_truncation () =
  let fixtures =
    [ ("elf", Fixture_builder.elf32_little ());
      ("elf", Fixture_builder.elf64_big ());
      ("pe", Fixture_builder.pe32 ());
      ("pe", Fixture_builder.pe32_plus ());
      ("nes", Fixture_builder.nes ());
      ("gameboy", Fixture_builder.gameboy ());
      ("gba", Fixture_builder.gba ())
    ]
  in
  List.iter
    (fun (format, bytes) ->
      for length = 0 to Bytes.length bytes do
        let prefix = Fixture_builder.truncate bytes length in
        try ignore (parse format prefix)
        with exception_ ->
          Alcotest.failf "%s prefix %d raised %s" format length
            (Printexc.to_string exception_)
      done)
    fixtures

let () =
  Alcotest.run "formats"
    [ ( "ELF",
        [ Alcotest.test_case "four class and endian variants" `Quick
            test_elf_variants;
          Alcotest.test_case "malformed" `Quick test_elf_malformed
        ] );
      ( "PE",
        [ Alcotest.test_case "PE32 and PE32+" `Quick test_pe_variants;
          Alcotest.test_case "malformed" `Quick test_pe_malformed;
          Alcotest.test_case "limits and ranges" `Quick
            test_parser_limits_and_ranges
        ] );
      ( "ROM",
        [ Alcotest.test_case "valid headers" `Quick test_rom_headers;
          Alcotest.test_case "malformed headers" `Quick test_rom_malformed
        ] );
      ("detection", [ Alcotest.test_case "all formats" `Quick test_detection ]);
      ("truncation", [ Alcotest.test_case "every prefix" `Slow test_truncation ])
    ]
