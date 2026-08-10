open Binlens

let parse format bytes =
  match Registry.parse ~format Limits.default (Reader.of_bytes bytes) with
  | Ok (_, result) -> result
  | Error error -> Alcotest.fail (Error.to_string error)

let parse_with_limits format limits bytes =
  match Registry.parse ~format limits (Reader.of_bytes bytes) with
  | Ok (_, result) -> result
  | Error error -> Alcotest.fail (Error.to_string error)

let require_root result =
  match result.Format.root with
  | Some root -> root
  | None -> Alcotest.fail "missing root"

let assert_path result path =
  let root = require_root result in
  Alcotest.(check bool) path true (Option.is_some (Node.find_by_path root path))

let require_path result path =
  let root = require_root result in
  match Node.find_by_path root path with
  | Some node -> node
  | None -> Alcotest.failf "missing path %s" path

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

let test_elf_extended_numbering () =
  List.iter
    (fun bytes ->
      let result = parse "elf" bytes in
      assert_no_errors result;
      assert_path result "elf.resolved_program_header_count";
      assert_path result "elf.resolved_section_header_count";
      assert_path result "elf.resolved_section_name_string_table_index";
      assert_path result "elf.program_headers[0].offset";
      assert_path result "elf.section_headers[1].name")
    [ Fixture_builder.elf32_little_extended ();
      Fixture_builder.elf32_big_extended ();
      Fixture_builder.elf64_little_extended ();
      Fixture_builder.elf64_big_extended ()
    ];
  let result = parse "elf" (Fixture_builder.elf32_little_extended ()) in
  let sections = require_path result "elf.resolved_section_header_count" in
  Alcotest.(check int64)
    "resolved count span" 104L
    (Span.start sections.Node.span);
  Alcotest.(check int64)
    "resolved count length" 4L
    (Span.length sections.Node.span)

let test_elf_metadata () =
  let fixtures =
    [ (16L, Fixture_builder.elf32_little_metadata ());
      (16L, Fixture_builder.elf32_big_metadata ());
      (24L, Fixture_builder.elf64_little_metadata ());
      (24L, Fixture_builder.elf64_big_metadata ())
    ]
  in
  List.iter
    (fun (symbol_size, bytes) ->
      let result = parse "elf" bytes in
      assert_no_errors result;
      assert_path result "elf.section_headers[3].symbols[0].name";
      assert_path result "elf.section_headers[4].dynamic_entries[0].string";
      assert_path result "elf.section_headers[5].relocations[0].relocation_type";
      assert_path result "elf.section_headers[6].relocations[0].addend";
      assert_path result "elf.section_headers[7].notes[0].name";
      assert_path result "elf.section_headers[7].notes[0].descriptor";
      assert_path result "elf.section_headers[8].dwarf_section";
      let symbol = require_path result "elf.section_headers[3].symbols[0]" in
      Alcotest.(check int64)
        "symbol entry span" symbol_size
        (Span.length symbol.Node.span);
      let flags = require_path result "elf.flags" in
      match flags.Node.value with
      | Value.Bitfield { flags; _ } ->
          Alcotest.(check bool)
            "RISC-V compressed flag" true
            (List.assoc "Compressed instructions" flags)
      | _ -> Alcotest.fail "expected decoded RISC-V flags")
    fixtures

let test_elf_metadata_malformed () =
  let invalid_link = Fixture_builder.elf32_little_metadata () in
  Fixture_builder.set_u32 invalid_link Endian.Little 196 99L;
  Alcotest.(check bool)
    "invalid symbol link" true (parse "elf" invalid_link).partial;
  let zero_entry = Fixture_builder.elf32_little_metadata () in
  Fixture_builder.set_u32 zero_entry Endian.Little 208 0L;
  Alcotest.(check bool)
    "zero metadata entry" true (parse "elf" zero_entry).partial;
  let invalid_string = Fixture_builder.elf32_little_metadata () in
  let parsed = parse "elf" invalid_string in
  let symbol = require_path parsed "elf.section_headers[3].symbols[0]" in
  Fixture_builder.set_u32 invalid_string Endian.Little
    (Int64.to_int (Span.start symbol.Node.span))
    0xffffL;
  Alcotest.(check bool)
    "invalid symbol string" true (parse "elf" invalid_string).partial;
  let truncated_note = Fixture_builder.elf32_little_metadata () in
  let note_header = 52 + (7 * 40) in
  Fixture_builder.set_u32 truncated_note Endian.Little (note_header + 20) 19L;
  Alcotest.(check bool)
    "truncated note" true (parse "elf" truncated_note).partial;
  let huge_base = Fixture_builder.elf32_little_metadata () in
  let parsed = parse "elf" huge_base in
  let symbol = require_path parsed "elf.section_headers[3].symbols[0]" in
  let table_size = 16 * 4097 in
  let needed = Int64.to_int (Span.start symbol.Node.span) + table_size in
  let huge =
    Bytes.extend huge_base 0 (max 0 (needed - Bytes.length huge_base))
  in
  Fixture_builder.set_u32 huge Endian.Little
    (52 + (3 * 40) + 20)
    (Int64.of_int table_size);
  Alcotest.(check bool)
    "metadata count limit" true (parse "elf" huge).limit_reached;
  let trailing = Fixture_builder.elf32_little_metadata () in
  Fixture_builder.set_u32 trailing Endian.Little (52 + (3 * 40) + 20) 15L;
  let result = parse "elf" trailing in
  Alcotest.(check bool)
    "trailing entry bytes" true
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code "elf.metadata_trailing_bytes")
       result.diagnostics);
  let overflow = Fixture_builder.elf64_little_metadata () in
  Fixture_builder.set_u64 overflow Endian.Little (64 + (3 * 64) + 24)
    Int64.min_int;
  Alcotest.(check bool)
    "metadata offset overflow" true (parse "elf" overflow).partial

let test_elf_machine_flags () =
  let check machine raw expected =
    let bytes = Fixture_builder.elf32_little () in
    Fixture_builder.set_u16 bytes Endian.Little 18 machine;
    Fixture_builder.set_u32 bytes Endian.Little 36 raw;
    let flags = require_path (parse "elf" bytes) "elf.flags" in
    match flags.Node.value with
    | Value.Bitfield { flags; _ } ->
        Alcotest.(check bool) expected true (List.assoc expected flags)
    | _ -> Alcotest.failf "expected decoded flags for machine %d" machine
  in
  check 8 0x2L "Position-independent code";
  check 40 0x4L "Interworking";
  check 243 0x1L "Compressed instructions"

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
  Alcotest.(check bool) "outside table partial" true result.partial;
  let small_entry = Fixture_builder.elf32_little_extended () in
  Fixture_builder.set_u16 small_entry Endian.Little 46 20;
  let result = parse "elf" small_entry in
  Alcotest.(check bool) "extended entry partial" true result.partial;
  let huge_count = Fixture_builder.elf32_little_extended () in
  Fixture_builder.set_u32 huge_count Endian.Little 104 0xffff_ffffL;
  let result = parse "elf" huge_count in
  Alcotest.(check bool) "extended count limit" true result.limit_reached

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
  Fixture_builder.set_u16 elf Endian.Little 44 0xfffe;
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
  assert_path nes "nes.prg_bank_count";
  assert_path nes "nes.payload.prg_rom";
  let prg = require_path nes "nes.payload.prg_rom" in
  Alcotest.(check int64) "PRG start" 16L (Span.start prg.Node.span);
  Alcotest.(check int64) "PRG length" 16_384L (Span.length prg.Node.span);
  let nes2 = parse "nes" (Fixture_builder.nes ~nes2:true ()) in
  assert_path nes2 "nes.submapper";
  let gb = parse "gameboy" (Fixture_builder.gameboy ()) in
  assert_no_errors gb;
  assert_path gb "gameboy.header_checksum";
  assert_path gb "gameboy.rom_bank_count";
  assert_path gb "gameboy.rom_payload";
  let rom = require_path gb "gameboy.rom_payload" in
  Alcotest.(check int64) "GB ROM length" 32_768L (Span.length rom.Node.span);
  let gba = parse "gba" (Fixture_builder.gba ()) in
  assert_no_errors gba;
  assert_path gba "gba.nintendo_logo";
  assert_path gba "gba.header_checksum";
  let logo = require_path gba "gba.nintendo_logo" in
  Alcotest.(check int64) "GBA logo start" 4L (Span.start logo.Node.span);
  Alcotest.(check int64) "GBA logo length" 156L (Span.length logo.Node.span);
  let trainer = parse "nes" (Fixture_builder.nes ~trainer:true ()) in
  assert_no_errors trainer;
  assert_path trainer "nes.payload.trainer";
  let save =
    parse "gba" (Fixture_builder.gba ~save_signature:"FLASH1M_V103" ())
  in
  assert_no_errors save;
  assert_path save "gba.save_memory.flash_128k";
  let several =
    parse "gba" (Fixture_builder.gba ~save_signature:"EEPROM_V000SRAM_V000" ())
  in
  assert_path several "gba.save_memory.eeprom";
  assert_path several "gba.save_memory.sram";
  Alcotest.(check bool)
    "several save signatures" true
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code "gba.multiple_save_signatures")
       several.diagnostics)

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
  List.iter
    (fun logo_index ->
      let offset = 4 + logo_index in
      let bytes =
        Fixture_builder.corrupt_u8 (Fixture_builder.gba ()) offset 0
      in
      let result = parse "gba" bytes in
      let diagnostic =
        List.find_opt
          (fun diagnostic ->
            String.equal diagnostic.Diagnostic.code "gba.invalid_logo")
          result.diagnostics
      in
      match diagnostic with
      | Some { Diagnostic.span = Some span; _ } ->
          Alcotest.(check int64)
            "logo mismatch offset" (Int64.of_int offset) (Span.start span)
      | _ -> Alcotest.fail "missing GBA logo diagnostic span")
    [ 0; 78; 155 ];
  let allowed_logo_bits = Bytes.copy (Fixture_builder.gba ()) in
  Fixture_builder.set_u8 allowed_logo_bits 0x9c 0xa5;
  Fixture_builder.set_u8 allowed_logo_bits 0x9e 0xfb;
  let result = parse "gba" allowed_logo_bits in
  Alcotest.(check bool)
    "allowed GBA logo bits" false
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code "gba.invalid_logo")
       result.diagnostics);
  let short_nes =
    Fixture_builder.truncate (Fixture_builder.nes ()) (16 + 128)
  in
  let result = parse "nes" short_nes in
  Alcotest.(check bool) "truncated NES payload is partial" true result.partial;
  Alcotest.(check bool)
    "NES payload error" true
    (List.exists
       (fun diagnostic ->
         String.equal diagnostic.Diagnostic.code
           "nes.declared_size_exceeds_file")
       result.diagnostics);
  let exponent_nes = Bytes.copy (Fixture_builder.nes ~nes2:true ()) in
  Fixture_builder.set_u8 exponent_nes 4 6;
  Fixture_builder.set_u8 exponent_nes 9 0x0f;
  let result = parse "nes" exponent_nes in
  let size = require_path result "nes.prg_size" in
  Alcotest.(check string)
    "NES 2.0 exponent size" "10"
    (Value.to_string size.Node.value);
  let small_work_limit = { Limits.default with max_work_units = 2 } in
  let result =
    parse_with_limits "gba" small_work_limit
      (Fixture_builder.gba ~save_signature:"SRAM_V110" ())
  in
  Alcotest.(check bool) "save scan work limit" true result.limit_reached;
  Alcotest.(check bool)
    "truncated NES" true
    (parse "nes" (Fixture_builder.truncate (Fixture_builder.nes ()) 8)).partial

let test_detection () =
  let cases =
    [ ("elf", Fixture_builder.elf64_little ());
      ("pe", Fixture_builder.pe32 ());
      ("nes", Fixture_builder.nes ());
      ("gameboy", Fixture_builder.gameboy ~full_payload:false ());
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
      ("elf", Fixture_builder.elf32_big_metadata ());
      ("elf", Fixture_builder.elf64_little_metadata ());
      ("pe", Fixture_builder.pe32 ());
      ("pe", Fixture_builder.pe32_plus ());
      ("nes", Fixture_builder.nes ());
      ("gameboy", Fixture_builder.gameboy ~full_payload:false ());
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
          Alcotest.test_case "extended numbering" `Quick
            test_elf_extended_numbering;
          Alcotest.test_case "metadata tables" `Quick test_elf_metadata;
          Alcotest.test_case "malformed metadata" `Quick
            test_elf_metadata_malformed;
          Alcotest.test_case "machine flags" `Quick test_elf_machine_flags;
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
