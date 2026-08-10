let id = "gameboy"
let display_name = "Game Boy cartridge header"

let coverage =
  { Format.summary =
      "Game Boy and Game Boy Color cartridge metadata and checksums";
    supported =
      [ "title and CGB flag";
        "cartridge, ROM, and RAM size codes";
        "declared ROM span and bank counts";
        "destination and version";
        "header checksum";
        "global checksum within the work budget"
      ];
    unsupported = [ "bank-switch behavior"; "save-data decoding"; "emulation" ]
  }

let logo =
  [| 0xce;
     0xed;
     0x66;
     0x66;
     0xcc;
     0x0d;
     0x00;
     0x0b;
     0x03;
     0x73;
     0x00;
     0x83;
     0x00;
     0x0c;
     0x00;
     0x0d;
     0x00;
     0x08;
     0x11;
     0x1f;
     0x88;
     0x89;
     0x00;
     0x0e;
     0xdc;
     0xcc;
     0x6e;
     0xe6;
     0xdd;
     0xdd;
     0xd9;
     0x99;
     0xbb;
     0xbb;
     0x67;
     0x63;
     0x6e;
     0x0e;
     0xec;
     0xcc;
     0xdd;
     0xdc;
     0x99;
     0x9f;
     0xbb;
     0xb9;
     0x33;
     0x3e
  |]

let logo_matches reader =
  if Int64.compare (Reader.length reader) 0x134L < 0 then false
  else
    let matches = ref true in
    for index = 0 to Array.length logo - 1 do
      match Reader.byte reader (Int64.of_int (0x104 + index)) with
      | Ok byte when byte = logo.(index) -> ()
      | _ -> matches := false
    done;
    !matches

let detect _limits reader =
  if logo_matches reader then
    { Format.format_id = id;
      display_name;
      confidence = 100;
      evidence = [ "Nintendo logo bytes at offsets 0104 through 0133" ];
      contradictions = [];
      required_minimum_length = 0x150L;
      definitive = true
    }
  else
    Format.no_detection ~format_id:id ~display_name
      ~required_minimum_length:0x150L

let cartridge_types =
  [ (0x00L, "ROM only");
    (0x01L, "MBC1");
    (0x02L, "MBC1 and RAM");
    (0x03L, "MBC1, RAM, and battery");
    (0x05L, "MBC2");
    (0x0fL, "MBC3, timer, and battery");
    (0x10L, "MBC3, timer, RAM, and battery");
    (0x19L, "MBC5");
    (0x1bL, "MBC5, RAM, and battery");
    (0x1cL, "MBC5 and rumble")
  ]

let rom_size code =
  match code with
  | 0x00 -> Some 32_768L
  | 0x01 -> Some 65_536L
  | 0x02 -> Some 131_072L
  | 0x03 -> Some 262_144L
  | 0x04 -> Some 524_288L
  | 0x05 -> Some 1_048_576L
  | 0x06 -> Some 2_097_152L
  | 0x07 -> Some 4_194_304L
  | 0x08 -> Some 8_388_608L
  | 0x52 -> Some 1_179_648L
  | 0x53 -> Some 1_310_720L
  | 0x54 -> Some 1_572_864L
  | _ -> None

let ram_size code =
  match code with
  | 0 -> Some 0L
  | 1 -> Some 2_048L
  | 2 -> Some 8_192L
  | 3 -> Some 32_768L
  | 4 -> Some 131_072L
  | 5 -> Some 65_536L
  | _ -> None

let parse limits reader =
  let context = Parse_context.create ~reader ~source_format:id limits in
  let children = ref [] in
  let add id label offset length value =
    match
      Parser_common.field context ~parent:"gameboy" ~id ~label ~offset ~length
        value
    with
    | None -> ()
    | Some node -> children := node :: !children
  in
  if not (logo_matches reader) then
    Parse_context.error context ~code:"gameboy.invalid_logo"
      ~message:"The Nintendo logo bytes do not match a Game Boy header."
      ~component:"gameboy.header" ~recoverable:false ();
  if
    Parser_common.require_length context ~minimum:0x150L
      ~code:"gameboy.truncated_header" ~component:"gameboy.header"
  then (
    let cgb = Parser_common.u8 context 0x143L in
    let title_length = match cgb with Some (0x80L | 0xc0L) -> 11 | _ -> 16 in
    (match Parser_common.string context 0x134L (Int64.of_int title_length) with
    | Some title ->
        add "title" "Title" 0x134L
          (Int64.of_int title_length)
          (Value.String
             { text = Sanitize.trimmed_text title;
               raw_hex = None;
               valid_utf8 = true
             })
    | None -> ());
    (match cgb with
    | Some value ->
        add "cgb_flag" "CGB flag" 0x143L 1L
          (Value.enum 8 value
             (match value with
             | 0x80L -> Some "Supports Game Boy Color"
             | 0xc0L -> Some "Game Boy Color only"
             | _ -> Some "Game Boy"))
    | None -> ());
    let cartridge = Parser_common.u8 context 0x147L
    and rom_code = Parser_common.u8 context 0x148L
    and ram_code = Parser_common.u8 context 0x149L
    and destination = Parser_common.u8 context 0x14aL
    and version = Parser_common.u8 context 0x14cL
    and stored_header_checksum = Parser_common.u8 context 0x14dL
    and stored_global_checksum = Parser_common.u16 context Endian.Big 0x14eL in
    let declared_rom_size =
      Option.bind rom_code (fun value -> rom_size (Int64.to_int value))
    and declared_ram_size =
      Option.bind ram_code (fun value -> ram_size (Int64.to_int value))
    in
    (match cartridge with
    | Some value ->
        add "cartridge_type" "Cartridge type" 0x147L 1L
          (Value.enum 8 value (Parser_common.enum_name cartridge_types value))
    | None -> ());
    (match rom_code with
    | Some value -> (
        add "rom_size_code" "ROM size code" 0x148L 1L (Value.unsigned 8 value);
        match declared_rom_size with
        | Some size ->
            add "rom_size" "Declared ROM size" 0x148L 1L
              (Value.unsigned 64 size);
            add "rom_bank_count" "ROM bank count" 0x148L 1L
              (Value.unsigned 64 (Int64.div size 16_384L))
        | None ->
            Parse_context.warning context ~code:"gameboy.unknown_rom_size"
              ~message:"The Game Boy ROM size code is not recognized."
              ~component:"gameboy.header" ())
    | None -> ());
    (match ram_code with
    | Some value -> (
        add "ram_size_code" "RAM size code" 0x149L 1L
          (Value.enum 8 value
             (Option.map
                (fun size -> Int64.to_string size ^ " bytes")
                declared_ram_size));
        match declared_ram_size with
        | Some size ->
            add "ram_size" "External RAM size" 0x149L 1L
              (Value.unsigned 64 size);
            let banks =
              if Int64.equal size 0L then 0L
              else Int64.div (Int64.add size 8_191L) 8_192L
            in
            add "ram_bank_count" "External RAM bank count" 0x149L 1L
              (Value.unsigned 64 banks)
        | None ->
            Parse_context.warning context ~code:"gameboy.unknown_ram_size"
              ~message:"The Game Boy RAM size code is not recognized."
              ~component:"gameboy.header" ())
    | None -> ());
    (match destination with
    | Some value ->
        add "destination" "Destination" 0x14aL 1L
          (Value.enum 8 value
             (Some (if Int64.equal value 0L then "Japan" else "Outside Japan")))
    | None -> ());
    (match version with
    | Some value -> add "version" "Version" 0x14cL 1L (Value.unsigned 8 value)
    | None -> ());
    let checksum = ref 0 in
    for offset = 0x134 to 0x14c do
      match Reader.byte reader (Int64.of_int offset) with
      | Ok byte -> checksum := (!checksum - byte - 1) land 0xff
      | Error _ -> ()
    done;
    (match stored_header_checksum with
    | Some stored ->
        let valid = Int64.to_int stored = !checksum in
        add "header_checksum" "Header checksum" 0x14dL 1L (Value.Boolean valid);
        if not valid then
          Parse_context.warning context ~code:"gameboy.header_checksum_mismatch"
            ~message:"The Game Boy header checksum is invalid."
            ~component:"gameboy.checksum" ()
    | None -> ());
    (match stored_global_checksum with
    | Some stored ->
        let length = Reader.length reader in
        if
          Int64.compare length
            (Int64.of_int context.Parse_context.limits.max_work_units)
          > 0
        then
          Parse_context.warning context ~code:"gameboy.global_checksum_skipped"
            ~message:
              "The global checksum was skipped because the file exceeds the \
               work budget."
            ~component:"gameboy.checksum" ()
        else
          let sum = ref 0 in
          for offset = 0 to Int64.to_int length - 1 do
            if offset <> 0x14e && offset <> 0x14f then
              match Reader.byte reader (Int64.of_int offset) with
              | Ok byte -> sum := (!sum + byte) land 0xffff
              | Error _ -> ()
          done;
          ignore
            (Limits.consume_work context.Parse_context.tracker
               (Int64.to_int length));
          let valid = Int64.to_int stored = !sum in
          add "global_checksum" "Global checksum" 0x14eL 2L
            (Value.Boolean valid);
          if not valid then
            Parse_context.warning context
              ~code:"gameboy.global_checksum_mismatch"
              ~message:"The Game Boy global checksum is invalid."
              ~component:"gameboy.checksum" ()
    | None -> ());
    match declared_rom_size with
    | Some size when Int64.compare size (Reader.length reader) <= 0 ->
        (match
           Parse_context.node context ~id:"rom_payload"
             ~path:"gameboy.rom_payload" ~label:"ROM image"
             ~span:(Span.unsafe ~start:0L ~length:size)
             ~value:(Value.Bytes { summary = "not copied"; length = size })
             ()
         with
        | None -> ()
        | Some node -> children := node :: !children);
        if Int64.compare size (Reader.length reader) < 0 then
          Parse_context.warning context ~code:"gameboy.trailing_data"
            ~message:"Bytes remain after the declared Game Boy ROM image."
            ~component:"gameboy.payload" ()
    | Some size ->
        Parse_context.error context ~code:"gameboy.rom_size_exceeds_file"
          ~message:"The declared Game Boy ROM size is larger than the file."
          ~component:"gameboy.payload"
          ~span:(Span.unsafe ~start:0x148L ~length:1L)
          ~expected:(Int64.to_string size ^ " bytes")
          ~actual:(Int64.to_string (Reader.length reader) ^ " bytes")
          ~recoverable:true ()
    | None -> ());
  let root =
    Parse_context.node context ~id:"gameboy" ~path:"gameboy"
      ~label:"Game Boy cartridge header"
      ~span:(Parser_common.root_span reader 0x150L)
      ~value:(Value.Collection (List.length !children))
      ~children:(List.rev !children)
      ~diagnostics:(Parse_context.diagnostics context)
      ()
  in
  Parse_context.result context root

let parser =
  { Format.id;
    display_name;
    extensions = [ ".gb"; ".gbc" ];
    coverage;
    detect;
    parse
  }
