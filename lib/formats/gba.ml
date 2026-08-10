let id = "gba"
let display_name = "Game Boy Advance cartridge header"

let coverage =
  { Format.summary =
      "Game Boy Advance title, identity fields, logo, header checksum, and \
       bounded save-memory hints";
    supported =
      [ "complete Nintendo logo validation";
        "title, game code, and maker code";
        "unit, device, and software version fields";
        "fixed-value validation";
        "header checksum";
        "bounded save-memory signature detection"
      ];
    unsupported =
      [ "ROM payload structures"; "save-data decoding"; "emulation" ]
  }

let logo =
  [| 0x24;
     0xff;
     0xae;
     0x51;
     0x69;
     0x9a;
     0xa2;
     0x21;
     0x3d;
     0x84;
     0x82;
     0x0a;
     0x84;
     0xe4;
     0x09;
     0xad;
     0x11;
     0x24;
     0x8b;
     0x98;
     0xc0;
     0x81;
     0x7f;
     0x21;
     0xa3;
     0x52;
     0xbe;
     0x19;
     0x93;
     0x09;
     0xce;
     0x20;
     0x10;
     0x46;
     0x4a;
     0x4a;
     0xf8;
     0x27;
     0x31;
     0xec;
     0x58;
     0xc7;
     0xe8;
     0x33;
     0x82;
     0xe3;
     0xce;
     0xbf;
     0x85;
     0xf4;
     0xdf;
     0x94;
     0xce;
     0x4b;
     0x09;
     0xc1;
     0x94;
     0x56;
     0x8a;
     0xc0;
     0x13;
     0x72;
     0xa7;
     0xfc;
     0x9f;
     0x84;
     0x4d;
     0x73;
     0xa3;
     0xca;
     0x9a;
     0x61;
     0x58;
     0x97;
     0xa3;
     0x27;
     0xfc;
     0x03;
     0x98;
     0x76;
     0x23;
     0x1d;
     0xc7;
     0x61;
     0x03;
     0x04;
     0xae;
     0x56;
     0xbf;
     0x38;
     0x84;
     0x00;
     0x40;
     0xa7;
     0x0e;
     0xfd;
     0xff;
     0x52;
     0xfe;
     0x03;
     0x6f;
     0x95;
     0x30;
     0xf1;
     0x97;
     0xfb;
     0xc0;
     0x85;
     0x60;
     0xd6;
     0x80;
     0x25;
     0xa9;
     0x63;
     0xbe;
     0x03;
     0x01;
     0x4e;
     0x38;
     0xe2;
     0xf9;
     0xa2;
     0x34;
     0xff;
     0xbb;
     0x3e;
     0x03;
     0x44;
     0x78;
     0x00;
     0x90;
     0xcb;
     0x88;
     0x11;
     0x3a;
     0x94;
     0x65;
     0xc0;
     0x7c;
     0x63;
     0x87;
     0xf0;
     0x3c;
     0xaf;
     0xd6;
     0x25;
     0xe4;
     0x8b;
     0x38;
     0x0a;
     0xac;
     0x72;
     0x21;
     0xd4;
     0xf8;
     0x07
  |]

let logo_mask index =
  match 4 + index with 0x9c -> 0x7b | 0x9e -> 0xfc | _ -> 0xff

let logo_byte_matches index actual =
  let mask = logo_mask index in
  actual land mask = logo.(index) land mask

let first_logo_mismatch reader =
  if Int64.compare (Reader.length reader) 0xa0L < 0 then None
  else
    let mismatch = ref None in
    let index = ref 0 in
    while !index < Array.length logo && Option.is_none !mismatch do
      match Reader.byte reader (Int64.of_int (4 + !index)) with
      | Ok byte when logo_byte_matches !index byte -> incr index
      | Ok byte -> mismatch := Some (!index, byte)
      | Error _ -> mismatch := Some (!index, -1)
    done;
    !mismatch

let logo_matches reader =
  if Int64.compare (Reader.length reader) 0xa0L < 0 then false
  else Option.is_none (first_logo_mismatch reader)

type save_signature = { id : string; label : string; pattern : string }

let save_signatures =
  [ { id = "eeprom"; label = "EEPROM"; pattern = "EEPROM_V" };
    { id = "sram"; label = "SRAM"; pattern = "SRAM_V" };
    { id = "flash_64k"; label = "Flash 64 KiB"; pattern = "FLASH_V" };
    { id = "flash_64k_extended";
      label = "Flash 64 KiB";
      pattern = "FLASH512_V"
    };
    { id = "flash_128k"; label = "Flash 128 KiB"; pattern = "FLASH1M_V" }
  ]

let signature_matches reader offset pattern =
  let length = String.length pattern in
  match Reader.range reader ~offset ~length:(Int64.of_int length) with
  | Error _ -> false
  | Ok () ->
      let matches = ref true in
      let index = ref 0 in
      while !matches && !index < length do
        match Reader.byte reader (Int64.add offset (Int64.of_int !index)) with
        | Ok byte when byte = Char.code pattern.[!index] -> incr index
        | _ -> matches := false
      done;
      !matches

let parse_save_signatures context =
  let reader = context.Parse_context.reader in
  let offset = ref 0xc0L in
  let found = Hashtbl.create (List.length save_signatures) in
  let scanning = ref true in
  while !scanning && Int64.compare !offset (Reader.length reader) < 0 do
    match Limits.consume_work context.Parse_context.tracker 1 with
    | Error error ->
        Parse_context.error_from_reader context ~component:"gba.save_memory"
          error;
        scanning := false
    | Ok () ->
        List.iter
          (fun signature ->
            if
              (not (Hashtbl.mem found signature.id))
              && signature_matches reader !offset signature.pattern
            then Hashtbl.add found signature.id (signature, !offset))
          save_signatures;
        offset := Int64.succ !offset
  done;
  let matches =
    save_signatures
    |> List.filter_map (fun signature ->
        Option.map
          (fun (_, offset) -> (signature, offset))
          (Hashtbl.find_opt found signature.id))
  in
  if List.length matches > 1 then
    Parse_context.information context ~code:"gba.multiple_save_signatures"
      ~message:
        "Several save-memory signatures were found; the ROM may contain unused \
         library code."
      ~component:"gba.save_memory" ();
  let children =
    matches
    |> List.filter_map (fun (signature, offset) ->
        Parser_common.field context ~parent:"gba.save_memory" ~id:signature.id
          ~label:(signature.label ^ " signature")
          ~offset
          ~length:(Int64.of_int (String.length signature.pattern))
          (Value.String
             { text = signature.pattern; raw_hex = None; valid_utf8 = true }))
  in
  match children with
  | [] -> None
  | first :: rest ->
      let start =
        List.fold_left
          (fun current node -> Int64.min current (Span.start node.Node.span))
          (Span.start first.Node.span)
          rest
      in
      let finish =
        List.fold_left
          (fun current node ->
            match Span.end_offset node.Node.span with
            | Ok value -> Int64.max current value
            | Error _ -> current)
          (match Span.end_offset first.Node.span with
          | Ok value -> value
          | Error _ -> start)
          rest
      in
      Parse_context.node context ~id:"save_memory" ~path:"gba.save_memory"
        ~label:"Save-memory signatures"
        ~span:(Span.unsafe ~start ~length:(Int64.sub finish start))
        ~value:(Value.Collection (List.length children))
        ~children ()

let detect _limits reader =
  let fixed =
    match Reader.byte reader 0xb2L with Ok 0x96 -> true | _ -> false
  in
  if logo_matches reader && fixed then
    { Format.format_id = id;
      display_name;
      confidence = 100;
      evidence =
        [ "complete Game Boy Advance logo"; "fixed byte 96 at offset 00B2" ];
      contradictions = [];
      required_minimum_length = 0xc0L;
      definitive = true
    }
  else if fixed then
    { Format.format_id = id;
      display_name;
      confidence = 45;
      evidence = [ "fixed byte 96 at offset 00B2" ];
      contradictions = [ "Nintendo logo does not match" ];
      required_minimum_length = 0xc0L;
      definitive = false
    }
  else
    Format.no_detection ~format_id:id ~display_name
      ~required_minimum_length:0xc0L

let parse limits reader =
  let context = Parse_context.create ~reader ~source_format:id limits in
  let children = ref [] in
  let add id label offset length value =
    match
      Parser_common.field context ~parent:"gba" ~id ~label ~offset ~length value
    with
    | None -> ()
    | Some node -> children := node :: !children
  in
  (match first_logo_mismatch reader with
  | Some (index, actual) ->
      let offset = Int64.of_int (4 + index) in
      Parse_context.error context ~code:"gba.invalid_logo"
        ~message:"A Nintendo logo byte does not match the expected value."
        ~component:"gba.header"
        ~span:(Span.unsafe ~start:offset ~length:1L)
        ~expected:(Printf.sprintf "%02X" logo.(index))
        ~actual:
          (if actual < 0 then "unreadable" else Printf.sprintf "%02X" actual)
        ~recoverable:false ()
  | None -> ());
  if
    Parser_common.require_length context ~minimum:0xc0L
      ~code:"gba.truncated_header" ~component:"gba.header"
  then (
    add "nintendo_logo" "Nintendo logo" 4L 156L
      (Value.Boolean (logo_matches reader));
    let add_string id label offset length =
      match Parser_common.string context offset length with
      | Some raw ->
          add id label offset length
            (Value.String
               { text = Sanitize.trimmed_text raw;
                 raw_hex = None;
                 valid_utf8 = true
               })
      | None -> ()
    in
    add_string "title" "Title" 0xa0L 12L;
    add_string "game_code" "Game code" 0xacL 4L;
    add_string "maker_code" "Maker code" 0xb0L 2L;
    let fixed = Parser_common.u8 context 0xb2L
    and unit_code = Parser_common.u8 context 0xb3L
    and device_type = Parser_common.u8 context 0xb4L
    and software_version = Parser_common.u8 context 0xbcL
    and stored_checksum = Parser_common.u8 context 0xbdL in
    (match fixed with
    | Some value ->
        add "fixed_value" "Fixed value" 0xb2L 1L
          (Value.enum 8 value
             (if Int64.equal value 0x96L then Some "Valid" else Some "Invalid"));
        if not (Int64.equal value 0x96L) then
          Parse_context.warning context ~code:"gba.invalid_fixed_value"
            ~message:"The Game Boy Advance fixed byte is not 96."
            ~component:"gba.header" ()
    | None -> ());
    (match parse_save_signatures context with
    | Some node -> children := node :: !children
    | None -> ());
    (match unit_code with
    | Some value ->
        add "unit_code" "Unit code" 0xb3L 1L (Value.unsigned 8 value)
    | None -> ());
    (match device_type with
    | Some value ->
        add "device_type" "Device type" 0xb4L 1L (Value.unsigned 8 value)
    | None -> ());
    (match software_version with
    | Some value ->
        add "software_version" "Software version" 0xbcL 1L
          (Value.unsigned 8 value)
    | None -> ());
    let sum = ref 0 in
    for offset = 0xa0 to 0xbc do
      match Reader.byte reader (Int64.of_int offset) with
      | Ok byte -> sum := (!sum + byte) land 0xff
      | Error _ -> ()
    done;
    let expected = (- !sum - 0x19) land 0xff in
    match stored_checksum with
    | Some stored ->
        let valid = Int64.to_int stored = expected in
        add "header_checksum" "Header checksum" 0xbdL 1L (Value.Boolean valid);
        if not valid then
          Parse_context.warning context ~code:"gba.header_checksum_mismatch"
            ~message:"The Game Boy Advance header checksum is invalid."
            ~component:"gba.checksum" ()
    | None -> ());
  let root =
    Parse_context.node context ~id:"gba" ~path:"gba"
      ~label:"Game Boy Advance cartridge header"
      ~span:(Parser_common.root_span reader 0xc0L)
      ~value:(Value.Collection (List.length !children))
      ~children:(List.rev !children)
      ~diagnostics:(Parse_context.diagnostics context)
      ()
  in
  Parse_context.result context root

let parser =
  { Format.id; display_name; extensions = [ ".gba" ]; coverage; detect; parse }
