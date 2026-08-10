let id = "gba"
let display_name = "Game Boy Advance cartridge header"

let coverage =
  {
    Format.summary =
      "Game Boy Advance title, identity fields, fixed value, and header checksum";
    supported =
      [
        "Nintendo logo detection";
        "title, game code, and maker code";
        "unit, device, and software version fields";
        "fixed-value validation";
        "header checksum";
      ];
    unsupported = [ "ROM payload structures"; "save-memory detection"; "emulation" ];
  }

let logo_prefix = [| 0x24; 0xff; 0xae; 0x51; 0x69; 0x9a; 0xa2; 0x21 |]

let logo_matches reader =
  if Int64.compare (Reader.length reader) 0xa0L < 0 then false
  else
    let matches = ref true in
    for index = 0 to Array.length logo_prefix - 1 do
      match Reader.byte reader (Int64.of_int (4 + index)) with
      | Ok byte when byte = logo_prefix.(index) -> ()
      | _ -> matches := false
    done;
    !matches

let detect _limits reader =
  let fixed = match Reader.byte reader 0xb2L with Ok 0x96 -> true | _ -> false in
  if logo_matches reader && fixed then
    {
      Format.format_id = id;
      display_name;
      confidence = 100;
      evidence = [ "Game Boy Advance logo prefix"; "fixed byte 96 at offset 00B2" ];
      contradictions = [];
      required_minimum_length = 0xc0L;
      definitive = true;
    }
  else if fixed then
    {
      Format.format_id = id;
      display_name;
      confidence = 45;
      evidence = [ "fixed byte 96 at offset 00B2" ];
      contradictions = [ "Nintendo logo prefix does not match" ];
      required_minimum_length = 0xc0L;
      definitive = false;
    }
  else Format.no_detection ~format_id:id ~display_name ~required_minimum_length:0xc0L

let parse limits reader =
  let context = Parse_context.create ~reader ~source_format:id limits in
  let children = ref [] in
  let add id label offset length value =
    match Parser_common.field context ~parent:"gba" ~id ~label ~offset ~length value with
    | None -> ()
    | Some node -> children := node :: !children
  in
  if not (logo_matches reader) then
    Parse_context.error context ~code:"gba.invalid_logo"
      ~message:"The Nintendo logo prefix does not match a Game Boy Advance header."
      ~component:"gba.header" ~recoverable:false ();
  if Parser_common.require_length context ~minimum:0xc0L
       ~code:"gba.truncated_header" ~component:"gba.header"
  then (
    let add_string id label offset length =
      match Parser_common.string context offset length with
      | Some raw ->
          add id label offset length
            (Value.String
               {
                 text = Sanitize.trimmed_text raw;
                 raw_hex = None;
                 valid_utf8 = true;
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
          (Value.enum 8 value (if Int64.equal value 0x96L then Some "Valid" else Some "Invalid"));
        if not (Int64.equal value 0x96L) then
          Parse_context.warning context ~code:"gba.invalid_fixed_value"
            ~message:"The Game Boy Advance fixed byte is not 96."
            ~component:"gba.header" ()
    | None -> ());
    (match unit_code with Some value -> add "unit_code" "Unit code" 0xb3L 1L (Value.unsigned 8 value) | None -> ());
    (match device_type with Some value -> add "device_type" "Device type" 0xb4L 1L (Value.unsigned 8 value) | None -> ());
    (match software_version with Some value -> add "software_version" "Software version" 0xbcL 1L (Value.unsigned 8 value) | None -> ());
    let sum = ref 0 in
    for offset = 0xa0 to 0xbc do
      match Reader.byte reader (Int64.of_int offset) with
      | Ok byte -> sum := (!sum + byte) land 0xff
      | Error _ -> ()
    done;
    let expected = (- !sum - 0x19) land 0xff in
    (match stored_checksum with
    | Some stored ->
        let valid = Int64.to_int stored = expected in
        add "header_checksum" "Header checksum" 0xbdL 1L (Value.Boolean valid);
        if not valid then
          Parse_context.warning context ~code:"gba.header_checksum_mismatch"
            ~message:"The Game Boy Advance header checksum is invalid."
            ~component:"gba.checksum" ()
    | None -> ()));
  let root =
    Parse_context.node context ~id:"gba" ~path:"gba"
      ~label:"Game Boy Advance cartridge header"
      ~span:(Parser_common.root_span reader 0xc0L)
      ~value:(Value.Collection (List.length !children)) ~children:(List.rev !children)
      ~diagnostics:(Parse_context.diagnostics context) ()
  in
  Parse_context.result context root

let parser =
  { Format.id; display_name; extensions = [ ".gba" ]; coverage; detect; parse }
