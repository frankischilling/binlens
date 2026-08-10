let id = "nes"
let display_name = "NES ROM header"

let coverage =
  {
    Format.summary = "iNES and NES 2.0 header fields and declared payload sizes";
    supported =
      [
        "iNES header";
        "NES 2.0 identification";
        "PRG and CHR sizes";
        "mapper and submapper";
        "mirroring, battery, trainer, and console flags";
      ];
    unsupported = [ "ROM payload semantics"; "emulation"; "archive containers" ];
  }

let has_magic reader =
  match
    ( Reader.byte reader 0L,
      Reader.byte reader 1L,
      Reader.byte reader 2L,
      Reader.byte reader 3L )
  with
  | Ok 0x4e, Ok 0x45, Ok 0x53, Ok 0x1a -> true
  | _ -> false

let detect _limits reader =
  if has_magic reader then
    {
      Format.format_id = id;
      display_name;
      confidence = 100;
      evidence = [ "NES followed by 1A magic at offset 0" ];
      contradictions = [];
      required_minimum_length = 16L;
      definitive = true;
    }
  else Format.no_detection ~format_id:id ~display_name ~required_minimum_length:16L

let console_name = function
  | 0 -> Some "NES or Famicom"
  | 1 -> Some "Vs. System"
  | 2 -> Some "PlayChoice-10"
  | 3 -> Some "Extended console type"
  | _ -> None

let checked_shift context exponent multiplier component =
  if exponent < 0 || exponent > 62 then (
    Parse_context.warning context ~code:"nes.size_overflow"
      ~message:"A NES 2.0 exponent size cannot be represented safely."
      ~component ();
    None)
  else
    match Reader.checked_mul (Int64.shift_left 1L exponent) multiplier with
    | Ok result -> Some result
    | Error error ->
        Parse_context.error_from_reader context ~component error;
        None

let nes2_size context lsb upper unit_size component =
  if upper <> 0x0f then
    Reader.checked_mul (Int64.of_int (lsb lor (upper lsl 8))) unit_size
    |> (function
         | Ok value -> Some value
         | Error error ->
             Parse_context.error_from_reader context ~component error;
             None)
  else
    let exponent = lsb lsr 2 in
    let multiplier = (lsb land 3) * 2 + 1 in
    checked_shift context exponent (Int64.of_int multiplier) component

let parse limits reader =
  let context = Parse_context.create ~reader ~source_format:id limits in
  let children = ref [] in
  let add id label offset length value =
    children :=
      (match
         Parser_common.field context ~parent:"nes" ~id ~label ~offset ~length value
       with
      | None -> !children
      | Some node -> node :: !children)
  in
  (if Int64.compare (Reader.length reader) 4L >= 0 then
    match Parser_common.hex context 0L 4L with
    | Some value -> add "magic" "Magic" 0L 4L (Value.Bytes { summary = value; length = 4L })
    | None -> ());
  if not (has_magic reader) then
    Parse_context.error context ~code:"nes.invalid_magic"
      ~message:"The input does not start with NES ROM magic."
      ~component:"nes.header" ~recoverable:false ();
  if Parser_common.require_length context ~minimum:16L
       ~code:"nes.truncated_header" ~component:"nes.header"
  then (
    let bytes =
      Array.init 12 (fun index ->
          Parser_common.u8 context (Int64.of_int (index + 4)))
    in
    if Array.for_all Option.is_some bytes then (
      let get index = Int64.to_int (Option.get bytes.(index)) in
      let prg_lsb = get 0 and chr_lsb = get 1 and flags6 = get 2 and flags7 = get 3 in
      let nes2 = flags7 land 0x0c = 0x08 in
      let format_name = if nes2 then "NES 2.0" else "iNES" in
      add "format_version" "Header format" 7L 1L
        (Value.enum 8 (Int64.of_int (flags7 land 0x0c)) (Some format_name));
      let mapper =
        (flags6 lsr 4) lor (flags7 land 0xf0)
        lor (if nes2 then (get 4 land 0x0f) lsl 8 else 0)
      in
      add "mapper" "Mapper" 6L (if nes2 then 3L else 2L)
        (Value.unsigned (if nes2 then 12 else 8) (Int64.of_int mapper));
      if nes2 then
        add "submapper" "Submapper" 8L 1L
          (Value.unsigned 4 (Int64.of_int (get 4 lsr 4)));
      add "mirroring" "Mirroring" 6L 1L
        (Value.enum 1 (Int64.of_int (flags6 land 1))
           (Some (if flags6 land 1 <> 0 then "Vertical" else "Horizontal")));
      add "battery" "Battery-backed memory" 6L 1L
        (Value.Boolean (flags6 land 2 <> 0));
      add "trainer" "Trainer present" 6L 1L
        (Value.Boolean (flags6 land 4 <> 0));
      let console = flags7 land 3 in
      add "console_type" "Console type" 7L 1L
        (Value.enum 2 (Int64.of_int console) (console_name console));
      let prg_size, chr_size =
        if nes2 then
          let size_msb = get 5 in
          ( nes2_size context prg_lsb (size_msb land 0x0f) 16_384L
              "nes.prg_size",
            nes2_size context chr_lsb (size_msb lsr 4) 8_192L "nes.chr_size" )
        else
          ( Some (Int64.mul (Int64.of_int prg_lsb) 16_384L),
            Some (Int64.mul (Int64.of_int chr_lsb) 8_192L) )
      in
      (match prg_size with
      | Some size ->
          add "prg_size" "PRG ROM size" 4L (if nes2 then 6L else 1L)
            (Value.unsigned 64 size)
      | None -> ());
      (match chr_size with
      | Some size ->
          add "chr_size" "CHR ROM size" 5L (if nes2 then 5L else 1L)
            (Value.unsigned 64 size)
      | None -> ());
      (match (prg_size, chr_size) with
      | Some prg, Some chr ->
          let trainer = if flags6 land 4 <> 0 then 512L else 0L in
          (match Reader.checked_add 16L trainer with
          | Error error -> Parse_context.error_from_reader context ~component:"nes.payload" error
          | Ok prefix -> (
              match Reader.checked_add prg chr with
              | Error error -> Parse_context.error_from_reader context ~component:"nes.payload" error
              | Ok payload -> (
                  match Reader.checked_add prefix payload with
                  | Error error -> Parse_context.error_from_reader context ~component:"nes.payload" error
                  | Ok expected when Int64.compare expected (Reader.length reader) > 0 ->
                      Parse_context.warning context ~code:"nes.declared_size_exceeds_file"
                        ~message:"The declared NES ROM payload is larger than the file."
                        ~component:"nes.payload" ()
                  | Ok _ -> ())))
      | _ -> ())));
  let root =
    Parse_context.node context ~id:"nes" ~path:"nes" ~label:"NES ROM header"
      ~span:(Parser_common.root_span reader 16L)
      ~value:(Value.Collection (List.length !children)) ~children:(List.rev !children)
      ~diagnostics:(Parse_context.diagnostics context) ()
  in
  Parse_context.result context root

let parser =
  { Format.id; display_name; extensions = [ ".nes" ]; coverage; detect; parse }
