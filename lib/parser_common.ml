let span_exn ~start ~length =
  match Span.create ~start ~length with
  | Ok span -> span
  | Error _ -> assert false

let field context ?description ?metadata ~parent ~id ~label ~offset ~length
    value =
  match Parse_context.span context ~start:offset ~length with
  | None -> None
  | Some span ->
      Parse_context.node ?description ?metadata context ~id
        ~path:(parent ^ "." ^ id)
        ~label ~span ~value ()

let root_span reader requested =
  span_exn ~start:0L ~length:(min requested (Reader.length reader))

let read context ~component operation =
  match operation with
  | Ok value -> Some value
  | Error error ->
      Parse_context.error_from_reader context ~component error;
      None

let u8 context offset =
  read context ~component:"reader"
    (Reader.u8 context.Parse_context.reader offset)

let u16 context endian offset =
  read context ~component:"reader"
    (Reader.u16 context.Parse_context.reader endian offset)

let u32 context endian offset =
  read context ~component:"reader"
    (Reader.u32 context.Parse_context.reader endian offset)

let u64 context endian offset =
  read context ~component:"reader"
    (Reader.u64 context.Parse_context.reader endian offset)

let string context offset length =
  read context ~component:"reader"
    (Reader.fixed_string ~tracker:context.Parse_context.tracker
       context.Parse_context.reader ~offset ~length)

let hex context offset length =
  read context ~component:"reader"
    (Reader.hex context.Parse_context.reader ~offset ~length)

let enum_name entries value = List.assoc_opt value entries

let require_length context ~minimum ~code ~component =
  if Int64.compare (Reader.length context.Parse_context.reader) minimum >= 0
  then true
  else (
    Parse_context.error context ~code
      ~message:
        (Printf.sprintf "The header requires at least %Ld bytes." minimum)
      ~component ~recoverable:true ();
    false)

let add_if_some value output =
  match value with None -> output | Some node -> node :: output

let list_filter_map_indexed function_ values =
  let rec loop index input output =
    match input with
    | [] -> List.rev output
    | value :: rest ->
        let output =
          match function_ index value with
          | None -> output
          | Some mapped -> mapped :: output
        in
        loop (index + 1) rest output
  in
  loop 0 values []
