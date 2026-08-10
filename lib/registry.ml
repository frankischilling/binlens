let parsers = [ Elf.parser; Pe.parser; Nes.parser; Gameboy.parser; Gba.parser ]

let all () = parsers
let find id = List.find_opt (fun parser -> String.equal parser.Format.id id) parsers

let safe_detect limits reader parser =
  try parser.Format.detect limits reader
  with _ ->
    {
      Format.format_id = parser.id;
      display_name = parser.display_name;
      confidence = 0;
      evidence = [];
      contradictions = [ "The detector returned an internal error." ];
      required_minimum_length = 0L;
      definitive = false;
    }

let detect limits reader =
  parsers
  |> List.map (safe_detect limits reader)
  |> List.sort (fun left right ->
         let confidence = Int.compare right.Format.confidence left.Format.confidence in
         if confidence <> 0 then confidence
         else String.compare left.Format.format_id right.Format.format_id)

let unexpected_failure format_id =
  let diagnostic =
    Diagnostic.make ~severity:Diagnostic.Error
      ~code:"parser.internal_exception"
      ~message:"The parser stopped after an internal error."
      ~component:format_id ~recoverable:false ()
  in
  {
    Format.format_id;
    root = None;
    diagnostics = [ diagnostic ];
    partial = true;
    limit_reached = false;
  }

let safe_parse parser limits reader =
  try parser.Format.parse limits reader
  with _ -> unexpected_failure parser.Format.id

let choose limits reader =
  match detect limits reader with
  | best :: _ when best.Format.confidence > 0 -> find best.format_id
  | _ -> None

let parse ?(format = "auto") limits reader =
  let parser = if String.equal format "auto" then choose limits reader else find format in
  match parser with
  | None ->
      Error
        (Error.make Error.Unsupported "format.unrecognized"
           "No supported binary format matched the input.")
  | Some parser -> Ok (parser, safe_parse parser limits reader)
