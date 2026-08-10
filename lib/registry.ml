type t = { parsers : Format.parser list }

let api_version = 1

let first_party_parsers =
  [ Elf.parser; Pe.parser; Nes.parser; Gameboy.parser; Gba.parser ]

let valid_identifier value =
  let length = String.length value in
  let is_lower letter = letter >= 'a' && letter <= 'z' in
  let is_digit letter = letter >= '0' && letter <= '9' in
  let valid_tail letter =
    is_lower letter || is_digit letter || letter = '-' || letter = '_'
  in
  length > 0 && is_lower value.[0] && String.for_all valid_tail value

let valid_extension value =
  let length = String.length value in
  let valid letter =
    (letter >= 'a' && letter <= 'z')
    || (letter >= '0' && letter <= '9')
    || letter = '-' || letter = '_'
  in
  length > 1
  && value.[0] = '.'
  && String.for_all valid (String.sub value 1 (length - 1))

let registration_error code message =
  Error (Error.make Error.Invalid_argument code message)

let validate parsers =
  let identifiers = Hashtbl.create (List.length parsers) in
  let extensions = Hashtbl.create (List.length parsers * 2) in
  let rec validate_extensions parser_id = function
    | [] -> Ok ()
    | extension :: rest ->
        if not (valid_extension extension) then
          registration_error "registry.invalid_extension"
            (Printf.sprintf "Parser %s has an invalid file extension: %S."
               parser_id extension)
        else if Hashtbl.mem extensions extension then
          registration_error "registry.duplicate_extension"
            (Printf.sprintf "More than one parser registered file extension %S."
               extension)
        else (
          Hashtbl.add extensions extension parser_id;
          validate_extensions parser_id rest)
  in
  let rec loop = function
    | [] -> Ok ()
    | parser :: rest ->
        if not (valid_identifier parser.Format.id) then
          registration_error "registry.invalid_id"
            (Printf.sprintf "Parser identifier %S is invalid." parser.id)
        else if Hashtbl.mem identifiers parser.id then
          registration_error "registry.duplicate_id"
            (Printf.sprintf "Parser identifier %S is already registered."
               parser.id)
        else (
          Hashtbl.add identifiers parser.id ();
          match validate_extensions parser.id parser.extensions with
          | Error _ as error -> error
          | Ok () -> loop rest)
  in
  loop parsers

let create parsers =
  match validate parsers with
  | Error _ as error -> error
  | Ok () ->
      Ok
        { parsers =
            List.sort
              (fun left right -> String.compare left.Format.id right.Format.id)
              parsers
        }

let builtins =
  match validate first_party_parsers with
  | Ok () -> { parsers = first_party_parsers }
  | Error _ -> assert false

let with_parser registry parser = create (parser :: registry.parsers)
let all ?(registry = builtins) () = registry.parsers

let find ?(registry = builtins) id =
  List.find_opt
    (fun parser -> String.equal parser.Format.id id)
    registry.parsers

let safe_detect limits reader parser =
  try parser.Format.detect limits reader
  with _ ->
    { Format.format_id = parser.id;
      display_name = parser.display_name;
      confidence = 0;
      evidence = [];
      contradictions = [ "The detector returned an internal error." ];
      required_minimum_length = 0L;
      definitive = false
    }

let detect ?(registry = builtins) limits reader =
  registry.parsers
  |> List.map (safe_detect limits reader)
  |> List.sort (fun left right ->
      let confidence =
        Int.compare right.Format.confidence left.Format.confidence
      in
      if confidence <> 0 then confidence
      else String.compare left.Format.format_id right.Format.format_id)

let unexpected_failure format_id =
  let diagnostic =
    Diagnostic.make ~severity:Diagnostic.Error ~code:"parser.internal_exception"
      ~message:"The parser stopped after an internal error."
      ~component:format_id ~recoverable:false ()
  in
  { Format.format_id;
    root = None;
    diagnostics = [ diagnostic ];
    partial = true;
    limit_reached = false
  }

let safe_parse parser limits reader =
  try parser.Format.parse limits reader
  with _ -> unexpected_failure parser.Format.id

let choose registry limits reader =
  match detect ~registry limits reader with
  | best :: _ when best.Format.confidence > 0 -> find ~registry best.format_id
  | _ -> None

let parse ?(registry = builtins) ?(format = "auto") limits reader =
  let parser =
    if String.equal format "auto" then choose registry limits reader
    else find ~registry format
  in
  match parser with
  | None ->
      Error
        (Error.make Error.Unsupported "format.unrecognized"
           "No registered binary format matched the input.")
  | Some parser -> Ok (parser, safe_parse parser limits reader)
