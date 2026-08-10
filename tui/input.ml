type key =
  | Character of string
  | Up
  | Down
  | Left
  | Right
  | Page_up
  | Page_down
  | Enter
  | Tab
  | Escape

let read_source () = Terml.Input.Input.read ()

let rec next_non_retry attempts =
  if attempts <= 0 then None
  else
    match read_source () with
    | `Read value -> Some value
    | `End -> None
    | `Malformed _ -> None
    | `Retry ->
        Unix.sleepf 0.002;
        next_non_retry (attempts - 1)

let decode_escape () =
  match next_non_retry 10 with
  | Some "[" -> (
      match next_non_retry 10 with
      | Some "A" -> Up
      | Some "B" -> Down
      | Some "C" -> Right
      | Some "D" -> Left
      | Some "5" ->
          ignore (next_non_retry 10);
          Page_up
      | Some "6" ->
          ignore (next_non_retry 10);
          Page_down
      | _ -> Escape)
  | _ -> Escape

let next () =
  match read_source () with
  | `Retry -> None
  | `End | `Malformed _ -> Some Escape
  | `Read "\x1b" -> Some (decode_escape ())
  | `Read ("\r" | "\n") -> Some Enter
  | `Read "\t" -> Some Tab
  | `Read value -> Some (Character value)
