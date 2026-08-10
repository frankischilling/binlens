type kind =
  | Bounds
  | Overflow
  | Invalid_argument
  | Resource_limit
  | Io
  | Malformed
  | Unsupported

type t =
  { kind : kind;
    code : string;
    message : string;
    offset : int64 option;
    requested : int64 option;
    available : int64 option
  }

let make ?offset ?requested ?available kind code message =
  { kind; code; message; offset; requested; available }

let kind_to_string = function
  | Bounds -> "bounds"
  | Overflow -> "overflow"
  | Invalid_argument -> "invalid_argument"
  | Resource_limit -> "resource_limit"
  | Io -> "io"
  | Malformed -> "malformed"
  | Unsupported -> "unsupported"

let to_string error =
  match error.offset with
  | None -> Printf.sprintf "%s: %s" error.code error.message
  | Some offset ->
      Printf.sprintf "%s at 0x%Lx: %s" error.code offset error.message
