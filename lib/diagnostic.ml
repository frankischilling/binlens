type severity = Information | Warning | Error

type t =
  { severity : severity;
    code : string;
    message : string;
    span : Span.t option;
    component : string;
    expected : string option;
    actual : string option;
    recoverable : bool;
    hint : string option
  }

let make ?span ?expected ?actual ?hint ~severity ~code ~message ~component
    ~recoverable () =
  { severity;
    code;
    message;
    span;
    component;
    expected;
    actual;
    recoverable;
    hint
  }

let severity_to_string = function
  | Information -> "information"
  | Warning -> "warning"
  | Error -> "error"

let severity_rank = function Information -> 0 | Warning -> 1 | Error -> 2

let to_string diagnostic =
  let location =
    match diagnostic.span with
    | None -> ""
    | Some span -> " " ^ Span.to_string span
  in
  Printf.sprintf "%s %s%s: %s"
    (String.uppercase_ascii (severity_to_string diagnostic.severity))
    diagnostic.code location diagnostic.message
