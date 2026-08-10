type detection = {
  format_id : string;
  display_name : string;
  confidence : int;
  evidence : string list;
  contradictions : string list;
  required_minimum_length : int64;
  definitive : bool;
}

type coverage = {
  summary : string;
  supported : string list;
  unsupported : string list;
}

type parse_result = {
  format_id : string;
  root : Node.t option;
  diagnostics : Diagnostic.t list;
  partial : bool;
  limit_reached : bool;
}

type parser = {
  id : string;
  display_name : string;
  extensions : string list;
  coverage : coverage;
  detect : Limits.t -> Reader.t -> detection;
  parse : Limits.t -> Reader.t -> parse_result;
}

let no_detection ~format_id ~display_name ~required_minimum_length =
  {
    format_id;
    display_name;
    confidence = 0;
    evidence = [];
    contradictions = [];
    required_minimum_length;
    definitive = false;
  }

let diagnostic_of_error ~component error =
  let severity =
    match error.Error.kind with
    | Error.Resource_limit -> Diagnostic.Warning
    | _ -> Diagnostic.Error
  in
  let span =
    match error.Error.offset with
    | None -> None
    | Some start ->
        let length = Option.value error.Error.requested ~default:0L in
        (match Span.create ~start ~length with Ok span -> Some span | Error _ -> None)
  in
  Diagnostic.make ?span ~severity ~code:error.Error.code
    ~message:error.Error.message ~component ~recoverable:true ()

let failed ~format_id diagnostic =
  {
    format_id;
    root = None;
    diagnostics = [ diagnostic ];
    partial = true;
    limit_reached = false;
  }
