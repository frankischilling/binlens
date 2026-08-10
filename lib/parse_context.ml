type t = {
  reader : Reader.t;
  source_format : string;
  limits : Limits.t;
  tracker : Limits.tracker;
  mutable diagnostics_rev : Diagnostic.t list;
  mutable partial : bool;
}

let create ~reader ~source_format limits =
  {
    reader;
    source_format;
    limits;
    tracker = Limits.tracker limits;
    diagnostics_rev = [];
    partial = false;
  }

let add_diagnostic context diagnostic =
  match Limits.consume_diagnostic context.tracker with
  | Ok () -> context.diagnostics_rev <- diagnostic :: context.diagnostics_rev
  | Error _ -> context.partial <- true

let error ?span ?expected ?actual ?hint context ~code ~message ~component
    ~recoverable () =
  context.partial <- true;
  add_diagnostic context
    (Diagnostic.make ?span ?expected ?actual ?hint ~severity:Diagnostic.Error
       ~code ~message ~component ~recoverable ())

let warning ?span ?expected ?actual ?hint context ~code ~message ~component () =
  add_diagnostic context
    (Diagnostic.make ?span ?expected ?actual ?hint ~severity:Diagnostic.Warning
       ~code ~message ~component ~recoverable:true ())

let information ?span context ~code ~message ~component () =
  add_diagnostic context
    (Diagnostic.make ?span ~severity:Diagnostic.Information ~code ~message
       ~component ~recoverable:true ())

let error_from_reader context ~component error =
  context.partial <- true;
  add_diagnostic context (Format.diagnostic_of_error ~component error)

let span context ~start ~length =
  match Span.create ~start ~length with
  | Error error ->
      error_from_reader context ~component:context.source_format error;
      None
  | Ok span when Span.within ~input_length:(Reader.length context.reader) span ->
      Some span
  | Ok span ->
      error ~span context ~code:"node.span_out_of_bounds"
        ~message:"A parsed field points outside the input."
        ~component:context.source_format ~recoverable:true ();
      None

let node ?description ?(children = []) ?(diagnostics = []) ?metadata context ~id
    ~path ~label ~span ~value () =
  if not (Span.within ~input_length:(Reader.length context.reader) span) then (
    error ~span context ~code:"node.span_out_of_bounds"
      ~message:"A parsed field points outside the input."
      ~component:context.source_format ~recoverable:true ();
    None)
  else
    match Limits.consume_nodes context.tracker 1 with
    | Error resource_error ->
        error_from_reader context ~component:context.source_format resource_error;
        None
    | Ok () ->
        Some
          (Node.make ?description ~children ~diagnostics
             ?metadata:(Option.map (fun value -> value) metadata) ~id ~path ~label
             ~span ~value ~source_format:context.source_format ())

let diagnostics context = List.rev context.diagnostics_rev
let set_partial context = context.partial <- true

let result context root =
  {
    Format.format_id = context.source_format;
    root;
    diagnostics = diagnostics context;
    partial = context.partial;
    limit_reached = Limits.limit_reached context.tracker;
  }
