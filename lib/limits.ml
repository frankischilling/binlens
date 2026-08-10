type t =
  { max_nodes : int;
    max_table_entries : int;
    max_string_bytes : int;
    max_depth : int;
    max_total_bytes_copied : int;
    max_diagnostics : int;
    max_work_units : int
  }

let default =
  { max_nodes = 20_000;
    max_table_entries = 4_096;
    max_string_bytes = 4_096;
    max_depth = 64;
    max_total_bytes_copied = 16 * 1024 * 1024;
    max_diagnostics = 1_000;
    max_work_units = 2_000_000
  }

let validate limits =
  let values =
    [ ("max_nodes", limits.max_nodes);
      ("max_table_entries", limits.max_table_entries);
      ("max_string_bytes", limits.max_string_bytes);
      ("max_depth", limits.max_depth);
      ("max_total_bytes_copied", limits.max_total_bytes_copied);
      ("max_diagnostics", limits.max_diagnostics);
      ("max_work_units", limits.max_work_units)
    ]
  in
  match List.find_opt (fun (_, value) -> value < 0) values with
  | None -> Ok limits
  | Some (name, _) ->
      Error
        (Error.make Error.Invalid_argument "limits.negative"
           (name ^ " cannot be negative."))

type tracker =
  { limits : t;
    mutable nodes : int;
    mutable table_entries : int;
    mutable bytes_copied : int;
    mutable diagnostics : int;
    mutable work_units : int;
    mutable limit_reached : bool
  }

let tracker limits =
  { limits;
    nodes = 0;
    table_entries = 0;
    bytes_copied = 0;
    diagnostics = 0;
    work_units = 0;
    limit_reached = false
  }

let resource_error code message = Error.make Error.Resource_limit code message

let consume tracker field amount maximum code message =
  if amount < 0 || field > maximum - amount then (
    tracker.limit_reached <- true;
    Error (resource_error code message))
  else Ok (field + amount)

let consume_nodes tracker amount =
  match
    consume tracker tracker.nodes amount tracker.limits.max_nodes "limit.nodes"
      "The parse-tree node limit was reached."
  with
  | Ok value ->
      tracker.nodes <- value;
      Ok ()
  | Error error -> Error error

let consume_table_entries tracker amount =
  match
    consume tracker tracker.table_entries amount
      tracker.limits.max_table_entries "limit.table_entries"
      "The parser table-entry limit was reached."
  with
  | Ok value ->
      tracker.table_entries <- value;
      Ok ()
  | Error error -> Error error

let consume_bytes_copied tracker amount =
  match
    consume tracker tracker.bytes_copied amount
      tracker.limits.max_total_bytes_copied "limit.bytes_copied"
      "The parser byte-copy limit was reached."
  with
  | Ok value ->
      tracker.bytes_copied <- value;
      Ok ()
  | Error error -> Error error

let consume_diagnostic tracker =
  match
    consume tracker tracker.diagnostics 1 tracker.limits.max_diagnostics
      "limit.diagnostics" "The parser diagnostic limit was reached."
  with
  | Ok value ->
      tracker.diagnostics <- value;
      Ok ()
  | Error error -> Error error

let consume_work tracker amount =
  match
    consume tracker tracker.work_units amount tracker.limits.max_work_units
      "limit.work" "The parser work-unit limit was reached."
  with
  | Ok value ->
      tracker.work_units <- value;
      Ok ()
  | Error error -> Error error

let limit_reached tracker = tracker.limit_reached
