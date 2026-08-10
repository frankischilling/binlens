type options = {
  max_depth : int;
  show_descriptions : bool;
  show_diagnostics : bool;
  show_raw : bool;
  decimal_offsets : bool;
}

let default_options =
  {
    max_depth = 32;
    show_descriptions = false;
    show_diagnostics = true;
    show_raw = false;
    decimal_offsets = false;
  }

let span options span =
  match Span.end_offset span with
  | Error _ -> "[invalid span]"
  | Ok finish ->
      if options.decimal_offsets then
        Printf.sprintf "[%Ld..%Ld)" (Span.start span) finish
      else Printf.sprintf "[0x%08Lx..0x%08Lx)" (Span.start span) finish

let render ?(options = default_options) root =
  let output = Buffer.create 4096 in
  let line depth text =
    Buffer.add_string output (String.make (depth * 2) ' ');
    Buffer.add_string output text;
    Buffer.add_char output '\n'
  in
  let rec visit depth node =
    if depth <= options.max_depth then (
      line depth
        (Printf.sprintf "%s %s = %s" node.Node.label (span options node.span)
           (Value.to_string node.value));
      if options.show_descriptions then
        Option.iter (fun description -> line (depth + 1) description) node.description;
      if options.show_raw then
        Option.iter
          (fun raw -> line (depth + 1) ("raw: " ^ raw))
          node.metadata.raw;
      if options.show_diagnostics then
        List.iter
          (fun diagnostic -> line (depth + 1) (Diagnostic.to_string diagnostic))
          node.diagnostics;
      if depth < options.max_depth then List.iter (visit (depth + 1)) node.children
      else if node.children <> [] then line (depth + 1) "... depth limit reached")
  in
  visit 0 root;
  Buffer.contents output
