open Binlens

let pad width value =
  let value = Tree_view.crop width value in
  value ^ String.make (max 0 (width - String.length value)) ' '

let nth_or_empty lines index =
  match List.nth_opt lines index with None -> "" | Some value -> value

let help_lines =
  [
    "BinLens keys";
    "j/k or arrows: move";
    "h/l or arrows: collapse or expand";
    "Enter: toggle selected node";
    "Tab: switch pane";
    "Page Up/Page Down: move one page";
    "g: go to byte offset";
    "/: search labels and paths";
    "n/N: next or previous match";
    "d: toggle diagnostics";
    "r: toggle raw details";
    "x: toggle hexadecimal values";
    "q: quit";
    "?: close help";
  ]

let render ~filename ~format model =
  if model.Model.cols < 60 || model.rows < 14 then
    Printf.sprintf
      "BinLens needs a terminal at least 60 columns wide and 14 rows high.\nCurrent size: %d x %d\nPress q to quit."
      model.cols model.rows
  else if model.show_help then String.concat "\n" help_lines
  else
    let pane = match model.pane with Model.Tree -> "tree" | Hex -> "hex" in
    let header =
      Printf.sprintf "BinLens  %s  format: %s  pane: %s"
        (Sanitize.text filename) format pane
    in
    let body_height = max 1 (model.rows - 5) in
    let tree_width = max 24 (model.cols / 2) in
    let hex_width = model.cols - tree_width - 1 in
    let tree = Tree_view.render model ~height:body_height ~width:tree_width in
    let node = Option.value (Model.selected_node model) ~default:model.root in
    let window =
      Hex_view.calculate ~input_length:(Reader.length model.reader)
        ~selected:node.span ~rows:body_height ~bytes_per_line:8
    in
    let hex = Hex_view.render model.reader node.span window in
    let output = Buffer.create (model.rows * model.cols) in
    Buffer.add_string output (pad model.cols header);
    Buffer.add_char output '\n';
    for index = 0 to body_height - 1 do
      Buffer.add_string output (pad tree_width (nth_or_empty tree index));
      Buffer.add_char output '|';
      Buffer.add_string output (pad hex_width (nth_or_empty hex index));
      Buffer.add_char output '\n'
    done;
    let selected =
      Printf.sprintf "%s  offset 0x%Lx  size %Ld" node.path
        (Span.start node.span) (Span.length node.span)
    in
    Buffer.add_string output (pad model.cols selected);
    Buffer.add_char output '\n';
    if model.raw_details then (
      Buffer.add_string output
        (pad model.cols ("value: " ^ Value.to_string node.value));
      Buffer.add_char output '\n');
    if model.show_diagnostics then (
      let diagnostic =
        match node.diagnostics with
        | first :: _ -> Diagnostic.to_string first
        | [] -> "No diagnostics for the selected node."
      in
      Buffer.add_string output (pad model.cols diagnostic);
      Buffer.add_char output '\n');
    Buffer.contents output
