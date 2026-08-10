open Binlens

module String_set = Set.Make (String)

type pane = Tree | Hex

type row = { node : Node.t; depth : int }

type t = {
  root : Node.t;
  reader : Reader.t;
  expanded : String_set.t;
  visible : row array;
  selected : int;
  pane : pane;
  rows : int;
  cols : int;
  raw_details : bool;
  hexadecimal_values : bool;
  show_diagnostics : bool;
  show_help : bool;
  search_query : string option;
  search_matches : string array;
  search_index : int;
}

let flatten_visible root expanded =
  let rec walk depth node output =
    let output = { node; depth } :: output in
    if String_set.mem node.Node.path expanded then
      List.fold_left (fun output child -> walk (depth + 1) child output) output
        node.children
    else output
  in
  walk 0 root [] |> List.rev |> Array.of_list

let create ~reader ~root ~rows ~cols =
  let expanded = String_set.singleton root.Node.path in
  {
    root;
    reader;
    expanded;
    visible = flatten_visible root expanded;
    selected = 0;
    pane = Tree;
    rows;
    cols;
    raw_details = false;
    hexadecimal_values = true;
    show_diagnostics = true;
    show_help = false;
    search_query = None;
    search_matches = [||];
    search_index = 0;
  }

let selected_row model =
  if Array.length model.visible = 0 then None
  else Some model.visible.(min model.selected (Array.length model.visible - 1))

let selected_node model = Option.map (fun row -> row.node) (selected_row model)

let select_path model path =
  let rec find index =
    if index = Array.length model.visible then None
    else if String.equal model.visible.(index).node.Node.path path then Some index
    else find (index + 1)
  in
  match find 0 with None -> model | Some selected -> { model with selected }

let rebuild model expanded preferred_path =
  let visible = flatten_visible model.root expanded in
  let selected =
    let rec find index =
      if index = Array.length visible then
        min model.selected (max 0 (Array.length visible - 1))
      else if String.equal visible.(index).node.Node.path preferred_path then index
      else find (index + 1)
    in
    find 0
  in
  { model with expanded; visible; selected }

let move model delta =
  if Array.length model.visible = 0 then model
  else
    {
      model with
      selected = max 0 (min (Array.length model.visible - 1) (model.selected + delta));
    }

let page model direction = move model (direction * max 1 (model.rows - 6))

let expand model =
  match selected_row model with
  | None -> model
  | Some { node; _ } when node.Node.children = [] -> model
  | Some { node; _ } ->
      rebuild model (String_set.add node.path model.expanded) node.path

let collapse model =
  match selected_row model with
  | None -> model
  | Some { node; _ } when String_set.mem node.Node.path model.expanded ->
      rebuild model (String_set.remove node.path model.expanded) node.path
  | Some { node; _ } -> (
      match String.rindex_opt node.path '.' with
      | None -> model
      | Some index ->
          let parent = String.sub node.path 0 index in
          select_path model parent)

let toggle_expand model =
  match selected_node model with
  | None -> model
  | Some node when String_set.mem node.Node.path model.expanded -> collapse model
  | Some _ -> expand model

let resize model ~rows ~cols = { model with rows = max 1 rows; cols = max 1 cols }

let matches query node =
  if String.equal query "" then true
  else
    let expression = Str.regexp_string (String.lowercase_ascii query) in
    let search value =
      try
        ignore (Str.search_forward expression (String.lowercase_ascii value) 0);
        true
      with Not_found -> false
    in
    search node.Node.label || search node.path

let search model query =
  let matches =
    Node.flatten model.root
    |> List.filter (matches query)
    |> List.map (fun node -> node.Node.path)
    |> Array.of_list
  in
  let model =
    { model with search_query = Some query; search_matches = matches; search_index = 0 }
  in
  if Array.length matches = 0 then model else select_path model matches.(0)

let next_match model direction =
  let count = Array.length model.search_matches in
  if count = 0 then model
  else
    let index = (model.search_index + direction + count) mod count in
    select_path { model with search_index = index } model.search_matches.(index)

let goto_offset model offset =
  let point = Span.unsafe ~start:offset ~length:0L in
  let candidates =
    Node.flatten model.root
    |> List.filter (fun node -> Span.contains node.Node.span point)
    |> List.sort (fun left right ->
           Int64.compare (Span.length left.Node.span) (Span.length right.Node.span))
  in
  match candidates with [] -> model | node :: _ -> select_path model node.Node.path
