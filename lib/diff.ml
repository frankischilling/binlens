module Path_map = Map.Make (String)

type kind =
  | Added_node
  | Removed_node
  | Changed_type
  | Changed_value
  | Changed_span
  | Changed_raw
  | Changed_diagnostic
  | Format_changed
  | Partial_changed

type difference =
  { kind : kind; path : string; before : string option; after : string option }

type options =
  { ignore_paths : string list; compare_raw : bool; max_raw_bytes : int }

let default_options =
  { ignore_paths = []; compare_raw = false; max_raw_bytes = 65_536 }

let kind_to_string = function
  | Added_node -> "added_node"
  | Removed_node -> "removed_node"
  | Changed_type -> "changed_type"
  | Changed_value -> "changed_value"
  | Changed_span -> "changed_span"
  | Changed_raw -> "changed_raw_bytes"
  | Changed_diagnostic -> "changed_diagnostic"
  | Format_changed -> "format_changed"
  | Partial_changed -> "partial_changed"

let value_type = function
  | Value.Unsigned _ -> "unsigned"
  | Signed _ -> "signed"
  | Boolean _ -> "boolean"
  | Enumeration _ -> "enumeration"
  | Bitfield _ -> "bitfield"
  | String _ -> "string"
  | Bytes _ -> "bytes"
  | Address _ -> "address"
  | Offset _ -> "offset"
  | Collection _ -> "collection"
  | Null -> "null"
  | Invalid _ -> "invalid"

let map_nodes root =
  Node.flatten root
  |> List.fold_left
       (fun map node -> Path_map.add node.Node.path node map)
       Path_map.empty

let ignored options path = List.exists (String.equal path) options.ignore_paths
let difference kind path before after = { kind; path; before; after }

let diagnostics_signature diagnostics =
  diagnostics
  |> List.map (fun diagnostic ->
      Diagnostic.severity_to_string diagnostic.Diagnostic.severity
      ^ ":" ^ diagnostic.code)
  |> String.concat ","

let raw_diff options left_reader right_reader left right =
  if
    (not options.compare_raw) || not (Span.equal left.Node.span right.Node.span)
  then false
  else
    let length = Span.length left.span in
    if Int64.compare length (Int64.of_int options.max_raw_bytes) > 0 then false
    else
      match
        ( Reader.bytes left_reader ~offset:(Span.start left.span) ~length,
          Reader.bytes right_reader ~offset:(Span.start right.span) ~length )
      with
      | Ok left, Ok right -> not (Bytes.equal left right)
      | _ -> false

let compare ?(options = default_options) ~left_reader ~right_reader left right =
  let differences = ref [] in
  if not (String.equal left.Format.format_id right.Format.format_id) then
    differences :=
      difference Format_changed "$format" (Some left.format_id)
        (Some right.format_id)
      :: !differences;
  if left.partial <> right.partial then
    differences :=
      difference Partial_changed "$partial"
        (Some (string_of_bool left.partial))
        (Some (string_of_bool right.partial))
      :: !differences;
  let left_nodes = Option.fold ~none:Path_map.empty ~some:map_nodes left.root in
  let right_nodes =
    Option.fold ~none:Path_map.empty ~some:map_nodes right.root
  in
  let paths =
    Path_map.fold
      (fun path _ set -> Path_map.add path () set)
      left_nodes Path_map.empty
    |> fun set ->
    Path_map.fold (fun path _ set -> Path_map.add path () set) right_nodes set
  in
  Path_map.iter
    (fun path () ->
      if not (ignored options path) then
        match
          (Path_map.find_opt path left_nodes, Path_map.find_opt path right_nodes)
        with
        | None, Some node ->
            differences :=
              difference Added_node path None (Some node.Node.label)
              :: !differences
        | Some node, None ->
            differences :=
              difference Removed_node path (Some node.Node.label) None
              :: !differences
        | Some left, Some right ->
            let left_type = value_type left.value
            and right_type = value_type right.value in
            if not (String.equal left_type right_type) then
              differences :=
                difference Changed_type path (Some left_type) (Some right_type)
                :: !differences;
            if not (Value.equal left.value right.value) then
              differences :=
                difference Changed_value path
                  (Some (Value.to_string left.value))
                  (Some (Value.to_string right.value))
                :: !differences;
            if left.span <> right.span then
              differences :=
                difference Changed_span path
                  (Some (Span.to_string left.span))
                  (Some (Span.to_string right.span))
                :: !differences;
            let left_diagnostics = diagnostics_signature left.diagnostics
            and right_diagnostics = diagnostics_signature right.diagnostics in
            if not (String.equal left_diagnostics right_diagnostics) then
              differences :=
                difference Changed_diagnostic path (Some left_diagnostics)
                  (Some right_diagnostics)
                :: !differences;
            if raw_diff options left_reader right_reader left right then
              differences :=
                difference Changed_raw path None None :: !differences
        | None, None -> ())
    paths;
  List.sort
    (fun left right ->
      let path = String.compare left.path right.path in
      if path <> 0 then path
      else String.compare (kind_to_string left.kind) (kind_to_string right.kind))
    !differences

let render_text differences =
  if differences = [] then "No structural differences.\n"
  else
    differences
    |> List.map (fun difference ->
        let before = Option.value difference.before ~default:"<none>"
        and after = Option.value difference.after ~default:"<none>" in
        Printf.sprintf "%s %s: %s -> %s"
          (kind_to_string difference.kind)
          difference.path before after)
    |> String.concat "\n"
    |> fun value -> value ^ "\n"

let to_yojson differences =
  `Assoc
    [ ("schema_version", `String Version.schema_version);
      ( "differences",
        `List
          (List.map
             (fun difference ->
               `Assoc
                 ([ ("kind", `String (kind_to_string difference.kind));
                    ("path", `String difference.path)
                  ]
                 @ Render_json.option "before"
                     (fun value -> `String value)
                     difference.before
                 @ Render_json.option "after"
                     (fun value -> `String value)
                     difference.after))
             differences) )
    ]
