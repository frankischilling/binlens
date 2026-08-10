open Binlens

let crop width value =
  if width <= 0 then ""
  else if String.length value <= width then value
  else if width <= 3 then String.sub value 0 width
  else String.sub value 0 (width - 3) ^ "..."

let render model ~height ~width =
  let count = Array.length model.Model.visible in
  let start = max 0 (min model.selected (max 0 (count - height))) in
  let lines = ref [] in
  for row_index = start to min (count - 1) (start + height - 1) do
    let row = model.visible.(row_index) in
    let marker = if row_index = model.selected then ">" else " " in
    let expansion =
      if row.node.Node.children = [] then " "
      else if Model.String_set.mem row.node.path model.expanded then "-"
      else "+"
    in
    let line =
      Printf.sprintf "%s%s%s %s" marker
        (String.make (row.depth * 2) ' ')
        expansion row.node.label
    in
    lines := crop width line :: !lines
  done;
  List.rev !lines
