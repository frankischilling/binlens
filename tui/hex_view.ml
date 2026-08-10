open Binlens

type window =
  { first_offset : int64;
    bytes_per_line : int;
    line_count : int;
    selected_before : bool;
    selected_after : bool
  }

let align_down value alignment =
  Int64.sub value (Int64.rem value (Int64.of_int alignment))

let calculate ~input_length ~selected ~rows ~bytes_per_line =
  let rows = max 1 rows and bytes_per_line = max 1 bytes_per_line in
  let selected_start = Span.start selected in
  let visible_bytes = Int64.of_int (rows * bytes_per_line) in
  let half = Int64.div visible_bytes 2L in
  let proposed = max 0L (Int64.sub selected_start half) in
  let first_offset = align_down proposed bytes_per_line in
  let last_visible = min input_length (Int64.add first_offset visible_bytes) in
  let selected_end =
    match Span.end_offset selected with
    | Ok value -> value
    | Error _ -> selected_start
  in
  { first_offset;
    bytes_per_line;
    line_count = rows;
    selected_before = Int64.compare selected_start first_offset < 0;
    selected_after = Int64.compare selected_end last_visible > 0
  }

let contains span offset =
  match Span.end_offset span with
  | Error _ -> false
  | Ok finish ->
      Int64.compare offset (Span.start span) >= 0
      && Int64.compare offset finish < 0

let render_line reader selected offset bytes_per_line =
  let output = Buffer.create 80 in
  Buffer.add_string output (Printf.sprintf "%08Lx " offset);
  for index = 0 to bytes_per_line - 1 do
    let current = Int64.add offset (Int64.of_int index) in
    match Reader.byte reader current with
    | Error _ -> Buffer.add_string output "    "
    | Ok byte ->
        if contains selected current then
          Buffer.add_string output (Printf.sprintf "[%02X]" byte)
        else Buffer.add_string output (Printf.sprintf " %02X " byte)
  done;
  Buffer.contents output

let render reader selected window =
  let lines = ref [] in
  if window.selected_before then
    lines := "^ selected range starts above" :: !lines;
  for line = 0 to window.line_count - 1 do
    let offset =
      Int64.add window.first_offset
        (Int64.of_int (line * window.bytes_per_line))
    in
    if Int64.compare offset (Reader.length reader) < 0 then
      lines :=
        render_line reader selected offset window.bytes_per_line :: !lines
  done;
  if window.selected_after then
    lines := "v selected range continues below" :: !lines;
  List.rev !lines
