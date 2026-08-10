type t = { start : int64; length : int64 }

let checked_add left right =
  if Int64.compare left 0L < 0 || Int64.compare right 0L < 0 then
    Error
      (Error.make Error.Invalid_argument "span.negative"
         "Byte span offsets and lengths cannot be negative.")
  else if Int64.compare left (Int64.sub Int64.max_int right) > 0 then
    Error
      (Error.make Error.Overflow "span.end_overflow"
         "The byte span end offset exceeds signed 64-bit range.")
  else Ok (Int64.add left right)

let create ~start ~length =
  match checked_add start length with
  | Error error -> Error error
  | Ok _ -> Ok { start; length }

let unsafe ~start ~length = { start; length }
let start span = span.start
let length span = span.length
let end_offset span = checked_add span.start span.length

let within ~input_length span =
  if Int64.compare input_length 0L < 0 then false
  else
    match end_offset span with
    | Error _ -> false
    | Ok finish -> Int64.compare finish input_length <= 0

let contains outer inner =
  match (end_offset outer, end_offset inner) with
  | Ok outer_end, Ok inner_end ->
      Int64.compare inner.start outer.start >= 0
      && Int64.compare inner_end outer_end <= 0
  | _ -> false

let overlaps left right =
  match (end_offset left, end_offset right) with
  | Ok left_end, Ok right_end ->
      Int64.compare left.start right_end < 0
      && Int64.compare right.start left_end < 0
  | _ -> false

let equal left right =
  Int64.equal left.start right.start && Int64.equal left.length right.length

let to_string span =
  match end_offset span with
  | Ok finish -> Printf.sprintf "[0x%08Lx..0x%08Lx)" span.start finish
  | Error _ -> Printf.sprintf "[0x%08Lx, invalid length]" span.start
