type numeric = { width : int; value : Unsigned.t }

type t =
  | Unsigned of numeric
  | Signed of { width : int; value : int64 }
  | Boolean of bool
  | Enumeration of { raw : numeric; name : string option }
  | Bitfield of { raw : numeric; flags : (string * bool) list }
  | String of { text : string; raw_hex : string option; valid_utf8 : bool }
  | Bytes of { summary : string; length : int64 }
  | Address of numeric
  | Offset of numeric
  | Collection of int
  | Null
  | Invalid of string

let unsigned width bits =
  Unsigned { width; value = Unsigned.of_int64 ~width bits }

let address width bits =
  Address { width; value = Unsigned.of_int64 ~width bits }

let offset width bits = Offset { width; value = Unsigned.of_int64 ~width bits }

let enum width bits name =
  Enumeration { raw = { width; value = Unsigned.of_int64 ~width bits }; name }

let bitfield width bits flags =
  Bitfield { raw = { width; value = Unsigned.of_int64 ~width bits }; flags }

let numeric_to_string numeric =
  Printf.sprintf "%s (%s)"
    (Unsigned.to_hex numeric.value)
    (Unsigned.to_decimal numeric.value)

let to_string = function
  | Unsigned numeric -> Unsigned.to_decimal numeric.value
  | Signed { value; _ } -> Int64.to_string value
  | Boolean value -> string_of_bool value
  | Enumeration { raw; name = Some name } ->
      Printf.sprintf "%s (%s)" name (Unsigned.to_hex raw.value)
  | Enumeration { raw; name = None } -> numeric_to_string raw
  | Bitfield { raw; flags } ->
      let enabled =
        flags
        |> List.filter_map (fun (name, set) -> if set then Some name else None)
        |> String.concat ", "
      in
      if String.equal enabled "" then Unsigned.to_hex raw.value
      else Printf.sprintf "%s [%s]" (Unsigned.to_hex raw.value) enabled
  | String { text; _ } -> Printf.sprintf "%S" text
  | Bytes { summary; _ } -> summary
  | Address numeric | Offset numeric -> Unsigned.to_hex numeric.value
  | Collection count -> Printf.sprintf "%d items" count
  | Null -> "null"
  | Invalid message -> "invalid: " ^ message

let to_string_base ~hexadecimal value =
  match value with
  | Unsigned numeric | Address numeric | Offset numeric ->
      if hexadecimal then Unsigned.to_hex numeric.value
      else Unsigned.to_decimal numeric.value
  | Signed { value; _ } ->
      if hexadecimal then Printf.sprintf "0x%Lx" value
      else Int64.to_string value
  | other -> to_string other

let equal left right = left = right
