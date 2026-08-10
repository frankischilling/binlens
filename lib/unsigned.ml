type t = { width : int; bits : int64 }

let create ~width bits =
  if width <= 0 || width > 64 then
    Error
      (Error.make Error.Invalid_argument "unsigned.width"
         "Unsigned integer width must be between 1 and 64 bits.")
  else Ok { width; bits }

let of_int64 ~width bits = { width; bits }
let width value = value.width
let bits value = value.bits

let mask width =
  if width = 64 then Int64.minus_one
  else Int64.pred (Int64.shift_left 1L width)

let normalized value = Int64.logand value.bits (mask value.width)

let to_hex value =
  let digits = (value.width + 3) / 4 in
  Printf.sprintf "0x%0*Lx" digits (normalized value)

let to_decimal value =
  let number = normalized value in
  if value.width < 64 || Int64.compare number 0L >= 0 then Int64.to_string number
  else
    let buffer = Buffer.create 20 in
    let rec collect current =
      if Int64.equal current 0L then ()
      else
        let quotient = Int64.unsigned_div current 10L in
        let remainder = Int64.unsigned_rem current 10L in
        Buffer.add_char buffer (Char.chr (48 + Int64.to_int remainder));
        collect quotient
    in
    collect number;
    let reversed = Buffer.contents buffer in
    String.init (String.length reversed) (fun index ->
        reversed.[String.length reversed - index - 1])

let equal left right =
  left.width = right.width && Int64.equal (normalized left) (normalized right)
