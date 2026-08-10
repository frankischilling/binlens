type t = { data : bytes; base : int64; length : int64 }

let of_bytes data =
  let copy = Bytes.copy data in
  { data = copy; base = 0L; length = Int64.of_int (Bytes.length copy) }

let of_string data =
  let data = Bytes.of_string data in
  { data; base = 0L; length = Int64.of_int (Bytes.length data) }

let length reader = reader.length
let absolute_offset reader offset = Span.checked_add reader.base offset
let checked_add = Span.checked_add

let checked_mul left right =
  if Int64.compare left 0L < 0 || Int64.compare right 0L < 0 then
    Error
      (Error.make Error.Invalid_argument "reader.negative_product"
         "Offsets and sizes cannot be negative.")
  else if Int64.equal left 0L || Int64.equal right 0L then Ok 0L
  else if Int64.compare left (Int64.div Int64.max_int right) > 0 then
    Error
      (Error.make Error.Overflow "reader.multiply_overflow"
         "Offset multiplication exceeds signed 64-bit range.")
  else Ok (Int64.mul left right)

let range reader ~offset ~length =
  if Int64.compare offset 0L < 0 || Int64.compare length 0L < 0 then
    Error
      (Error.make ~offset Error.Invalid_argument "reader.negative_range"
         "Read offsets and lengths cannot be negative.")
  else
    match checked_add offset length with
    | Error _ as error -> error
    | Ok finish when Int64.compare finish reader.length > 0 ->
        Error
          (Error.make ~offset ~requested:length ~available:reader.length
             Error.Bounds "reader.out_of_bounds"
             "The requested byte range is outside the input.")
    | Ok _ -> Ok ()

let index reader offset =
  match checked_add reader.base offset with
  | Error _ as error -> error
  | Ok absolute ->
      if Int64.compare absolute (Int64.of_int max_int) > 0 then
        Error
          (Error.make ~offset:absolute Error.Overflow "reader.index_overflow"
             "The byte offset cannot be represented by this runtime.")
      else Ok (Int64.to_int absolute)

let get_u8 reader offset =
  match range reader ~offset ~length:1L with
  | Error _ as error -> error
  | Ok () -> (
      match index reader offset with
      | Error _ as error -> error
      | Ok index -> Ok (Char.code (Bytes.get reader.data index)))

let u8 reader offset =
  match get_u8 reader offset with
  | Ok value -> Ok (Int64.of_int value)
  | Error _ as error -> error

let fold_integer reader endian offset width =
  match range reader ~offset ~length:(Int64.of_int width) with
  | Error _ as error -> error
  | Ok () ->
      let result = ref 0L in
      for byte_index = 0 to width - 1 do
        let source_index =
          match endian with
          | Endian.Little -> byte_index
          | Endian.Big -> width - byte_index - 1
        in
        match get_u8 reader (Int64.add offset (Int64.of_int source_index)) with
        | Error _ -> assert false
        | Ok byte ->
            result :=
              Int64.logor !result
                (Int64.shift_left (Int64.of_int byte) (byte_index * 8))
      done;
      Ok !result

let u16 reader endian offset = fold_integer reader endian offset 2
let u32 reader endian offset = fold_integer reader endian offset 4
let u64 reader endian offset = fold_integer reader endian offset 8

let signed width value =
  let shift = 64 - width in
  Int64.shift_right (Int64.shift_left value shift) shift

let i8 reader offset = Result.map (signed 8) (u8 reader offset)
let i16 reader endian offset = Result.map (signed 16) (u16 reader endian offset)
let i32 reader endian offset = Result.map (signed 32) (u32 reader endian offset)
let i64 reader endian offset = u64 reader endian offset

let slice reader ~offset ~length =
  match range reader ~offset ~length with
  | Error _ as error -> error
  | Ok () -> (
      match checked_add reader.base offset with
      | Error _ as error -> error
      | Ok base -> Ok { data = reader.data; base; length })

let bytes ?tracker reader ~offset ~length =
  match range reader ~offset ~length with
  | Error _ as error -> error
  | Ok () -> (
      if Int64.compare length (Int64.of_int max_int) > 0 then
        Error
          (Error.make ~offset ~requested:length Error.Resource_limit
             "reader.copy_too_large"
             "The requested byte copy exceeds the runtime limit.")
      else
        let count = Int64.to_int length in
        let budget =
          match tracker with
          | None -> Ok ()
          | Some tracker -> Limits.consume_bytes_copied tracker count
        in
        match budget with
        | Error _ as error -> error
        | Ok () -> (
            match index reader offset with
            | Error _ as error -> error
            | Ok start -> Ok (Bytes.sub reader.data start count)))

let fixed_string ?tracker reader ~offset ~length =
  Result.map Bytes.to_string (bytes ?tracker reader ~offset ~length)

let c_string ?tracker reader ~offset ~max_length =
  if max_length < 0 then
    Error
      (Error.make ~offset Error.Invalid_argument "reader.negative_string_limit"
         "The string limit cannot be negative.")
  else
    let available = Int64.sub reader.length offset in
    if Int64.compare available 0L < 0 then
      Error
        (Error.make ~offset Error.Bounds "reader.string_out_of_bounds"
           "The string offset is outside the input.")
    else
      let scan_length =
        min max_length (Int64.to_int (min available (Int64.of_int max_int)))
      in
      let count = ref 0 in
      let scanning = ref true in
      while !scanning && !count < scan_length do
        match get_u8 reader (Int64.add offset (Int64.of_int !count)) with
        | Ok 0 -> scanning := false
        | Ok _ -> incr count
        | Error _ -> scanning := false
      done;
      let count = !count in
      fixed_string ?tracker reader ~offset ~length:(Int64.of_int count)

let align offset alignment =
  if Int64.compare offset 0L < 0 || Int64.compare alignment 1L < 0 then
    Error
      (Error.make Error.Invalid_argument "reader.invalid_alignment"
         "Alignment requires a nonnegative offset and a positive boundary.")
  else
    let remainder = Int64.rem offset alignment in
    if Int64.equal remainder 0L then Ok offset
    else checked_add offset (Int64.sub alignment remainder)

let table_range reader ~offset ~entry_size ~count =
  match checked_mul entry_size count with
  | Error _ as error -> error
  | Ok total -> (
      match range reader ~offset ~length:total with
      | Error _ as error -> error
      | Ok () -> Ok (Span.unsafe ~start:offset ~length:total))

let sub_reader reader span =
  slice reader ~offset:(Span.start span) ~length:(Span.length span)

let byte reader offset = get_u8 reader offset

let hex reader ~offset ~length =
  match range reader ~offset ~length with
  | Error _ as error -> error
  | Ok () when Int64.compare length (Int64.of_int (max_int / 3)) > 0 ->
      Error
        (Error.make ~offset ~requested:length Error.Resource_limit
           "reader.hex_too_large"
           "The hexadecimal summary would exceed the runtime allocation limit.")
  | Ok () ->
      let buffer = Buffer.create (Int64.to_int length * 3) in
      let count = Int64.to_int length in
      for index = 0 to count - 1 do
        if index > 0 then Buffer.add_char buffer ' ';
        match get_u8 reader (Int64.add offset (Int64.of_int index)) with
        | Ok byte -> Buffer.add_string buffer (Printf.sprintf "%02X" byte)
        | Error _ -> assert false
      done;
      Ok (Buffer.contents buffer)
