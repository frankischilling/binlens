type backend_policy = Auto | Bytes | Paged
type backend = Byte_backend | Paged_backend

type t =
  { filename : string; reader : Reader.t; size : int64; backend : backend }

let default_max_bytes = 512 * 1024 * 1024

let backend_name = function
  | { backend = Byte_backend; _ } -> "bytes"
  | { backend = Paged_backend; _ } -> "paged"

let unix_error code operation error =
  Error.make Error.Io code
    (Printf.sprintf "%s failed: %s." operation (Unix.error_message error))

let close_descriptor descriptor =
  try
    Unix.close descriptor;
    Ok ()
  with Unix.Unix_error (error, operation, _) ->
    Error (unix_error "input.close_failed" operation error)

let stat descriptor =
  try Ok (Unix.LargeFile.fstat descriptor)
  with Unix.Unix_error (error, operation, _) ->
    Error (unix_error "input.stat_failed" operation error)

let validate_stat stat =
  if stat.Unix.LargeFile.st_kind <> Unix.S_REG then
    Error
      (Error.make Error.Io "input.unsupported_file_kind"
         "BinLens accepts regular files only.")
  else if Int64.compare stat.st_size 0L < 0 then
    Error
      (Error.make Error.Io "input.invalid_size"
         "The operating system returned an invalid file size.")
  else Ok stat.st_size

let check_unchanged descriptor expected =
  match stat descriptor with
  | Error _ as error -> error
  | Ok current when Int64.equal current.Unix.LargeFile.st_size expected -> Ok ()
  | Ok _ ->
      Error
        (Error.make Error.Io "input.changed_during_read"
           "The file size changed while BinLens was opening it.")

let read_bytes descriptor size =
  let count = Int64.to_int size in
  try
    let data = Bytes.create count in
    ignore (Unix.lseek descriptor 0 Unix.SEEK_SET);
    let read = ref 0 in
    while !read < count do
      let amount = Unix.read descriptor data !read (count - !read) in
      if amount = 0 then raise End_of_file;
      read := !read + amount
    done;
    Ok data
  with
  | End_of_file ->
      Error
        (Error.make Error.Io "input.changed_during_read"
           "The file became shorter while BinLens was opening it.")
  | Out_of_memory ->
      Error
        (Error.make Error.Resource_limit "input.allocation_failed"
           "The runtime could not allocate the byte-backend snapshot.")
  | Unix.Unix_error (error, operation, _) ->
      Error (unix_error "input.read_failed" operation error)
  | Invalid_argument message ->
      Error (Error.make Error.Io "input.invalid_read" message)

let choose_backend ~policy ~max_bytes size =
  match policy with
  | Paged -> Ok Paged_backend
  | Bytes ->
      if
        Int64.compare size (Int64.of_int (min max_bytes Sys.max_string_length))
        > 0
      then
        Error
          (Error.make Error.Resource_limit "input.too_large"
             "The file exceeds the configured byte-backend input limit.")
      else Ok Byte_backend
  | Auto ->
      if
        Int64.compare size (Int64.of_int (min max_bytes Sys.max_string_length))
        <= 0
      then Ok Byte_backend
      else Ok Paged_backend

let read ?(backend = Auto) ?(max_bytes = default_max_bytes) filename =
  if max_bytes < 0 then
    Error
      (Error.make Error.Invalid_argument "input.negative_byte_limit"
         "The byte-backend input limit cannot be negative.")
  else
    try
      let descriptor = Unix.openfile filename [ Unix.O_RDONLY ] 0 in
      let fail error =
        ignore (close_descriptor descriptor);
        Error error
      in
      match stat descriptor with
      | Error error -> fail error
      | Ok file_stat -> (
          match validate_stat file_stat with
          | Error error -> fail error
          | Ok size -> (
              match choose_backend ~policy:backend ~max_bytes size with
              | Error error -> fail error
              | Ok Byte_backend -> (
                  match read_bytes descriptor size with
                  | Error error -> fail error
                  | Ok data -> (
                      match check_unchanged descriptor size with
                      | Error error -> fail error
                      | Ok () -> (
                          match close_descriptor descriptor with
                          | Error _ as error -> error
                          | Ok () ->
                              let reader =
                                Reader_backend.of_owned_bytes data
                                |> Reader.of_backend
                              in
                              Ok
                                { filename;
                                  reader;
                                  size;
                                  backend = Byte_backend
                                })))
              | Ok Paged_backend -> (
                  match check_unchanged descriptor size with
                  | Error error -> fail error
                  | Ok () -> (
                      match
                        Reader_backend.of_file_descriptor descriptor
                          ~length:size
                      with
                      | Error error -> fail error
                      | Ok storage ->
                          Ok
                            { filename;
                              reader = Reader.of_backend storage;
                              size;
                              backend = Paged_backend
                            }))))
    with
    | Unix.Unix_error (error, operation, _) ->
        Error (unix_error "input.open_failed" operation error)
    | Sys_error message ->
        Error (Error.make Error.Io "input.open_failed" message)

let close input = Reader.close input.reader

let with_open ?backend ?max_bytes filename operation =
  match read ?backend ?max_bytes filename with
  | Error _ as error -> error
  | Ok input -> (
      match operation input with
      | result -> (
          match close input with
          | Ok () -> Ok result
          | Error _ as error -> error)
      | exception exception_ ->
          ignore (close input);
          raise exception_)

let output filename contents =
  try
    let channel = open_out_bin filename in
    Fun.protect
      ~finally:(fun () -> close_out_noerr channel)
      (fun () -> output_string channel contents);
    Ok ()
  with Sys_error message ->
    Error (Error.make Error.Io "output.write_failed" message)
