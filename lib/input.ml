type t = { filename : string; reader : Reader.t; size : int64 }

let read filename =
  try
    let channel = open_in_bin filename in
    Fun.protect
      ~finally:(fun () -> close_in_noerr channel)
      (fun () ->
        let stat = Unix.fstat (Unix.descr_of_in_channel channel) in
        if stat.Unix.st_size < 0 then
          Error
            (Error.make Error.Io "input.invalid_size"
               "The operating system returned an invalid file size.")
        else if stat.st_size > Sys.max_string_length then
          Error
            (Error.make Error.Resource_limit "input.too_large"
               "The file is too large for the byte backend on this runtime.")
        else
          let contents = really_input_string channel stat.st_size in
          let bytes = Bytes.of_string contents in
          let reader = Reader.of_bytes bytes in
          Ok { filename; reader; size = Int64.of_int stat.st_size })
  with
  | Sys_error message -> Error (Error.make Error.Io "input.read_failed" message)
  | End_of_file ->
      Error
        (Error.make Error.Io "input.changed_during_read"
           "The file changed or became unreadable while BinLens was reading it.")

let output filename contents =
  try
    let channel = open_out_bin filename in
    Fun.protect
      ~finally:(fun () -> close_out_noerr channel)
      (fun () -> output_string channel contents);
    Ok ()
  with Sys_error message -> Error (Error.make Error.Io "output.write_failed" message)
