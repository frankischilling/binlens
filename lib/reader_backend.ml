type file =
  { descriptor : Unix.file_descr;
    size : int64;
    page : bytes;
    mutable page_start : int64;
    mutable page_length : int;
    mutable page_valid : bool;
    mutable closed : bool
  }

type t = Memory of bytes | Paged_file of file
type kind = [ `Bytes | `Paged ]

let default_page_size = 64 * 1024

let error_of_unix code operation error =
  Error.make Error.Io code
    (Printf.sprintf "%s failed: %s." operation (Unix.error_message error))

let length = function
  | Memory data -> Int64.of_int (Bytes.length data)
  | Paged_file file -> file.size

let kind = function Memory _ -> `Bytes | Paged_file _ -> `Paged
let of_bytes data = Memory (Bytes.copy data)
let of_owned_bytes data = Memory data

let of_file_descriptor ?(page_size = default_page_size) descriptor ~length =
  if Int64.compare length 0L < 0 then
    Error
      (Error.make Error.Io "input.invalid_size"
         "The operating system returned a negative file size.")
  else if page_size <= 0 then
    Error
      (Error.make Error.Invalid_argument "reader.invalid_page_size"
         "The file page size must be positive.")
  else
    try
      Ok
        (Paged_file
           { descriptor;
             size = length;
             page = Bytes.create page_size;
             page_start = 0L;
             page_length = 0;
             page_valid = false;
             closed = false
           })
    with
    | Out_of_memory ->
        Error
          (Error.make Error.Resource_limit "reader.page_allocation_failed"
             "The runtime could not allocate the file-reader page.")
    | Invalid_argument message ->
        Error
          (Error.make Error.Invalid_argument "reader.invalid_page_size" message)

let check_open file =
  if file.closed then
    Error
      (Error.make Error.Io "reader.backend_closed"
         "The file reader has already been closed.")
  else Ok ()

let check_size file =
  try
    let stat = Unix.LargeFile.fstat file.descriptor in
    if Int64.equal stat.Unix.LargeFile.st_size file.size then Ok ()
    else
      Error
        (Error.make Error.Io "input.changed_during_read"
           "The file size changed while BinLens was reading it.")
  with Unix.Unix_error (error, operation, _) ->
    Error (error_of_unix "reader.file_stat_failed" operation error)

let page_contains file offset =
  file.page_valid
  && Int64.compare offset file.page_start >= 0
  && Int64.compare offset
       (Int64.add file.page_start (Int64.of_int file.page_length))
     < 0

let seek descriptor offset =
  if Int64.compare offset (Int64.of_int max_int) > 0 then
    Error
      (Error.make ~offset Error.Overflow "reader.file_offset_unrepresentable"
         "The file offset cannot be represented by this OCaml runtime.")
  else
    try
      ignore (Unix.lseek descriptor (Int64.to_int offset) Unix.SEEK_SET);
      Ok ()
    with Unix.Unix_error (error, operation, _) ->
      Error (error_of_unix "reader.file_seek_failed" operation error)

let fill_page file offset =
  match check_open file with
  | Error _ as error -> error
  | Ok () -> (
      match check_size file with
      | Error _ as error -> error
      | Ok () -> (
          let page_size = Bytes.length file.page in
          let page_size64 = Int64.of_int page_size in
          let page_start =
            Int64.mul (Int64.div offset page_size64) page_size64
          in
          let remaining = Int64.sub file.size page_start in
          let wanted = Int64.to_int (min remaining page_size64) in
          match seek file.descriptor page_start with
          | Error _ as error -> error
          | Ok () -> (
              try
                let read = ref 0 in
                while !read < wanted do
                  let count =
                    Unix.read file.descriptor file.page !read (wanted - !read)
                  in
                  if count = 0 then raise End_of_file;
                  read := !read + count
                done;
                match check_size file with
                | Error _ as error -> error
                | Ok () ->
                    file.page_start <- page_start;
                    file.page_length <- wanted;
                    file.page_valid <- true;
                    Ok ()
              with
              | End_of_file ->
                  Error
                    (Error.make Error.Io "input.changed_during_read"
                       "The file became shorter while BinLens was reading it.")
              | Unix.Unix_error (error, operation, _) ->
                  Error
                    (error_of_unix "reader.file_read_failed" operation error)
              | Invalid_argument message ->
                  Error (Error.make Error.Io "reader.file_read_failed" message))
          ))

let get storage offset =
  match storage with
  | Memory data ->
      if Int64.compare offset (Int64.of_int max_int) > 0 then
        Error
          (Error.make ~offset Error.Overflow "reader.index_overflow"
             "The byte offset cannot be represented by this runtime.")
      else Ok (Char.code (Bytes.get data (Int64.to_int offset)))
  | Paged_file file -> (
      let ready =
        if page_contains file offset then Ok () else fill_page file offset
      in
      match ready with
      | Error _ as error -> error
      | Ok () ->
          let index = Int64.to_int (Int64.sub offset file.page_start) in
          Ok (Char.code (Bytes.get file.page index)))

let blit storage ~offset output ~output_offset ~length =
  match storage with
  | Memory data ->
      if Int64.compare offset (Int64.of_int max_int) > 0 then
        Error
          (Error.make ~offset Error.Overflow "reader.index_overflow"
             "The byte offset cannot be represented by this runtime.")
      else (
        Bytes.blit data (Int64.to_int offset) output output_offset length;
        Ok ())
  | Paged_file file -> (
      let source = ref offset in
      let destination = ref output_offset in
      let remaining = ref length in
      let failure = ref None in
      while !remaining > 0 && Option.is_none !failure do
        let ready =
          if page_contains file !source then Ok () else fill_page file !source
        in
        match ready with
        | Error error -> failure := Some error
        | Ok () ->
            let page_index = Int64.to_int (Int64.sub !source file.page_start) in
            let available = file.page_length - page_index in
            let count = min available !remaining in
            Bytes.blit file.page page_index output !destination count;
            source := Int64.add !source (Int64.of_int count);
            destination := !destination + count;
            remaining := !remaining - count
      done;
      match !failure with None -> Ok () | Some error -> Error error)

let close = function
  | Memory _ -> Ok ()
  | Paged_file file -> (
      if file.closed then Ok ()
      else
        try
          Unix.close file.descriptor;
          file.closed <- true;
          file.page_valid <- false;
          Ok ()
        with Unix.Unix_error (error, operation, _) ->
          file.closed <- true;
          file.page_valid <- false;
          Error (error_of_unix "input.close_failed" operation error))
