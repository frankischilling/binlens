open Binlens

let ok = function
  | Ok value -> value
  | Error error -> Alcotest.fail (Error.to_string error)

let is_error_code code = function
  | Error error -> String.equal error.Error.code code
  | Ok _ -> false

let with_temp_file bytes operation =
  let filename = Filename.temp_file "binlens-input-" ".bin" in
  let channel = open_out_bin filename in
  output_bytes channel bytes;
  close_out channel;
  Fun.protect
    ~finally:(fun () -> if Sys.file_exists filename then Sys.remove filename)
    (fun () -> operation filename)

let with_input backend filename operation =
  let input = ok (Input.read ~backend filename) in
  Fun.protect
    ~finally:(fun () -> ignore (Input.close input))
    (fun () -> operation input)

let exercise_reader reader =
  Alcotest.(check int64) "length" 8L (Reader.length reader);
  Alcotest.(check int64) "u8" 1L (ok (Reader.u8 reader 0L));
  Alcotest.(check int64)
    "u16 little" 0x0201L
    (ok (Reader.u16 reader Endian.Little 0L));
  Alcotest.(check int64)
    "u16 big" 0x0102L
    (ok (Reader.u16 reader Endian.Big 0L));
  Alcotest.(check int64)
    "u32 little" 0x04030201L
    (ok (Reader.u32 reader Endian.Little 0L));
  Alcotest.(check int64)
    "u32 big" 0x01020304L
    (ok (Reader.u32 reader Endian.Big 0L));
  Alcotest.(check int64)
    "u64 little" 0x0807060504030201L
    (ok (Reader.u64 reader Endian.Little 0L));
  Alcotest.(check int64)
    "u64 big" 0x0102030405060708L
    (ok (Reader.u64 reader Endian.Big 0L));
  Alcotest.(check string)
    "copy" "\x03\x04\x05"
    (Bytes.to_string (ok (Reader.bytes reader ~offset:2L ~length:3L)));
  let first = ok (Reader.slice reader ~offset:1L ~length:6L) in
  let second = ok (Reader.slice first ~offset:2L ~length:3L) in
  Alcotest.(check string)
    "nested shared slice" "\x04\x05\x06"
    (Bytes.to_string (ok (Reader.bytes second ~offset:0L ~length:3L)));
  Alcotest.(check bool)
    "exact EOF" false
    (is_error_code "reader.out_of_bounds"
       (Reader.bytes reader ~offset:8L ~length:0L));
  Alcotest.(check string)
    "bounded C string" "\x01\x02\x03"
    (ok (Reader.c_string reader ~offset:0L ~max_length:3));
  Alcotest.(check bool)
    "past EOF" true
    (is_error_code "reader.out_of_bounds" (Reader.u8 reader 8L))

let test_backends_match () =
  let bytes = Bytes.of_string "\x01\x02\x03\x04\x05\x06\x07\x08" in
  exercise_reader (Reader.of_bytes bytes);
  with_temp_file bytes (fun filename ->
      with_input Input.Bytes filename (fun input ->
          Alcotest.(check string) "backend" "bytes" (Input.backend_name input);
          exercise_reader input.Input.reader);
      with_input Input.Paged filename (fun input ->
          Alcotest.(check string) "backend" "paged" (Input.backend_name input);
          exercise_reader input.Input.reader))

let test_empty_and_cleanup () =
  with_temp_file Bytes.empty (fun filename ->
      let input = ok (Input.read ~backend:Input.Paged filename) in
      Alcotest.(check int64) "empty length" 0L input.size;
      Alcotest.(check bool)
        "empty EOF" true
        (is_error_code "reader.out_of_bounds" (Reader.u8 input.reader 0L));
      ignore (ok (Input.close input)));
  with_temp_file (Bytes.of_string "x") (fun filename ->
      let input = ok (Input.read ~backend:Input.Paged filename) in
      let parsed =
        ok (Registry.parse ~format:"nes" Limits.default input.reader)
      in
      let _, result = parsed in
      Alcotest.(check bool) "malformed parse" true result.Format.partial;
      ignore (ok (Input.close input));
      Alcotest.(check bool)
        "read after close" true
        (is_error_code "reader.backend_closed" (Reader.u8 input.reader 0L));
      ignore (ok (Input.close input)))

let test_size_change () =
  with_temp_file (Bytes.make 128 '\x5a') (fun filename ->
      let input = ok (Input.read ~backend:Input.Paged filename) in
      Fun.protect
        ~finally:(fun () -> ignore (Input.close input))
        (fun () ->
          if Sys.win32 then
            Alcotest.(check string)
              "Windows paged backend" "paged" (Input.backend_name input)
          else (
            Unix.LargeFile.truncate filename 64L;
            Alcotest.(check bool)
              "truncation detected" true
              (is_error_code "input.changed_during_read"
                 (Reader.u8 input.reader 0L)))))

let test_sparse_large_file () =
  let filename = Filename.temp_file "binlens-sparse-" ".bin" in
  Fun.protect
    ~finally:(fun () -> if Sys.file_exists filename then Sys.remove filename)
    (fun () ->
      let descriptor =
        Unix.openfile filename [ Unix.O_RDWR; Unix.O_TRUNC ] 0o600
      in
      let size = Int64.add (Int64.of_int Input.default_max_bytes) 1L in
      Unix.LargeFile.ftruncate descriptor size;
      Unix.close descriptor;
      let input = ok (Input.read ~backend:Input.Paged filename) in
      Alcotest.(check int64) "large size" size input.size;
      Alcotest.(check int64)
        "first sparse byte" 0L
        (ok (Reader.u8 input.reader 0L));
      Alcotest.(check int64)
        "last sparse byte" 0L
        (ok (Reader.u8 input.reader (Int64.pred size)));
      ignore (ok (Input.close input));
      let automatic = ok (Input.read filename) in
      Alcotest.(check string)
        "large auto backend" "paged"
        (Input.backend_name automatic);
      ignore (ok (Input.close automatic));
      Alcotest.(check bool)
        "byte backend rejects large file" true
        (is_error_code "input.too_large"
           (Input.read ~backend:Input.Bytes filename)))

let () =
  Alcotest.run "input"
    [ ( "backends",
        [ Alcotest.test_case "matching reader behavior" `Quick
            test_backends_match;
          Alcotest.test_case "empty input and cleanup" `Quick
            test_empty_and_cleanup;
          Alcotest.test_case "size change" `Quick test_size_change;
          Alcotest.test_case "sparse file above byte limit" `Slow
            test_sparse_large_file
        ] )
    ]
