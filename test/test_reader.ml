open Binlens

let ok = function Ok value -> value | Error error -> Alcotest.fail (Error.to_string error)
let is_error = function Error _ -> true | Ok _ -> false

let test_integer_reads () =
  let reader = Reader.of_string "\x01\x02\x03\x04\x05\x06\x07\x08" in
  Alcotest.(check int64) "u8 at zero" 1L (ok (Reader.u8 reader 0L));
  Alcotest.(check int64) "u16 little" 0x0201L (ok (Reader.u16 reader Endian.Little 0L));
  Alcotest.(check int64) "u16 big" 0x0102L (ok (Reader.u16 reader Endian.Big 0L));
  Alcotest.(check int64) "u32 little" 0x04030201L (ok (Reader.u32 reader Endian.Little 0L));
  Alcotest.(check int64) "u32 big" 0x01020304L (ok (Reader.u32 reader Endian.Big 0L));
  Alcotest.(check int64) "u64 little" 0x0807060504030201L (ok (Reader.u64 reader Endian.Little 0L));
  Alcotest.(check int64) "u64 big" 0x0102030405060708L (ok (Reader.u64 reader Endian.Big 0L))

let test_boundaries () =
  let reader = Reader.of_string "\x01\x02" in
  Alcotest.(check int64) "ends at EOF" 0x0201L (ok (Reader.u16 reader Endian.Little 0L));
  Alcotest.(check bool) "one byte beyond EOF" true (is_error (Reader.u16 reader Endian.Little 1L));
  Alcotest.(check bool) "offset at EOF" true (is_error (Reader.u8 reader 2L));
  Alcotest.(check bool) "negative offset" true (is_error (Reader.u8 reader (-1L)))

let test_arithmetic () =
  Alcotest.(check bool) "addition overflow" true (is_error (Reader.checked_add Int64.max_int 1L));
  Alcotest.(check bool) "multiplication overflow" true (is_error (Reader.checked_mul Int64.max_int 2L));
  Alcotest.(check int64) "multiply zero" 0L (ok (Reader.checked_mul Int64.max_int 0L));
  Alcotest.(check int64) "align exact" 16L (ok (Reader.align 16L 8L));
  Alcotest.(check int64) "align upward" 24L (ok (Reader.align 17L 8L));
  Alcotest.(check bool) "invalid alignment" true (is_error (Reader.align 1L 0L))

let test_sub_reader_and_strings () =
  let reader = Reader.of_string "abc\000def" in
  let sub = ok (Reader.slice reader ~offset:1L ~length:3L) in
  Alcotest.(check int64) "sub length" 3L (Reader.length sub);
  Alcotest.(check string) "sub bytes" "bc\000" (Bytes.to_string (ok (Reader.bytes sub ~offset:0L ~length:3L)));
  Alcotest.(check bool) "sub outside" true (is_error (Reader.u8 sub 3L));
  Alcotest.(check string) "limited C string" "abc" (ok (Reader.c_string reader ~offset:0L ~max_length:7));
  Alcotest.(check string) "C string max" "ab" (ok (Reader.c_string reader ~offset:0L ~max_length:2))

let test_signed_and_unsigned () =
  let reader = Reader.of_string "\xff\x80\x00\x00\x00\x00\x00\x00" in
  Alcotest.(check int64) "signed byte" (-1L) (ok (Reader.i8 reader 0L));
  let unsigned = Unsigned.of_int64 ~width:64 Int64.minus_one in
  Alcotest.(check string) "unsigned 64 decimal" "18446744073709551615" (Unsigned.to_decimal unsigned);
  Alcotest.(check string) "unsigned 64 hex" "0xffffffffffffffff" (Unsigned.to_hex unsigned)

let test_span () =
  let span = ok (Span.create ~start:5L ~length:5L) in
  Alcotest.(check bool) "inside input" true (Span.within ~input_length:10L span);
  Alcotest.(check bool) "zero span" true (Span.within ~input_length:10L (ok (Span.create ~start:10L ~length:0L)));
  Alcotest.(check bool) "overflow end" true (is_error (Span.create ~start:Int64.max_int ~length:1L));
  Alcotest.(check bool) "contains" true (Span.contains span (ok (Span.create ~start:6L ~length:2L)));
  Alcotest.(check bool) "overlap" true (Span.overlaps span (ok (Span.create ~start:9L ~length:2L)));
  Alcotest.(check bool) "touching is not overlap" false (Span.overlaps span (ok (Span.create ~start:10L ~length:2L)))

let () =
  Alcotest.run "reader"
    [
      ( "reader",
        [
          Alcotest.test_case "integer widths and endian" `Quick test_integer_reads;
          Alcotest.test_case "boundaries" `Quick test_boundaries;
          Alcotest.test_case "arithmetic" `Quick test_arithmetic;
          Alcotest.test_case "sub-reader and strings" `Quick test_sub_reader_and_strings;
          Alcotest.test_case "signed and unsigned" `Quick test_signed_and_unsigned;
        ] );
      ("span", [ Alcotest.test_case "span invariants" `Quick test_span ]);
    ]
