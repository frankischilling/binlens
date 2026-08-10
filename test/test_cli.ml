let executable = Sys.getenv "BINLENS_TEST_EXE"

let read_all channel =
  let buffer = Buffer.create 1024 in
  (try
     while true do
       Buffer.add_channel buffer channel 4096
     done
   with End_of_file -> ());
  Buffer.contents buffer

let contains text fragment =
  let text_length = String.length text
  and fragment_length = String.length fragment in
  let rec search offset =
    if offset + fragment_length > text_length then false
    else if String.sub text offset fragment_length = fragment then true
    else search (offset + 1)
  in
  search 0

let run arguments =
  let command = Array.of_list (executable :: arguments) in
  let stdout, stdin, stderr =
    Unix.open_process_args_full executable command (Unix.environment ())
  in
  close_out stdin;
  let output = read_all stdout in
  let errors = read_all stderr in
  let status = Unix.close_process_full (stdout, stdin, stderr) in
  let code =
    match status with
    | Unix.WEXITED code -> code
    | Unix.WSIGNALED signal | Unix.WSTOPPED signal -> 128 + signal
  in
  (code, output, errors)

let with_file bytes function_ =
  let filename = Filename.temp_file "binlens-test-" ".bin" in
  let channel = open_out_bin filename in
  output_bytes channel bytes;
  close_out channel;
  Fun.protect
    ~finally:(fun () -> Sys.remove filename)
    (fun () -> function_ filename)

let test_version_and_formats () =
  let code, output, _ = run [ "version" ] in
  Alcotest.(check int) "version status" 0 code;
  Alcotest.(check bool)
    "version output" true
    (String.starts_with ~prefix:"binlens 0.1.0" output);
  let code, output, _ = run [ "formats"; "--json" ] in
  Alcotest.(check int) "formats status" 0 code;
  ignore (Yojson.Safe.from_string output);
  let code, output, _ = run [ "inspect"; "--help=plain" ] in
  Alcotest.(check int) "help status" 0 code;
  Alcotest.(check bool)
    "documented exit status" true
    (contains output "6   Structural differences were found");
  Alcotest.(check bool)
    "no Cmdliner internal status" false
    (contains output "124 on command line parsing errors");
  Alcotest.(check bool) "backend help" true (contains output "--backend")

let test_inspect_detect_json () =
  with_file (Fixture_builder.nes ()) (fun filename ->
      let code, output, errors =
        run [ "detect"; "--backend"; "paged"; filename ]
      in
      Alcotest.(check int) "detect status" 0 code;
      Alcotest.(check bool)
        "detect NES" true
        (String.starts_with ~prefix:"nes" output);
      Alcotest.(check string) "detect stderr" "" errors;
      let code, output, errors = run [ "inspect"; filename ] in
      Alcotest.(check int) "inspect status" 0 code;
      Alcotest.(check bool) "tree" true (String.contains output 'M');
      Alcotest.(check string) "inspect stderr" "" errors;
      let code, output, errors =
        run [ "json"; "--backend"; "paged"; filename ]
      in
      Alcotest.(check int) "JSON status" 0 code;
      Alcotest.(check string) "JSON stderr" "" errors;
      let json = Yojson.Safe.from_string output in
      Alcotest.(check string)
        "schema" "1.1"
        Yojson.Safe.Util.(json |> member "schema_version" |> to_string);
      Alcotest.(check string)
        "paged backend" "paged"
        Yojson.Safe.Util.(
          json |> member "input" |> member "backend" |> to_string))

let test_validate_and_arguments () =
  with_file Bytes.empty (fun filename ->
      let code, _, errors = run [ "validate"; "--format"; "nes"; filename ] in
      Alcotest.(check int) "malformed status" 4 code;
      Alcotest.(check bool)
        "diagnostic on stderr" true
        (String.length errors > 0));
  let code, _, _ = run [ "inspect" ] in
  Alcotest.(check int) "argument status" 2 code

let test_diff_check () =
  with_file (Fixture_builder.nes ()) (fun left ->
      with_file
        (Fixture_builder.corrupt_u8 (Fixture_builder.nes ()) 6 2)
        (fun right ->
          let code, output, _ = run [ "diff"; "--check"; left; right ] in
          Alcotest.(check int) "difference status" 6 code;
          Alcotest.(check bool)
            "difference output" true
            (String.length output > 0));
      let code, _, _ = run [ "diff"; "--check"; left; left ] in
      Alcotest.(check int) "identical status" 0 code)

let test_output_file () =
  with_file (Fixture_builder.nes ()) (fun input ->
      let output = Filename.temp_file "binlens-output-" ".json" in
      Fun.protect
        ~finally:(fun () -> Sys.remove output)
        (fun () ->
          let code, stdout, _ = run [ "json"; "--output"; output; input ] in
          Alcotest.(check int) "output status" 0 code;
          Alcotest.(check string) "stdout empty" "" stdout;
          let channel = open_in_bin output in
          let contents =
            really_input_string channel (in_channel_length channel)
          in
          close_in channel;
          ignore (Yojson.Safe.from_string contents)))

let () =
  Alcotest.run "cli"
    [ ( "commands",
        [ Alcotest.test_case "version and formats" `Quick
            test_version_and_formats;
          Alcotest.test_case "inspect detect JSON" `Quick
            test_inspect_detect_json;
          Alcotest.test_case "validate and arguments" `Quick
            test_validate_and_arguments;
          Alcotest.test_case "diff check" `Quick test_diff_check;
          Alcotest.test_case "output file" `Quick test_output_file
        ] )
    ]
