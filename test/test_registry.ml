open Binlens

let coverage =
  { Format.summary = "test parser"; supported = []; unsupported = [] }

let parser ?(confidence = 80) ?(detect_raises = false) ?(parse_raises = false)
    ~id ~extensions () =
  let detect _limits _reader =
    if detect_raises then failwith "detector failure"
    else
      { Format.format_id = id;
        display_name = id;
        confidence;
        evidence = [ "test evidence" ];
        contradictions = [];
        required_minimum_length = 0L;
        definitive = true
      }
  in
  let parse _limits _reader =
    if parse_raises then failwith "parser failure"
    else
      { Format.format_id = id;
        root = None;
        diagnostics = [];
        partial = false;
        limit_reached = false
      }
  in
  { Format.id; display_name = id; extensions; coverage; detect; parse }

let require_registry parsers =
  match Registry.create parsers with
  | Ok registry -> registry
  | Error error -> Alcotest.fail (Error.to_string error)

let check_error expected = function
  | Ok _ -> Alcotest.failf "expected registry error %s" expected
  | Error error ->
      Alcotest.(check string) "error code" expected error.Error.code

let test_registration_and_order () =
  let alpha = parser ~id:"alpha" ~extensions:[ ".alpha" ] ()
  and beta = parser ~id:"beta" ~extensions:[ ".beta" ] () in
  let registry = require_registry [ beta; alpha ] in
  Alcotest.(check int) "API version" 1 Registry.api_version;
  Alcotest.(check (list string))
    "sorted parser identifiers" [ "alpha"; "beta" ]
    (Registry.all ~registry () |> List.map (fun parser -> parser.Format.id));
  Alcotest.(check bool)
    "find custom parser" true
    (Option.is_some (Registry.find ~registry "beta"));
  let extended =
    match
      Registry.with_parser registry
        (parser ~id:"gamma" ~extensions:[ ".gamma" ] ())
    with
    | Ok registry -> registry
    | Error error -> Alcotest.fail (Error.to_string error)
  in
  Alcotest.(check int)
    "extended registry" 3
    (List.length (Registry.all ~registry:extended ()))

let test_registration_errors () =
  check_error "registry.invalid_id"
    (Registry.create [ parser ~id:"Bad" ~extensions:[ ".bad" ] () ]);
  check_error "registry.invalid_extension"
    (Registry.create [ parser ~id:"bad" ~extensions:[ "bad" ] () ]);
  (match
     Registry.create [ parser ~id:"escape" ~extensions:[ ".\027bad" ] () ]
   with
  | Ok _ -> Alcotest.fail "expected escaped extension error"
  | Error error ->
      Alcotest.(check bool)
        "invalid extension is escaped" false
        (String.contains error.Error.message '\027'));
  check_error "registry.duplicate_id"
    (Registry.create
       [ parser ~id:"same" ~extensions:[ ".one" ] ();
         parser ~id:"same" ~extensions:[ ".two" ] ()
       ]);
  check_error "registry.duplicate_extension"
    (Registry.create
       [ parser ~id:"one" ~extensions:[ ".same" ] ();
         parser ~id:"two" ~extensions:[ ".same" ] ()
       ])

let test_detection_order () =
  let registry =
    require_registry
      [ parser ~id:"zeta" ~extensions:[ ".zeta" ] ();
        parser ~id:"alpha" ~extensions:[ ".alpha" ] ()
      ]
  in
  let detections =
    Registry.detect ~registry Limits.default (Reader.of_string "")
  in
  Alcotest.(check (list string))
    "confidence tie order" [ "alpha"; "zeta" ]
    (List.map
       (fun (detection : Format.detection) -> detection.Format.format_id)
       detections)

let test_exception_boundaries () =
  let broken_detector =
    parser ~detect_raises:true ~id:"broken-detector" ~extensions:[ ".detect" ]
      ()
  and broken_parser =
    parser ~parse_raises:true ~id:"broken-parser" ~extensions:[ ".parse" ] ()
  in
  let registry = require_registry [ broken_detector; broken_parser ] in
  let detections =
    Registry.detect ~registry Limits.default (Reader.of_string "")
  in
  let detector =
    List.find
      (fun (detection : Format.detection) ->
        String.equal detection.Format.format_id "broken-detector")
      detections
  in
  Alcotest.(check int) "failed detector confidence" 0 detector.confidence;
  match
    Registry.parse ~registry ~format:"broken-parser" Limits.default
      (Reader.of_string "")
  with
  | Error error -> Alcotest.fail (Error.to_string error)
  | Ok (_, result) ->
      Alcotest.(check bool) "partial parser result" true result.Format.partial;
      Alcotest.(check bool)
        "internal diagnostic" true
        (List.exists
           (fun diagnostic ->
             String.equal diagnostic.Diagnostic.code "parser.internal_exception")
           result.diagnostics)

let test_empty_and_compatibility () =
  let empty = require_registry [] in
  Alcotest.(check (list string))
    "empty registry" []
    (Registry.all ~registry:empty ()
    |> List.map (fun parser -> parser.Format.id));
  check_error "format.unrecognized"
    (Registry.parse ~registry:empty Limits.default (Reader.of_string ""));
  Alcotest.(check bool)
    "built-in compatibility" true
    (Option.is_some (Registry.find "elf"));
  Alcotest.(check int) "built-in parser count" 5 (List.length (Registry.all ()))

let () =
  Alcotest.run "registry"
    [ ( "registration",
        [ Alcotest.test_case "custom parser and order" `Quick
            test_registration_and_order;
          Alcotest.test_case "invalid and duplicate values" `Quick
            test_registration_errors;
          Alcotest.test_case "empty and compatibility" `Quick
            test_empty_and_compatibility
        ] );
      ( "boundaries",
        [ Alcotest.test_case "detection order" `Quick test_detection_order;
          Alcotest.test_case "exceptions" `Quick test_exception_boundaries
        ] )
    ]
