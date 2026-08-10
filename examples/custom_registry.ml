open Binlens

let demo_parser =
  let id = "demo" in
  let display_name = "Demo format" in
  let coverage =
    { Format.summary = "Four-byte DEMO marker";
      supported = [ "DEMO marker" ];
      unsupported = []
    }
  in
  let detect _limits reader =
    let matches =
      match Reader.fixed_string reader ~offset:0L ~length:4L with
      | Ok "DEMO" -> true
      | _ -> false
    in
    if matches then
      { Format.format_id = id;
        display_name;
        confidence = 100;
        evidence = [ "DEMO marker at offset 0" ];
        contradictions = [];
        required_minimum_length = 4L;
        definitive = true
      }
    else
      Format.no_detection ~format_id:id ~display_name
        ~required_minimum_length:4L
  in
  let parse _limits _reader =
    { Format.format_id = id;
      root = None;
      diagnostics = [];
      partial = false;
      limit_reached = false
    }
  in
  { Format.id; display_name; extensions = [ ".demo" ]; coverage; detect; parse }

let () =
  match Registry.with_parser Registry.builtins demo_parser with
  | Error error -> prerr_endline (Error.to_string error)
  | Ok registry -> (
      match
        Registry.parse ~registry Limits.default (Reader.of_string "DEMO")
      with
      | Error error -> prerr_endline (Error.to_string error)
      | Ok (parser, _) ->
          Printf.printf "Detected %s.\n" parser.Format.display_name)
