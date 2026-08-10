let id = "pe"
let display_name = "Portable Executable"

let coverage =
  { Format.summary =
      "DOS header, PE signature, COFF header, PE32 and PE32+ optional headers, \
       checked RVA mapping, core data directories, and section table";
    supported =
      [ "DOS MZ header and e_lfanew";
        "COFF file header";
        "PE32 and PE32+ core optional-header fields";
        "mapped export, import, resource, certificate, relocation, and debug directories";
        "section headers and raw-data ranges"
      ];
    unsupported =
      [ "loaded-image semantics";
        "resource payload decoding";
        "Authenticode verification";
        "CLR metadata";
        "architecture-specific directory payloads"
      ]
  }

let has_mz reader =
  match (Reader.byte reader 0L, Reader.byte reader 1L) with
  | Ok 0x4d, Ok 0x5a -> true
  | _ -> false

let pe_offset reader =
  if Int64.compare (Reader.length reader) 64L < 0 then None
  else
    match Reader.u32 reader Endian.Little 0x3cL with
    | Ok value -> Some value
    | Error _ -> None

let has_signature reader offset =
  match
    ( Reader.byte reader offset,
      Reader.byte reader (Int64.add offset 1L),
      Reader.byte reader (Int64.add offset 2L),
      Reader.byte reader (Int64.add offset 3L) )
  with
  | Ok 0x50, Ok 0x45, Ok 0, Ok 0 -> true
  | _ -> false

let detect _limits reader =
  if not (has_mz reader) then
    Format.no_detection ~format_id:id ~display_name ~required_minimum_length:64L
  else
    match pe_offset reader with
    | Some offset when has_signature reader offset ->
        { Format.format_id = id;
          display_name;
          confidence = 100;
          evidence = [ "DOS MZ magic at offset 0"; "PE signature at e_lfanew" ];
          contradictions = [];
          required_minimum_length = 88L;
          definitive = true
        }
    | Some _ ->
        { Format.format_id = id;
          display_name;
          confidence = 55;
          evidence = [ "DOS MZ magic at offset 0" ];
          contradictions = [ "PE signature was not found at e_lfanew" ];
          required_minimum_length = 64L;
          definitive = false
        }
    | None ->
        { Format.format_id = id;
          display_name;
          confidence = 40;
          evidence = [ "DOS MZ magic at offset 0" ];
          contradictions = [ "DOS header is truncated before e_lfanew" ];
          required_minimum_length = 64L;
          definitive = false
        }

let machine_names =
  [ (0x14cL, "Intel 386");
    (0x1c0L, "ARM");
    (0x1c4L, "ARMv7 Thumb-2");
    (0x8664L, "x86-64");
    (0xaa64L, "ARM64");
    (0x5064L, "RISC-V 64")
  ]

let subsystem_names =
  [ (1L, "Native");
    (2L, "Windows GUI");
    (3L, "Windows console");
    (7L, "POSIX console");
    (9L, "Windows CE GUI");
    (10L, "EFI application");
    (14L, "Xbox")
  ]

let directory_names =
  [| "Export";
     "Import";
     "Resource";
     "Exception";
     "Certificate";
     "Base relocation";
     "Debug";
     "Architecture";
     "Global pointer";
     "TLS";
     "Load configuration";
     "Bound import";
     "Import address table";
     "Delay import";
     "CLR runtime";
     "Reserved"
  |]

let add_field context children ?metadata ~parent ~id ~label ~offset ~length
    value =
  match
    Parser_common.field context ?metadata ~parent ~id ~label ~offset ~length
      value
  with
  | None -> children
  | Some node -> node :: children

type directory_record =
  { index : int; rva : int64; size : int64; span : Span.t }

type section_map =
  { virtual_address : int64;
    virtual_size : int64;
    raw_offset : int64;
    raw_size : int64
  }

type mapped_window = { file_offset : int64; available : int64 }

let collect_directories reader ~offset ~declared_size ~count ~maximum =
  let wanted = min count (max 0 (declared_size / 8)) |> min maximum in
  match
    Reader.table_range reader ~offset ~entry_size:8L
      ~count:(Int64.of_int wanted)
  with
  | Error _ -> []
  | Ok _ ->
      List.init wanted (fun index ->
          let base = Int64.add offset (Int64.of_int (index * 8)) in
          match
            ( Reader.u32 reader Endian.Little base,
              Reader.u32 reader Endian.Little (Int64.add base 4L) )
          with
          | Ok rva, Ok size ->
              Some
                { index; rva; size; span = Span.unsafe ~start:base ~length:8L }
          | _ -> None)
      |> List.filter_map Fun.id

let collect_section_map reader ~offset ~count ~maximum =
  if count > maximum then []
  else
    match
      Reader.table_range reader ~offset ~entry_size:40L
        ~count:(Int64.of_int count)
    with
    | Error _ -> []
    | Ok _ ->
        List.init count (fun index ->
            let base = Int64.add offset (Int64.of_int (index * 40)) in
            match
              ( Reader.u32 reader Endian.Little (Int64.add base 8L),
                Reader.u32 reader Endian.Little (Int64.add base 12L),
                Reader.u32 reader Endian.Little (Int64.add base 16L),
                Reader.u32 reader Endian.Little (Int64.add base 20L) )
            with
            | Ok virtual_size, Ok virtual_address, Ok raw_size, Ok raw_offset ->
                Some { virtual_address; virtual_size; raw_offset; raw_size }
            | _ -> None)
        |> List.filter_map Fun.id

let section_window reader section ~rva =
  if Int64.compare rva section.virtual_address < 0 then None
  else
    let relative = Int64.sub rva section.virtual_address in
    let virtual_length = max section.virtual_size section.raw_size in
    match Reader.checked_add section.raw_offset relative with
    | Ok file_offset
      when Int64.compare relative virtual_length < 0
           && Int64.compare relative section.raw_size < 0 -> (
        match Reader.range reader ~offset:file_offset ~length:0L with
        | Error _ -> None
        | Ok () ->
            let available =
              min (Int64.sub virtual_length relative)
                (Int64.sub section.raw_size relative)
              |> min (Int64.sub (Reader.length reader) file_offset)
            in
            Some { file_offset; available })
    | _ -> None

let rva_windows reader sections ~header_size ~rva =
  let header =
    if Int64.compare rva header_size < 0 then
      match Reader.range reader ~offset:rva ~length:0L with
      | Error _ -> []
      | Ok () ->
          [ { file_offset = rva;
              available =
                min (Int64.sub header_size rva)
                  (Int64.sub (Reader.length reader) rva)
            }
          ]
    else []
  in
  header @ List.filter_map (fun section -> section_window reader section ~rva) sections

let map_rva_range reader sections ~header_size ~rva ~size =
  rva_windows reader sections ~header_size ~rva
  |> List.filter (fun mapping -> Int64.compare size mapping.available <= 0)

let map_directory reader sections ~header_size record =
  if record.index = 4 then
    match Reader.range reader ~offset:record.rva ~length:record.size with
    | Ok () -> [ record.rva ]
    | Error _ -> []
  else
    map_rva_range reader sections ~header_size ~rva:record.rva ~size:record.size
    |> List.map (fun mapping -> mapping.file_offset)

let consume_pe_entries context ~component count =
  match
    Limits.consume_table_entries_int64 context.Parse_context.tracker count
  with
  | Error error ->
      Parse_context.error_from_reader context ~component error;
      None
  | Ok () -> (
      let count = Int64.to_int count in
      match Limits.consume_work context.Parse_context.tracker count with
      | Ok () -> Some count
      | Error error ->
          Parse_context.error_from_reader context ~component error;
          None)

let consume_mapping_work context sections ~component =
  match
    Limits.consume_work context.Parse_context.tracker (1 + List.length sections)
  with
  | Ok () -> true
  | Error error ->
      Parse_context.error_from_reader context ~component error;
      false

let resolve_rva_window context sections ~header_size ~component ~span ~rva =
  if not (consume_mapping_work context sections ~component) then None
  else
    match
      rva_windows context.Parse_context.reader sections ~header_size ~rva
    with
    | [] ->
        Parse_context.error context ~span ~code:"pe.rva_unmapped"
          ~message:"A PE relative virtual address does not map to the file."
          ~component ~recoverable:true ();
        None
    | _ :: _ :: _ ->
        Parse_context.error context ~span ~code:"pe.rva_ambiguous"
          ~message:
            "A PE relative virtual address maps through more than one section."
          ~component ~recoverable:true ();
        None
    | [ mapping ] -> Some mapping

let resolve_rva_range context sections ~header_size ~component ~span ~rva ~size =
  if not (consume_mapping_work context sections ~component) then None
  else
    match
      map_rva_range context.Parse_context.reader sections ~header_size ~rva
        ~size
    with
    | [] ->
        Parse_context.error context ~span ~code:"pe.rva_range_unmapped"
          ~message:"A PE relative virtual address range does not map to the file."
          ~component ~recoverable:true ();
        None
    | _ :: _ :: _ ->
        Parse_context.error context ~span ~code:"pe.rva_range_ambiguous"
          ~message:
            "A PE relative virtual address range maps through more than one section."
          ~component ~recoverable:true ();
        None
    | [ mapping ] -> Some mapping.file_offset

let read_rva_string context sections ~header_size ~component ~span ~rva =
  match
    resolve_rva_window context sections ~header_size ~component ~span ~rva
  with
  | None -> None
  | Some mapping ->
      let available = min mapping.available (Int64.of_int max_int) in
      let maximum =
        min context.Parse_context.limits.max_string_bytes
          (Int64.to_int available)
      in
      if maximum = 0 then (
        Parse_context.error context ~span ~code:"pe.string_limit"
          ~message:"A PE string cannot be read under the configured string limit."
          ~component ~recoverable:true ();
        None)
      else
        match
          Reader.c_string ~tracker:context.Parse_context.tracker
            context.Parse_context.reader ~offset:mapping.file_offset
            ~max_length:maximum
        with
        | Error error ->
            Parse_context.error_from_reader context ~component error;
            None
        | Ok value ->
            let length = String.length value in
            if length = maximum then
              if Int64.compare (Int64.of_int maximum) mapping.available < 0 then
                Parse_context.error context ~span ~code:"pe.string_limit"
                  ~message:"A PE string exceeds the configured string limit."
                  ~component ~recoverable:true ()
              else
                Parse_context.error context ~span ~code:"pe.unterminated_string"
                  ~message:"A PE string is not terminated inside its mapped range."
                  ~component ~recoverable:true ();
            Some (Sanitize.text value, mapping.file_offset, Int64.of_int length)

let mapped_string_field context sections ~header_size ~component ~span ~rva
    ~parent ~id ~label =
  match
    read_rva_string context sections ~header_size ~component ~span ~rva
  with
  | None -> None
  | Some (text, offset, length) ->
      Parser_common.field context ~parent ~id ~label ~offset ~length
        (Value.String { text; raw_hex = None; valid_utf8 = true })

let export_directory_fields context ~offset ~parent =
  let fields = ref [] in
  let add16 id label relative =
    match
      Parser_common.u16 context Endian.Little (Int64.add offset relative)
    with
    | None -> None
    | Some value ->
        fields :=
          add_field context !fields ~parent ~id ~label
            ~offset:(Int64.add offset relative) ~length:2L
            (Value.unsigned 16 value);
        Some value
  in
  let add32 id label relative =
    match
      Parser_common.u32 context Endian.Little (Int64.add offset relative)
    with
    | None -> None
    | Some value ->
        fields :=
          add_field context !fields ~parent ~id ~label
            ~offset:(Int64.add offset relative) ~length:4L
            (Value.unsigned 32 value);
        Some value
  in
  ignore (add32 "characteristics" "Characteristics" 0L);
  ignore (add32 "timestamp" "Timestamp" 4L);
  ignore (add16 "major_version" "Major version" 8L);
  ignore (add16 "minor_version" "Minor version" 10L);
  let name_rva = add32 "name_rva" "Name RVA" 12L in
  let ordinal_base = add32 "ordinal_base" "Ordinal base" 16L in
  let function_count = add32 "function_count" "Function count" 20L in
  let name_count = add32 "name_count" "Name count" 24L in
  let functions_rva = add32 "functions_rva" "Function table RVA" 28L in
  let names_rva = add32 "names_rva" "Name pointer table RVA" 32L in
  let ordinals_rva = add32 "ordinals_rva" "Ordinal table RVA" 36L in
  ( List.rev !fields,
    name_rva,
    ordinal_base,
    function_count,
    name_count,
    functions_rva,
    names_rva,
    ordinals_rva )

let parse_exports context record sections ~header_size ~offset ~parent =
  let component = "pe.exports" in
  if Int64.compare record.size 40L < 0 then (
    Parse_context.error context ~span:record.span
      ~code:"pe.export_directory_too_small"
      ~message:"The export directory is smaller than its 40-byte header."
      ~component ~recoverable:true ();
    None)
  else
    let ( fields,
          name_rva,
          ordinal_base,
          function_count,
          name_count,
          functions_rva,
          names_rva,
          ordinals_rva ) =
      export_directory_fields context ~offset ~parent:(parent ^ ".exports")
    in
    let fields = ref fields in
    (match name_rva with
    | Some rva when not (Int64.equal rva 0L) -> (
        let span = Span.unsafe ~start:(Int64.add offset 12L) ~length:4L in
        match
          mapped_string_field context sections ~header_size ~component ~span
            ~rva ~parent:(parent ^ ".exports") ~id:"module_name"
            ~label:"Module name"
        with
        | None -> ()
        | Some node -> fields := !fields @ [ node ])
    | _ -> ());
    let names = ref [] in
    (match
       ( ordinal_base,
         function_count,
         name_count,
         functions_rva,
         names_rva,
         ordinals_rva )
     with
    | ( Some ordinal_base,
        Some function_count,
        Some name_count,
        Some functions_rva,
        Some names_rva,
        Some ordinals_rva )
      when not (Int64.equal name_count 0L) -> (
        match
          ( consume_pe_entries context ~component function_count,
            consume_pe_entries context ~component name_count,
            Reader.checked_mul name_count 4L,
            Reader.checked_mul name_count 2L,
            Reader.checked_mul function_count 4L )
        with
        | ( Some _,
            Some count,
            Ok names_size,
            Ok ordinals_size,
            Ok functions_size ) ->
            let name_span =
              Span.unsafe ~start:(Int64.add offset 32L) ~length:4L
            and ordinal_span =
              Span.unsafe ~start:(Int64.add offset 36L) ~length:4L
            and function_span =
              Span.unsafe ~start:(Int64.add offset 28L) ~length:4L
            in
            let mapped_names =
              resolve_rva_range context sections ~header_size ~component
                ~span:name_span ~rva:names_rva ~size:names_size
            and mapped_ordinals =
              resolve_rva_range context sections ~header_size ~component
                ~span:ordinal_span ~rva:ordinals_rva ~size:ordinals_size
            and mapped_functions =
              resolve_rva_range context sections ~header_size ~component
                ~span:function_span ~rva:functions_rva ~size:functions_size
            in
            (match (mapped_names, mapped_ordinals, mapped_functions) with
            | Some name_table, Some ordinal_table, Some function_table ->
                for index = 0 to count - 1 do
                  let name_pointer_offset =
                    Int64.add name_table (Int64.of_int (index * 4))
                  and ordinal_offset =
                    Int64.add ordinal_table (Int64.of_int (index * 2))
                  in
                  match
                    ( Parser_common.u32 context Endian.Little
                        name_pointer_offset,
                      Parser_common.u16 context Endian.Little ordinal_offset )
                  with
                  | Some export_name_rva, Some ordinal_index ->
                      let entry_parent =
                        Printf.sprintf "%s.exports.names[%d]" parent index
                      in
                      let entry_fields = ref [] in
                      entry_fields :=
                        add_field context !entry_fields ~parent:entry_parent
                          ~id:"name_rva" ~label:"Name RVA"
                          ~offset:name_pointer_offset ~length:4L
                          (Value.address 32 export_name_rva);
                      entry_fields :=
                        add_field context !entry_fields ~parent:entry_parent
                          ~id:"ordinal_index" ~label:"Ordinal index"
                          ~offset:ordinal_offset ~length:2L
                          (Value.unsigned 16 ordinal_index);
                      (match Reader.checked_add ordinal_base ordinal_index with
                      | Ok ordinal ->
                          entry_fields :=
                            add_field context !entry_fields ~parent:entry_parent
                              ~id:"ordinal" ~label:"Ordinal"
                              ~offset:ordinal_offset ~length:2L
                              (Value.unsigned 32 ordinal)
                      | Error error ->
                          Parse_context.error_from_reader context ~component
                            error);
                      if Int64.compare ordinal_index function_count >= 0 then
                        Parse_context.error context
                          ~span:
                            (Span.unsafe ~start:ordinal_offset ~length:2L)
                          ~code:"pe.export_ordinal_out_of_range"
                          ~message:
                            "An export ordinal index is outside the function table."
                          ~component ~recoverable:true ()
                      else
                        let function_offset =
                          Int64.add function_table
                            (Int64.mul ordinal_index 4L)
                        in
                        (match
                           Parser_common.u32 context Endian.Little
                             function_offset
                         with
                        | None -> ()
                        | Some function_rva ->
                            entry_fields :=
                              add_field context !entry_fields
                                ~parent:entry_parent ~id:"function_rva"
                                ~label:"Function RVA" ~offset:function_offset
                                ~length:4L (Value.address 32 function_rva));
                      (match
                         mapped_string_field context sections ~header_size
                           ~component
                           ~span:
                             (Span.unsafe ~start:name_pointer_offset ~length:4L)
                           ~rva:export_name_rva ~parent:entry_parent ~id:"name"
                           ~label:"Name"
                       with
                      | None -> ()
                      | Some node -> entry_fields := node :: !entry_fields);
                      let entry_fields = List.rev !entry_fields in
                      (match
                         Parse_context.node context
                           ~id:(Printf.sprintf "name[%d]" index)
                           ~path:entry_parent
                           ~label:(Printf.sprintf "Export name %d" index)
                           ~span:
                             (Span.unsafe ~start:name_pointer_offset ~length:4L)
                           ~value:
                             (Value.Collection (List.length entry_fields))
                           ~children:entry_fields ()
                       with
                      | None -> ()
                      | Some node -> names := node :: !names)
                  | _ -> ()
                done
            | _ -> ())
        | _ -> ())
    | _ -> ());
    let children = !fields @ List.rev !names in
    Parse_context.node context ~id:"exports" ~path:(parent ^ ".exports")
      ~label:"Exports" ~span:(Span.unsafe ~start:offset ~length:record.size)
      ~value:(Value.Collection (List.length children)) ~children ()

let parse_import_thunks context sections ~header_size ~plus ~table_rva
    ~source_span ~parent =
  let component = "pe.import_thunks" in
  let width = if plus then 8L else 4L in
  let bit_width = if plus then 64 else 32 in
  let ordinal_flag = if plus then Int64.min_int else 0x8000_0000L in
  let address_mask = if plus then Int64.max_int else 0x7fff_ffffL in
  match
    resolve_rva_window context sections ~header_size ~component
      ~span:source_span ~rva:table_rva
  with
  | None -> None
  | Some mapping ->
      let maximum_entries =
        Int64.div mapping.available width |> min (Int64.of_int max_int)
        |> Int64.to_int
      in
      let nodes = ref [] and index = ref 0 and running = ref true in
      let terminated = ref false and parsed_length = ref 0L in
      while !running && !index < maximum_entries do
        match consume_pe_entries context ~component 1L with
        | None -> running := false
        | Some _ ->
            let entry_offset =
              Int64.add mapping.file_offset
                (Int64.mul (Int64.of_int !index) width)
            in
            let raw =
              if plus then
                Parser_common.u64 context Endian.Little entry_offset
              else Parser_common.u32 context Endian.Little entry_offset
            in
            (match raw with
            | None -> running := false
            | Some raw when Int64.equal raw 0L ->
                terminated := true;
                running := false
            | Some raw ->
                parsed_length := Int64.add !parsed_length width;
                let entry_parent =
                  Printf.sprintf "%s.thunks[%d]" parent !index
                in
                let fields = ref [] in
                fields :=
                  add_field context !fields ~parent:entry_parent ~id:"raw"
                    ~label:"Raw thunk" ~offset:entry_offset ~length:width
                    (Value.address bit_width raw);
                (if not (Int64.equal (Int64.logand raw ordinal_flag) 0L) then
                   fields :=
                     add_field context !fields ~parent:entry_parent
                       ~id:"ordinal" ~label:"Import ordinal"
                       ~offset:entry_offset ~length:width
                       (Value.unsigned 16 (Int64.logand raw 0xffffL))
                 else
                   let name_rva = Int64.logand raw address_mask in
                   match
                     resolve_rva_range context sections ~header_size ~component
                       ~span:source_span ~rva:name_rva ~size:2L
                   with
                   | None -> ()
                   | Some hint_offset ->
                       (match
                          Parser_common.u16 context Endian.Little hint_offset
                        with
                       | None -> ()
                       | Some hint ->
                           fields :=
                             add_field context !fields ~parent:entry_parent
                               ~id:"hint" ~label:"Import hint"
                               ~offset:hint_offset ~length:2L
                               (Value.unsigned 16 hint));
                       (match Reader.checked_add name_rva 2L with
                       | Error error ->
                           Parse_context.error_from_reader context ~component
                             error
                       | Ok string_rva -> (
                           match
                             mapped_string_field context sections ~header_size
                               ~component ~span:source_span ~rva:string_rva
                               ~parent:entry_parent ~id:"name"
                               ~label:"Import name"
                           with
                           | None -> ()
                           | Some node -> fields := node :: !fields)));
                let fields = List.rev !fields in
                (match
                   Parse_context.node context
                     ~id:(Printf.sprintf "thunk[%d]" !index)
                     ~path:entry_parent
                     ~label:(Printf.sprintf "Import thunk %d" !index)
                     ~span:(Span.unsafe ~start:entry_offset ~length:width)
                     ~value:(Value.Collection (List.length fields))
                     ~children:fields ()
                 with
                | None -> ()
                | Some node -> nodes := node :: !nodes);
                incr index)
      done;
      if !running && not !terminated then
        Parse_context.error context ~span:source_span
          ~code:"pe.import_thunks_unterminated"
          ~message:"An import thunk table has no null entry in its mapped range."
          ~component ~recoverable:true ();
      let nodes = List.rev !nodes in
      if nodes = [] then None
      else
        Parse_context.node context ~id:"thunks" ~path:(parent ^ ".thunks")
          ~label:"Import thunks"
          ~span:
            (Span.unsafe ~start:mapping.file_offset ~length:!parsed_length)
          ~value:(Value.Collection (List.length nodes)) ~children:nodes ()

let parse_imports context record sections ~header_size ~plus ~offset ~parent =
  let component = "pe.imports" in
  if not (Int64.equal (Int64.rem record.size 20L) 0L) then
    Parse_context.error context ~span:record.span
      ~code:"pe.import_directory_size"
      ~message:"The import directory size is not a multiple of 20 bytes."
      ~component ~recoverable:true ();
  let count64 = Int64.div record.size 20L in
  match consume_pe_entries context ~component count64 with
  | None -> None
  | Some count ->
      let descriptors = ref [] and running = ref true in
      let terminated = ref false in
      for index = 0 to count - 1 do
        if !running then
          let base = Int64.add offset (Int64.of_int (index * 20)) in
          let original_thunk =
            Parser_common.u32 context Endian.Little base
          and timestamp =
            Parser_common.u32 context Endian.Little (Int64.add base 4L)
          and forwarder_chain =
            Parser_common.u32 context Endian.Little (Int64.add base 8L)
          and name_rva =
            Parser_common.u32 context Endian.Little (Int64.add base 12L)
          and first_thunk =
            Parser_common.u32 context Endian.Little (Int64.add base 16L)
          in
          match
            ( original_thunk,
              timestamp,
              forwarder_chain,
              name_rva,
              first_thunk )
          with
          | Some 0L, Some 0L, Some 0L, Some 0L, Some 0L ->
              terminated := true;
              running := false
          | ( Some original_thunk,
              Some timestamp,
              Some forwarder_chain,
              Some name_rva,
              Some first_thunk ) ->
              let entry_parent =
                Printf.sprintf "%s.imports[%d]" parent index
              in
              let fields = ref [] in
              let add32 id label relative value =
                fields :=
                  add_field context !fields ~parent:entry_parent ~id ~label
                    ~offset:(Int64.add base relative) ~length:4L
                    (Value.address 32 value)
              in
              add32 "original_first_thunk" "Original first thunk RVA" 0L
                original_thunk;
              fields :=
                add_field context !fields ~parent:entry_parent ~id:"timestamp"
                  ~label:"Timestamp" ~offset:(Int64.add base 4L) ~length:4L
                  (Value.unsigned 32 timestamp);
              fields :=
                add_field context !fields ~parent:entry_parent
                  ~id:"forwarder_chain" ~label:"Forwarder chain"
                  ~offset:(Int64.add base 8L) ~length:4L
                  (Value.unsigned 32 forwarder_chain);
              add32 "name_rva" "Library name RVA" 12L name_rva;
              add32 "first_thunk" "First thunk RVA" 16L first_thunk;
              (if not (Int64.equal name_rva 0L) then
                 match
                   mapped_string_field context sections ~header_size ~component
                     ~span:
                       (Span.unsafe ~start:(Int64.add base 12L) ~length:4L)
                     ~rva:name_rva ~parent:entry_parent ~id:"library"
                     ~label:"Library"
                 with
                 | None -> ()
                 | Some node -> fields := node :: !fields);
              let thunk_rva =
                if Int64.equal original_thunk 0L then first_thunk
                else original_thunk
              in
              (if not (Int64.equal thunk_rva 0L) then
                 match
                   parse_import_thunks context sections ~header_size ~plus
                     ~table_rva:thunk_rva
                     ~source_span:
                       (Span.unsafe ~start:base ~length:20L)
                     ~parent:entry_parent
                 with
                 | None -> ()
                 | Some node -> fields := node :: !fields);
              let fields = List.rev !fields in
              (match
                 Parse_context.node context
                   ~id:(Printf.sprintf "import[%d]" index) ~path:entry_parent
                   ~label:(Printf.sprintf "Import descriptor %d" index)
                   ~span:(Span.unsafe ~start:base ~length:20L)
                   ~value:(Value.Collection (List.length fields))
                   ~children:fields ()
               with
              | None -> ()
              | Some node -> descriptors := node :: !descriptors)
          | _ -> running := false
      done;
      if not !terminated then
        Parse_context.error context ~span:record.span
          ~code:"pe.import_descriptors_unterminated"
          ~message:"The import directory has no complete null descriptor."
          ~component ~recoverable:true ();
      let descriptors = List.rev !descriptors in
      Parse_context.node context ~id:"imports" ~path:(parent ^ ".imports")
        ~label:"Imports" ~span:(Span.unsafe ~start:offset ~length:record.size)
        ~value:(Value.Collection (List.length descriptors))
        ~children:descriptors ()

let resource_relative_range context record ~root ~component ~span ~relative
    ~length =
  match Reader.checked_add relative length with
  | Error error ->
      Parse_context.error_from_reader context ~component error;
      None
  | Ok finish when Int64.compare finish record.size > 0 ->
      Parse_context.error context ~span ~code:"pe.resource_offset_out_of_table"
        ~message:"A resource offset points outside the resource directory."
        ~component ~recoverable:true ();
      None
  | Ok _ -> (
      match Reader.checked_add root relative with
      | Error error ->
          Parse_context.error_from_reader context ~component error;
          None
      | Ok absolute -> (
          match
            Reader.range context.Parse_context.reader ~offset:absolute ~length
          with
          | Ok () -> Some absolute
          | Error error ->
              Parse_context.error_from_reader context ~component error;
              None))

let resource_name context record ~root ~component ~span ~relative ~parent =
  match
    resource_relative_range context record ~root ~component ~span ~relative
      ~length:2L
  with
  | None -> None
  | Some offset -> (
      match Parser_common.u16 context Endian.Little offset with
      | None -> None
      | Some character_count -> (
          match Reader.checked_mul character_count 2L with
          | Error error ->
              Parse_context.error_from_reader context ~component error;
              None
          | Ok byte_length -> (
              match
                resource_relative_range context record ~root ~component ~span
                  ~relative:(Int64.add relative 2L) ~length:byte_length
              with
              | None -> None
              | Some text_offset ->
                  if Int64.compare byte_length (Int64.of_int max_int) > 0 then (
                    Parse_context.error context ~span
                      ~code:"pe.resource_name_unrepresentable"
                      ~message:
                        "A resource name is too large for this OCaml runtime."
                      ~component ~recoverable:true ();
                    None)
                  else
                    let byte_count = Int64.to_int byte_length in
                    match
                      Limits.check_string_length context.Parse_context.tracker
                        byte_count
                    with
                    | Error error ->
                        Parse_context.error_from_reader context ~component
                          error;
                        None
                    | Ok () -> (
                        match
                          Reader.fixed_string
                            ~tracker:context.Parse_context.tracker
                            context.Parse_context.reader ~offset:text_offset
                            ~length:byte_length
                        with
                        | Error error ->
                            Parse_context.error_from_reader context ~component
                              error;
                            None
                        | Ok raw ->
                            let text = Buffer.create byte_count in
                            for index = 0 to (byte_count / 2) - 1 do
                              let low = Char.code raw.[index * 2]
                              and high = Char.code raw.[(index * 2) + 1] in
                              let code = low lor (high lsl 8) in
                              if high = 0 && low >= 0x20 && low <= 0x7e then
                                Buffer.add_string text
                                  (Sanitize.text (String.make 1 (Char.chr low)))
                              else
                                Buffer.add_string text
                                  (Printf.sprintf "\\u%04X" code)
                            done;
                            Parser_common.field context ~parent ~id:"name"
                              ~label:"Name" ~offset
                              ~length:(Int64.add 2L byte_length)
                              (Value.String
                                 { text = Buffer.contents text;
                                   raw_hex = None;
                                   valid_utf8 = true
                                 })))))

let parse_resources context record sections ~header_size ~offset ~parent =
  let component = "pe.resources" in
  let visited = Hashtbl.create 16 in
  let rec parse_directory ~relative ~depth ~source_span ~path ~label =
    match Limits.check_depth context.Parse_context.tracker depth with
    | Error error ->
        Parse_context.error_from_reader context ~component error;
        None
    | Ok () ->
        if Hashtbl.mem visited relative then (
          Parse_context.error context ~span:source_span
            ~code:"pe.resource_cycle"
            ~message:"A resource directory points to an already visited directory."
            ~component ~recoverable:true ();
          None)
        else (
          Hashtbl.add visited relative ();
          match
            resource_relative_range context record ~root:offset ~component
              ~span:source_span ~relative ~length:16L
          with
          | None -> None
          | Some directory_offset ->
              let characteristics =
                Parser_common.u32 context Endian.Little directory_offset
              and timestamp =
                Parser_common.u32 context Endian.Little
                  (Int64.add directory_offset 4L)
              and major =
                Parser_common.u16 context Endian.Little
                  (Int64.add directory_offset 8L)
              and minor =
                Parser_common.u16 context Endian.Little
                  (Int64.add directory_offset 10L)
              and named_count =
                Parser_common.u16 context Endian.Little
                  (Int64.add directory_offset 12L)
              and id_count =
                Parser_common.u16 context Endian.Little
                  (Int64.add directory_offset 14L)
              in
              let fields = ref [] in
              let add32 id label relative value =
                match value with
                | None -> ()
                | Some value ->
                    fields :=
                      add_field context !fields ~parent:path ~id ~label
                        ~offset:(Int64.add directory_offset relative) ~length:4L
                        (Value.unsigned 32 value)
              and add16 id label relative value =
                match value with
                | None -> ()
                | Some value ->
                    fields :=
                      add_field context !fields ~parent:path ~id ~label
                        ~offset:(Int64.add directory_offset relative) ~length:2L
                        (Value.unsigned 16 value)
              in
              add32 "characteristics" "Characteristics" 0L characteristics;
              add32 "timestamp" "Timestamp" 4L timestamp;
              add16 "major_version" "Major version" 8L major;
              add16 "minor_version" "Minor version" 10L minor;
              add16 "named_entry_count" "Named entry count" 12L named_count;
              add16 "id_entry_count" "ID entry count" 14L id_count;
              let entries = ref [] in
              (match (named_count, id_count) with
              | Some named_count, Some id_count -> (
                  match Reader.checked_add named_count id_count with
                  | Error error ->
                      Parse_context.error_from_reader context ~component error
                  | Ok entry_count -> (
                      match consume_pe_entries context ~component entry_count with
                      | None -> ()
                      | Some count -> (
                          match Reader.checked_mul entry_count 8L with
                          | Error error ->
                              Parse_context.error_from_reader context ~component
                                error
                          | Ok entries_length -> (
                              match
                                Result.bind
                                  (Reader.checked_add relative 16L)
                                  (fun entries_relative ->
                                    match
                                      resource_relative_range context record
                                        ~root:offset ~component ~span:source_span
                                        ~relative:entries_relative
                                        ~length:entries_length
                                    with
                                    | None ->
                                        Error
                                          (Error.make Error.Bounds
                                             "pe.resource_entries_out_of_table"
                                             "Resource entries are outside the directory.")
                                    | Some absolute -> Ok absolute)
                              with
                              | Error _ -> ()
                              | Ok entries_offset ->
                                  for index = 0 to count - 1 do
                                    let entry_offset =
                                      Int64.add entries_offset
                                        (Int64.of_int (index * 8))
                                    in
                                    let name_raw =
                                      Parser_common.u32 context Endian.Little
                                        entry_offset
                                    and data_raw =
                                      Parser_common.u32 context Endian.Little
                                        (Int64.add entry_offset 4L)
                                    in
                                    match (name_raw, data_raw) with
                                    | Some name_raw, Some data_raw ->
                                        let entry_path =
                                          Printf.sprintf "%s.entries[%d]" path
                                            index
                                        in
                                        let entry_fields = ref [] in
                                        (if
                                           Int64.equal
                                             (Int64.logand name_raw
                                                0x8000_0000L)
                                             0L
                                         then
                                           entry_fields :=
                                             add_field context !entry_fields
                                               ~parent:entry_path ~id:"id"
                                               ~label:"Identifier"
                                               ~offset:entry_offset ~length:4L
                                               (Value.unsigned 31 name_raw)
                                         else
                                           let name_relative =
                                             Int64.logand name_raw 0x7fff_ffffL
                                           in
                                           match
                                             resource_name context record
                                               ~root:offset ~component
                                               ~span:
                                                 (Span.unsafe
                                                    ~start:entry_offset
                                                    ~length:4L)
                                               ~relative:name_relative
                                               ~parent:entry_path
                                           with
                                           | None -> ()
                                           | Some node ->
                                               entry_fields :=
                                                 node :: !entry_fields);
                                        let child =
                                          let target_relative =
                                            Int64.logand data_raw 0x7fff_ffffL
                                          in
                                          if
                                            not
                                              (Int64.equal
                                                 (Int64.logand data_raw
                                                    0x8000_0000L)
                                                 0L)
                                          then
                                            parse_directory
                                              ~relative:target_relative
                                              ~depth:(depth + 1)
                                              ~source_span:
                                                (Span.unsafe
                                                   ~start:
                                                     (Int64.add entry_offset 4L)
                                                   ~length:4L)
                                              ~path:(entry_path ^ ".directory")
                                              ~label:"Resource subdirectory"
                                          else
                                            parse_data_entry ~relative:target_relative
                                              ~source_span:
                                                (Span.unsafe
                                                   ~start:
                                                     (Int64.add entry_offset 4L)
                                                   ~length:4L)
                                              ~path:(entry_path ^ ".data")
                                        in
                                        let children =
                                          List.rev !entry_fields
                                          @ Option.to_list child
                                        in
                                        (match
                                           Parse_context.node context
                                             ~id:
                                               (Printf.sprintf "entry[%d]" index)
                                             ~path:entry_path
                                             ~label:
                                               (Printf.sprintf
                                                  "Resource entry %d" index)
                                             ~span:
                                               (Span.unsafe
                                                  ~start:entry_offset ~length:8L)
                                             ~value:
                                               (Value.Collection
                                                  (List.length children))
                                             ~children ()
                                         with
                                        | None -> ()
                                        | Some node ->
                                            entries := node :: !entries)
                                    | _ -> ()
                                  done))))
              | _ -> ());
              let children = List.rev !fields @ List.rev !entries in
              Parse_context.node context ~id:"directory" ~path ~label
                ~span:(Span.unsafe ~start:directory_offset ~length:16L)
                ~value:(Value.Collection (List.length children)) ~children ())
  and parse_data_entry ~relative ~source_span ~path =
    match
      resource_relative_range context record ~root:offset ~component
        ~span:source_span ~relative ~length:16L
    with
    | None -> None
    | Some data_offset ->
        let data_rva =
          Parser_common.u32 context Endian.Little data_offset
        and size =
          Parser_common.u32 context Endian.Little (Int64.add data_offset 4L)
        and code_page =
          Parser_common.u32 context Endian.Little (Int64.add data_offset 8L)
        and reserved =
          Parser_common.u32 context Endian.Little (Int64.add data_offset 12L)
        in
        let fields = ref [] in
        let add32 id label relative value constructor =
          match value with
          | None -> ()
          | Some value ->
              fields :=
                add_field context !fields ~parent:path ~id ~label
                  ~offset:(Int64.add data_offset relative) ~length:4L
                  (constructor value)
        in
        add32 "data_rva" "Data RVA" 0L data_rva (Value.address 32);
        add32 "size" "Data size" 4L size (Value.unsigned 32);
        add32 "code_page" "Code page" 8L code_page (Value.unsigned 32);
        add32 "reserved" "Reserved" 12L reserved (Value.unsigned 32);
        (match (data_rva, size) with
        | Some rva, Some size when not (Int64.equal size 0L) -> (
            match
              resolve_rva_range context sections ~header_size ~component
                ~span:(Span.unsafe ~start:data_offset ~length:4L) ~rva ~size
            with
            | None -> ()
            | Some payload_offset ->
                fields :=
                  add_field context !fields ~parent:path ~id:"file_offset"
                    ~label:"File offset" ~offset:data_offset ~length:4L
                    (Value.offset 64 payload_offset);
                let summary =
                  Option.value ~default:""
                    (Parser_common.hex context payload_offset (min size 16L))
                in
                (match
                   Parse_context.node context ~id:"payload"
                     ~path:(path ^ ".payload") ~label:"Resource payload"
                     ~span:(Span.unsafe ~start:payload_offset ~length:size)
                     ~value:(Value.Bytes { summary; length = size }) ()
                 with
                | None -> ()
                | Some node -> fields := node :: !fields))
        | _ -> ());
        let fields = List.rev !fields in
        Parse_context.node context ~id:"data" ~path ~label:"Resource data"
          ~span:(Span.unsafe ~start:data_offset ~length:16L)
          ~value:(Value.Collection (List.length fields)) ~children:fields ()
  in
  let root_span = Span.unsafe ~start:offset ~length:(min record.size 16L) in
  let root =
    parse_directory ~relative:0L ~depth:0 ~source_span:record.span
      ~path:(parent ^ ".resources.root") ~label:"Resource root"
  in
  Parse_context.node context ~id:"resources" ~path:(parent ^ ".resources")
    ~label:"Resources" ~span:root_span
    ~value:(Value.Collection (Option.fold ~none:0 ~some:(fun _ -> 1) root))
    ~children:(Option.to_list root) ()

let certificate_revisions = [ (0x100L, "Version 1.0"); (0x200L, "Version 2.0") ]

let certificate_types =
  [ (1L, "X.509");
    (2L, "PKCS signed data");
    (3L, "Reserved");
    (4L, "Terminal Server protocol stack")
  ]

let parse_certificates context record ~offset ~parent =
  let component = "pe.certificates" in
  if not (Int64.equal (Int64.rem offset 8L) 0L) then
    Parse_context.error context ~span:record.span
      ~code:"pe.certificate_table_misaligned"
      ~message:"The PE certificate table is not aligned to eight bytes."
      ~component ~recoverable:true ();
  let finish = Int64.add offset record.size in
  let cursor = ref offset and index = ref 0 and running = ref true in
  let nodes = ref [] in
  while !running && Int64.compare !cursor finish < 0 do
    let remaining = Int64.sub finish !cursor in
    if Int64.compare remaining 8L < 0 then (
      Parse_context.error context
        ~span:(Span.unsafe ~start:!cursor ~length:remaining)
        ~code:"pe.certificate_truncated_header"
        ~message:"The certificate table ends before a complete entry header."
        ~component ~recoverable:true ();
      running := false)
    else
      match consume_pe_entries context ~component 1L with
      | None -> running := false
      | Some _ -> (
          let length = Parser_common.u32 context Endian.Little !cursor
          and revision =
            Parser_common.u16 context Endian.Little (Int64.add !cursor 4L)
          and kind =
            Parser_common.u16 context Endian.Little (Int64.add !cursor 6L)
          in
          match (length, revision, kind) with
          | Some length, Some revision, Some kind
            when Int64.compare length 8L >= 0 -> (
              match Reader.align length 8L with
              | Error error ->
                  Parse_context.error_from_reader context ~component error;
                  running := false
              | Ok padded when Int64.compare padded remaining > 0 ->
                  Parse_context.error context ~span:record.span
                    ~code:"pe.certificate_out_of_table"
                    ~message:
                      "A certificate entry extends beyond the certificate \
                       table."
                    ~component ~recoverable:true ();
                  running := false
              | Ok padded ->
                  let entry_parent =
                    Printf.sprintf "%s.certificates[%d]" parent !index
                  in
                  let fields = ref [] in
                  fields :=
                    add_field context !fields ~parent:entry_parent ~id:"length"
                      ~label:"Length" ~offset:!cursor ~length:4L
                      (Value.unsigned 32 length);
                  fields :=
                    add_field context !fields ~parent:entry_parent
                      ~id:"revision" ~label:"Revision"
                      ~offset:(Int64.add !cursor 4L) ~length:2L
                      (Value.enum 16 revision
                         (Parser_common.enum_name certificate_revisions revision));
                  fields :=
                    add_field context !fields ~parent:entry_parent ~id:"type"
                      ~label:"Certificate type" ~offset:(Int64.add !cursor 6L)
                      ~length:2L
                      (Value.enum 16 kind
                         (Parser_common.enum_name certificate_types kind));
                  let payload_length = Int64.sub length 8L in
                  (if not (Int64.equal payload_length 0L) then
                     match
                       Parser_common.hex context (Int64.add !cursor 8L)
                         (min payload_length 16L)
                     with
                     | None -> ()
                     | Some summary ->
                         fields :=
                           add_field context !fields ~parent:entry_parent
                             ~id:"certificate" ~label:"Certificate bytes"
                             ~offset:(Int64.add !cursor 8L)
                             ~length:payload_length
                             (Value.Bytes { summary; length = payload_length }));
                  let children = List.rev !fields in
                  (match
                     Parse_context.node context
                       ~id:(Printf.sprintf "certificate[%d]" !index)
                       ~path:entry_parent
                       ~label:(Printf.sprintf "Certificate %d" !index)
                       ~span:(Span.unsafe ~start:!cursor ~length:padded)
                       ~value:(Value.Collection (List.length children))
                       ~children ()
                   with
                  | None -> ()
                  | Some node -> nodes := node :: !nodes);
                  cursor := Int64.add !cursor padded;
                  incr index)
          | Some _, Some _, Some _ ->
              Parse_context.error context ~span:record.span
                ~code:"pe.certificate_length_too_small"
                ~message:"A certificate entry is shorter than eight bytes."
                ~component ~recoverable:true ();
              running := false
          | _ -> running := false)
  done;
  let nodes = List.rev !nodes in
  Parse_context.node context ~id:"certificates" ~path:(parent ^ ".certificates")
    ~label:"Certificates"
    ~span:(Span.unsafe ~start:offset ~length:record.size)
    ~value:(Value.Collection (List.length nodes))
    ~children:nodes ()

let relocation_types =
  [ (0L, "Absolute");
    (1L, "High");
    (2L, "Low");
    (3L, "High-low");
    (4L, "High-adjust");
    (8L, "Machine-specific");
    (9L, "Machine-specific 16-bit");
    (10L, "64-bit")
  ]

let parse_base_relocations context record ~offset ~parent =
  let component = "pe.base_relocations" in
  let finish = Int64.add offset record.size in
  let cursor = ref offset and block_index = ref 0 and running = ref true in
  let blocks = ref [] in
  while !running && Int64.compare !cursor finish < 0 do
    let remaining = Int64.sub finish !cursor in
    if Int64.compare remaining 8L < 0 then (
      Parse_context.error context ~span:record.span
        ~code:"pe.relocation_truncated_block"
        ~message:
          "The base-relocation table ends before a complete block header."
        ~component ~recoverable:true ();
      running := false)
    else
      let page_rva = Parser_common.u32 context Endian.Little !cursor
      and block_size =
        Parser_common.u32 context Endian.Little (Int64.add !cursor 4L)
      in
      match (page_rva, block_size) with
      | Some page_rva, Some block_size
        when Int64.compare block_size 8L >= 0
             && Int64.compare block_size remaining <= 0 -> (
          let entry_bytes = Int64.sub block_size 8L in
          if not (Int64.equal (Int64.rem entry_bytes 2L) 0L) then (
            Parse_context.error context ~span:record.span
              ~code:"pe.relocation_odd_block_size"
              ~message:"A base-relocation block has an incomplete entry."
              ~component ~recoverable:true ();
            running := false)
          else
            match
              consume_pe_entries context ~component (Int64.div entry_bytes 2L)
            with
            | None -> running := false
            | Some count ->
                let block_parent =
                  Printf.sprintf "%s.base_relocation_blocks[%d]" parent
                    !block_index
                in
                let entries = ref [] in
                for index = 0 to count - 1 do
                  let entry_offset =
                    Int64.add !cursor (Int64.of_int (8 + (index * 2)))
                  in
                  match
                    Parser_common.u16 context Endian.Little entry_offset
                  with
                  | None -> ()
                  | Some raw -> (
                      let kind = Int64.shift_right_logical raw 12
                      and page_offset = Int64.logand raw 0xfffL in
                      let entry_parent =
                        Printf.sprintf "%s.entries[%d]" block_parent index
                      in
                      let fields = [] in
                      let fields =
                        add_field context fields ~parent:entry_parent ~id:"type"
                          ~label:"Type" ~offset:entry_offset ~length:2L
                          (Value.enum 4 kind
                             (Parser_common.enum_name relocation_types kind))
                      in
                      let fields =
                        add_field context fields ~parent:entry_parent
                          ~id:"page_offset" ~label:"Page offset"
                          ~offset:entry_offset ~length:2L
                          (Value.offset 12 page_offset)
                      in
                      match
                        Parse_context.node context
                          ~id:(Printf.sprintf "entry[%d]" index)
                          ~path:entry_parent
                          ~label:(Printf.sprintf "Relocation %d" index)
                          ~span:(Span.unsafe ~start:entry_offset ~length:2L)
                          ~value:(Value.Collection (List.length fields))
                          ~children:(List.rev fields) ()
                      with
                      | None -> ()
                      | Some node -> entries := node :: !entries)
                done;
                let header_fields = [] in
                let header_fields =
                  add_field context header_fields ~parent:block_parent
                    ~id:"page_rva" ~label:"Page RVA" ~offset:!cursor ~length:4L
                    (Value.address 32 page_rva)
                in
                let header_fields =
                  add_field context header_fields ~parent:block_parent
                    ~id:"block_size" ~label:"Block size"
                    ~offset:(Int64.add !cursor 4L) ~length:4L
                    (Value.unsigned 32 block_size)
                in
                let children = List.rev header_fields @ List.rev !entries in
                (match
                   Parse_context.node context
                     ~id:
                       (Printf.sprintf "base_relocation_block[%d]" !block_index)
                     ~path:block_parent
                     ~label:
                       (Printf.sprintf "Base-relocation block %d" !block_index)
                     ~span:(Span.unsafe ~start:!cursor ~length:block_size)
                     ~value:(Value.Collection (List.length children))
                     ~children ()
                 with
                | None -> ()
                | Some node -> blocks := node :: !blocks);
                cursor := Int64.add !cursor block_size;
                incr block_index)
      | Some _, Some _ ->
          Parse_context.error context ~span:record.span
            ~code:"pe.relocation_invalid_block_size"
            ~message:"A base-relocation block has an invalid size." ~component
            ~recoverable:true ();
          running := false
      | _ -> running := false
  done;
  let blocks = List.rev !blocks in
  Parse_context.node context ~id:"base_relocation_blocks"
    ~path:(parent ^ ".base_relocation_blocks")
    ~label:"Base relocations"
    ~span:(Span.unsafe ~start:offset ~length:record.size)
    ~value:(Value.Collection (List.length blocks))
    ~children:blocks ()

let debug_types =
  [ (0L, "Unknown");
    (1L, "COFF");
    (2L, "CodeView");
    (3L, "Frame pointer omission");
    (4L, "Miscellaneous");
    (9L, "Borland");
    (10L, "Reserved");
    (11L, "CLSID");
    (16L, "Reproducible")
  ]

let parse_debug_directories context record ~offset ~parent =
  let component = "pe.debug_directories" in
  if not (Int64.equal (Int64.rem record.size 28L) 0L) then
    Parse_context.error context ~span:record.span
      ~code:"pe.debug_directory_size"
      ~message:"The debug directory size is not a multiple of 28 bytes."
      ~component ~recoverable:true ();
  let count64 = Int64.div record.size 28L in
  match consume_pe_entries context ~component count64 with
  | None -> None
  | Some count ->
      let nodes = ref [] in
      for index = 0 to count - 1 do
        let base = Int64.add offset (Int64.of_int (index * 28)) in
        let entry_parent =
          Printf.sprintf "%s.debug_directories[%d]" parent index
        in
        let fields = ref [] in
        let add32 id label relative value =
          match value with
          | None -> ()
          | Some raw ->
              fields :=
                add_field context !fields ~parent:entry_parent ~id ~label
                  ~offset:(Int64.add base relative) ~length:4L
                  (Value.unsigned 32 raw)
        in
        add32 "characteristics" "Characteristics" 0L
          (Parser_common.u32 context Endian.Little base);
        add32 "timestamp" "Timestamp" 4L
          (Parser_common.u32 context Endian.Little (Int64.add base 4L));
        (match
           ( Parser_common.u16 context Endian.Little (Int64.add base 8L),
             Parser_common.u16 context Endian.Little (Int64.add base 10L) )
         with
        | Some major, Some minor ->
            fields :=
              add_field context !fields ~parent:entry_parent ~id:"major_version"
                ~label:"Major version" ~offset:(Int64.add base 8L) ~length:2L
                (Value.unsigned 16 major);
            fields :=
              add_field context !fields ~parent:entry_parent ~id:"minor_version"
                ~label:"Minor version" ~offset:(Int64.add base 10L) ~length:2L
                (Value.unsigned 16 minor)
        | _ -> ());
        (match Parser_common.u32 context Endian.Little (Int64.add base 12L) with
        | Some raw ->
            fields :=
              add_field context !fields ~parent:entry_parent ~id:"type"
                ~label:"Type" ~offset:(Int64.add base 12L) ~length:4L
                (Value.enum 32 raw (Parser_common.enum_name debug_types raw))
        | None -> ());
        let data_size =
          Parser_common.u32 context Endian.Little (Int64.add base 16L)
        and data_rva =
          Parser_common.u32 context Endian.Little (Int64.add base 20L)
        and data_offset =
          Parser_common.u32 context Endian.Little (Int64.add base 24L)
        in
        add32 "data_size" "Data size" 16L data_size;
        add32 "data_rva" "Data RVA" 20L data_rva;
        add32 "data_file_offset" "Data file offset" 24L data_offset;
        (match (data_size, data_offset) with
        | Some size, Some pointer
          when not (Int64.equal size 0L || Int64.equal pointer 0L) -> (
            match
              Reader.range context.Parse_context.reader ~offset:pointer
                ~length:size
            with
            | Ok () -> ()
            | Error _ ->
                Parse_context.error context
                  ~span:(Span.unsafe ~start:(Int64.add base 24L) ~length:4L)
                  ~code:"pe.debug_data_out_of_file"
                  ~message:"A debug record points outside the input." ~component
                  ~recoverable:true ())
        | _ -> ());
        let children = List.rev !fields in
        match
          Parse_context.node context
            ~id:(Printf.sprintf "debug_directory[%d]" index)
            ~path:entry_parent
            ~label:(Printf.sprintf "Debug directory %d" index)
            ~span:(Span.unsafe ~start:base ~length:28L)
            ~value:(Value.Collection (List.length children))
            ~children ()
        with
        | None -> ()
        | Some node -> nodes := node :: !nodes
      done;
      let nodes = List.rev !nodes in
      Parse_context.node context ~id:"debug_directories"
        ~path:(parent ^ ".debug_directories")
        ~label:"Debug directories"
        ~span:(Span.unsafe ~start:offset ~length:record.size)
        ~value:(Value.Collection (List.length nodes))
        ~children:nodes ()

let parse_mapped_directory context record sections ~header_size ~plus
    ~file_offset ~parent =
  match record.index with
  | 0 -> parse_exports context record sections ~header_size ~offset:file_offset ~parent
  | 1 ->
      parse_imports context record sections ~header_size ~plus
        ~offset:file_offset ~parent
  | 2 ->
      parse_resources context record sections ~header_size ~offset:file_offset
        ~parent
  | 4 -> parse_certificates context record ~offset:file_offset ~parent
  | 5 -> parse_base_relocations context record ~offset:file_offset ~parent
  | 6 -> parse_debug_directories context record ~offset:file_offset ~parent
  | _ -> None

let parse_directory_mappings context records sections ~header_size ~plus =
  let nodes = ref [] in
  let running = ref true in
  List.iter
    (fun record ->
      if
        !running && not (Int64.equal record.rva 0L || Int64.equal record.size 0L)
      then
        match
          Limits.consume_work context.Parse_context.tracker
            (1 + List.length sections)
        with
        | Error error ->
            Parse_context.error_from_reader context ~component:"pe.rva_mapping"
              error;
            running := false
        | Ok () -> (
            match
              map_directory context.Parse_context.reader sections ~header_size
                record
            with
            | [] ->
                Parse_context.error context ~span:record.span
                  ~code:"pe.directory_unmapped"
                  ~message:
                    "A PE data directory cannot be mapped to a complete file \
                     range."
                  ~component:"pe.rva_mapping" ~recoverable:true ()
            | _ :: _ :: _ ->
                Parse_context.error context ~span:record.span
                  ~code:"pe.directory_ambiguous"
                  ~message:
                    "A PE data directory maps through more than one section."
                  ~component:"pe.rva_mapping" ~recoverable:true ()
            | [ file_offset ] -> (
                let parent =
                  Printf.sprintf "pe.directory_mappings[%d]" record.index
                in
                let offset_node =
                  Parser_common.field context ~parent ~id:"file_offset"
                    ~label:"File offset" ~offset:(Span.start record.span)
                    ~length:4L
                    (Value.offset 64 file_offset)
                in
                let content =
                  parse_mapped_directory context record sections ~header_size
                    ~plus ~file_offset ~parent
                in
                let children =
                  Option.to_list offset_node @ Option.to_list content
                in
                let label =
                  if record.index < Array.length directory_names then
                    directory_names.(record.index)
                  else Printf.sprintf "Directory %d" record.index
                in
                match
                  Parse_context.node context
                    ~id:(Printf.sprintf "directory_mapping[%d]" record.index)
                    ~path:parent ~label:(label ^ " file range")
                    ~span:(Span.unsafe ~start:file_offset ~length:record.size)
                    ~value:(Value.Collection (List.length children))
                    ~children ()
                with
                | None -> ()
                | Some node -> nodes := node :: !nodes)))
    records;
  let nodes = List.rev !nodes in
  match records with
  | [] -> None
  | first :: _ ->
      let last = List.hd (List.rev records) in
      let start = Span.start first.span in
      let finish =
        match Span.end_offset last.span with
        | Ok value -> value
        | Error _ -> start
      in
      Parse_context.node context ~id:"directory_mappings"
        ~path:"pe.directory_mappings" ~label:"Mapped directory ranges"
        ~span:(Span.unsafe ~start ~length:(Int64.sub finish start))
        ~value:(Value.Collection (List.length nodes))
        ~children:nodes ()

let is_power_of_two value =
  Int64.compare value 0L > 0
  && Int64.equal (Int64.logand value (Int64.pred value)) 0L

let parse_data_directories context ~parent ~offset ~declared_size ~count
    ~size_of_image =
  let available_entries = max 0 (declared_size / 8) in
  let wanted = min count available_entries in
  let wanted = min wanted context.Parse_context.limits.max_table_entries in
  if count > wanted then
    Parse_context.warning context ~code:"pe.data_directories_limited"
      ~message:
        "The data-directory count exceeds the optional header or parser limit."
      ~component:"pe.data_directories" ();
  if wanted = 0 then None
  else
    match Limits.consume_table_entries context.Parse_context.tracker wanted with
    | Error error ->
        Parse_context.error_from_reader context ~component:"pe.data_directories"
          error;
        None
    | Ok () -> (
        match
          Reader.table_range context.Parse_context.reader ~offset ~entry_size:8L
            ~count:(Int64.of_int wanted)
        with
        | Error error ->
            Parse_context.error_from_reader context
              ~component:"pe.data_directories" error;
            None
        | Ok span ->
            let nodes = ref [] in
            for index = 0 to wanted - 1 do
              let base = Int64.add offset (Int64.of_int (index * 8)) in
              let path =
                Printf.sprintf "%s.data_directories[%d]" parent index
              in
              let rva = Parser_common.u32 context Endian.Little base in
              let size =
                Parser_common.u32 context Endian.Little (Int64.add base 4L)
              in
              let fields = [] in
              let fields =
                match rva with
                | None -> fields
                | Some value ->
                    add_field context fields ~parent:path ~id:"rva"
                      ~label:"Relative virtual address" ~offset:base ~length:4L
                      (Value.address 32 value)
              in
              let fields =
                match size with
                | None -> fields
                | Some value ->
                    add_field context fields ~parent:path ~id:"size"
                      ~label:"Size" ~offset:(Int64.add base 4L) ~length:4L
                      (Value.unsigned 32 value)
              in
              (match (rva, size, size_of_image) with
              | Some rva, Some size, Some image_size
                when (not (Int64.equal rva 0L)) && not (Int64.equal size 0L)
                -> (
                  match Reader.checked_add rva size with
                  | Ok finish when Int64.compare finish image_size <= 0 -> ()
                  | _ ->
                      Parse_context.warning context
                        ~code:"pe.data_directory_out_of_image"
                        ~message:
                          "A data directory extends beyond the declared image \
                           size."
                        ~component:"pe.data_directories" ())
              | _ -> ());
              let label =
                if index < Array.length directory_names then
                  directory_names.(index)
                else Printf.sprintf "Directory %d" index
              in
              match
                Parse_context.node context
                  ~id:(Printf.sprintf "data_directory[%d]" index)
                  ~path ~label:(label ^ " directory")
                  ~span:(Span.unsafe ~start:base ~length:8L)
                  ~value:(Value.Collection (List.length fields))
                  ~children:(List.rev fields) ()
              with
              | None -> ()
              | Some node -> nodes := node :: !nodes
            done;
            Parse_context.node context ~id:"data_directories"
              ~path:(parent ^ ".data_directories")
              ~label:"Data directories" ~span
              ~value:(Value.Collection (List.length !nodes))
              ~children:(List.rev !nodes) ())

let parse_sections context ~offset ~count =
  if count = 0 then None
  else
    match Limits.consume_table_entries context.Parse_context.tracker count with
    | Error error ->
        Parse_context.error_from_reader context ~component:"pe.sections" error;
        None
    | Ok () -> (
        match
          Reader.table_range context.Parse_context.reader ~offset
            ~entry_size:40L ~count:(Int64.of_int count)
        with
        | Error error ->
            Parse_context.error_from_reader context ~component:"pe.sections"
              error;
            None
        | Ok table_span ->
            let nodes = ref [] in
            for index = 0 to count - 1 do
              let base = Int64.add offset (Int64.of_int (index * 40)) in
              let path = Printf.sprintf "pe.sections[%d]" index in
              let name = Parser_common.string context base 8L
              and virtual_size =
                Parser_common.u32 context Endian.Little (Int64.add base 8L)
              and virtual_address =
                Parser_common.u32 context Endian.Little (Int64.add base 12L)
              and raw_size =
                Parser_common.u32 context Endian.Little (Int64.add base 16L)
              and raw_offset =
                Parser_common.u32 context Endian.Little (Int64.add base 20L)
              and characteristics =
                Parser_common.u32 context Endian.Little (Int64.add base 36L)
              in
              let safe_name = Option.map Sanitize.trimmed_text name in
              let fields = [] in
              let fields =
                match (name, safe_name) with
                | Some raw, Some text ->
                    add_field context fields ~parent:path ~id:"name"
                      ~label:"Name" ~offset:base ~length:8L
                      (Value.String
                         { text;
                           raw_hex =
                             Some
                               (String.to_seq raw
                               |> Seq.map (fun c ->
                                   Printf.sprintf "%02X" (Char.code c))
                               |> List.of_seq |> String.concat " ");
                           valid_utf8 = true
                         })
                | _ -> fields
              in
              let numeric id label relative value fields =
                match value with
                | None -> fields
                | Some value ->
                    add_field context fields ~parent:path ~id ~label
                      ~offset:(Int64.add base relative) ~length:4L
                      (Value.unsigned 32 value)
              in
              let fields =
                numeric "virtual_size" "Virtual size" 8L virtual_size fields
              in
              let fields =
                numeric "virtual_address" "Virtual address" 12L virtual_address
                  fields
              in
              let fields =
                numeric "raw_size" "Raw-data size" 16L raw_size fields
              in
              let fields =
                numeric "raw_offset" "Raw-data offset" 20L raw_offset fields
              in
              let fields =
                numeric "characteristics" "Characteristics" 36L characteristics
                  fields
              in
              (match (raw_offset, raw_size) with
              | Some raw_offset, Some raw_size
                when not (Int64.equal raw_size 0L) -> (
                  match
                    Reader.range context.Parse_context.reader ~offset:raw_offset
                      ~length:raw_size
                  with
                  | Ok () -> ()
                  | Error _ ->
                      Parse_context.warning context
                        ~code:"pe.section_raw_data_out_of_file"
                        ~message:
                          "A section raw-data range points outside the file."
                        ~component:"pe.sections" ())
              | _ -> ());
              let label =
                match safe_name with
                | Some name when not (String.equal name "") ->
                    Printf.sprintf "Section %d: %s" index name
                | _ -> Printf.sprintf "Section %d" index
              in
              match
                Parse_context.node context
                  ~id:(Printf.sprintf "section[%d]" index)
                  ~path ~label
                  ~span:(Span.unsafe ~start:base ~length:40L)
                  ~value:(Value.Collection (List.length fields))
                  ~children:(List.rev fields) ()
              with
              | None -> ()
              | Some node -> nodes := node :: !nodes
            done;
            Parse_context.node context ~id:"sections" ~path:"pe.sections"
              ~label:"Section table" ~span:table_span
              ~value:(Value.Collection (List.length !nodes))
              ~children:(List.rev !nodes) ())

let parse limits reader =
  let context = Parse_context.create ~reader ~source_format:id limits in
  let children = ref [] in
  let directory_spec = ref None
  and section_spec = ref None
  and mapped_header_size = ref None
  and mapped_plus = ref None in
  let add ~parent id label offset length value =
    children :=
      add_field context !children ~parent ~id ~label ~offset ~length value
  in
  (if Int64.compare (Reader.length reader) 2L >= 0 then
     match Parser_common.hex context 0L 2L with
     | Some hex ->
         add ~parent:"pe" "dos_magic" "DOS magic" 0L 2L
           (Value.Bytes { summary = hex; length = 2L })
     | None -> ());
  if not (has_mz reader) then
    Parse_context.error context ~code:"pe.invalid_mz_magic"
      ~message:"The input does not start with DOS MZ magic."
      ~component:"pe.dos_header" ~recoverable:false ();
  (if
     Parser_common.require_length context ~minimum:64L
       ~code:"pe.truncated_dos_header" ~component:"pe.dos_header"
   then
     match Parser_common.u32 context Endian.Little 0x3cL with
     | None -> ()
     | Some pe_offset -> (
         add ~parent:"pe" "e_lfanew" "PE header offset" 0x3cL 4L
           (Value.offset 32 pe_offset);
         match Reader.range reader ~offset:pe_offset ~length:24L with
         | Error error ->
             Parse_context.error_from_reader context ~component:"pe.signature"
               error
         | Ok () ->
             if not (has_signature reader pe_offset) then
               Parse_context.error context ~code:"pe.missing_signature"
                 ~message:"The PE signature is missing at e_lfanew."
                 ~component:"pe.signature" ~recoverable:false ()
             else (
               (match Parser_common.hex context pe_offset 4L with
               | Some hex ->
                   add ~parent:"pe" "signature" "PE signature" pe_offset 4L
                     (Value.Bytes { summary = hex; length = 4L })
               | None -> ());
               let coff = Int64.add pe_offset 4L in
               let machine = Parser_common.u16 context Endian.Little coff
               and section_count =
                 Parser_common.u16 context Endian.Little (Int64.add coff 2L)
               and timestamp =
                 Parser_common.u32 context Endian.Little (Int64.add coff 4L)
               and optional_size =
                 Parser_common.u16 context Endian.Little (Int64.add coff 16L)
               and characteristics =
                 Parser_common.u16 context Endian.Little (Int64.add coff 18L)
               in
               (match machine with
               | Some value ->
                   add ~parent:"pe.coff" "machine" "Machine" coff 2L
                     (Value.enum 16 value
                        (Parser_common.enum_name machine_names value))
               | None -> ());
               (match section_count with
               | Some value ->
                   add ~parent:"pe.coff" "section_count" "Section count"
                     (Int64.add coff 2L) 2L (Value.unsigned 16 value)
               | None -> ());
               (match timestamp with
               | Some value ->
                   add ~parent:"pe.coff" "timestamp" "Timestamp"
                     (Int64.add coff 4L) 4L (Value.unsigned 32 value)
               | None -> ());
               (match optional_size with
               | Some value ->
                   add ~parent:"pe.coff" "optional_header_size"
                     "Optional-header size" (Int64.add coff 16L) 2L
                     (Value.unsigned 16 value)
               | None -> ());
               (match characteristics with
               | Some value ->
                   add ~parent:"pe.coff" "characteristics" "Characteristics"
                     (Int64.add coff 18L) 2L (Value.unsigned 16 value)
               | None -> ());
               match (section_count, optional_size) with
               | Some section_count, Some optional_size -> (
                   let optional_offset = Int64.add coff 20L in
                   let optional_size_int = Int64.to_int optional_size in
                   (match
                      Reader.range reader ~offset:optional_offset
                        ~length:optional_size
                    with
                   | Error error ->
                       Parse_context.error_from_reader context
                         ~component:"pe.optional_header" error
                   | Ok () -> (
                       let magic =
                         Parser_common.u16 context Endian.Little optional_offset
                       in
                       (match magic with
                       | Some value ->
                           add ~parent:"pe.optional_header" "magic"
                             "Optional-header magic" optional_offset 2L
                             (Value.enum 16 value
                                (match value with
                                | 0x10bL -> Some "PE32"
                                | 0x20bL -> Some "PE32+"
                                | _ -> None))
                       | None -> ());
                       match magic with
                       | Some ((0x10bL | 0x20bL) as magic) -> (
                           let plus = Int64.equal magic 0x20bL in
                           mapped_plus := Some plus;
                           let minimum = if plus then 112 else 96 in
                           if optional_size_int < minimum then
                             Parse_context.error context
                               ~code:"pe.optional_header_too_small"
                               ~message:
                                 "The declared optional header is too small \
                                  for its magic."
                               ~component:"pe.optional_header" ~recoverable:true
                               ()
                           else
                             let entry_point =
                               Parser_common.u32 context Endian.Little
                                 (Int64.add optional_offset 16L)
                             in
                             let image_base =
                               if plus then
                                 Parser_common.u64 context Endian.Little
                                   (Int64.add optional_offset 24L)
                               else
                                 Parser_common.u32 context Endian.Little
                                   (Int64.add optional_offset 28L)
                             in
                             let section_alignment =
                               Parser_common.u32 context Endian.Little
                                 (Int64.add optional_offset 32L)
                             and file_alignment =
                               Parser_common.u32 context Endian.Little
                                 (Int64.add optional_offset 36L)
                             and size_of_image =
                               Parser_common.u32 context Endian.Little
                                 (Int64.add optional_offset 56L)
                             and size_of_headers =
                               Parser_common.u32 context Endian.Little
                                 (Int64.add optional_offset 60L)
                             and subsystem =
                               Parser_common.u16 context Endian.Little
                                 (Int64.add optional_offset 68L)
                             and dll_characteristics =
                               Parser_common.u16 context Endian.Little
                                 (Int64.add optional_offset 70L)
                             and directory_count =
                               Parser_common.u32 context Endian.Little
                                 (Int64.add optional_offset
                                    (if plus then 108L else 92L))
                             in
                             mapped_header_size := size_of_headers;
                             (match entry_point with
                             | Some value ->
                                 add ~parent:"pe.optional_header" "entry_point"
                                   "Entry point RVA"
                                   (Int64.add optional_offset 16L)
                                   4L (Value.address 32 value)
                             | None -> ());
                             let image_width = if plus then 64 else 32 in
                             let image_length = if plus then 8L else 4L in
                             let image_offset =
                               Int64.add optional_offset
                                 (if plus then 24L else 28L)
                             in
                             (match image_base with
                             | Some value ->
                                 add ~parent:"pe.optional_header" "image_base"
                                   "Image base" image_offset image_length
                                   (Value.address image_width value)
                             | None -> ());
                             let add32 id label relative value =
                               match value with
                               | Some value ->
                                   add ~parent:"pe.optional_header" id label
                                     (Int64.add optional_offset relative)
                                     4L (Value.unsigned 32 value)
                               | None -> ()
                             in
                             add32 "section_alignment" "Section alignment" 32L
                               section_alignment;
                             add32 "file_alignment" "File alignment" 36L
                               file_alignment;
                             add32 "image_size" "Image size" 56L size_of_image;
                             add32 "header_size" "Header size" 60L
                               size_of_headers;
                             (match subsystem with
                             | Some value ->
                                 add ~parent:"pe.optional_header" "subsystem"
                                   "Subsystem"
                                   (Int64.add optional_offset 68L)
                                   2L
                                   (Value.enum 16 value
                                      (Parser_common.enum_name subsystem_names
                                         value))
                             | None -> ());
                             (match dll_characteristics with
                             | Some value ->
                                 add ~parent:"pe.optional_header"
                                   "dll_characteristics" "DLL characteristics"
                                   (Int64.add optional_offset 70L)
                                   2L (Value.unsigned 16 value)
                             | None -> ());
                             (match directory_count with
                             | Some value ->
                                 add ~parent:"pe.optional_header"
                                   "data_directory_count" "Data-directory count"
                                   (Int64.add optional_offset
                                      (if plus then 108L else 92L))
                                   4L (Value.unsigned 32 value)
                             | None -> ());
                             (match (section_alignment, file_alignment) with
                             | Some section, Some file ->
                                 if
                                   not
                                     (is_power_of_two section
                                    && is_power_of_two file)
                                 then
                                   Parse_context.warning context
                                     ~code:"pe.invalid_alignment"
                                     ~message:
                                       "PE file and section alignments should \
                                        be powers of two."
                                     ~component:"pe.optional_header" ();
                                 if Int64.compare section file < 0 then
                                   Parse_context.warning context
                                     ~code:"pe.section_alignment_too_small"
                                     ~message:
                                       "Section alignment is smaller than file \
                                        alignment."
                                     ~component:"pe.optional_header" ()
                             | _ -> ());
                             match directory_count with
                             | Some count -> (
                                 let count =
                                   if
                                     Int64.compare count (Int64.of_int max_int)
                                     > 0
                                   then max_int
                                   else Int64.to_int count
                                 in
                                 let directory_offset =
                                   Int64.add optional_offset
                                     (if plus then 112L else 96L)
                                 in
                                 let declared_size =
                                   optional_size_int - minimum
                                 in
                                 directory_spec :=
                                   Some (directory_offset, declared_size, count);
                                 match
                                   parse_data_directories context
                                     ~parent:"pe.optional_header"
                                     ~offset:directory_offset ~declared_size
                                     ~count ~size_of_image
                                 with
                                 | Some node -> children := node :: !children
                                 | None -> ())
                             | None -> ())
                       | Some _ ->
                           Parse_context.error context
                             ~code:"pe.unsupported_optional_magic"
                             ~message:
                               "The optional-header magic is not PE32 or PE32+."
                             ~component:"pe.optional_header" ~recoverable:true
                             ()
                       | None -> ()));
                   let section_table =
                     Int64.add optional_offset optional_size
                   in
                   let count = Int64.to_int section_count in
                   section_spec := Some (section_table, count);
                   match
                     parse_sections context ~offset:section_table ~count
                   with
                   | Some node -> children := node :: !children
                   | None -> ())
               | _ -> ())));
  (match
     (!directory_spec, !section_spec, !mapped_header_size, !mapped_plus)
   with
  | ( Some (directory_offset, declared_size, directory_count),
      Some (section_offset, section_count),
      Some header_size,
      Some plus ) -> (
      let records =
        collect_directories reader ~offset:directory_offset ~declared_size
          ~count:directory_count
          ~maximum:context.Parse_context.limits.max_table_entries
      in
      let sections =
        collect_section_map reader ~offset:section_offset ~count:section_count
          ~maximum:context.Parse_context.limits.max_table_entries
      in
      match
        parse_directory_mappings context records sections ~header_size ~plus
      with
      | Some node -> children := node :: !children
      | None -> ())
  | _ -> ());
  let root =
    Parse_context.node context ~id:"pe" ~path:"pe" ~label:"Portable Executable"
      ~span:(Parser_common.root_span reader 64L)
      ~value:(Value.Collection (List.length !children))
      ~children:(List.rev !children)
      ~diagnostics:(Parse_context.diagnostics context)
      ()
  in
  Parse_context.result context root

let parser =
  { Format.id;
    display_name;
    extensions = [ ".exe"; ".dll"; ".sys"; ".obj" ];
    coverage;
    detect;
    parse
  }
