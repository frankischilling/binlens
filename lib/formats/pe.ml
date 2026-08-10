let id = "pe"
let display_name = "Portable Executable"

let coverage =
  { Format.summary =
      "DOS header, PE signature, COFF header, PE32 and PE32+ optional headers, \
       basic data directories, and section table";
    supported =
      [ "DOS MZ header and e_lfanew";
        "COFF file header";
        "PE32 and PE32+ core optional-header fields";
        "basic data-directory ranges";
        "section headers and raw-data ranges"
      ];
    unsupported =
      [ "import table contents";
        "resource tree contents";
        "base relocations";
        "debug directory contents";
        "complete RVA mapping"
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

let section_mapping reader section ~rva ~size =
  if Int64.compare rva section.virtual_address < 0 then None
  else
    let relative = Int64.sub rva section.virtual_address in
    let virtual_length = max section.virtual_size section.raw_size in
    match
      ( Reader.checked_add relative size,
        Reader.checked_add section.raw_offset relative )
    with
    | Ok relative_end, Ok file_offset
      when Int64.compare relative_end virtual_length <= 0
           && Int64.compare relative_end section.raw_size <= 0 -> (
        match Reader.range reader ~offset:file_offset ~length:size with
        | Ok () -> Some file_offset
        | Error _ -> None)
    | _ -> None

let map_directory reader sections ~header_size record =
  if record.index = 4 then
    match Reader.range reader ~offset:record.rva ~length:record.size with
    | Ok () -> [ record.rva ]
    | Error _ -> []
  else
    let header =
      match Reader.checked_add record.rva record.size with
      | Ok finish
        when Int64.compare finish header_size <= 0
             && Reader.range reader ~offset:record.rva ~length:record.size
                = Ok () ->
          [ record.rva ]
      | _ -> []
    in
    header
    @ List.filter_map
        (fun section ->
          section_mapping reader section ~rva:record.rva ~size:record.size)
        sections

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

let parse_mapped_directory context record ~file_offset ~parent =
  match record.index with
  | 4 -> parse_certificates context record ~offset:file_offset ~parent
  | 5 -> parse_base_relocations context record ~offset:file_offset ~parent
  | 6 -> parse_debug_directories context record ~offset:file_offset ~parent
  | _ -> None

let parse_directory_mappings context records sections ~header_size =
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
                  parse_mapped_directory context record ~file_offset ~parent
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
  and mapped_header_size = ref None in
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
  (match (!directory_spec, !section_spec, !mapped_header_size) with
  | ( Some (directory_offset, declared_size, directory_count),
      Some (section_offset, section_count),
      Some header_size ) -> (
      let records =
        collect_directories reader ~offset:directory_offset ~declared_size
          ~count:directory_count
          ~maximum:context.Parse_context.limits.max_table_entries
      in
      let sections =
        collect_section_map reader ~offset:section_offset ~count:section_count
          ~maximum:context.Parse_context.limits.max_table_entries
      in
      match parse_directory_mappings context records sections ~header_size with
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
