let id = "elf"
let display_name = "Executable and Linkable Format"

let coverage =
  { Format.summary =
      "ELF32 and ELF64 headers, program headers, section headers, and section \
       names";
    supported =
      [ "ELF identification";
        "ELF32 and ELF64 main headers";
        "little-endian and big-endian files";
        "program header tables";
        "section header tables";
        "section names from the section-name string table";
        "basic file-range validation"
      ];
    unsupported =
      [ "extended section numbering";
        "dynamic linking semantics";
        "relocations and symbols";
        "DWARF";
        "architecture-specific flag decoding"
      ]
  }

let magic reader =
  match
    ( Reader.byte reader 0L,
      Reader.byte reader 1L,
      Reader.byte reader 2L,
      Reader.byte reader 3L )
  with
  | Ok 0x7f, Ok 0x45, Ok 0x4c, Ok 0x46 -> true
  | _ -> false

let detect _limits reader =
  if magic reader then
    { Format.format_id = id;
      display_name;
      confidence = 100;
      evidence = [ "ELF magic 7F 45 4C 46 at offset 0" ];
      contradictions = [];
      required_minimum_length = 16L;
      definitive = true
    }
  else
    Format.no_detection ~format_id:id ~display_name ~required_minimum_length:16L

let object_types =
  [ (0L, "None");
    (1L, "Relocatable");
    (2L, "Executable");
    (3L, "Shared object");
    (4L, "Core")
  ]

let machines =
  [ (0L, "None");
    (3L, "Intel 80386");
    (8L, "MIPS");
    (20L, "PowerPC");
    (40L, "ARM");
    (62L, "x86-64");
    (183L, "AArch64");
    (243L, "RISC-V")
  ]

let program_types =
  [ (0L, "Null");
    (1L, "Load");
    (2L, "Dynamic");
    (3L, "Interpreter");
    (4L, "Note");
    (6L, "Program header table");
    (7L, "TLS")
  ]

let section_types =
  [ (0L, "Null");
    (1L, "Program data");
    (2L, "Symbol table");
    (3L, "String table");
    (4L, "Rela relocations");
    (7L, "Note");
    (8L, "No bits");
    (9L, "Rel relocations");
    (11L, "Dynamic symbols")
  ]

let add_field context children ?description ?metadata ~parent ~id ~label ~offset
    ~length value =
  match
    Parser_common.field context ?description ?metadata ~parent ~id ~label
      ~offset ~length value
  with
  | None -> children
  | Some node -> node :: children

let parse_program_headers context ~class_ ~endian ~table_offset ~entry_size
    ~count =
  if count = 0 then None
  else
    let expected = if class_ = 1 then 32 else 56 in
    if entry_size < expected then (
      Parse_context.error context ~code:"elf.program_entry_too_small"
        ~message:"The ELF program-header entry size is smaller than required."
        ~component:"elf.program_headers" ~recoverable:true ();
      None)
    else
      match
        Limits.consume_table_entries context.Parse_context.tracker count
      with
      | Error error ->
          Parse_context.error_from_reader context
            ~component:"elf.program_headers" error;
          None
      | Ok () -> (
          match
            Reader.table_range context.Parse_context.reader ~offset:table_offset
              ~entry_size:(Int64.of_int entry_size) ~count:(Int64.of_int count)
          with
          | Error error ->
              Parse_context.error_from_reader context
                ~component:"elf.program_headers" error;
              None
          | Ok table_span ->
              let entries = ref [] in
              for index = 0 to count - 1 do
                let base =
                  Int64.add table_offset (Int64.of_int (index * entry_size))
                in
                let parent = Printf.sprintf "elf.program_headers[%d]" index in
                let read32 relative =
                  Parser_common.u32 context endian (Int64.add base relative)
                in
                let read64 relative =
                  Parser_common.u64 context endian (Int64.add base relative)
                in
                let fields, file_offset, file_size =
                  if class_ = 1 then
                    let p_type = read32 0L
                    and p_offset = read32 4L
                    and p_vaddr = read32 8L
                    and p_paddr = read32 12L
                    and p_filesz = read32 16L
                    and p_memsz = read32 20L
                    and p_flags = read32 24L
                    and p_align = read32 28L in
                    let fields = [] in
                    let fields =
                      match p_type with
                      | None -> fields
                      | Some value ->
                          add_field context fields ~parent ~id:"type"
                            ~label:"Type" ~offset:base ~length:4L
                            (Value.enum 32 value
                               (Parser_common.enum_name program_types value))
                    in
                    let numeric id label relative value fields =
                      match value with
                      | None -> fields
                      | Some value ->
                          add_field context fields ~parent ~id ~label
                            ~offset:(Int64.add base relative) ~length:4L
                            (Value.unsigned 32 value)
                    in
                    let fields =
                      numeric "offset" "File offset" 4L p_offset fields
                    in
                    let fields =
                      numeric "virtual_address" "Virtual address" 8L p_vaddr
                        fields
                    in
                    let fields =
                      numeric "physical_address" "Physical address" 12L p_paddr
                        fields
                    in
                    let fields =
                      numeric "file_size" "File size" 16L p_filesz fields
                    in
                    let fields =
                      numeric "memory_size" "Memory size" 20L p_memsz fields
                    in
                    let fields = numeric "flags" "Flags" 24L p_flags fields in
                    let fields =
                      numeric "alignment" "Alignment" 28L p_align fields
                    in
                    (fields, p_offset, p_filesz)
                  else
                    let p_type = read32 0L
                    and p_flags = read32 4L
                    and p_offset = read64 8L
                    and p_vaddr = read64 16L
                    and p_paddr = read64 24L
                    and p_filesz = read64 32L
                    and p_memsz = read64 40L
                    and p_align = read64 48L in
                    let fields = [] in
                    let fields =
                      match p_type with
                      | None -> fields
                      | Some value ->
                          add_field context fields ~parent ~id:"type"
                            ~label:"Type" ~offset:base ~length:4L
                            (Value.enum 32 value
                               (Parser_common.enum_name program_types value))
                    in
                    let fields =
                      match p_flags with
                      | None -> fields
                      | Some value ->
                          add_field context fields ~parent ~id:"flags"
                            ~label:"Flags" ~offset:(Int64.add base 4L)
                            ~length:4L (Value.unsigned 32 value)
                    in
                    let numeric id label relative value fields =
                      match value with
                      | None -> fields
                      | Some value ->
                          add_field context fields ~parent ~id ~label
                            ~offset:(Int64.add base relative) ~length:8L
                            (Value.unsigned 64 value)
                    in
                    let fields =
                      numeric "offset" "File offset" 8L p_offset fields
                    in
                    let fields =
                      numeric "virtual_address" "Virtual address" 16L p_vaddr
                        fields
                    in
                    let fields =
                      numeric "physical_address" "Physical address" 24L p_paddr
                        fields
                    in
                    let fields =
                      numeric "file_size" "File size" 32L p_filesz fields
                    in
                    let fields =
                      numeric "memory_size" "Memory size" 40L p_memsz fields
                    in
                    let fields =
                      numeric "alignment" "Alignment" 48L p_align fields
                    in
                    (fields, p_offset, p_filesz)
                in
                (match (file_offset, file_size) with
                | Some offset, Some length when not (Int64.equal length 0L) -> (
                    match
                      Reader.range context.Parse_context.reader ~offset ~length
                    with
                    | Ok () -> ()
                    | Error _ ->
                        Parse_context.warning context
                          ~code:"elf.segment_out_of_file"
                          ~message:"A program segment points outside the file."
                          ~component:"elf.program_headers" ())
                | _ -> ());
                let entry_span =
                  Span.unsafe ~start:base ~length:(Int64.of_int entry_size)
                in
                match
                  Parse_context.node context
                    ~id:(Printf.sprintf "program_header[%d]" index)
                    ~path:parent
                    ~label:(Printf.sprintf "Program header %d" index)
                    ~span:entry_span
                    ~value:(Value.Collection (List.length fields))
                    ~children:(List.rev fields) ()
                with
                | None -> ()
                | Some node -> entries := node :: !entries
              done;
              Parse_context.node context ~id:"program_headers"
                ~path:"elf.program_headers" ~label:"Program header table"
                ~span:table_span
                ~value:(Value.Collection (List.length !entries))
                ~children:(List.rev !entries) ())

type section_info =
  { index : int;
    parent : string;
    span : Span.t;
    children : Node.t list;
    name_offset : int64 option;
    section_type : int64 option;
    file_offset : int64 option;
    file_size : int64 option
  }

let parse_section_headers context ~class_ ~endian ~table_offset ~entry_size
    ~count ~string_index =
  if count = 0 then None
  else
    let expected = if class_ = 1 then 40 else 64 in
    if entry_size < expected then (
      Parse_context.error context ~code:"elf.section_entry_too_small"
        ~message:"The ELF section-header entry size is smaller than required."
        ~component:"elf.section_headers" ~recoverable:true ();
      None)
    else
      match
        Limits.consume_table_entries context.Parse_context.tracker count
      with
      | Error error ->
          Parse_context.error_from_reader context
            ~component:"elf.section_headers" error;
          None
      | Ok () -> (
          match
            Reader.table_range context.Parse_context.reader ~offset:table_offset
              ~entry_size:(Int64.of_int entry_size) ~count:(Int64.of_int count)
          with
          | Error error ->
              Parse_context.error_from_reader context
                ~component:"elf.section_headers" error;
              None
          | Ok table_span ->
              let infos = ref [] in
              for index = 0 to count - 1 do
                let base =
                  Int64.add table_offset (Int64.of_int (index * entry_size))
                in
                let parent = Printf.sprintf "elf.section_headers[%d]" index in
                let read32 relative =
                  Parser_common.u32 context endian (Int64.add base relative)
                in
                let read64 relative =
                  Parser_common.u64 context endian (Int64.add base relative)
                in
                let name = read32 0L and section_type = read32 4L in
                let ( flags,
                      address,
                      file_offset,
                      file_size,
                      link,
                      info,
                      alignment,
                      element_size ) =
                  if class_ = 1 then
                    ( read32 8L,
                      read32 12L,
                      read32 16L,
                      read32 20L,
                      read32 24L,
                      read32 28L,
                      read32 32L,
                      read32 36L )
                  else
                    ( read64 8L,
                      read64 16L,
                      read64 24L,
                      read64 32L,
                      read32 40L,
                      read32 44L,
                      read64 48L,
                      read64 56L )
                in
                let fields = [] in
                let fields =
                  match name with
                  | None -> fields
                  | Some value ->
                      add_field context fields ~parent ~id:"name_offset"
                        ~label:"Name offset" ~offset:base ~length:4L
                        (Value.offset 32 value)
                in
                let fields =
                  match section_type with
                  | None -> fields
                  | Some value ->
                      add_field context fields ~parent ~id:"type" ~label:"Type"
                        ~offset:(Int64.add base 4L) ~length:4L
                        (Value.enum 32 value
                           (Parser_common.enum_name section_types value))
                in
                let numeric width id label relative value fields =
                  match value with
                  | None -> fields
                  | Some value ->
                      add_field context fields ~parent ~id ~label
                        ~offset:(Int64.add base relative)
                        ~length:(Int64.of_int (width / 8))
                        (Value.unsigned width value)
                in
                let word = if class_ = 1 then 32 else 64 in
                let fields = numeric word "flags" "Flags" 8L flags fields in
                let fields =
                  numeric word "address" "Address"
                    (if class_ = 1 then 12L else 16L)
                    address fields
                in
                let fields =
                  numeric word "offset" "File offset"
                    (if class_ = 1 then 16L else 24L)
                    file_offset fields
                in
                let fields =
                  numeric word "size" "Size"
                    (if class_ = 1 then 20L else 32L)
                    file_size fields
                in
                let fields =
                  numeric 32 "link" "Link"
                    (if class_ = 1 then 24L else 40L)
                    link fields
                in
                let fields =
                  numeric 32 "info" "Information"
                    (if class_ = 1 then 28L else 44L)
                    info fields
                in
                let fields =
                  numeric word "alignment" "Alignment"
                    (if class_ = 1 then 32L else 48L)
                    alignment fields
                in
                let fields =
                  numeric word "entry_size" "Entry size"
                    (if class_ = 1 then 36L else 56L)
                    element_size fields
                in
                (match (section_type, file_offset, file_size) with
                | Some kind, Some offset, Some length
                  when (not (Int64.equal kind 8L))
                       && not (Int64.equal length 0L) -> (
                    match
                      Reader.range context.Parse_context.reader ~offset ~length
                    with
                    | Ok () -> ()
                    | Error _ ->
                        Parse_context.warning context
                          ~code:"elf.section_out_of_file"
                          ~message:"A section points outside the file."
                          ~component:"elf.section_headers" ())
                | _ -> ());
                infos :=
                  { index;
                    parent;
                    span =
                      Span.unsafe ~start:base ~length:(Int64.of_int entry_size);
                    children = List.rev fields;
                    name_offset = name;
                    section_type;
                    file_offset;
                    file_size
                  }
                  :: !infos
              done;
              let infos = List.rev !infos in
              let string_table =
                if string_index < 0 || string_index >= count then (
                  Parse_context.warning context
                    ~code:"elf.invalid_string_table_index"
                    ~message:
                      "The section-name string-table index is outside the \
                       section table."
                    ~component:"elf.section_headers" ();
                  None)
                else
                  let entry = List.nth infos string_index in
                  match (entry.file_offset, entry.file_size) with
                  | Some offset, Some length -> (
                      match
                        Reader.range context.Parse_context.reader ~offset
                          ~length
                      with
                      | Ok () -> Some (offset, length)
                      | Error _ ->
                          Parse_context.warning context
                            ~code:"elf.string_table_out_of_file"
                            ~message:
                              "The section-name string table points outside \
                               the file."
                            ~component:"elf.section_headers" ();
                          None)
                  | _ -> None
              in
              let nodes =
                infos
                |> List.filter_map (fun entry ->
                    let resolved_name, name_node =
                      match (string_table, entry.name_offset) with
                      | Some (table_offset, table_length), Some name_offset
                        when Int64.compare name_offset table_length < 0 -> (
                          let absolute = Int64.add table_offset name_offset in
                          let remaining = Int64.sub table_length name_offset in
                          let maximum =
                            min context.Parse_context.limits.max_string_bytes
                              (Int64.to_int
                                 (min remaining (Int64.of_int max_int)))
                          in
                          match
                            Reader.c_string
                              ~tracker:context.Parse_context.tracker
                              context.Parse_context.reader ~offset:absolute
                              ~max_length:maximum
                          with
                          | Error error ->
                              Parse_context.error_from_reader context
                                ~component:"elf.section_names" error;
                              (None, None)
                          | Ok name ->
                              let safe = Sanitize.text name in
                              let node =
                                Parser_common.field context ~parent:entry.parent
                                  ~id:"name" ~label:"Name" ~offset:absolute
                                  ~length:(Int64.of_int (String.length name))
                                  (Value.String
                                     { text = safe;
                                       raw_hex = None;
                                       valid_utf8 = true
                                     })
                              in
                              (Some safe, node))
                      | Some _, Some _ ->
                          Parse_context.warning context
                            ~code:"elf.section_name_out_of_table"
                            ~message:
                              "A section-name offset is outside the string \
                               table."
                            ~component:"elf.section_names" ();
                          (None, None)
                      | _ -> (None, None)
                    in
                    let children =
                      match name_node with
                      | None -> entry.children
                      | Some node -> node :: entry.children
                    in
                    let label =
                      match resolved_name with
                      | Some name when not (String.equal name "") ->
                          Printf.sprintf "Section header %d: %s" entry.index
                            name
                      | _ -> Printf.sprintf "Section header %d" entry.index
                    in
                    Parse_context.node context
                      ~id:(Printf.sprintf "section_header[%d]" entry.index)
                      ~path:entry.parent ~label ~span:entry.span
                      ~value:(Value.Collection (List.length children))
                      ~children ())
              in
              Parse_context.node context ~id:"section_headers"
                ~path:"elf.section_headers" ~label:"Section header table"
                ~span:table_span
                ~value:(Value.Collection (List.length nodes))
                ~children:nodes ())

let parse limits reader =
  let context = Parse_context.create ~reader ~source_format:id limits in
  let root_path = "elf" in
  let identification = ref [] in
  let add_ident id label offset length value =
    identification :=
      add_field context !identification ~parent:root_path ~id ~label ~offset
        ~length value
  in
  (if Int64.compare (Reader.length reader) 4L >= 0 then
     match Parser_common.hex context 0L 4L with
     | Some value ->
         add_ident "magic" "Magic" 0L 4L
           (Value.Bytes { summary = value; length = 4L })
     | None -> ());
  if not (magic reader) then
    Parse_context.error context ~code:"elf.invalid_magic"
      ~message:"The input does not start with ELF magic."
      ~component:"elf.identification" ~recoverable:false ();
  let class_ =
    if Int64.compare (Reader.length reader) 5L >= 0 then
      Parser_common.u8 context 4L
    else None
  in
  let data =
    if Int64.compare (Reader.length reader) 6L >= 0 then
      Parser_common.u8 context 5L
    else None
  in
  (match class_ with
  | Some value ->
      add_ident "class" "Class" 4L 1L
        (Value.enum 8 value
           (match value with
           | 1L -> Some "ELF32"
           | 2L -> Some "ELF64"
           | _ -> None))
  | None -> ());
  (match data with
  | Some value ->
      add_ident "endianness" "Endianness" 5L 1L
        (Value.enum 8 value
           (match value with
           | 1L -> Some "Little endian"
           | 2L -> Some "Big endian"
           | _ -> None))
  | None -> ());
  let class_value =
    match class_ with
    | Some ((1L | 2L) as value) -> Some (Int64.to_int value)
    | _ -> None
  in
  let endian =
    match data with
    | Some 1L -> Some Endian.Little
    | Some 2L -> Some Endian.Big
    | _ -> None
  in
  if class_value = None && class_ <> None then
    Parse_context.error context ~code:"elf.unsupported_class"
      ~message:"The ELF class marker is not ELF32 or ELF64."
      ~component:"elf.identification" ~recoverable:false ();
  if endian = None && data <> None then
    Parse_context.error context ~code:"elf.unsupported_encoding"
      ~message:"The ELF data encoding is not little endian or big endian."
      ~component:"elf.identification" ~recoverable:false ();
  let children = ref !identification in
  (match (class_value, endian) with
  | Some class_, Some endian ->
      let required = if class_ = 1 then 52L else 64L in
      if
        Parser_common.require_length context ~minimum:required
          ~code:"elf.truncated_header" ~component:"elf.header"
      then (
        let read16 offset = Parser_common.u16 context endian offset
        and read32 offset = Parser_common.u32 context endian offset
        and read_word offset =
          if class_ = 1 then Parser_common.u32 context endian offset
          else Parser_common.u64 context endian offset
        in
        let type_ = read16 16L
        and machine = read16 18L
        and version = read32 20L
        and entry = read_word 24L
        and program_offset = read_word (if class_ = 1 then 28L else 32L)
        and section_offset = read_word (if class_ = 1 then 32L else 40L)
        and flags = read32 (if class_ = 1 then 36L else 48L)
        and header_size = read16 (if class_ = 1 then 40L else 52L)
        and program_entry_size = read16 (if class_ = 1 then 42L else 54L)
        and program_count = read16 (if class_ = 1 then 44L else 56L)
        and section_entry_size = read16 (if class_ = 1 then 46L else 58L)
        and section_count = read16 (if class_ = 1 then 48L else 60L)
        and string_index = read16 (if class_ = 1 then 50L else 62L) in
        let add id label offset length value =
          children :=
            add_field context !children ~parent:root_path ~id ~label ~offset
              ~length value
        in
        (match type_ with
        | Some value ->
            add "type" "Object type" 16L 2L
              (Value.enum 16 value (Parser_common.enum_name object_types value))
        | None -> ());
        (match machine with
        | Some value ->
            add "machine" "Machine" 18L 2L
              (Value.enum 16 value (Parser_common.enum_name machines value))
        | None -> ());
        (match version with
        | Some value -> add "version" "Version" 20L 4L (Value.unsigned 32 value)
        | None -> ());
        let word_width = if class_ = 1 then 32 else 64 in
        let word_length = if class_ = 1 then 4L else 8L in
        (match entry with
        | Some value ->
            add "entry_point" "Entry point" 24L word_length
              (Value.address word_width value)
        | None -> ());
        let program_offset_field = if class_ = 1 then 28L else 32L in
        let section_offset_field = if class_ = 1 then 32L else 40L in
        (match program_offset with
        | Some value ->
            add "program_header_offset" "Program-header offset"
              program_offset_field word_length
              (Value.offset word_width value)
        | None -> ());
        (match section_offset with
        | Some value ->
            add "section_header_offset" "Section-header offset"
              section_offset_field word_length
              (Value.offset word_width value)
        | None -> ());
        (match flags with
        | Some value ->
            add "flags" "Flags"
              (if class_ = 1 then 36L else 48L)
              4L (Value.unsigned 32 value)
        | None -> ());
        let add16 id label offset value =
          match value with
          | Some value -> add id label offset 2L (Value.unsigned 16 value)
          | None -> ()
        in
        add16 "header_size" "ELF header size"
          (if class_ = 1 then 40L else 52L)
          header_size;
        add16 "program_header_entry_size" "Program-header entry size"
          (if class_ = 1 then 42L else 54L)
          program_entry_size;
        add16 "program_header_count" "Program-header count"
          (if class_ = 1 then 44L else 56L)
          program_count;
        add16 "section_header_entry_size" "Section-header entry size"
          (if class_ = 1 then 46L else 58L)
          section_entry_size;
        add16 "section_header_count" "Section-header count"
          (if class_ = 1 then 48L else 60L)
          section_count;
        add16 "section_name_string_table_index"
          "Section-name string-table index"
          (if class_ = 1 then 50L else 62L)
          string_index;
        (match header_size with
        | Some size when Int64.compare size required < 0 ->
            Parse_context.warning context ~code:"elf.header_size_too_small"
              ~message:
                "The declared ELF header size is smaller than the required \
                 header."
              ~component:"elf.header" ()
        | _ -> ());
        (match (program_offset, program_entry_size, program_count) with
        | Some offset, Some size, Some count -> (
            let node =
              parse_program_headers context ~class_ ~endian ~table_offset:offset
                ~entry_size:(Int64.to_int size) ~count:(Int64.to_int count)
            in
            match node with
            | Some node -> children := node :: !children
            | None -> ())
        | _ -> ());
        match
          (section_offset, section_entry_size, section_count, string_index)
        with
        | Some offset, Some size, Some count, Some index -> (
            let node =
              parse_section_headers context ~class_ ~endian ~table_offset:offset
                ~entry_size:(Int64.to_int size) ~count:(Int64.to_int count)
                ~string_index:(Int64.to_int index)
            in
            match node with
            | Some node -> children := node :: !children
            | None -> ())
        | _ -> ())
  | _ ->
      if Int64.compare (Reader.length reader) 16L < 0 then
        Parse_context.error context ~code:"elf.truncated_identification"
          ~message:"The ELF identification block is truncated."
          ~component:"elf.identification" ~recoverable:true ());
  let root =
    Parse_context.node context ~id:"elf" ~path:root_path ~label:"ELF"
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
    extensions = [ ".elf"; ".so"; ".o" ];
    coverage;
    detect;
    parse
  }
