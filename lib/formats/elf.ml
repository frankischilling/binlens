let id = "elf"
let display_name = "Executable and Linkable Format"

let coverage =
  { Format.summary =
      "ELF32 and ELF64 headers, structure tables, section metadata, and \
       section names";
    supported =
      [ "ELF identification";
        "ELF32 and ELF64 main headers";
        "little-endian and big-endian files";
        "extended table numbering through section header zero";
        "program header tables";
        "section header tables";
        "section names from the section-name string table";
        "symbol and dynamic table entry layouts";
        "REL and RELA entry layouts";
        "ELF note records";
        "common DWARF section identification";
        "documented MIPS, ARM, and RISC-V header flag subsets";
        "basic file-range validation"
      ];
    unsupported =
      [ "dynamic loader behavior";
        "applying relocations";
        "DWARF payload decoding";
        "complete architecture-specific flag decoding";
        "symbol versioning and hash-table semantics"
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
    (6L, "Dynamic");
    (7L, "Note");
    (8L, "No bits");
    (9L, "Rel relocations");
    (11L, "Dynamic symbols")
  ]

let decoded_header_flags machine value =
  let bit name mask = (name, not (Int64.equal (Int64.logand value mask) 0L)) in
  match machine with
  | Some 8L ->
      Value.bitfield 32 value
        [ bit "No instruction reordering" 0x1L;
          bit "Position-independent code" 0x2L;
          bit "CPIC" 0x4L;
          bit "Extended GOT" 0x8L;
          bit "Obsolete microcode" 0x10L;
          bit "ABI2" 0x20L;
          bit "Options first" 0x80L;
          bit "32-bit mode" 0x100L;
          bit "64-bit floating-point registers" 0x200L;
          bit "IEEE 754-2008 NaN encoding" 0x400L
        ]
  | Some 40L ->
      let eabi =
        Int64.shift_right_logical (Int64.logand value 0xff00_0000L) 24
      in
      Value.bitfield 32 value
        [ bit "Relocation executable" 0x1L;
          bit "Entry point present" 0x2L;
          bit "Interworking" 0x4L;
          bit "APCS-26" 0x8L;
          bit "APCS floating point" 0x10L;
          bit "Position-independent code" 0x20L;
          bit "8-byte structure alignment" 0x40L;
          bit "New ABI" 0x80L;
          bit "Old ABI" 0x100L;
          bit "Software floating-point ABI" 0x200L;
          bit "VFP floating-point ABI" 0x400L;
          bit "Maverick floating-point ABI" 0x800L;
          (Printf.sprintf "EABI version %Ld" eabi, not (Int64.equal eabi 0L))
        ]
  | Some 243L ->
      let float_abi = Int64.shift_right_logical (Int64.logand value 0x6L) 1 in
      let float_name =
        match float_abi with
        | 0L -> "Soft-float ABI"
        | 1L -> "Single-float ABI"
        | 2L -> "Double-float ABI"
        | _ -> "Quad-float ABI"
      in
      Value.bitfield 32 value
        [ bit "Compressed instructions" 0x1L;
          (float_name, true);
          bit "Embedded ABI" 0x8L;
          bit "Total store ordering" 0x10L;
          bit "RV64ILP32 ABI" 0x20L
        ]
  | _ -> Value.unsigned 32 value

let add_field context children ?description ?metadata ~parent ~id ~label ~offset
    ~length value =
  match
    Parser_common.field context ?description ?metadata ~parent ~id ~label
      ~offset ~length value
  with
  | None -> children
  | Some node -> node :: children

let consume_entries context ~component count =
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

let parse_program_headers context ~class_ ~endian ~table_offset ~entry_size
    ~count =
  if Int64.equal count 0L then None
  else
    let expected = if class_ = 1 then 32 else 56 in
    if entry_size < expected then (
      Parse_context.error context ~code:"elf.program_entry_too_small"
        ~message:"The ELF program-header entry size is smaller than required."
        ~component:"elf.program_headers" ~recoverable:true ();
      None)
    else
      match consume_entries context ~component:"elf.program_headers" count with
      | None -> None
      | Some count -> (
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
    file_size : int64 option;
    link : int64 option;
    info : int64 option;
    alignment : int64 option;
    element_size : int64 option
  }

type metadata_table =
  { offset : int64; entry_size : int64; count : int; span : Span.t }

let section_at infos index =
  if
    Int64.compare index 0L < 0
    || Int64.compare index (Int64.of_int (List.length infos)) >= 0
  then None
  else Some (List.nth infos (Int64.to_int index))

let linked_string_table context infos section ~component =
  match section.link with
  | None -> None
  | Some index -> (
      match section_at infos index with
      | None ->
          Parse_context.error context ~span:section.span
            ~code:"elf.metadata_invalid_link"
            ~message:
              "An ELF metadata section links to a section index outside the \
               section table."
            ~component ~recoverable:true ();
          None
      | Some linked when linked.section_type <> Some 3L ->
          Parse_context.error context ~span:section.span
            ~code:"elf.metadata_link_not_string_table"
            ~message:
              "An ELF metadata section does not link to a string-table section."
            ~component ~recoverable:true ();
          None
      | Some linked -> (
          match (linked.file_offset, linked.file_size) with
          | Some offset, Some length -> (
              match
                Reader.range context.Parse_context.reader ~offset ~length
              with
              | Ok () -> Some (offset, length)
              | Error _ ->
                  Parse_context.error context ~span:linked.span
                    ~code:"elf.metadata_string_table_out_of_file"
                    ~message:
                      "A linked ELF string table points outside the input."
                    ~component ~recoverable:true ();
                  None)
          | _ -> None))

let resolve_table_string context ~component ~table_offset ~table_length
    ~name_offset ~field_span =
  if
    Int64.compare name_offset 0L < 0
    || Int64.compare name_offset table_length >= 0
  then (
    Parse_context.error context ~span:field_span
      ~code:"elf.metadata_string_offset_out_of_table"
      ~message:"An ELF metadata string offset is outside its linked table."
      ~component ~recoverable:true ();
    None)
  else
    match Reader.checked_add table_offset name_offset with
    | Error error ->
        Parse_context.error_from_reader context ~component error;
        None
    | Ok absolute -> (
        let remaining = Int64.sub table_length name_offset in
        let maximum =
          min context.Parse_context.limits.max_string_bytes
            (Int64.to_int (min remaining (Int64.of_int max_int)))
        in
        match
          Reader.c_string ~tracker:context.Parse_context.tracker
            context.Parse_context.reader ~offset:absolute ~max_length:maximum
        with
        | Error error ->
            Parse_context.error_from_reader context ~component error;
            None
        | Ok value -> Some (Sanitize.text value, absolute, String.length value))

let prepare_metadata_table context section ~minimum ~component =
  match (section.file_offset, section.file_size, section.element_size) with
  | Some offset, Some length, Some entry_size -> (
      if Int64.equal entry_size 0L then (
        Parse_context.error context ~span:section.span
          ~code:"elf.metadata_zero_entry_size"
          ~message:"An ELF metadata table declares a zero entry size."
          ~component ~recoverable:true ();
        None)
      else if Int64.compare entry_size minimum < 0 then (
        Parse_context.error context ~span:section.span
          ~code:"elf.metadata_entry_too_small"
          ~message:
            "An ELF metadata entry is smaller than the required structure."
          ~component ~recoverable:true ();
        None)
      else if Int64.compare offset 0L < 0 || Int64.compare length 0L < 0 then (
        Parse_context.error context ~span:section.span
          ~code:"elf.metadata_range_unrepresentable"
          ~message:"An ELF metadata range exceeds supported file offsets."
          ~component ~recoverable:true ();
        None)
      else
        match Reader.range context.Parse_context.reader ~offset ~length with
        | Error _ ->
            Parse_context.error context ~span:section.span
              ~code:"elf.metadata_table_out_of_file"
              ~message:"An ELF metadata table points outside the input."
              ~component ~recoverable:true ();
            None
        | Ok () -> (
            let count = Int64.div length entry_size in
            if not (Int64.equal (Int64.rem length entry_size) 0L) then
              Parse_context.warning context ~span:section.span
                ~code:"elf.metadata_trailing_bytes"
                ~message:
                  "An ELF metadata section has bytes after its last complete \
                   entry."
                ~component ();
            match consume_entries context ~component count with
            | None -> None
            | Some count -> (
                match
                  Reader.table_range context.Parse_context.reader ~offset
                    ~entry_size ~count:(Int64.of_int count)
                with
                | Error error ->
                    Parse_context.error_from_reader context ~component error;
                    None
                | Ok _ ->
                    Some
                      { offset;
                        entry_size;
                        count;
                        span = Span.unsafe ~start:offset ~length
                      })))
  | _ -> None

let metadata_entry_offset context table index ~component =
  match Reader.checked_mul (Int64.of_int index) table.entry_size with
  | Error error ->
      Parse_context.error_from_reader context ~component error;
      None
  | Ok relative -> (
      match Reader.checked_add table.offset relative with
      | Ok value -> Some value
      | Error error ->
          Parse_context.error_from_reader context ~component error;
          None)

let symbol_bindings =
  [ (0L, "Local"); (1L, "Global"); (2L, "Weak"); (10L, "GNU unique") ]

let symbol_types =
  [ (0L, "None");
    (1L, "Object");
    (2L, "Function");
    (3L, "Section");
    (4L, "File");
    (5L, "Common");
    (6L, "TLS");
    (10L, "GNU indirect function")
  ]

let symbol_visibilities =
  [ (0L, "Default"); (1L, "Internal"); (2L, "Hidden"); (3L, "Protected") ]

let symbol_section_name value =
  match value with
  | 0L -> Some "Undefined"
  | 0xfff1L -> Some "Absolute"
  | 0xfff2L -> Some "Common"
  | 0xffffL -> Some "Extended index"
  | _ -> None

let parse_symbol_table context ~class_ ~endian infos section =
  let component = "elf.symbols" in
  let minimum = if class_ = 1 then 16L else 24L in
  match prepare_metadata_table context section ~minimum ~component with
  | None -> None
  | Some table ->
      let strings = linked_string_table context infos section ~component in
      let nodes = ref [] in
      for index = 0 to table.count - 1 do
        match metadata_entry_offset context table index ~component with
        | None -> ()
        | Some base -> (
            let read8 relative =
              Parser_common.u8 context (Int64.add base relative)
            and read16 relative =
              Parser_common.u16 context endian (Int64.add base relative)
            and read32 relative =
              Parser_common.u32 context endian (Int64.add base relative)
            and read_word relative =
              if class_ = 1 then
                Parser_common.u32 context endian (Int64.add base relative)
              else Parser_common.u64 context endian (Int64.add base relative)
            in
            let name_offset = read32 0L in
            let info = read8 (if class_ = 1 then 12L else 4L) in
            let other = read8 (if class_ = 1 then 13L else 5L) in
            let section_index = read16 (if class_ = 1 then 14L else 6L) in
            let value = read_word (if class_ = 1 then 4L else 8L) in
            let size = read_word (if class_ = 1 then 8L else 16L) in
            let parent = Printf.sprintf "%s.symbols[%d]" section.parent index in
            let fields = ref [] in
            let add id label relative length value =
              fields :=
                add_field context !fields ~parent ~id ~label
                  ~offset:(Int64.add base relative) ~length value
            in
            (match name_offset with
            | Some raw -> (
                add "name_offset" "Name offset" 0L 4L (Value.offset 32 raw);
                match strings with
                | None -> ()
                | Some (table_offset, table_length) -> (
                    let field_span = Span.unsafe ~start:base ~length:4L in
                    match
                      resolve_table_string context ~component ~table_offset
                        ~table_length ~name_offset:raw ~field_span
                    with
                    | None -> ()
                    | Some (name, offset, length) ->
                        fields :=
                          add_field context !fields ~parent ~id:"name"
                            ~label:"Name" ~offset ~length:(Int64.of_int length)
                            (Value.String
                               { text = name;
                                 raw_hex = None;
                                 valid_utf8 = true
                               })))
            | None -> ());
            (match value with
            | Some raw ->
                add "value" "Value"
                  (if class_ = 1 then 4L else 8L)
                  (if class_ = 1 then 4L else 8L)
                  (Value.address (if class_ = 1 then 32 else 64) raw)
            | None -> ());
            (match size with
            | Some raw ->
                add "size" "Size"
                  (if class_ = 1 then 8L else 16L)
                  (if class_ = 1 then 4L else 8L)
                  (Value.unsigned (if class_ = 1 then 32 else 64) raw)
            | None -> ());
            (match info with
            | Some raw ->
                let relative = if class_ = 1 then 12L else 4L in
                let binding = Int64.shift_right_logical raw 4
                and kind = Int64.logand raw 0xfL in
                add "binding" "Binding" relative 1L
                  (Value.enum 4 binding
                     (Parser_common.enum_name symbol_bindings binding));
                add "symbol_type" "Symbol type" relative 1L
                  (Value.enum 4 kind
                     (Parser_common.enum_name symbol_types kind))
            | None -> ());
            (match other with
            | Some raw ->
                let visibility = Int64.logand raw 0x3L in
                add "visibility" "Visibility"
                  (if class_ = 1 then 13L else 5L)
                  1L
                  (Value.enum 2 visibility
                     (Parser_common.enum_name symbol_visibilities visibility))
            | None -> ());
            (match section_index with
            | Some raw ->
                add "section_index" "Section index"
                  (if class_ = 1 then 14L else 6L)
                  2L
                  (Value.enum 16 raw (symbol_section_name raw))
            | None -> ());
            let children = List.rev !fields in
            let span = Span.unsafe ~start:base ~length:table.entry_size in
            match
              Parse_context.node context
                ~id:(Printf.sprintf "symbol[%d]" index)
                ~path:parent
                ~label:(Printf.sprintf "Symbol %d" index)
                ~span
                ~value:(Value.Collection (List.length children))
                ~children ()
            with
            | None -> ()
            | Some node -> nodes := node :: !nodes)
      done;
      let nodes = List.rev !nodes in
      Parse_context.node context ~id:"symbols"
        ~path:(section.parent ^ ".symbols")
        ~label:
          (if section.section_type = Some 11L then "Dynamic symbol table"
           else "Symbol table")
        ~span:table.span
        ~value:(Value.Collection (List.length nodes))
        ~children:nodes ()

let dynamic_tags =
  [ (0L, "Null");
    (1L, "Needed library");
    (2L, "PLT relocation size");
    (3L, "PLT or GOT address");
    (4L, "Symbol hash table");
    (5L, "String table");
    (6L, "Symbol table");
    (7L, "Rela table");
    (8L, "Rela table size");
    (9L, "Rela entry size");
    (10L, "String table size");
    (11L, "Symbol entry size");
    (12L, "Initialization function");
    (13L, "Termination function");
    (14L, "Shared object name");
    (15L, "Library search path");
    (16L, "Symbolic lookup");
    (17L, "Rel table");
    (18L, "Rel table size");
    (19L, "Rel entry size");
    (20L, "PLT relocation kind");
    (21L, "Debug");
    (22L, "Text relocations");
    (23L, "PLT relocations");
    (24L, "Bind now");
    (25L, "Initialization array");
    (26L, "Termination array");
    (27L, "Initialization array size");
    (28L, "Termination array size");
    (29L, "Run path");
    (30L, "Flags")
  ]

let dynamic_string_tag = function 1L | 14L | 15L | 29L -> true | _ -> false

let parse_dynamic_table context ~class_ ~endian infos section =
  let component = "elf.dynamic" in
  let minimum = if class_ = 1 then 8L else 16L in
  match prepare_metadata_table context section ~minimum ~component with
  | None -> None
  | Some table ->
      let strings = linked_string_table context infos section ~component in
      let nodes = ref [] in
      for index = 0 to table.count - 1 do
        match metadata_entry_offset context table index ~component with
        | None -> ()
        | Some base -> (
            let width = if class_ = 1 then 32 else 64 in
            let length = if class_ = 1 then 4L else 8L in
            let read_tag () =
              Parser_common.read context ~component
                (if class_ = 1 then
                   Reader.i32 context.Parse_context.reader endian base
                 else Reader.i64 context.Parse_context.reader endian base)
            in
            let read_value () =
              if class_ = 1 then
                Parser_common.u32 context endian (Int64.add base 4L)
              else Parser_common.u64 context endian (Int64.add base 8L)
            in
            let tag = read_tag () and value = read_value () in
            let parent =
              Printf.sprintf "%s.dynamic_entries[%d]" section.parent index
            in
            let fields = ref [] in
            (match tag with
            | Some raw ->
                fields :=
                  add_field context !fields ~parent ~id:"tag" ~label:"Tag"
                    ~offset:base ~length
                    (match Parser_common.enum_name dynamic_tags raw with
                    | Some name -> Value.enum width raw (Some name)
                    | None -> Value.Signed { width; value = raw })
            | None -> ());
            (match value with
            | Some raw -> (
                fields :=
                  add_field context !fields ~parent ~id:"value" ~label:"Value"
                    ~offset:(Int64.add base length) ~length
                    (Value.unsigned width raw);
                match (tag, strings) with
                | Some tag, Some (table_offset, table_length)
                  when dynamic_string_tag tag -> (
                    let field_span =
                      Span.unsafe ~start:(Int64.add base length) ~length
                    in
                    match
                      resolve_table_string context ~component ~table_offset
                        ~table_length ~name_offset:raw ~field_span
                    with
                    | None -> ()
                    | Some (text, offset, text_length) ->
                        fields :=
                          add_field context !fields ~parent ~id:"string"
                            ~label:"String" ~offset
                            ~length:(Int64.of_int text_length)
                            (Value.String
                               { text; raw_hex = None; valid_utf8 = true }))
                | _ -> ())
            | None -> ());
            let children = List.rev !fields in
            let span = Span.unsafe ~start:base ~length:table.entry_size in
            match
              Parse_context.node context
                ~id:(Printf.sprintf "dynamic_entry[%d]" index)
                ~path:parent
                ~label:(Printf.sprintf "Dynamic entry %d" index)
                ~span
                ~value:(Value.Collection (List.length children))
                ~children ()
            with
            | None -> ()
            | Some node -> nodes := node :: !nodes)
      done;
      let nodes = List.rev !nodes in
      Parse_context.node context ~id:"dynamic_entries"
        ~path:(section.parent ^ ".dynamic_entries")
        ~label:"Dynamic table" ~span:table.span
        ~value:(Value.Collection (List.length nodes))
        ~children:nodes ()

let validate_relocation_links context infos section =
  (match section.link with
  | Some index -> (
      match section_at infos index with
      | Some linked
        when linked.section_type = Some 2L || linked.section_type = Some 11L ->
          ()
      | _ ->
          Parse_context.error context ~span:section.span
            ~code:"elf.relocation_invalid_symbol_link"
            ~message:
              "An ELF relocation section does not link to a symbol table."
            ~component:"elf.relocations" ~recoverable:true ())
  | None -> ());
  match section.info with
  | Some 0L | None -> ()
  | Some index ->
      if section_at infos index = None then
        Parse_context.error context ~span:section.span
          ~code:"elf.relocation_invalid_target"
          ~message:
            "An ELF relocation section names a target outside the section \
             table."
          ~component:"elf.relocations" ~recoverable:true ()

let parse_relocation_table context ~class_ ~endian infos section =
  let component = "elf.relocations" in
  let with_addend = section.section_type = Some 4L in
  let minimum =
    match (class_, with_addend) with
    | 1, false -> 8L
    | 1, true -> 12L
    | _, false -> 16L
    | _, true -> 24L
  in
  match prepare_metadata_table context section ~minimum ~component with
  | None -> None
  | Some table ->
      validate_relocation_links context infos section;
      let nodes = ref [] in
      for index = 0 to table.count - 1 do
        match metadata_entry_offset context table index ~component with
        | None -> ()
        | Some base -> (
            let width = if class_ = 1 then 32 else 64 in
            let length = if class_ = 1 then 4L else 8L in
            let offset =
              if class_ = 1 then Parser_common.u32 context endian base
              else Parser_common.u64 context endian base
            in
            let info_offset = Int64.add base length in
            let info =
              if class_ = 1 then Parser_common.u32 context endian info_offset
              else Parser_common.u64 context endian info_offset
            in
            let addend =
              if not with_addend then None
              else
                let addend_offset = Int64.add info_offset length in
                Parser_common.read context ~component
                  (if class_ = 1 then
                     Reader.i32 context.Parse_context.reader endian
                       addend_offset
                   else
                     Reader.i64 context.Parse_context.reader endian
                       addend_offset)
            in
            let parent =
              Printf.sprintf "%s.relocations[%d]" section.parent index
            in
            let fields = ref [] in
            (match offset with
            | Some raw ->
                fields :=
                  add_field context !fields ~parent ~id:"offset"
                    ~label:"Relocation offset" ~offset:base ~length
                    (Value.address width raw)
            | None -> ());
            (match info with
            | Some raw ->
                fields :=
                  add_field context !fields ~parent ~id:"info" ~label:"Info"
                    ~offset:info_offset ~length (Value.unsigned width raw);
                let symbol, kind =
                  if class_ = 1 then
                    (Int64.shift_right_logical raw 8, Int64.logand raw 0xffL)
                  else
                    ( Int64.shift_right_logical raw 32,
                      Int64.logand raw 0xffff_ffffL )
                in
                fields :=
                  add_field context !fields ~parent ~id:"symbol_index"
                    ~label:"Symbol index" ~offset:info_offset ~length
                    (Value.unsigned (if class_ = 1 then 24 else 32) symbol);
                fields :=
                  add_field context !fields ~parent ~id:"relocation_type"
                    ~label:"Relocation type" ~offset:info_offset ~length
                    (Value.unsigned (if class_ = 1 then 8 else 32) kind)
            | None -> ());
            (match addend with
            | Some raw ->
                fields :=
                  add_field context !fields ~parent ~id:"addend" ~label:"Addend"
                    ~offset:(Int64.add info_offset length)
                    ~length
                    (Value.Signed { width; value = raw })
            | None -> ());
            let children = List.rev !fields in
            let span = Span.unsafe ~start:base ~length:table.entry_size in
            match
              Parse_context.node context
                ~id:(Printf.sprintf "relocation[%d]" index)
                ~path:parent
                ~label:(Printf.sprintf "Relocation %d" index)
                ~span
                ~value:(Value.Collection (List.length children))
                ~children ()
            with
            | None -> ()
            | Some node -> nodes := node :: !nodes)
      done;
      let nodes = List.rev !nodes in
      Parse_context.node context ~id:"relocations"
        ~path:(section.parent ^ ".relocations")
        ~label:(if with_addend then "Rela relocations" else "Rel relocations")
        ~span:table.span
        ~value:(Value.Collection (List.length nodes))
        ~children:nodes ()

let strip_note_terminator value =
  match String.index_opt value (Char.chr 0) with
  | None -> value
  | Some index -> String.sub value 0 index

let parse_note_record context ~endian (section : section_info) ~cursor ~finish
    ~index =
  let component = "elf.notes" in
  let namesz = Parser_common.u32 context endian cursor
  and descsz = Parser_common.u32 context endian (Int64.add cursor 4L)
  and kind = Parser_common.u32 context endian (Int64.add cursor 8L) in
  match (namesz, descsz, kind) with
  | Some namesz, Some descsz, Some kind -> (
      match
        ( Reader.align namesz 4L,
          Reader.align descsz 4L,
          Reader.checked_add cursor 12L )
      with
      | Ok padded_name, Ok padded_desc, Ok name_start -> (
          match Reader.checked_add name_start padded_name with
          | Error error ->
              Parse_context.error_from_reader context ~component error;
              None
          | Ok desc_start -> (
              match Reader.checked_add desc_start padded_desc with
              | Error error ->
                  Parse_context.error_from_reader context ~component error;
                  None
              | Ok next when Int64.compare next finish > 0 ->
                  Parse_context.error context ~span:section.span
                    ~code:"elf.note_record_out_of_section"
                    ~message:"An ELF note record extends beyond its section."
                    ~component ~recoverable:true ();
                  None
              | Ok next ->
                  let parent =
                    Printf.sprintf "%s.notes[%d]" section.parent index
                  in
                  let fields = ref [] in
                  fields :=
                    add_field context !fields ~parent ~id:"name_size"
                      ~label:"Name size" ~offset:cursor ~length:4L
                      (Value.unsigned 32 namesz);
                  fields :=
                    add_field context !fields ~parent ~id:"descriptor_size"
                      ~label:"Descriptor size" ~offset:(Int64.add cursor 4L)
                      ~length:4L (Value.unsigned 32 descsz);
                  fields :=
                    add_field context !fields ~parent ~id:"type" ~label:"Type"
                      ~offset:(Int64.add cursor 8L) ~length:4L
                      (Value.unsigned 32 kind);
                  (if not (Int64.equal namesz 0L) then
                     if
                       Int64.compare namesz
                         (Int64.of_int
                            context.Parse_context.limits.max_string_bytes)
                       > 0
                     then
                       Parse_context.error context
                         ~span:(Span.unsafe ~start:name_start ~length:namesz)
                         ~code:"elf.note_name_too_long"
                         ~message:
                           "An ELF note name exceeds the configured string \
                            limit."
                         ~component ~recoverable:true ()
                     else
                       match
                         Reader.fixed_string
                           ~tracker:context.Parse_context.tracker
                           context.Parse_context.reader ~offset:name_start
                           ~length:namesz
                       with
                       | Error error ->
                           Parse_context.error_from_reader context ~component
                             error
                       | Ok name ->
                           let name =
                             Sanitize.text (strip_note_terminator name)
                           in
                           fields :=
                             add_field context !fields ~parent ~id:"name"
                               ~label:"Name" ~offset:name_start ~length:namesz
                               (Value.String
                                  { text = name;
                                    raw_hex = None;
                                    valid_utf8 = true
                                  }));
                  (if not (Int64.equal descsz 0L) then
                     match
                       Parser_common.hex context desc_start (min descsz 16L)
                     with
                     | None -> ()
                     | Some summary ->
                         fields :=
                           add_field context !fields ~parent ~id:"descriptor"
                             ~label:"Descriptor" ~offset:desc_start
                             ~length:descsz
                             (Value.Bytes { summary; length = descsz }));
                  let children = List.rev !fields in
                  let span =
                    Span.unsafe ~start:cursor ~length:(Int64.sub next cursor)
                  in
                  let node =
                    Parse_context.node context
                      ~id:(Printf.sprintf "note[%d]" index)
                      ~path:parent
                      ~label:(Printf.sprintf "Note %d" index)
                      ~span
                      ~value:(Value.Collection (List.length children))
                      ~children ()
                  in
                  Some (node, next)))
      | Error error, _, _ | _, Error error, _ | _, _, Error error ->
          Parse_context.error_from_reader context ~component error;
          None)
  | _ -> None

let parse_note_section context ~endian (section : section_info) =
  let component = "elf.notes" in
  match (section.file_offset, section.file_size) with
  | Some offset, Some length -> (
      match Reader.range context.Parse_context.reader ~offset ~length with
      | Error _ ->
          Parse_context.error context ~span:section.span
            ~code:"elf.note_section_out_of_file"
            ~message:"An ELF note section points outside the input." ~component
            ~recoverable:true ();
          None
      | Ok () ->
          let finish = Int64.add offset length in
          let cursor = ref offset and index = ref 0 and running = ref true in
          let nodes = ref [] in
          while !running && Int64.compare !cursor finish < 0 do
            let remaining = Int64.sub finish !cursor in
            if Int64.compare remaining 12L < 0 then (
              Parse_context.error context
                ~span:(Span.unsafe ~start:!cursor ~length:remaining)
                ~code:"elf.note_truncated_header"
                ~message:
                  "An ELF note section ends before a complete note header."
                ~component ~recoverable:true ();
              running := false)
            else
              match consume_entries context ~component 1L with
              | None -> running := false
              | Some _ -> (
                  match
                    parse_note_record context ~endian section ~cursor:!cursor
                      ~finish ~index:!index
                  with
                  | None -> running := false
                  | Some (node, next) ->
                      Option.iter (fun node -> nodes := node :: !nodes) node;
                      cursor := next;
                      incr index)
          done;
          let nodes = List.rev !nodes in
          Parse_context.node context ~id:"notes"
            ~path:(section.parent ^ ".notes")
            ~label:"Notes"
            ~span:(Span.unsafe ~start:offset ~length)
            ~value:(Value.Collection (List.length nodes))
            ~children:nodes ())
  | _ -> None

let is_dwarf_section name =
  let common =
    [ ".debug_abbrev";
      ".debug_addr";
      ".debug_aranges";
      ".debug_frame";
      ".debug_info";
      ".debug_line";
      ".debug_line_str";
      ".debug_loc";
      ".debug_loclists";
      ".debug_names";
      ".debug_pubnames";
      ".debug_pubtypes";
      ".debug_ranges";
      ".debug_rnglists";
      ".debug_str";
      ".debug_str_offsets";
      ".debug_types";
      ".eh_frame"
    ]
  in
  List.mem name common
  || (String.length name >= 8 && String.sub name 0 8 = ".zdebug_")

let parse_section_headers context ~class_ ~endian ~table_offset ~entry_size
    ~count ~string_index =
  if Int64.equal count 0L then None
  else
    let expected = if class_ = 1 then 40 else 64 in
    if entry_size < expected then (
      Parse_context.error context ~code:"elf.section_entry_too_small"
        ~message:"The ELF section-header entry size is smaller than required."
        ~component:"elf.section_headers" ~recoverable:true ();
      None)
    else
      match consume_entries context ~component:"elf.section_headers" count with
      | None -> None
      | Some count -> (
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
                    file_size;
                    link;
                    info;
                    alignment;
                    element_size
                  }
                  :: !infos
              done;
              let infos = List.rev !infos in
              let string_table =
                if
                  Int64.compare string_index 0L < 0
                  || Int64.compare string_index (Int64.of_int count) >= 0
                then (
                  Parse_context.warning context
                    ~code:"elf.invalid_string_table_index"
                    ~message:
                      "The section-name string-table index is outside the \
                       section table."
                    ~component:"elf.section_headers" ();
                  None)
                else
                  let entry = List.nth infos (Int64.to_int string_index) in
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
                    let children =
                      match (resolved_name, name_node) with
                      | Some name, Some name_node when is_dwarf_section name
                        -> (
                          match
                            Parse_context.node context ~id:"dwarf_section"
                              ~path:(entry.parent ^ ".dwarf_section")
                              ~label:"DWARF section" ~span:name_node.Node.span
                              ~value:(Value.Boolean true) ()
                          with
                          | None -> children
                          | Some node -> children @ [ node ])
                      | _ -> children
                    in
                    let metadata =
                      match entry.section_type with
                      | Some (2L | 11L) ->
                          parse_symbol_table context ~class_ ~endian infos entry
                      | Some 6L ->
                          parse_dynamic_table context ~class_ ~endian infos
                            entry
                      | Some (4L | 9L) ->
                          parse_relocation_table context ~class_ ~endian infos
                            entry
                      | Some 7L -> parse_note_section context ~endian entry
                      | _ -> None
                    in
                    let children =
                      match metadata with
                      | None -> children
                      | Some node -> children @ [ node ]
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

type resolved_counts =
  { program_count : int64 option;
    section_count : int64 option;
    string_index : int64 option;
    fields : Node.t list
  }

let resolve_extended_counts context ~class_ ~endian ~section_offset
    ~section_entry_size ~program_count ~section_count ~string_index =
  let extended_program = Int64.equal program_count 0xffffL in
  let extended_sections =
    Int64.equal section_count 0L && not (Int64.equal section_offset 0L)
  in
  let extended_strings = Int64.equal string_index 0xffffL in
  let fallback () =
    { program_count = (if extended_program then None else Some program_count);
      section_count = (if extended_sections then None else Some section_count);
      string_index = (if extended_strings then None else Some string_index);
      fields = []
    }
  in
  if not (extended_program || extended_sections || extended_strings) then
    { program_count = Some program_count;
      section_count = Some section_count;
      string_index = Some string_index;
      fields = []
    }
  else if Int64.equal section_offset 0L then (
    Parse_context.error context
      ~code:"elf.extended_numbering_without_section_zero"
      ~message:
        "ELF extended numbering requires section header zero, but the section \
         +         table offset is zero."
      ~component:"elf.extended_numbering" ~recoverable:true ();
    fallback ())
  else
    let expected = if class_ = 1 then 40 else 64 in
    if Int64.compare section_entry_size (Int64.of_int expected) < 0 then (
      Parse_context.error context ~code:"elf.extended_entry_too_small"
        ~message:
          "Section header zero is too small to hold ELF extended numbering."
        ~component:"elf.extended_numbering" ~recoverable:true ();
      fallback ())
    else
      match
        Reader.range context.Parse_context.reader ~offset:section_offset
          ~length:section_entry_size
      with
      | Error error ->
          Parse_context.error_from_reader context
            ~component:"elf.extended_numbering" error;
          fallback ()
      | Ok () ->
          let read32 relative =
            Parser_common.u32 context endian (Int64.add section_offset relative)
          in
          let read_size () =
            if class_ = 1 then read32 20L
            else Parser_common.u64 context endian (Int64.add section_offset 32L)
          in
          let resolved_program =
            if extended_program then read32 (if class_ = 1 then 28L else 44L)
            else Some program_count
          in
          let resolved_sections =
            if extended_sections then read_size () else Some section_count
          in
          let resolved_strings =
            if extended_strings then read32 (if class_ = 1 then 24L else 40L)
            else Some string_index
          in
          let fields = ref [] in
          let add id label relative length width value =
            match value with
            | None -> ()
            | Some value ->
                fields :=
                  add_field context !fields ~parent:"elf" ~id ~label
                    ~offset:(Int64.add section_offset relative)
                    ~length
                    (Value.unsigned width value)
          in
          if extended_program then
            add "resolved_program_header_count" "Resolved program-header count"
              (if class_ = 1 then 28L else 44L)
              4L 32 resolved_program;
          if extended_sections then
            add "resolved_section_header_count" "Resolved section-header count"
              (if class_ = 1 then 20L else 32L)
              (if class_ = 1 then 4L else 8L)
              (if class_ = 1 then 32 else 64)
              resolved_sections;
          if extended_strings then
            add "resolved_section_name_string_table_index"
              "Resolved section-name string-table index"
              (if class_ = 1 then 24L else 40L)
              4L 32 resolved_strings;
          Parse_context.information context ~code:"elf.extended_numbering"
            ~message:
              "ELF table counts were resolved through section header zero."
            ~component:"elf.extended_numbering" ();
          { program_count = resolved_program;
            section_count = resolved_sections;
            string_index = resolved_strings;
            fields = List.rev !fields
          }

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
              4L
              (decoded_header_flags machine value)
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
        let resolved =
          match
            ( section_offset,
              section_entry_size,
              program_count,
              section_count,
              string_index )
          with
          | ( Some section_offset,
              Some section_entry_size,
              Some program_count,
              Some section_count,
              Some string_index ) ->
              resolve_extended_counts context ~class_ ~endian ~section_offset
                ~section_entry_size ~program_count ~section_count ~string_index
          | _ -> { program_count; section_count; string_index; fields = [] }
        in
        children := List.rev_append resolved.fields !children;
        (match (program_offset, program_entry_size, resolved.program_count) with
        | Some offset, Some size, Some count -> (
            let node =
              parse_program_headers context ~class_ ~endian ~table_offset:offset
                ~entry_size:(Int64.to_int size) ~count
            in
            match node with
            | Some node -> children := node :: !children
            | None -> ())
        | _ -> ());
        match
          ( section_offset,
            section_entry_size,
            resolved.section_count,
            resolved.string_index )
        with
        | Some offset, Some size, Some count, Some index -> (
            let node =
              parse_section_headers context ~class_ ~endian ~table_offset:offset
                ~entry_size:(Int64.to_int size) ~count ~string_index:index
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
