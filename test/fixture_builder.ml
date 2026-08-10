open Binlens

let set_u8 bytes offset value =
  Bytes.set bytes offset (Char.chr (value land 0xff))

let set_integer bytes endian offset width value =
  for index = 0 to width - 1 do
    let shift =
      match endian with
      | Endian.Little -> index * 8
      | Endian.Big -> (width - index - 1) * 8
    in
    set_u8 bytes (offset + index)
      (Int64.to_int
         (Int64.logand (Int64.shift_right_logical value shift) 0xffL))
  done

let set_u16 bytes endian offset value =
  set_integer bytes endian offset 2 (Int64.of_int value)

let set_u32 bytes endian offset value = set_integer bytes endian offset 4 value
let set_u64 bytes endian offset value = set_integer bytes endian offset 8 value

let set_string bytes offset value =
  Bytes.blit_string value 0 bytes offset (String.length value)

let elf ~class_ ~endian =
  let is_32 = class_ = 1 in
  let header_size = if is_32 then 52 else 64 in
  let program_size = if is_32 then 32 else 56 in
  let section_size = if is_32 then 40 else 64 in
  let program_offset = header_size in
  let section_offset = program_offset + program_size in
  let string_table = "\000.text\000.shstrtab\000" in
  let string_offset = section_offset + (3 * section_size) in
  let bytes = Bytes.make (string_offset + String.length string_table) '\000' in
  set_string bytes 0 "\x7fELF";
  set_u8 bytes 4 class_;
  set_u8 bytes 5 (match endian with Endian.Little -> 1 | Big -> 2);
  set_u8 bytes 6 1;
  set_u16 bytes endian 16 2;
  set_u16 bytes endian 18 (if is_32 then 3 else 62);
  set_u32 bytes endian 20 1L;
  if is_32 then (
    set_u32 bytes endian 24 0x1000L;
    set_u32 bytes endian 28 (Int64.of_int program_offset);
    set_u32 bytes endian 32 (Int64.of_int section_offset);
    set_u32 bytes endian 36 0L;
    set_u16 bytes endian 40 header_size;
    set_u16 bytes endian 42 program_size;
    set_u16 bytes endian 44 1;
    set_u16 bytes endian 46 section_size;
    set_u16 bytes endian 48 3;
    set_u16 bytes endian 50 2;
    set_u32 bytes endian program_offset 1L;
    set_u32 bytes endian (program_offset + 4) 0L;
    set_u32 bytes endian (program_offset + 8) 0x1000L;
    set_u32 bytes endian (program_offset + 12) 0x1000L;
    set_u32 bytes endian (program_offset + 16)
      (Int64.of_int (Bytes.length bytes));
    set_u32 bytes endian (program_offset + 20)
      (Int64.of_int (Bytes.length bytes));
    set_u32 bytes endian (program_offset + 24) 5L;
    set_u32 bytes endian (program_offset + 28) 0x1000L)
  else (
    set_u64 bytes endian 24 0x401000L;
    set_u64 bytes endian 32 (Int64.of_int program_offset);
    set_u64 bytes endian 40 (Int64.of_int section_offset);
    set_u32 bytes endian 48 0L;
    set_u16 bytes endian 52 header_size;
    set_u16 bytes endian 54 program_size;
    set_u16 bytes endian 56 1;
    set_u16 bytes endian 58 section_size;
    set_u16 bytes endian 60 3;
    set_u16 bytes endian 62 2;
    set_u32 bytes endian program_offset 1L;
    set_u32 bytes endian (program_offset + 4) 5L;
    set_u64 bytes endian (program_offset + 8) 0L;
    set_u64 bytes endian (program_offset + 16) 0x400000L;
    set_u64 bytes endian (program_offset + 24) 0x400000L;
    set_u64 bytes endian (program_offset + 32)
      (Int64.of_int (Bytes.length bytes));
    set_u64 bytes endian (program_offset + 40)
      (Int64.of_int (Bytes.length bytes));
    set_u64 bytes endian (program_offset + 48) 0x1000L);
  let section index = section_offset + (index * section_size) in
  (if is_32 then (
     let text = section 1 and strings = section 2 in
     set_u32 bytes endian text 1L;
     set_u32 bytes endian (text + 4) 1L;
     set_u32 bytes endian (text + 8) 6L;
     set_u32 bytes endian (text + 12) 0x1000L;
     set_u32 bytes endian (text + 16) 0L;
     set_u32 bytes endian (text + 20) 0L;
     set_u32 bytes endian (text + 32) 16L;
     set_u32 bytes endian strings 7L;
     set_u32 bytes endian (strings + 4) 3L;
     set_u32 bytes endian (strings + 16) (Int64.of_int string_offset);
     set_u32 bytes endian (strings + 20)
       (Int64.of_int (String.length string_table));
     set_u32 bytes endian (strings + 32) 1L)
   else
     let text = section 1 and strings = section 2 in
     set_u32 bytes endian text 1L;
     set_u32 bytes endian (text + 4) 1L;
     set_u64 bytes endian (text + 8) 6L;
     set_u64 bytes endian (text + 16) 0x401000L;
     set_u64 bytes endian (text + 24) 0L;
     set_u64 bytes endian (text + 32) 0L;
     set_u64 bytes endian (text + 48) 16L;
     set_u32 bytes endian strings 7L;
     set_u32 bytes endian (strings + 4) 3L;
     set_u64 bytes endian (strings + 24) (Int64.of_int string_offset);
     set_u64 bytes endian (strings + 32)
       (Int64.of_int (String.length string_table));
     set_u64 bytes endian (strings + 48) 1L);
  set_string bytes string_offset string_table;
  bytes

let elf32_little () = elf ~class_:1 ~endian:Endian.Little
let elf32_big () = elf ~class_:1 ~endian:Endian.Big
let elf64_little () = elf ~class_:2 ~endian:Endian.Little
let elf64_big () = elf ~class_:2 ~endian:Endian.Big

let elf_extended ~class_ ~endian =
  let bytes = elf ~class_ ~endian in
  let is_32 = class_ = 1 in
  let header_size = if is_32 then 52 else 64 in
  let program_size = if is_32 then 32 else 56 in
  let section_offset = header_size + program_size in
  set_u16 bytes endian (if is_32 then 44 else 56) 0xffff;
  set_u16 bytes endian (if is_32 then 48 else 60) 0;
  set_u16 bytes endian (if is_32 then 50 else 62) 0xffff;
  if is_32 then (
    set_u32 bytes endian (section_offset + 20) 3L;
    set_u32 bytes endian (section_offset + 24) 2L;
    set_u32 bytes endian (section_offset + 28) 1L)
  else (
    set_u64 bytes endian (section_offset + 32) 3L;
    set_u32 bytes endian (section_offset + 40) 2L;
    set_u32 bytes endian (section_offset + 44) 1L);
  bytes

let elf32_little_extended () = elf_extended ~class_:1 ~endian:Endian.Little
let elf32_big_extended () = elf_extended ~class_:1 ~endian:Endian.Big
let elf64_little_extended () = elf_extended ~class_:2 ~endian:Endian.Little
let elf64_big_extended () = elf_extended ~class_:2 ~endian:Endian.Big

let pe ~plus =
  let pe_offset = 0x80 in
  let optional_size = if plus then 240 else 224 in
  let optional_offset = pe_offset + 24 in
  let section_offset = optional_offset + optional_size in
  let bytes = Bytes.make 0x220 '\000' in
  set_string bytes 0 "MZ";
  set_u32 bytes Endian.Little 0x3c (Int64.of_int pe_offset);
  set_string bytes pe_offset "PE\000\000";
  let coff = pe_offset + 4 in
  set_u16 bytes Endian.Little coff (if plus then 0x8664 else 0x14c);
  set_u16 bytes Endian.Little (coff + 2) 1;
  set_u32 bytes Endian.Little (coff + 4) 0x65_000_000L;
  set_u16 bytes Endian.Little (coff + 16) optional_size;
  set_u16 bytes Endian.Little (coff + 18) 0x102;
  set_u16 bytes Endian.Little optional_offset (if plus then 0x20b else 0x10b);
  set_u32 bytes Endian.Little (optional_offset + 16) 0x1000L;
  if plus then set_u64 bytes Endian.Little (optional_offset + 24) 0x140000000L
  else set_u32 bytes Endian.Little (optional_offset + 28) 0x400000L;
  set_u32 bytes Endian.Little (optional_offset + 32) 0x1000L;
  set_u32 bytes Endian.Little (optional_offset + 36) 0x200L;
  set_u32 bytes Endian.Little (optional_offset + 56) 0x2000L;
  set_u32 bytes Endian.Little (optional_offset + 60) 0x200L;
  set_u16 bytes Endian.Little (optional_offset + 68) 3;
  set_u16 bytes Endian.Little (optional_offset + 70) 0x140;
  set_u32 bytes Endian.Little (optional_offset + if plus then 108 else 92) 16L;
  set_string bytes section_offset ".text\000\000\000";
  set_u32 bytes Endian.Little (section_offset + 8) 0x20L;
  set_u32 bytes Endian.Little (section_offset + 12) 0x1000L;
  set_u32 bytes Endian.Little (section_offset + 16) 0x20L;
  set_u32 bytes Endian.Little (section_offset + 20) 0x200L;
  set_u32 bytes Endian.Little (section_offset + 36) 0x60000020L;
  bytes

let pe32 () = pe ~plus:false
let pe32_plus () = pe ~plus:true

let nes ?(nes2 = false) ?(trainer = false) ?(prg_banks = 1) ?(chr_banks = 0) ()
    =
  let trainer_size = if trainer then 512 else 0 in
  let payload_size =
    trainer_size + (prg_banks * 16_384) + (chr_banks * 8_192)
  in
  let bytes = Bytes.make (16 + payload_size) '\000' in
  set_string bytes 0 "NES\x1a";
  set_u8 bytes 4 prg_banks;
  set_u8 bytes 5 chr_banks;
  set_u8 bytes 6 (1 lor if trainer then 4 else 0);
  set_u8 bytes 7 (if nes2 then 0x08 else 0);
  if nes2 then set_u8 bytes 8 0x10;
  bytes

let gameboy_logo =
  [| 0xce;
     0xed;
     0x66;
     0x66;
     0xcc;
     0x0d;
     0x00;
     0x0b;
     0x03;
     0x73;
     0x00;
     0x83;
     0x00;
     0x0c;
     0x00;
     0x0d;
     0x00;
     0x08;
     0x11;
     0x1f;
     0x88;
     0x89;
     0x00;
     0x0e;
     0xdc;
     0xcc;
     0x6e;
     0xe6;
     0xdd;
     0xdd;
     0xd9;
     0x99;
     0xbb;
     0xbb;
     0x67;
     0x63;
     0x6e;
     0x0e;
     0xec;
     0xcc;
     0xdd;
     0xdc;
     0x99;
     0x9f;
     0xbb;
     0xb9;
     0x33;
     0x3e
  |]

let gameboy ?(full_payload = true) () =
  let bytes = Bytes.make (if full_payload then 32_768 else 0x150) '\000' in
  Array.iteri (fun index byte -> set_u8 bytes (0x104 + index) byte) gameboy_logo;
  set_string bytes 0x134 "BINLENS";
  set_u8 bytes 0x143 0x80;
  set_u8 bytes 0x147 0;
  set_u8 bytes 0x148 0;
  set_u8 bytes 0x149 0;
  let checksum = ref 0 in
  for offset = 0x134 to 0x14c do
    checksum := (!checksum - Char.code (Bytes.get bytes offset) - 1) land 0xff
  done;
  set_u8 bytes 0x14d !checksum;
  let sum = ref 0 in
  for offset = 0 to Bytes.length bytes - 1 do
    if offset <> 0x14e && offset <> 0x14f then
      sum := (!sum + Char.code (Bytes.get bytes offset)) land 0xffff
  done;
  set_u16 bytes Endian.Big 0x14e !sum;
  bytes

let gba_logo =
  [| 0x24;
     0xff;
     0xae;
     0x51;
     0x69;
     0x9a;
     0xa2;
     0x21;
     0x3d;
     0x84;
     0x82;
     0x0a;
     0x84;
     0xe4;
     0x09;
     0xad;
     0x11;
     0x24;
     0x8b;
     0x98;
     0xc0;
     0x81;
     0x7f;
     0x21;
     0xa3;
     0x52;
     0xbe;
     0x19;
     0x93;
     0x09;
     0xce;
     0x20;
     0x10;
     0x46;
     0x4a;
     0x4a;
     0xf8;
     0x27;
     0x31;
     0xec;
     0x58;
     0xc7;
     0xe8;
     0x33;
     0x82;
     0xe3;
     0xce;
     0xbf;
     0x85;
     0xf4;
     0xdf;
     0x94;
     0xce;
     0x4b;
     0x09;
     0xc1;
     0x94;
     0x56;
     0x8a;
     0xc0;
     0x13;
     0x72;
     0xa7;
     0xfc;
     0x9f;
     0x84;
     0x4d;
     0x73;
     0xa3;
     0xca;
     0x9a;
     0x61;
     0x58;
     0x97;
     0xa3;
     0x27;
     0xfc;
     0x03;
     0x98;
     0x76;
     0x23;
     0x1d;
     0xc7;
     0x61;
     0x03;
     0x04;
     0xae;
     0x56;
     0xbf;
     0x38;
     0x84;
     0x00;
     0x40;
     0xa7;
     0x0e;
     0xfd;
     0xff;
     0x52;
     0xfe;
     0x03;
     0x6f;
     0x95;
     0x30;
     0xf1;
     0x97;
     0xfb;
     0xc0;
     0x85;
     0x60;
     0xd6;
     0x80;
     0x25;
     0xa9;
     0x63;
     0xbe;
     0x03;
     0x01;
     0x4e;
     0x38;
     0xe2;
     0xf9;
     0xa2;
     0x34;
     0xff;
     0xbb;
     0x3e;
     0x03;
     0x44;
     0x78;
     0x00;
     0x90;
     0xcb;
     0x88;
     0x11;
     0x3a;
     0x94;
     0x65;
     0xc0;
     0x7c;
     0x63;
     0x87;
     0xf0;
     0x3c;
     0xaf;
     0xd6;
     0x25;
     0xe4;
     0x8b;
     0x38;
     0x0a;
     0xac;
     0x72;
     0x21;
     0xd4;
     0xf8;
     0x07
  |]

let gba ?save_signature () =
  let extra =
    Option.fold ~none:0 ~some:(fun value -> String.length value) save_signature
  in
  let bytes = Bytes.make (0xc0 + extra) '\000' in
  Array.iteri (fun index byte -> set_u8 bytes (4 + index) byte) gba_logo;
  set_string bytes 0xa0 "BINLENS GBA ";
  set_string bytes 0xac "BLNE";
  set_string bytes 0xb0 "01";
  set_u8 bytes 0xb2 0x96;
  let sum = ref 0 in
  for offset = 0xa0 to 0xbc do
    sum := (!sum + Char.code (Bytes.get bytes offset)) land 0xff
  done;
  set_u8 bytes 0xbd ((- !sum - 0x19) land 0xff);
  Option.iter (set_string bytes 0xc0) save_signature;
  bytes

let corrupt_u8 bytes offset value =
  let copy = Bytes.copy bytes in
  set_u8 copy offset value;
  copy

let truncate bytes length = Bytes.sub bytes 0 length
