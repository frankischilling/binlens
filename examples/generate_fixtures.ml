let fixtures =
  [ ("minimal-elf32-le.elf", Fixture_builder.elf32_little);
    ("minimal-elf32-be.elf", Fixture_builder.elf32_big);
    ("minimal-elf64-le.elf", Fixture_builder.elf64_little);
    ("minimal-elf64-be.elf", Fixture_builder.elf64_big);
    ("metadata-elf32-le.elf", Fixture_builder.elf32_little_metadata);
    ("metadata-elf64-be.elf", Fixture_builder.elf64_big_metadata);
    ("minimal-pe32.exe", Fixture_builder.pe32);
    ("minimal-pe32-plus.exe", Fixture_builder.pe32_plus);
    ("directories-pe32.exe", Fixture_builder.pe32_directories);
    ("directories-pe32-plus.exe", Fixture_builder.pe32_plus_directories);
    ("minimal-ines.nes", fun () -> Fixture_builder.nes ());
    ("minimal-gameboy.gb", fun () -> Fixture_builder.gameboy ());
    ("minimal-gba.gba", fun () -> Fixture_builder.gba ())
  ]

let ensure_directory path =
  if Sys.file_exists path then () else Unix.mkdir path 0o755

let write directory (name, build) =
  let filename = Filename.concat directory name in
  let channel = open_out_bin filename in
  Fun.protect
    ~finally:(fun () -> close_out_noerr channel)
    (fun () -> output_bytes channel (build ()))

let () =
  let directory =
    if Array.length Sys.argv > 1 then Sys.argv.(1) else "examples/generated"
  in
  ensure_directory directory;
  List.iter (write directory) fixtures;
  Printf.printf "Wrote %d synthetic fixtures to %s\n" (List.length fixtures)
    directory
