open Binlens

let measure name iterations function_ =
  let started = Unix.gettimeofday () in
  for _ = 1 to iterations do
    function_ ()
  done;
  let elapsed = Unix.gettimeofday () -. started in
  Printf.printf "%-28s %8d iterations  %0.6f seconds\n" name iterations elapsed

let parse format bytes =
  let reader = Reader.of_bytes bytes in
  match Registry.parse ~format Limits.default reader with
  | Ok (_, result) -> (reader, result)
  | Error error -> failwith (Error.to_string error)

let () =
  let elf_bytes = Fixture_builder.elf64_little ()
  and pe_bytes = Fixture_builder.pe32_plus () in
  let elf_reader, elf = parse "elf" elf_bytes in
  measure "sequential reader u32" 100_000 (fun () ->
      ignore (Reader.u32 elf_reader Endian.Little 0L));
  measure "ELF parse" 2_000 (fun () -> ignore (parse "elf" elf_bytes));
  measure "PE parse" 2_000 (fun () -> ignore (parse "pe" pe_bytes));
  measure "tree text rendering" 5_000 (fun () ->
      Option.iter (fun root -> ignore (Render_text.render root)) elf.Format.root);
  measure "JSON rendering" 2_000 (fun () ->
      Option.iter
        (fun root -> ignore (Render_json.node root |> Yojson.Safe.to_string))
        elf.root);
  measure "structural diff" 5_000 (fun () ->
      ignore
        (Diff.compare ~left_reader:elf_reader ~right_reader:elf_reader elf elf));
  measure "hex-window rendering" 10_000 (fun () ->
      Option.iter
        (fun root ->
          let window =
            Binlens_tui.Hex_view.calculate
              ~input_length:(Reader.length elf_reader) ~selected:root.Node.span
              ~rows:20 ~bytes_per_line:8
          in
          ignore (Binlens_tui.Hex_view.render elf_reader root.span window))
        elf.root)
