(lang dune 3.15)
(name binlens)
(generate_opam_files false)

(package
 (name binlens)
 (synopsis "Terminal binary-format explorer and parsing library")
 (description
  "Inspect ELF, PE, NES, Game Boy, and Game Boy Advance headers as structured fields tied to exact byte ranges.")
 (depends ocaml dune cmdliner yojson terml alcotest qcheck qcheck-alcotest odoc))
