let text input =
  let output = Buffer.create (String.length input) in
  String.iter
    (fun byte ->
      let code = Char.code byte in
      if (code >= 0x20 && code <= 0x5b) || (code >= 0x5d && code <= 0x7e) then
        Buffer.add_char output byte
      else if code = 0x5c then Buffer.add_string output "\\\\"
      else Buffer.add_string output (Printf.sprintf "\\x%02X" code))
    input;
  Buffer.contents output

let trimmed_text input =
  let rec left index =
    if index >= String.length input then index
    else
      match input.[index] with '\000' | ' ' -> left (index + 1) | _ -> index
  in
  let rec right index =
    if index < 0 then index
    else
      match input.[index] with '\000' | ' ' -> right (index - 1) | _ -> index
  in
  let start = left 0 in
  let finish = right (String.length input - 1) in
  if finish < start then ""
  else text (String.sub input start (finish - start + 1))
