module Tui_input = Input

let getenv_int name fallback =
  match Sys.getenv_opt name with
  | None -> fallback
  | Some value -> ( try int_of_string value with Failure _ -> fallback)

let terminal_size () =
  let rows =
    Option.value (Terminal_size.get_rows ()) ~default:(getenv_int "LINES" 40)
  in
  let cols =
    Option.value
      (Terminal_size.get_columns ())
      ~default:(getenv_int "COLUMNS" 120)
  in
  (rows, cols)

let render ~filename ~format model =
  let screen = View.render ~filename ~format model in
  Terml.Command.execute
    [ Terml.Command.Terminal Terml.Terminal.BeginSyncUpdate;
      Terml.Command.Cursor (Terml.Cursor.MoveTo (1, 1));
      Terml.Command.Terminal (Terml.Terminal.ClearScreen Terml.Terminal.All);
      Terml.Command.Print screen;
      Terml.Command.Terminal Terml.Terminal.EndSyncUpdate
    ];
  flush stdout

let rec prompt ~filename ~format model label buffer =
  render ~filename ~format model;
  Printf.printf "%s%s" label (Buffer.contents buffer);
  flush stdout;
  match Tui_input.next () with
  | None ->
      Unix.sleepf 0.01;
      prompt ~filename ~format model label buffer
  | Some Tui_input.Enter -> Buffer.contents buffer
  | Some Tui_input.Escape -> ""
  | Some (Tui_input.Character "\x7f") ->
      if Buffer.length buffer > 0 then
        Buffer.truncate buffer (Buffer.length buffer - 1);
      prompt ~filename ~format model label buffer
  | Some (Tui_input.Character value) ->
      Buffer.add_string buffer value;
      prompt ~filename ~format model label buffer
  | Some _ -> prompt ~filename ~format model label buffer

let parse_offset value =
  try Some (Int64.of_string (String.trim value)) with Failure _ -> None

let handle_prompt ~filename ~format model = function
  | "g" ->
      let value =
        prompt ~filename ~format model "Go to offset: " (Buffer.create 16)
      in
      Option.fold ~none:model ~some:(Model.goto_offset model)
        (parse_offset value)
  | "/" ->
      let value =
        prompt ~filename ~format model "Search: " (Buffer.create 32)
      in
      if String.equal value "" then model else Model.search model value
  | _ -> model

let update ~filename ~format model = function
  | Tui_input.Up | Tui_input.Character "k" -> Model.move model (-1)
  | Tui_input.Down | Tui_input.Character "j" -> Model.move model 1
  | Tui_input.Left | Tui_input.Character "h" -> Model.collapse model
  | Tui_input.Right | Tui_input.Character "l" -> Model.expand model
  | Tui_input.Enter -> Model.toggle_expand model
  | Tui_input.Page_up -> Model.page model (-1)
  | Tui_input.Page_down -> Model.page model 1
  | Tui_input.Tab ->
      { model with
        pane = (match model.Model.pane with Tree -> Hex | Hex -> Tree)
      }
  | Tui_input.Character (("g" | "/") as key) ->
      handle_prompt ~filename ~format model key
  | Tui_input.Character "n" -> Model.next_match model 1
  | Tui_input.Character "N" -> Model.next_match model (-1)
  | Tui_input.Character "d" ->
      { model with show_diagnostics = not model.show_diagnostics }
  | Tui_input.Character "r" ->
      { model with raw_details = not model.raw_details }
  | Tui_input.Character "x" ->
      { model with hexadecimal_values = not model.hexadecimal_values }
  | Tui_input.Character "?" -> { model with show_help = not model.show_help }
  | _ -> model

let run ~filename ~format ~reader ~root =
  let rows, cols = terminal_size () in
  let model = ref (Model.create ~reader ~root ~rows ~cols) in
  let raw_settings =
    try Some (Terml.Terminal.enable_raw_mode ()) with _ -> None
  in
  let cleanup () =
    Option.iter
      (fun settings ->
        try Terml.Terminal.disable_raw_mode settings with _ -> ())
      raw_settings;
    Terml.Command.execute
      [ Terml.Command.Cursor Terml.Cursor.Show;
        Terml.Command.Terminal Terml.Terminal.EnableLineWrap;
        Terml.Command.Terminal Terml.Terminal.LeaveAlternateScreen
      ];
    flush stdout
  in
  Terml.Command.execute
    [ Terml.Command.Terminal Terml.Terminal.EnterAlternateScreen;
      Terml.Command.Terminal Terml.Terminal.DisableLineWrap;
      Terml.Command.Cursor Terml.Cursor.Hide
    ];
  Fun.protect ~finally:cleanup (fun () ->
      let running = ref true in
      while !running do
        let rows, cols = terminal_size () in
        model := Model.resize !model ~rows ~cols;
        render ~filename ~format !model;
        match Tui_input.next () with
        | None -> Unix.sleepf 0.01
        | Some (Tui_input.Character "q") -> running := false
        | Some key -> model := update ~filename ~format !model key
      done)
