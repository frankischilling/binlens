# Terminal interface

Run `binlens tui FILE`. The file is parsed once before the alternate screen opens.

## Layout

The left panel shows visible parse-tree rows. The right panel shows a bounded hexadecimal window around the selected span. Selected bytes use brackets such as `[7F]`. A marker reports when a selected range continues above or below the visible window.

The status rows show the current semantic path, offset, size, value details, and the first selected-node diagnostic. The header shows the file, detected format, and active pane.

Terminals smaller than 60 columns by 14 rows receive a size message instead of clipped panels. BinLens polls terminal dimensions through `terminal_size` and rebuilds the visible layout after a resize.

## Keys

| Key | Action |
| --- | --- |
| Up, `k` | Move to the previous visible tree row. |
| Down, `j` | Move to the next visible tree row. |
| Left, `h` | Collapse the selected node or move to its parent. |
| Right, `l` | Expand the selected node. |
| Enter | Toggle expansion. |
| Tab | Switch the active pane indicator. |
| Page Up | Move one visible page upward. |
| Page Down | Move one visible page downward. |
| `g` | Prompt for a decimal or `0x`-prefixed byte offset. |
| `/` | Search node labels and semantic paths. |
| `n` | Select the next search result. |
| `N` | Select the previous search result. |
| `d` | Toggle selected-node diagnostics. |
| `r` | Toggle value details. |
| `x` | Toggle hexadecimal and decimal numeric details. |
| `?` | Toggle the help screen. |
| `q` | Quit. |

## Terminal cleanup

The adapter uses `Fun.protect` around the event loop. Cleanup attempts to restore raw mode, show the cursor, enable line wrapping, and leave the alternate screen after normal quit or a handled exception.

If the host does not permit raw terminal mode, BinLens still opens but input may remain line buffered. Windows Terminal, current PowerShell terminals, and common Unix terminal emulators provide the ANSI behavior used by `terml`.

## Performance

Key presses update the model and visible windows. They do not rerun detection or parsing. The hex panel reads at most eight bytes per visible row. Tree flattening is limited by the node budget.

Binary editing, mouse input, persistent configuration, and dynamic parser loading are outside v0.1.0.
