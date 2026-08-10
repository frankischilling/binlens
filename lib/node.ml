type metadata =
  { endian : Endian.t option;
    numeric_base : [ `Decimal | `Hexadecimal ] option;
    raw : string option
  }

type t =
  { id : string;
    path : string;
    label : string;
    description : string option;
    span : Span.t;
    value : Value.t;
    children : t list;
    diagnostics : Diagnostic.t list;
    source_format : string;
    metadata : metadata
  }

let metadata ?endian ?numeric_base ?raw () = { endian; numeric_base; raw }
let empty_metadata = metadata ()

let make ?description ?(children = []) ?(diagnostics = [])
    ?(metadata = empty_metadata) ~id ~path ~label ~span ~value ~source_format ()
    =
  { id;
    path;
    label;
    description;
    span;
    value;
    children;
    diagnostics;
    source_format;
    metadata
  }

let rec count node =
  List.fold_left (fun total child -> total + count child) 1 node.children

let flatten root =
  let rec loop pending output =
    match pending with
    | [] -> List.rev output
    | node :: rest -> loop (node.children @ rest) (node :: output)
  in
  loop [ root ] []

let find_by_path root path =
  flatten root |> List.find_opt (fun node -> String.equal node.path path)
