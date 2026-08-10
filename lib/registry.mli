type t

val api_version : int
val builtins : t
val create : Format.parser list -> (t, Error.t) result
val with_parser : t -> Format.parser -> (t, Error.t) result
val all : ?registry:t -> unit -> Format.parser list
val find : ?registry:t -> string -> Format.parser option
val detect : ?registry:t -> Limits.t -> Reader.t -> Format.detection list

val parse :
  ?registry:t ->
  ?format:string ->
  Limits.t ->
  Reader.t ->
  (Format.parser * Format.parse_result, Error.t) result
