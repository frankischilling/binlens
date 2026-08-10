type t

val of_bytes : bytes -> t

val of_owned_bytes : bytes -> t
(** Takes ownership of [bytes]. The caller must not mutate it after this call.
*)

val of_owned_file_descriptor :
  ?page_size:int -> Unix.file_descr -> length:int64 -> (t, Error.t) result
(** Creates a paged reader. On success, the reader owns [descriptor] until
    [close] is called. On failure, ownership remains with the caller. *)

val of_string : string -> t
val length : t -> int64
val backend_kind : t -> [ `Bytes | `Paged ]

val close : t -> (unit, Error.t) result
(** Closes owned operating-system resources. Closing any shared slice closes the
    paged backend for every slice. Repeated calls are safe. *)

val absolute_offset : t -> int64 -> (int64, Error.t) result
val checked_add : int64 -> int64 -> (int64, Error.t) result
val checked_mul : int64 -> int64 -> (int64, Error.t) result
val range : t -> offset:int64 -> length:int64 -> (unit, Error.t) result
val get_u8 : t -> int64 -> (int, Error.t) result
val u8 : t -> int64 -> (int64, Error.t) result
val u16 : t -> Endian.t -> int64 -> (int64, Error.t) result
val u32 : t -> Endian.t -> int64 -> (int64, Error.t) result
val u64 : t -> Endian.t -> int64 -> (int64, Error.t) result
val i8 : t -> int64 -> (int64, Error.t) result
val i16 : t -> Endian.t -> int64 -> (int64, Error.t) result
val i32 : t -> Endian.t -> int64 -> (int64, Error.t) result
val i64 : t -> Endian.t -> int64 -> (int64, Error.t) result
val slice : t -> offset:int64 -> length:int64 -> (t, Error.t) result

val bytes :
  ?tracker:Limits.tracker ->
  t ->
  offset:int64 ->
  length:int64 ->
  (bytes, Error.t) result

val fixed_string :
  ?tracker:Limits.tracker ->
  t ->
  offset:int64 ->
  length:int64 ->
  (string, Error.t) result

val c_string :
  ?tracker:Limits.tracker ->
  t ->
  offset:int64 ->
  max_length:int ->
  (string, Error.t) result

val align : int64 -> int64 -> (int64, Error.t) result

val table_range :
  t ->
  offset:int64 ->
  entry_size:int64 ->
  count:int64 ->
  (Span.t, Error.t) result

val sub_reader : t -> Span.t -> (t, Error.t) result
val byte : t -> int64 -> (int, Error.t) result
val hex : t -> offset:int64 -> length:int64 -> (string, Error.t) result
