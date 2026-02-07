; =============================================================================
; CodeGraph: Erlang Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class (modules),
;           @definition.variable (records), @name

; ---------------------------------------------------------------------------
; Function clauses
; ---------------------------------------------------------------------------
(function_clause
  name: (atom) @name) @definition.function

; ---------------------------------------------------------------------------
; Module attribute: -module(name).
; ---------------------------------------------------------------------------
(module_attribute
  name: (atom) @name) @definition.class

; ---------------------------------------------------------------------------
; Record declarations: -record(name, {fields}).
; ---------------------------------------------------------------------------
(record_decl
  name: (atom) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(call
  (atom) @name) @reference.call

; Remote calls: module:function(args)
(call
  (remote
    (atom) @name)) @reference.call

; ---------------------------------------------------------------------------
; Import attributes: -import(module, [funcs]).
; ---------------------------------------------------------------------------
(import_attribute
  (atom) @name) @reference.import
