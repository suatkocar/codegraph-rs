; =============================================================================
; CodeGraph: Scala Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.interface,
;           @definition.variable, @name, @reference.call

; ---------------------------------------------------------------------------
; Class definitions
; ---------------------------------------------------------------------------
(class_definition
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Object definitions (singleton)
; ---------------------------------------------------------------------------
(object_definition
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Trait definitions
; ---------------------------------------------------------------------------
(trait_definition
  name: (identifier) @name) @definition.interface

; ---------------------------------------------------------------------------
; Function/method definitions
; ---------------------------------------------------------------------------
(function_definition
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Val definitions (immutable bindings)
; ---------------------------------------------------------------------------
(val_definition
  pattern: (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Var definitions (mutable bindings)
; ---------------------------------------------------------------------------
(var_definition
  pattern: (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Type definitions
; ---------------------------------------------------------------------------
(type_definition
  name: (type_identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(call_expression
  function: (identifier) @name) @reference.call

; Method calls
(call_expression
  function: (field_expression
    field: (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Import statements
; ---------------------------------------------------------------------------
(import_declaration
  path: (identifier) @name) @reference.import
