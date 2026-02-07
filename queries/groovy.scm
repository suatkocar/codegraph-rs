; =============================================================================
; CodeGraph: Groovy Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.method,
;           @definition.interface, @definition.enum, @name

; ---------------------------------------------------------------------------
; Class definitions
; ---------------------------------------------------------------------------
(class_declaration
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Interface definitions
; ---------------------------------------------------------------------------
(interface_declaration
  name: (identifier) @name) @definition.interface

; ---------------------------------------------------------------------------
; Enum definitions
; ---------------------------------------------------------------------------
(enum_declaration
  name: (identifier) @name) @definition.enum

; ---------------------------------------------------------------------------
; Method definitions
; ---------------------------------------------------------------------------
(method_declaration
  name: (identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Function/closure definitions
; ---------------------------------------------------------------------------
(function_definition
  (identifier) @name) @definition.function
