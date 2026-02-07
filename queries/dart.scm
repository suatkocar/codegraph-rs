; =============================================================================
; CodeGraph: Dart Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.enum,
;           @name

; ---------------------------------------------------------------------------
; Class definitions
; ---------------------------------------------------------------------------
(class_definition
  (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Enum declarations
; ---------------------------------------------------------------------------
(enum_declaration
  (identifier) @name) @definition.enum

; ---------------------------------------------------------------------------
; Function signatures (top-level)
; ---------------------------------------------------------------------------
(function_signature
  (identifier) @name) @definition.function
