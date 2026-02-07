; =============================================================================
; CodeGraph: Zig Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.variable, @name,
;           @reference.call

; ---------------------------------------------------------------------------
; Function declarations
; ---------------------------------------------------------------------------
(function_declaration
  (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Variable/constant declarations
; ---------------------------------------------------------------------------
(variable_declaration
  (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(call_expression
  (identifier) @name) @reference.call

; Field access calls
(call_expression
  (field_expression
    (identifier) @name)) @reference.call
