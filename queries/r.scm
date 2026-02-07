; =============================================================================
; CodeGraph: R Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @name, @reference.call

; ---------------------------------------------------------------------------
; Function definitions: name <- function(args) { body }
; R uses binary operator (<- or =) with function_definition on the right
; ---------------------------------------------------------------------------
(binary_operator
  (identifier) @name
  _
  (function_definition)) @definition.function

; ---------------------------------------------------------------------------
; Function calls: name(args)
; ---------------------------------------------------------------------------
(call
  function: (identifier) @name) @reference.call
