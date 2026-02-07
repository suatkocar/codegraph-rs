; =============================================================================
; CodeGraph: Bash Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.variable, @name,
;           @reference.call

; ---------------------------------------------------------------------------
; Function definitions
; ---------------------------------------------------------------------------
(function_definition
  name: (word) @name) @definition.function

; ---------------------------------------------------------------------------
; Variable assignments (top-level)
; ---------------------------------------------------------------------------
(variable_assignment
  name: (variable_name) @name) @definition.variable

; ---------------------------------------------------------------------------
; Command calls (function invocations)
; ---------------------------------------------------------------------------
(command
  name: (command_name
    (word) @name)) @reference.call

; ---------------------------------------------------------------------------
; Source/import statements
; ---------------------------------------------------------------------------
(command
  name: (command_name
    (word) @_cmd)
  argument: (word) @name
  (#match? @_cmd "^(source|\\.)$")) @reference.import
