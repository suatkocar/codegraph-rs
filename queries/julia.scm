; =============================================================================
; CodeGraph: Julia Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class (structs),
;           @definition.variable (module), @name

; ---------------------------------------------------------------------------
; Module definitions
; ---------------------------------------------------------------------------
(module_definition
  (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function definitions: function name(args) ... end
; ---------------------------------------------------------------------------
(function_definition
  (signature
    (call_expression
      (identifier) @name))) @definition.function

; ---------------------------------------------------------------------------
; Struct definitions
; ---------------------------------------------------------------------------
(struct_definition
  (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(call_expression
  (identifier) @name) @reference.call

; Method calls via dot syntax
(call_expression
  (field_expression
    (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Import/using statements
; ---------------------------------------------------------------------------
(import_statement
  (identifier) @name) @reference.import

(using_statement
  (identifier) @name) @reference.import
