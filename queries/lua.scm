; =============================================================================
; CodeGraph: Lua Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.method, @definition.variable,
;           @name, @reference.call

; ---------------------------------------------------------------------------
; Named function declarations: function name() end
; ---------------------------------------------------------------------------
(function_declaration
  name: (identifier) @name) @definition.function

; Dotted function declarations: function mod.name() end
(function_declaration
  name: (dot_index_expression) @name) @definition.function

; Method declarations: function obj:method() end
(function_declaration
  name: (method_index_expression) @name) @definition.method

; ---------------------------------------------------------------------------
; Local function declarations
; ---------------------------------------------------------------------------
(function_declaration
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Variable assignments
; ---------------------------------------------------------------------------
(variable_declaration
  (assignment_statement
    (variable_list
      (identifier) @name))) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(function_call
  name: (identifier) @name) @reference.call

; Method calls: obj:method()
(function_call
  name: (method_index_expression) @name) @reference.call

; Dotted calls: mod.func()
(function_call
  name: (dot_index_expression) @name) @reference.call

; ---------------------------------------------------------------------------
; Require calls (imports)
; ---------------------------------------------------------------------------
(function_call
  name: (identifier) @_fn
  arguments: (arguments
    (string) @name)
  (#eq? @_fn "require")) @reference.import
