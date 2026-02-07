; =============================================================================
; CodeGraph: Go Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.method, @definition.class (struct),
;           @definition.interface, @definition.type, @definition.variable,
;           @name, @reference.call, @reference.import, @reference.type

; ---------------------------------------------------------------------------
; Functions
; ---------------------------------------------------------------------------
(function_declaration
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Methods (receiver functions)
; ---------------------------------------------------------------------------
(method_declaration
  name: (field_identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Structs -> mapped to @definition.class for compatibility
; ---------------------------------------------------------------------------
(type_declaration
  (type_spec
    name: (type_identifier) @name
    type: (struct_type))) @definition.class

; ---------------------------------------------------------------------------
; Interfaces
; ---------------------------------------------------------------------------
(type_declaration
  (type_spec
    name: (type_identifier) @name
    type: (interface_type))) @definition.interface

; ---------------------------------------------------------------------------
; Type aliases and named types
; ---------------------------------------------------------------------------
(type_declaration
  (type_spec
    name: (type_identifier) @name)) @definition.type

; ---------------------------------------------------------------------------
; Variables
; ---------------------------------------------------------------------------
(var_declaration
  (var_spec
    name: (identifier) @name)) @definition.variable

; Short variable declarations (:=)
(short_var_declaration
  left: (expression_list
    (identifier) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Constants
; ---------------------------------------------------------------------------
(const_declaration
  (const_spec
    name: (identifier) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
; Direct calls: foo()
(call_expression
  function: (identifier) @name) @reference.call

; Method calls: obj.Method()
(call_expression
  function: (selector_expression
    field: (field_identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Imports
; ---------------------------------------------------------------------------
(import_spec
  path: (interpreted_string_literal) @name) @reference.import

; ---------------------------------------------------------------------------
; Goroutine launches: go func()
; ---------------------------------------------------------------------------
(go_statement
  (call_expression
    function: (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Type references
; ---------------------------------------------------------------------------
(type_identifier) @reference.type
