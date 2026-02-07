; =============================================================================
; CodeGraph: Rust Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class (struct), @definition.method,
;           @definition.interface (trait), @definition.enum, @definition.type,
;           @definition.variable, @name, @reference.call, @reference.import,
;           @reference.type

; ---------------------------------------------------------------------------
; Functions
; ---------------------------------------------------------------------------
(function_item
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Structs -> mapped to @definition.class
; ---------------------------------------------------------------------------
(struct_item
  name: (type_identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Enums
; ---------------------------------------------------------------------------
(enum_item
  name: (type_identifier) @name) @definition.enum

; ---------------------------------------------------------------------------
; Traits -> mapped to @definition.interface
; ---------------------------------------------------------------------------
(trait_item
  name: (type_identifier) @name) @definition.interface

; ---------------------------------------------------------------------------
; Impl blocks — methods inside impl
; ---------------------------------------------------------------------------
(impl_item
  body: (declaration_list
    (function_item
      name: (identifier) @name) @definition.method))

; ---------------------------------------------------------------------------
; Type aliases
; ---------------------------------------------------------------------------
(type_item
  name: (type_identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Constants and statics
; ---------------------------------------------------------------------------
(const_item
  name: (identifier) @name) @definition.variable

(static_item
  name: (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Let bindings
; ---------------------------------------------------------------------------
(let_declaration
  pattern: (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Module declarations
; ---------------------------------------------------------------------------
(mod_item
  name: (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
; Direct calls: foo()
(call_expression
  function: (identifier) @name) @reference.call

; Method calls: obj.method()
(call_expression
  function: (field_expression
    field: (field_identifier) @name)) @reference.call

; Scoped calls: Module::function()
(call_expression
  function: (scoped_identifier
    name: (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Use imports
; ---------------------------------------------------------------------------
(use_declaration
  argument: (scoped_identifier
    name: (identifier) @name)) @reference.import

(use_declaration
  argument: (identifier) @name) @reference.import

; Use with list: use crate::{A, B}
(use_declaration
  argument: (scoped_use_list
    list: (use_list
      (identifier) @name))) @reference.import

; ---------------------------------------------------------------------------
; Macro invocations
; ---------------------------------------------------------------------------
(macro_invocation
  macro: (identifier) @name) @reference.call

; Scoped macros: std::println!
(macro_invocation
  macro: (scoped_identifier
    name: (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Macro definitions
; ---------------------------------------------------------------------------
(macro_definition
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Type references
; ---------------------------------------------------------------------------
(type_identifier) @reference.type
