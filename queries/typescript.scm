; =============================================================================
; CodeGraph: TypeScript / TSX Tree-sitter Queries
; =============================================================================
; Captures follow the convention:
;   @definition.<kind>  – a symbol definition (function, class, method, ...)
;   @reference.<kind>   – a reference to a symbol (call, type, class, ...)
;   @import / @export    – module boundary crossings
;   @name               – the identifier token for a definition
;   @source             – the module specifier string in import/export
; =============================================================================

; ---------------------------------------------------------------------------
; Function declarations
; ---------------------------------------------------------------------------
(function_declaration
  name: (identifier) @name) @definition.function

; Arrow functions and function expressions assigned to const/let/var
(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: [(arrow_function) (function_expression)]) @definition.function)

(variable_declaration
  (variable_declarator
    name: (identifier) @name
    value: [(arrow_function) (function_expression)]) @definition.function)

; ---------------------------------------------------------------------------
; Class declarations
; ---------------------------------------------------------------------------
(class_declaration
  name: (type_identifier) @name) @definition.class

; Class heritage (extends / implements)
(class_declaration
  name: (type_identifier) @name
  (class_heritage
    (extends_clause
      value: (identifier) @superclass))) @definition.class_with_heritage

(class_declaration
  (class_heritage
    (implements_clause
      (type_identifier) @interface_name))) @implements

; ---------------------------------------------------------------------------
; Method definitions (inside class body)
; ---------------------------------------------------------------------------
(method_definition
  name: (property_identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Interface declarations
; ---------------------------------------------------------------------------
(interface_declaration
  name: (type_identifier) @name) @definition.interface

; Interface extends
(interface_declaration
  name: (type_identifier) @name
  (extends_type_clause
    (type_identifier) @superinterface)) @definition.interface_extends

; ---------------------------------------------------------------------------
; Type alias declarations
; ---------------------------------------------------------------------------
(type_alias_declaration
  name: (type_identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Enum declarations
; ---------------------------------------------------------------------------
(enum_declaration
  name: (identifier) @name) @definition.enum

; ---------------------------------------------------------------------------
; Variable declarations (non-function values)
; ---------------------------------------------------------------------------
(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (_) @value) @definition.variable
  (#not-match? @value "^(arrow_function|function_expression)$"))

; ---------------------------------------------------------------------------
; Import statements
; ---------------------------------------------------------------------------
; import x from "mod"
(import_statement
  source: (string) @source) @import

; import { a, b } from "mod"  –  capture individual named imports
(import_statement
  (import_clause
    (named_imports
      (import_specifier
        name: (identifier) @imported_name))))

; import * as ns from "mod"
(import_statement
  (import_clause
    (namespace_import (identifier) @imported_name)))

; ---------------------------------------------------------------------------
; Export statements
; ---------------------------------------------------------------------------
; export { ... }
(export_statement) @export

; Re-exports: export { ... } from "mod"
(export_statement
  source: (string) @source) @reexport

; export default ...
(export_statement
  "default" @is_default) @export_default

; ---------------------------------------------------------------------------
; Call expressions
; ---------------------------------------------------------------------------
; Direct calls: foo()
(call_expression
  function: (identifier) @name) @reference.call

; Method calls: obj.method()
(call_expression
  function: (member_expression
    object: (identifier) @object
    property: (property_identifier) @method)) @reference.call

; Chained method calls: obj.a.b()
(call_expression
  function: (member_expression
    property: (property_identifier) @method)) @reference.method_call

; new X()
(new_expression
  constructor: (identifier) @name) @reference.class

; ---------------------------------------------------------------------------
; Type references (TypeScript-specific)
; ---------------------------------------------------------------------------
; Variable type annotations: x: Foo
(type_annotation
  (type_identifier) @name) @reference.type

; Generic type arguments: Promise<Foo>
(generic_type
  name: (type_identifier) @name) @reference.type
