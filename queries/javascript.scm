; =============================================================================
; CodeGraph: JavaScript / JSX Tree-sitter Queries
; =============================================================================
; Same structure as typescript.scm but without type-specific patterns
; (no interfaces, type aliases, enums, type annotations, generics).
; =============================================================================

; ---------------------------------------------------------------------------
; Function declarations
; ---------------------------------------------------------------------------
(function_declaration
  name: (identifier) @name) @definition.function

; Arrow functions and function expressions assigned to variables
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
  name: (identifier) @name) @definition.class

; Class heritage (extends)
(class_declaration
  name: (identifier) @name
  (class_heritage
    (identifier) @superclass)) @definition.class_with_heritage

; ---------------------------------------------------------------------------
; Method definitions (inside class body)
; ---------------------------------------------------------------------------
(method_definition
  name: (property_identifier) @name) @definition.method

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

; import { a, b } from "mod"
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
(export_statement) @export

; Re-exports: export { ... } from "mod"
(export_statement
  source: (string) @source) @reexport

; export default
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
