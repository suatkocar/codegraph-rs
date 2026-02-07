; =============================================================================
; CodeGraph: PHP Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.method,
;           @definition.interface, @definition.enum, @definition.variable,
;           @name, @reference.call, @reference.import, @inheritance.extends,
;           @inheritance.implements, @reference.type

; ---------------------------------------------------------------------------
; Functions
; ---------------------------------------------------------------------------
(function_definition
  name: (name) @name) @definition.function

; ---------------------------------------------------------------------------
; Classes
; ---------------------------------------------------------------------------
(class_declaration
  name: (name) @name) @definition.class

; ---------------------------------------------------------------------------
; Interfaces
; ---------------------------------------------------------------------------
(interface_declaration
  name: (name) @name) @definition.interface

; ---------------------------------------------------------------------------
; Traits -> mapped to @definition.interface
; ---------------------------------------------------------------------------
(trait_declaration
  name: (name) @name) @definition.interface

; ---------------------------------------------------------------------------
; Enums (PHP 8.1+)
; ---------------------------------------------------------------------------
(enum_declaration
  name: (name) @name) @definition.enum

; ---------------------------------------------------------------------------
; Methods
; ---------------------------------------------------------------------------
(method_declaration
  name: (name) @name) @definition.method

; ---------------------------------------------------------------------------
; Properties
; ---------------------------------------------------------------------------
(property_declaration
  (property_element
    (variable_name) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Class constants
; ---------------------------------------------------------------------------
(const_element
  (name) @name) @definition.variable

; ---------------------------------------------------------------------------
; Namespace declarations
; ---------------------------------------------------------------------------
(namespace_definition
  name: (namespace_name) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
; Regular function calls
(function_call_expression
  function: (name) @name) @reference.call

; Method calls: $obj->method()
(member_call_expression
  name: (name) @name) @reference.call

; Static calls: ClassName::method()
(scoped_call_expression
  name: (name) @name) @reference.call

; ---------------------------------------------------------------------------
; Use/require imports
; ---------------------------------------------------------------------------
; use Namespace\Class
(namespace_use_clause
  (qualified_name) @name) @reference.import

; ---------------------------------------------------------------------------
; Extends
; ---------------------------------------------------------------------------
(base_clause
  (name) @name) @inheritance.extends

; ---------------------------------------------------------------------------
; Implements
; ---------------------------------------------------------------------------
(class_interface_clause
  (name) @name) @inheritance.implements

; ---------------------------------------------------------------------------
; Type references (function parameters, return types)
; ---------------------------------------------------------------------------
(named_type
  (name) @name) @reference.type

(named_type
  (qualified_name) @name) @reference.type
