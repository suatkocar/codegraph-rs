; =============================================================================
; CodeGraph: Java Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.method,
;           @definition.interface, @definition.enum, @definition.variable,
;           @name, @reference.call, @reference.import, @inheritance.extends,
;           @inheritance.implements, @reference.type

; ---------------------------------------------------------------------------
; Classes
; ---------------------------------------------------------------------------
(class_declaration
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Interfaces
; ---------------------------------------------------------------------------
(interface_declaration
  name: (identifier) @name) @definition.interface

; ---------------------------------------------------------------------------
; Enums
; ---------------------------------------------------------------------------
(enum_declaration
  name: (identifier) @name) @definition.enum

; ---------------------------------------------------------------------------
; Methods
; ---------------------------------------------------------------------------
(method_declaration
  name: (identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Constructors
; ---------------------------------------------------------------------------
(constructor_declaration
  name: (identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Fields
; ---------------------------------------------------------------------------
(field_declaration
  declarator: (variable_declarator
    name: (identifier) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Local variables
; ---------------------------------------------------------------------------
(local_variable_declaration
  declarator: (variable_declarator
    name: (identifier) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Annotations
; ---------------------------------------------------------------------------
(marker_annotation
  name: (identifier) @name) @reference.call

(annotation
  name: (identifier) @name) @reference.call

; ---------------------------------------------------------------------------
; Method invocations
; ---------------------------------------------------------------------------
(method_invocation
  name: (identifier) @name) @reference.call

; ---------------------------------------------------------------------------
; Object creation: new ClassName()
; ---------------------------------------------------------------------------
(object_creation_expression
  type: (type_identifier) @name) @reference.call

; ---------------------------------------------------------------------------
; Imports
; ---------------------------------------------------------------------------
(import_declaration
  (scoped_identifier) @name) @reference.import

; ---------------------------------------------------------------------------
; Package declaration
; ---------------------------------------------------------------------------
(package_declaration
  (scoped_identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Extends
; ---------------------------------------------------------------------------
(superclass
  (type_identifier) @name) @inheritance.extends

; ---------------------------------------------------------------------------
; Implements
; ---------------------------------------------------------------------------
(super_interfaces
  (type_list
    (type_identifier) @name)) @inheritance.implements

; ---------------------------------------------------------------------------
; Interface extends
; ---------------------------------------------------------------------------
(extends_interfaces
  (type_list
    (type_identifier) @name)) @inheritance.extends

; ---------------------------------------------------------------------------
; Type references
; ---------------------------------------------------------------------------
(type_identifier) @reference.type
