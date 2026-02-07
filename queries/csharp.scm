; =============================================================================
; CodeGraph: C# Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.method,
;           @definition.interface, @definition.enum, @definition.type,
;           @definition.variable, @name, @reference.call, @reference.import,
;           @inheritance.extends, @reference.type

; ---------------------------------------------------------------------------
; Classes
; ---------------------------------------------------------------------------
(class_declaration
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Records (C# 9+)
; ---------------------------------------------------------------------------
(record_declaration
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Interfaces
; ---------------------------------------------------------------------------
(interface_declaration
  name: (identifier) @name) @definition.interface

; ---------------------------------------------------------------------------
; Structs
; ---------------------------------------------------------------------------
(struct_declaration
  name: (identifier) @name) @definition.class

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
; Properties
; ---------------------------------------------------------------------------
(property_declaration
  name: (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Fields
; ---------------------------------------------------------------------------
(field_declaration
  (variable_declaration
    (variable_declarator
      (identifier) @name))) @definition.variable

; ---------------------------------------------------------------------------
; Delegates (function type)
; ---------------------------------------------------------------------------
(delegate_declaration
  name: (identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Events
; ---------------------------------------------------------------------------
(event_declaration
  name: (identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Namespaces
; ---------------------------------------------------------------------------
(namespace_declaration
  name: (_) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(invocation_expression
  function: (member_access_expression
    name: (identifier) @name)) @reference.call

(invocation_expression
  function: (identifier) @name) @reference.call

; Object creation: new ClassName()
(object_creation_expression
  type: (identifier) @name) @reference.call

; ---------------------------------------------------------------------------
; Using imports
; ---------------------------------------------------------------------------
(using_directive
  (_) @name) @reference.import

; ---------------------------------------------------------------------------
; Base class / interface inheritance
; ---------------------------------------------------------------------------
(base_list
  (identifier) @name) @inheritance.extends

; ---------------------------------------------------------------------------
; Attributes (annotations)
; ---------------------------------------------------------------------------
(attribute
  name: (identifier) @name) @reference.call

; ---------------------------------------------------------------------------
; Type references (generic names and predefined types)
; ---------------------------------------------------------------------------
(generic_name
  (identifier) @name) @reference.type
