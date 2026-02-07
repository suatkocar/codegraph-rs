; =============================================================================
; CodeGraph: Swift Tree-sitter Queries (tree-sitter-swift 0.7)
; =============================================================================
; Note: In this grammar, class/struct/enum/extension/actor are ALL represented
; as `class_declaration` with different `declaration_kind` field values.
; There is no separate `enum_declaration` or `struct_declaration`.
;
; Captures: @definition.function, @definition.class, @definition.interface,
;           @definition.variable, @name, @reference.call, @reference.import,
;           @inheritance.extends

; ---------------------------------------------------------------------------
; Functions (top-level and methods share function_declaration)
; ---------------------------------------------------------------------------
(function_declaration
  name: (simple_identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Classes / Structs / Enums / Extensions / Actors
; (all are class_declaration, differentiated by declaration_kind)
; ---------------------------------------------------------------------------
(class_declaration
  name: (type_identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Protocols → interface
; ---------------------------------------------------------------------------
(protocol_declaration
  name: (type_identifier) @name) @definition.interface

; ---------------------------------------------------------------------------
; Protocol function declarations → method
; ---------------------------------------------------------------------------
(protocol_function_declaration
  name: (simple_identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Properties (val / var / let)
; ---------------------------------------------------------------------------
(property_declaration
  name: (pattern
    (simple_identifier) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Enum entries (case values)
; ---------------------------------------------------------------------------
(enum_entry
  name: (simple_identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(call_expression
  (simple_identifier) @name) @reference.call

; Navigation calls: obj.method()
(call_expression
  (navigation_expression
    (simple_identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Imports
; ---------------------------------------------------------------------------
(import_declaration
  (identifier) @name) @reference.import

; ---------------------------------------------------------------------------
; Inheritance (via inheritance_specifier)
; ---------------------------------------------------------------------------
(inheritance_specifier
  inherits_from: (user_type
    (type_identifier) @name)) @inheritance.extends
