; =============================================================================
; CodeGraph: Kotlin Tree-sitter Queries (tree-sitter-kotlin-ng grammar)
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.method,
;           @definition.variable, @definition.type, @definition.enum,
;           @name, @reference.call, @reference.import, @inheritance.extends,
;           @reference.type

; ---------------------------------------------------------------------------
; Functions (top-level)
; ---------------------------------------------------------------------------
(function_declaration
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Classes (covers class, data class, interface, enum class via modifiers)
; ---------------------------------------------------------------------------
(class_declaration
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Objects (singleton)
; ---------------------------------------------------------------------------
(object_declaration
  name: (identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Type aliases
; ---------------------------------------------------------------------------
(type_alias
  type: (identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Properties (val / var)
; ---------------------------------------------------------------------------
(property_declaration
  (variable_declaration
    (identifier) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
; Direct calls: foo(), ClassName()
(call_expression
  (identifier) @name) @reference.call

; Method/navigation calls: obj.method()
(call_expression
  (navigation_expression
    (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Imports
; ---------------------------------------------------------------------------
(import
  (qualified_identifier) @name) @reference.import

; ---------------------------------------------------------------------------
; Inheritance (delegation specifiers: class Foo : Bar, Baz)
; ---------------------------------------------------------------------------
(delegation_specifier
  (user_type
    (identifier) @name)) @inheritance.extends

; ---------------------------------------------------------------------------
; Type references
; ---------------------------------------------------------------------------
(user_type
  (identifier) @name) @reference.type
