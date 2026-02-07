; =============================================================================
; CodeGraph: Ruby Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.method,
;           @definition.variable, @name, @reference.call, @reference.import,
;           @inheritance.extends

; ---------------------------------------------------------------------------
; Methods (def)
; ---------------------------------------------------------------------------
(method
  name: (identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Singleton methods (def self.method_name)
; ---------------------------------------------------------------------------
(singleton_method
  name: (identifier) @name) @definition.method

; ---------------------------------------------------------------------------
; Classes
; ---------------------------------------------------------------------------
(class
  name: (constant) @name) @definition.class

; Classes with scope resolution: class Foo::Bar
(class
  name: (scope_resolution
    name: (constant) @name)) @definition.class

; ---------------------------------------------------------------------------
; Modules -> mapped to @definition.class
; ---------------------------------------------------------------------------
(module
  name: (constant) @name) @definition.class

; ---------------------------------------------------------------------------
; Constants (CONSTANT = value)
; ---------------------------------------------------------------------------
(assignment
  left: (constant) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(call
  method: (identifier) @name) @reference.call

; ---------------------------------------------------------------------------
; Require / include / extend
; ---------------------------------------------------------------------------
(call
  method: (identifier) @_method
  arguments: (argument_list
    (string
      (string_content) @name))
  (#match? @_method "^(require|require_relative|include|extend|prepend|load)$")) @reference.import

; ---------------------------------------------------------------------------
; Superclass (inheritance)
; ---------------------------------------------------------------------------
(superclass
  (constant) @name) @inheritance.extends

; Superclass with scope resolution: class Foo < Bar::Baz
(superclass
  (scope_resolution
    name: (constant) @name)) @inheritance.extends

; ---------------------------------------------------------------------------
; Attribute accessors (define virtual methods)
; ---------------------------------------------------------------------------
(call
  method: (identifier) @_method
  arguments: (argument_list
    (simple_symbol) @name)
  (#match? @_method "^(attr_accessor|attr_reader|attr_writer)$")) @definition.method
