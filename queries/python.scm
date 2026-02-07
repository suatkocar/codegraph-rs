; =============================================================================
; CodeGraph: Python Tree-sitter Queries
; =============================================================================

; ---------------------------------------------------------------------------
; Function definitions
; ---------------------------------------------------------------------------
(function_definition
  name: (identifier) @name) @definition.function

; Decorated functions (captures the decorator for metadata)
(decorated_definition
  (decorator (identifier) @decorator)
  definition: (function_definition
    name: (identifier) @name)) @definition.decorated_function

; ---------------------------------------------------------------------------
; Class definitions
; ---------------------------------------------------------------------------
(class_definition
  name: (identifier) @name) @definition.class

; Class with base classes (inheritance)
(class_definition
  name: (identifier) @name
  superclasses: (argument_list
    (identifier) @superclass)) @definition.class_with_heritage

; ---------------------------------------------------------------------------
; Method definitions (functions inside a class body)
; ---------------------------------------------------------------------------
(class_definition
  body: (block
    (function_definition
      name: (identifier) @name) @definition.method))

(class_definition
  body: (block
    (decorated_definition
      definition: (function_definition
        name: (identifier) @name) @definition.method)))

; ---------------------------------------------------------------------------
; Variable assignments at module level
; ---------------------------------------------------------------------------
(module
  (expression_statement
    (assignment
      left: (identifier) @name) @definition.variable))

; ---------------------------------------------------------------------------
; Import statements
; ---------------------------------------------------------------------------
; import foo
(import_statement
  name: (dotted_name) @imported_name) @import

; from foo import bar
(import_from_statement
  module_name: (dotted_name) @source) @import

; from foo import bar, baz  – capture individual names
(import_from_statement
  name: (dotted_name) @imported_name)

; from foo import bar as alias
(import_from_statement
  (aliased_import
    name: (dotted_name) @imported_name
    alias: (identifier) @alias))

; ---------------------------------------------------------------------------
; Call expressions
; ---------------------------------------------------------------------------
; Direct calls: foo()
(call
  function: (identifier) @name) @reference.call

; Method calls: obj.method()
(call
  function: (attribute
    object: (identifier) @object
    attribute: (identifier) @method)) @reference.call

; Chained method calls: obj.a.method()
(call
  function: (attribute
    attribute: (identifier) @method)) @reference.method_call

; Constructor-style calls detected via naming convention are handled
; at the extractor level (Python has no `new` keyword).
