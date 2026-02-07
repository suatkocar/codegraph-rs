; =============================================================================
; CodeGraph: C Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class (struct), @definition.enum,
;           @definition.type, @definition.variable, @name, @reference.call,
;           @reference.import, @reference.type

; ---------------------------------------------------------------------------
; Function definitions
; ---------------------------------------------------------------------------
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name)) @definition.function

; ---------------------------------------------------------------------------
; Function declarations (prototypes)
; ---------------------------------------------------------------------------
(declaration
  declarator: (function_declarator
    declarator: (identifier) @name)) @definition.function

; ---------------------------------------------------------------------------
; Structs -> mapped to @definition.class
; ---------------------------------------------------------------------------
(struct_specifier
  name: (type_identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Unions -> mapped to @definition.class
; ---------------------------------------------------------------------------
(union_specifier
  name: (type_identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Enums
; ---------------------------------------------------------------------------
(enum_specifier
  name: (type_identifier) @name) @definition.enum

; ---------------------------------------------------------------------------
; Typedefs
; ---------------------------------------------------------------------------
(type_definition
  declarator: (type_identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Global variables (with initializer)
; ---------------------------------------------------------------------------
(declaration
  declarator: (init_declarator
    declarator: (identifier) @name)) @definition.variable

; ---------------------------------------------------------------------------
; Macro definitions (#define)
; ---------------------------------------------------------------------------
(preproc_def
  name: (identifier) @name) @definition.variable

(preproc_function_def
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
; Direct calls: foo()
(call_expression
  function: (identifier) @name) @reference.call

; Member calls: ptr->method() or obj.method()
(call_expression
  function: (field_expression
    field: (field_identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; #include
; ---------------------------------------------------------------------------
(preproc_include
  path: (_) @name) @reference.import

; ---------------------------------------------------------------------------
; Type references
; ---------------------------------------------------------------------------
(type_identifier) @reference.type
