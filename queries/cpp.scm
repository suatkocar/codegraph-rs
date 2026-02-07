; =============================================================================
; CodeGraph: C++ Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.method,
;           @definition.enum, @definition.type, @definition.variable,
;           @name, @reference.call, @reference.import, @inheritance.extends,
;           @reference.type

; ---------------------------------------------------------------------------
; Functions
; ---------------------------------------------------------------------------
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name)) @definition.function

; ---------------------------------------------------------------------------
; Qualified function definitions (ClassName::method)
; ---------------------------------------------------------------------------
(function_definition
  declarator: (function_declarator
    declarator: (qualified_identifier
      name: (identifier) @name))) @definition.method

; ---------------------------------------------------------------------------
; Classes
; ---------------------------------------------------------------------------
(class_specifier
  name: (type_identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Structs
; ---------------------------------------------------------------------------
(struct_specifier
  name: (type_identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Unions
; ---------------------------------------------------------------------------
(union_specifier
  name: (type_identifier) @name) @definition.class

; ---------------------------------------------------------------------------
; Enums (regular and scoped)
; ---------------------------------------------------------------------------
(enum_specifier
  name: (type_identifier) @name) @definition.enum

; ---------------------------------------------------------------------------
; Namespaces
; ---------------------------------------------------------------------------
(namespace_definition
  name: (namespace_identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Typedefs and using type aliases
; ---------------------------------------------------------------------------
(type_definition
  declarator: (type_identifier) @name) @definition.type

(alias_declaration
  name: (type_identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Field declarations inside classes/structs
; ---------------------------------------------------------------------------
(field_declaration
  declarator: (field_identifier) @name) @definition.variable

; ---------------------------------------------------------------------------
; Function declarations (prototypes in headers)
; ---------------------------------------------------------------------------
(declaration
  declarator: (function_declarator
    declarator: (identifier) @name)) @definition.function

; ---------------------------------------------------------------------------
; Template declarations
; ---------------------------------------------------------------------------
(template_declaration
  (function_definition
    declarator: (function_declarator
      declarator: (identifier) @name))) @definition.function

(template_declaration
  (class_specifier
    name: (type_identifier) @name)) @definition.class

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
; Direct calls: foo()
(call_expression
  function: (identifier) @name) @reference.call

; Member calls: obj.method() or ptr->method()
(call_expression
  function: (field_expression
    field: (field_identifier) @name)) @reference.call

; Qualified calls: ClassName::staticMethod()
(call_expression
  function: (qualified_identifier
    name: (identifier) @name)) @reference.call

; Scoped template calls: std::make_shared<T>()
(call_expression
  function: (template_function
    name: (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; #include
; ---------------------------------------------------------------------------
(preproc_include
  path: (_) @name) @reference.import

; ---------------------------------------------------------------------------
; Using declarations
; ---------------------------------------------------------------------------
(using_declaration
  (_) @name) @reference.import

; ---------------------------------------------------------------------------
; Macro definitions
; ---------------------------------------------------------------------------
(preproc_def
  name: (identifier) @name) @definition.variable

(preproc_function_def
  name: (identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Base class (inheritance)
; ---------------------------------------------------------------------------
(base_class_clause
  (type_identifier) @name) @inheritance.extends

; ---------------------------------------------------------------------------
; Type references
; ---------------------------------------------------------------------------
(type_identifier) @reference.type
