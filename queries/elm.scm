; =============================================================================
; CodeGraph: Elm Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.type, @name

; ---------------------------------------------------------------------------
; Value/function declarations
; ---------------------------------------------------------------------------
(value_declaration
  (function_declaration_left
    (lower_case_identifier) @name)) @definition.function

; ---------------------------------------------------------------------------
; Type alias declarations
; ---------------------------------------------------------------------------
(type_alias_declaration
  (upper_case_identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Custom type declarations (union types)
; ---------------------------------------------------------------------------
(type_declaration
  (upper_case_identifier) @name) @definition.type

; ---------------------------------------------------------------------------
; Port declarations
; ---------------------------------------------------------------------------
(port_annotation
  (lower_case_identifier) @name) @definition.function

; ---------------------------------------------------------------------------
; Module declarations
; ---------------------------------------------------------------------------
(module_declaration
  (upper_case_qid) @name) @definition.variable

; ---------------------------------------------------------------------------
; Import statements
; ---------------------------------------------------------------------------
(import_clause
  (upper_case_qid) @name) @reference.import
