; =============================================================================
; CodeGraph: Verilog/SystemVerilog Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class, @definition.interface,
;           @name

; ---------------------------------------------------------------------------
; Module declarations
; ---------------------------------------------------------------------------
(module_declaration
  (module_header
    (simple_identifier) @name)) @definition.class

; ---------------------------------------------------------------------------
; Interface declarations
; ---------------------------------------------------------------------------
(interface_declaration
  (interface_identifier
    (simple_identifier) @name)) @definition.interface

; ---------------------------------------------------------------------------
; Class declarations
; ---------------------------------------------------------------------------
(class_declaration
  (class_identifier
    (simple_identifier) @name)) @definition.class

; ---------------------------------------------------------------------------
; Task declarations
; ---------------------------------------------------------------------------
(task_body_declaration
  (task_identifier
    (task_identifier
      (simple_identifier) @name))) @definition.function

; ---------------------------------------------------------------------------
; Function declarations
; ---------------------------------------------------------------------------
(function_body_declaration
  (function_identifier
    (function_identifier
      (simple_identifier) @name))) @definition.function
