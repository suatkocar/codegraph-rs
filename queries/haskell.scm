; =============================================================================
; CodeGraph: Haskell Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class (data types),
;           @definition.interface (type classes), @name

; ---------------------------------------------------------------------------
; Function declarations
; ---------------------------------------------------------------------------
(decl
  name: (variable) @name) @definition.function

; Multiple bindings
(decl
  names: (binding_list
    (variable) @name)) @definition.function

; ---------------------------------------------------------------------------
; Data type declarations (mapped to class for compatibility)
; ---------------------------------------------------------------------------
(data_type
  (name) @name) @definition.class

; ---------------------------------------------------------------------------
; Newtype declarations
; ---------------------------------------------------------------------------
(newtype
  (name) @name) @definition.class

; ---------------------------------------------------------------------------
; Type class declarations (mapped to interface)
; ---------------------------------------------------------------------------
(class
  (name) @name) @definition.interface

; ---------------------------------------------------------------------------
; Import statements
; ---------------------------------------------------------------------------
(import
  (module) @name) @reference.import
