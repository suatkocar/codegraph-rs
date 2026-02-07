; =============================================================================
; CodeGraph: Clojure Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.variable, @name

; ---------------------------------------------------------------------------
; Function definitions: (defn name [...] body)
; Clojure's tree-sitter-clojure-orchard has a minimal AST — most things are
; list_lit nodes. We capture top-level lists for basic structure.
; ---------------------------------------------------------------------------
(list_lit) @definition.function

; ---------------------------------------------------------------------------
; Symbol references
; ---------------------------------------------------------------------------
(sym_lit) @name
