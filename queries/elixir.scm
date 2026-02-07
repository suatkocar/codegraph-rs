; =============================================================================
; CodeGraph: Elixir Tree-sitter Queries
; =============================================================================
; Captures: @definition.function, @definition.class (modules),
;           @name, @reference.call

; ---------------------------------------------------------------------------
; Module definitions: defmodule MyModule do ... end
; ---------------------------------------------------------------------------
(call
  target: (identifier) @_keyword
  (arguments
    (alias) @name)
  (#eq? @_keyword "defmodule")) @definition.class

; ---------------------------------------------------------------------------
; Function definitions: def name(...) do ... end
; ---------------------------------------------------------------------------
(call
  target: (identifier) @_keyword
  (arguments
    (identifier) @name)
  (#match? @_keyword "^(def|defp)$")) @definition.function

; Function definitions with call form: def name(args) do ... end
(call
  target: (identifier) @_keyword
  (arguments
    (call
      target: (identifier) @name))
  (#match? @_keyword "^(def|defp)$")) @definition.function

; ---------------------------------------------------------------------------
; Macro definitions: defmacro name(...) do ... end
; ---------------------------------------------------------------------------
(call
  target: (identifier) @_keyword
  (arguments
    (call
      target: (identifier) @name))
  (#match? @_keyword "^(defmacro|defmacrop)$")) @definition.function

; ---------------------------------------------------------------------------
; Function calls
; ---------------------------------------------------------------------------
(call
  target: (identifier) @name) @reference.call

; Remote calls: Module.function()
(call
  target: (dot
    right: (identifier) @name)) @reference.call

; ---------------------------------------------------------------------------
; Import/use/require
; ---------------------------------------------------------------------------
(call
  target: (identifier) @_keyword
  (arguments
    (alias) @name)
  (#match? @_keyword "^(import|use|require|alias)$")) @reference.import
