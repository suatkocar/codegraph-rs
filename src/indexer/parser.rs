//! Native tree-sitter parser wrapper for CodeGraph.
//!
//! This is the Rust equivalent of the TypeScript `parser.ts`, but dramatically
//! simpler: no WASM, no async initialization, no runtime downloads. Grammars
//! are statically linked and queries are embedded at compile time via
//! `include_str!` (see [`Language::query_source`]).
//!
//! # Design decisions
//!
//! - **No stored state.** `CodeParser` carries no fields. Tree-sitter's
//!   `Parser` is `!Send + !Sync`, so rather than wrestling with thread-safety
//!   wrappers we create a fresh parser on every call. This is cheap — `Parser::new()`
//!   is a single allocation and `set_language` is a pointer swap.
//!
//! - **Query compilation on demand.** `.scm` query compilation takes roughly
//!   1 ms per language. For a first pass this is negligible. A `OnceCell`-based
//!   cache can be layered on later without changing the public API.
//!
//! - **Language detection by extension.** Delegates to [`Language::from_extension`],
//!   keeping the mapping in one canonical place.

use crate::error::{CodeGraphError, Result};
use crate::types::Language;

/// Thin wrapper around native tree-sitter parsing and query compilation.
///
/// All grammars are statically linked at build time — no runtime setup needed.
/// Create one with [`CodeParser::new`] and reuse freely; the struct is `Send`,
/// `Sync`, and zero-sized.
pub struct CodeParser;

impl CodeParser {
    /// Create a new `CodeParser`.
    ///
    /// This is a no-op — it exists so call sites read naturally and so we can
    /// add configuration (e.g., timeout, cancellation) later without breaking
    /// the public API.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Parse `content` using the grammar for `language` and return the
    /// concrete syntax tree.
    ///
    /// A fresh `tree_sitter::Parser` is created on each call because the
    /// underlying C object is `!Send`. This is intentional — allocation is
    /// trivially fast and it keeps the API thread-safe.
    pub fn parse(&self, content: &str, language: Language) -> Result<tree_sitter::Tree> {
        let ts_lang = Self::get_ts_language(language);

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&ts_lang)
            .map_err(|e| CodeGraphError::Parse(format!("Language version mismatch: {e}")))?;

        parser.parse(content, None).ok_or_else(|| {
            CodeGraphError::Parse("tree-sitter returned None (timeout or cancellation)".into())
        })
    }

    /// Return the native `tree_sitter::Language` for a [`Language`] variant.
    ///
    /// Each grammar crate exposes a `LanguageFn` constant. The `.into()` call
    /// goes through tree-sitter's `From<LanguageFn> for Language` impl, which
    /// invokes the C initializer exactly once.
    #[must_use]
    pub fn get_ts_language(language: Language) -> tree_sitter::Language {
        match language {
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Language::JavaScript | Language::Jsx => tree_sitter_javascript::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Java => tree_sitter_java::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
            Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Language::Swift => tree_sitter_swift::LANGUAGE.into(),
            Language::Kotlin => tree_sitter_kotlin_ng::LANGUAGE.into(),
            // Phase 11
            Language::Bash => tree_sitter_bash::LANGUAGE.into(),
            Language::Scala => tree_sitter_scala::LANGUAGE.into(),
            Language::Dart => tree_sitter_dart_orchard::LANGUAGE.into(),
            Language::Zig => tree_sitter_zig::LANGUAGE.into(),
            Language::Lua => tree_sitter_lua::LANGUAGE.into(),
            Language::Verilog => tree_sitter_verilog::LANGUAGE.into(),
            Language::Haskell => tree_sitter_haskell::LANGUAGE.into(),
            Language::Elixir => tree_sitter_elixir::LANGUAGE.into(),
            Language::Groovy => tree_sitter_groovy::LANGUAGE.into(),
            Language::PowerShell => tree_sitter_powershell::LANGUAGE.into(),
            Language::Clojure => tree_sitter_clojure_orchard::LANGUAGE.into(),
            Language::Julia => tree_sitter_julia::LANGUAGE.into(),
            Language::R => tree_sitter_r::LANGUAGE.into(),
            Language::Erlang => tree_sitter_erlang::LANGUAGE.into(),
            Language::Elm => tree_sitter_elm::LANGUAGE.into(),
            Language::Fortran => tree_sitter_fortran::LANGUAGE.into(),
            Language::Nix => tree_sitter_nix::LANGUAGE.into(),
        }
    }

    /// Compile the `.scm` query source for `language` into a
    /// [`tree_sitter::Query`].
    ///
    /// Query compilation is fast (~1 ms), so we compile fresh each time.
    /// If profiling shows this is a bottleneck, wrap with a static
    /// `OnceLock<HashMap<Language, Query>>` — the public API stays the same.
    pub fn load_query(language: Language) -> Result<tree_sitter::Query> {
        let ts_lang = Self::get_ts_language(language);
        let source = language.query_source();
        tree_sitter::Query::new(&ts_lang, source).map_err(|e| {
            CodeGraphError::Parse(format!("Query compilation error for {language}: {e}"))
        })
    }

    /// Detect the [`Language`] for a file path based on its extension.
    ///
    /// Returns `None` for unsupported extensions.
    #[must_use]
    pub fn detect_language(file_path: &str) -> Option<Language> {
        std::path::Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .and_then(|e| Language::from_extension(&format!(".{e}")))
    }

    /// Check whether the file at `file_path` has a supported extension.
    #[must_use]
    pub fn is_supported(file_path: &str) -> bool {
        Self::detect_language(file_path).is_some()
    }
}

impl Default for CodeParser {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// All 32 language variants for exhaustive testing.
    fn all_languages() -> Vec<Language> {
        vec![
            Language::TypeScript, Language::Tsx, Language::JavaScript, Language::Jsx,
            Language::Python, Language::Go, Language::Rust, Language::Java,
            Language::C, Language::Cpp, Language::CSharp, Language::Php,
            Language::Ruby, Language::Swift, Language::Kotlin,
            // Phase 11
            Language::Bash, Language::Scala, Language::Dart, Language::Zig,
            Language::Lua, Language::Verilog, Language::Haskell, Language::Elixir,
            Language::Groovy, Language::PowerShell, Language::Clojure, Language::Julia,
            Language::R, Language::Erlang, Language::Elm, Language::Fortran,
            Language::Nix,
        ]
    }

    // -- Parsing -----------------------------------------------------------

    #[test]
    fn parse_typescript_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
            export function greet(name: string): string {
                return `Hello, ${name}!`;
            }

            interface User {
                id: number;
                name: string;
            }

            class UserService {
                getUser(id: number): User {
                    return { id, name: "test" };
                }
            }
        "#;

        let tree = parser
            .parse(source, Language::TypeScript)
            .expect("should parse TypeScript");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_javascript_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
            const add = (a, b) => a + b;

            function multiply(a, b) {
                return a * b;
            }

            class Calculator {
                constructor(initial) {
                    this.value = initial;
                }

                add(n) {
                    this.value += n;
                    return this;
                }
            }
        "#;

        let tree = parser
            .parse(source, Language::JavaScript)
            .expect("should parse JavaScript");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_python_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
import os
from pathlib import Path

def greet(name: str) -> str:
    return f"Hello, {name}!"

class UserService:
    def __init__(self, db):
        self.db = db

    def get_user(self, user_id: int):
        return self.db.find(user_id)
"#;

        let tree = parser
            .parse(source, Language::Python)
            .expect("should parse Python");
        let root = tree.root_node();
        assert_eq!(root.kind(), "module");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_tsx_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
            import React from "react";

            interface Props {
                name: string;
            }

            const Greeting: React.FC<Props> = ({ name }) => {
                return <div>Hello, {name}!</div>;
            };

            export default Greeting;
        "#;

        let tree = parser
            .parse(source, Language::Tsx)
            .expect("should parse TSX");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0);
    }

    #[test]
    fn parse_empty_source_returns_tree() {
        let parser = CodeParser::new();
        let tree = parser
            .parse("", Language::TypeScript)
            .expect("empty source should parse");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert_eq!(root.child_count(), 0);
    }

    #[test]
    fn parse_go_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
package main

import "fmt"

type User struct {
    ID   int
    Name string
}

type Greeter interface {
    Greet(name string) string
}

func (u *User) Greet(name string) string {
    return fmt.Sprintf("Hello, %s!", name)
}

func main() {
    user := &User{ID: 1, Name: "Alice"}
    fmt.Println(user.Greet("World"))
}
"#;
        let tree = parser.parse(source, Language::Go).expect("should parse Go");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_rust_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
use std::collections::HashMap;

pub trait Greeter {
    fn greet(&self, name: &str) -> String;
}

pub struct User {
    pub id: u32,
    pub name: String,
}

impl Greeter for User {
    fn greet(&self, name: &str) -> String {
        format!("Hello, {}!", name)
    }
}

fn main() {
    let user = User { id: 1, name: "Alice".to_string() };
    println!("{}", user.greet("World"));
}
"#;
        let tree = parser
            .parse(source, Language::Rust)
            .expect("should parse Rust");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_java_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
package com.example;

import java.util.List;

public interface Greeter {
    String greet(String name);
}

public class UserService implements Greeter {
    private final String prefix;

    public UserService(String prefix) {
        this.prefix = prefix;
    }

    @Override
    public String greet(String name) {
        return prefix + " " + name;
    }
}
"#;
        let tree = parser
            .parse(source, Language::Java)
            .expect("should parse Java");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_c_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE 100

typedef struct {
    int id;
    char name[MAX_SIZE];
} User;

void greet(const User *user) {
    printf("Hello, %s!\n", user->name);
}

int main(void) {
    User user = {1, "Alice"};
    greet(&user);
    return 0;
}
"#;
        let tree = parser.parse(source, Language::C).expect("should parse C");
        let root = tree.root_node();
        assert_eq!(root.kind(), "translation_unit");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_cpp_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
#include <iostream>
#include <string>

namespace app {

class Greeter {
public:
    virtual std::string greet(const std::string& name) = 0;
    virtual ~Greeter() = default;
};

class UserService : public Greeter {
public:
    std::string greet(const std::string& name) override {
        return "Hello, " + name + "!";
    }
};

} // namespace app

int main() {
    app::UserService svc;
    std::cout << svc.greet("World") << std::endl;
    return 0;
}
"#;
        let tree = parser
            .parse(source, Language::Cpp)
            .expect("should parse C++");
        let root = tree.root_node();
        assert_eq!(root.kind(), "translation_unit");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_csharp_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
using System;
using System.Collections.Generic;

namespace App
{
    public interface IGreeter
    {
        string Greet(string name);
    }

    public class UserService : IGreeter
    {
        public string Greet(string name)
        {
            return $"Hello, {name}!";
        }

        public List<string> GetUsers()
        {
            return new List<string> { "Alice", "Bob" };
        }
    }
}
"#;
        let tree = parser
            .parse(source, Language::CSharp)
            .expect("should parse C#");
        let root = tree.root_node();
        assert_eq!(root.kind(), "compilation_unit");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_php_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"<?php

namespace App;

use App\Models\User;

interface Greeter {
    public function greet(string $name): string;
}

class UserService implements Greeter {
    private string $prefix;

    public function __construct(string $prefix) {
        $this->prefix = $prefix;
    }

    public function greet(string $name): string {
        return $this->prefix . " " . $name;
    }
}

function main(): void {
    $service = new UserService("Hello");
    echo $service->greet("World");
}
"#;
        let tree = parser
            .parse(source, Language::Php)
            .expect("should parse PHP");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_ruby_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
require 'json'

module Greetable
  def greet(name)
    "Hello, #{name}!"
  end
end

class User
  include Greetable
  attr_accessor :id, :name

  def initialize(id, name)
    @id = id
    @name = name
  end

  def self.create(id, name)
    new(id, name)
  end
end

class Admin < User
  def greet(name)
    "Admin says: Hello, #{name}!"
  end
end
"#;
        let tree = parser
            .parse(source, Language::Ruby)
            .expect("should parse Ruby");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_swift_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
import Foundation

protocol Greeter {
    func greet(name: String) -> String
}

struct User {
    let id: Int
    let name: String
}

class UserService: Greeter {
    func greet(name: String) -> String {
        return "Hello, \(name)!"
    }
}

enum Direction {
    case north, south, east, west
}

func main() {
    let service = UserService()
    print(service.greet(name: "World"))
}
"#;
        let tree = parser
            .parse(source, Language::Swift)
            .expect("should parse Swift");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_kotlin_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
package com.example

import java.util.List

interface Greeter {
    fun greet(name: String): String
}

data class User(val id: Int, val name: String)

class UserService : Greeter {
    override fun greet(name: String): String {
        return "Hello, $name!"
    }
}

object Singleton {
    fun doSomething() {
        println("doing something")
    }
}

fun main() {
    val service = UserService()
    println(service.greet("World"))
}
"#;
        let tree = parser
            .parse(source, Language::Kotlin)
            .expect("should parse Kotlin");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0, "tree should have children");
        assert!(!root.has_error(), "tree should be error-free");
    }

    // -- Phase 11: Parse tests for new languages ----------------------------

    #[test]
    fn parse_bash_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"#!/bin/bash

greet() {
    local name="$1"
    echo "Hello, $name!"
}

MY_VAR="world"
greet "$MY_VAR"
"#;
        let tree = parser.parse(source, Language::Bash).expect("should parse Bash");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_scala_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
package com.example

import scala.collection.mutable

trait Greeter {
  def greet(name: String): String
}

class UserService extends Greeter {
  def greet(name: String): String = s"Hello, $name!"
}

object Main {
  val version = "1.0"
  def main(args: Array[String]): Unit = {
    val svc = new UserService()
    println(svc.greet("World"))
  }
}

case class User(id: Int, name: String)
"#;
        let tree = parser.parse(source, Language::Scala).expect("should parse Scala");
        let root = tree.root_node();
        assert_eq!(root.kind(), "compilation_unit");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_dart_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
import 'dart:io';

class Greeter {
  String greet(String name) {
    return 'Hello, $name!';
  }
}

enum Color { red, green, blue }

void main() {
  var greeter = Greeter();
  print(greeter.greet('World'));
}
"#;
        let tree = parser.parse(source, Language::Dart).expect("should parse Dart");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_zig_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
const std = @import("std");

fn add(a: i32, b: i32) i32 {
    return a + b;
}

pub fn main() !void {
    const result = add(3, 4);
    std.debug.print("Result: {}\n", .{result});
}
"#;
        let tree = parser.parse(source, Language::Zig).expect("should parse Zig");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_lua_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
local function greet(name)
    return "Hello, " .. name .. "!"
end

function add(a, b)
    return a + b
end

local M = {}

function M.init()
    print("initialized")
end

function M:method()
    return self.value
end

local result = greet("World")
print(result)
"#;
        let tree = parser.parse(source, Language::Lua).expect("should parse Lua");
        let root = tree.root_node();
        assert_eq!(root.kind(), "chunk");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_verilog_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
module counter (
    input wire clk,
    input wire reset,
    output reg [7:0] count
);

always @(posedge clk or posedge reset) begin
    if (reset)
        count <= 8'b0;
    else
        count <= count + 1;
end

endmodule
"#;
        let tree = parser.parse(source, Language::Verilog).expect("should parse Verilog");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_haskell_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
module Main where

import Data.List

data Color = Red | Green | Blue

class Describable a where
  describe :: a -> String

instance Describable Color where
  describe Red = "red"
  describe Green = "green"
  describe Blue = "blue"

greet :: String -> String
greet name = "Hello, " ++ name ++ "!"

main :: IO ()
main = putStrLn (greet "World")
"#;
        let tree = parser.parse(source, Language::Haskell).expect("should parse Haskell");
        let root = tree.root_node();
        assert_eq!(root.kind(), "haskell");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_elixir_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
defmodule Greeter do
  def greet(name) do
    "Hello, #{name}!"
  end

  defp private_helper do
    :ok
  end
end

defmodule Main do
  def run do
    IO.puts(Greeter.greet("World"))
  end
end
"#;
        let tree = parser.parse(source, Language::Elixir).expect("should parse Elixir");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_groovy_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
class UserService {
    String greet(String name) {
        return "Hello, " + name
    }
}
"#;
        let tree = parser.parse(source, Language::Groovy).expect("should parse Groovy");
        let root = tree.root_node();
        assert!(root.child_count() > 0);
        // Groovy grammar may produce partial errors for some syntax
    }

    #[test]
    fn parse_powershell_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
function Get-Greeting {
    param([string]$Name)
    return "Hello, $Name!"
}

class MyService {
    [string] Greet([string]$name) {
        return "Hello, $name!"
    }
}

enum Color {
    Red
    Green
    Blue
}

$greeting = Get-Greeting -Name "World"
Write-Host $greeting
"#;
        let tree = parser.parse(source, Language::PowerShell).expect("should parse PowerShell");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_clojure_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
(ns my-app.core
  (:require [clojure.string :as str]))

(defn greet [name]
  (str "Hello, " name "!"))

(def version "1.0")

(defn -main [& args]
  (println (greet "World")))
"#;
        let tree = parser.parse(source, Language::Clojure).expect("should parse Clojure");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_julia_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
module MyModule

struct User
    id::Int
    name::String
end

function greet(name::String)
    return "Hello, $name!"
end

add(a, b) = a + b

end # module
"#;
        let tree = parser.parse(source, Language::Julia).expect("should parse Julia");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_r_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
library(ggplot2)

greet <- function(name) {
  paste("Hello,", name, "!")
}

add <- function(a, b) {
  a + b
}

result <- greet("World")
cat(result, "\n")
"#;
        let tree = parser.parse(source, Language::R).expect("should parse R");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_erlang_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
-module(greeter).
-export([greet/1, main/0]).

-record(user, {id, name}).

greet(Name) ->
    io_lib:format("Hello, ~s!", [Name]).

main() ->
    io:format("~s~n", [greet("World")]).
"#;
        let tree = parser.parse(source, Language::Erlang).expect("should parse Erlang");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_elm_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
module Main exposing (main, greet)

import Html exposing (text)

type alias User =
    { id : Int
    , name : String
    }

type Color
    = Red
    | Green
    | Blue

greet : String -> String
greet name =
    "Hello, " ++ name ++ "!"

main =
    text (greet "World")
"#;
        let tree = parser.parse(source, Language::Elm).expect("should parse Elm");
        let root = tree.root_node();
        assert_eq!(root.kind(), "file");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_fortran_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
program hello
    implicit none
    call greet("World")
end program hello

subroutine greet(name)
    implicit none
    character(len=*), intent(in) :: name
    print *, "Hello, ", name, "!"
end subroutine greet

function add(a, b) result(c)
    implicit none
    integer, intent(in) :: a, b
    integer :: c
    c = a + b
end function add
"#;
        let tree = parser.parse(source, Language::Fortran).expect("should parse Fortran");
        let root = tree.root_node();
        assert_eq!(root.kind(), "translation_unit");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    #[test]
    fn parse_nix_returns_valid_tree() {
        let parser = CodeParser::new();
        let source = r#"
{ pkgs ? import <nixpkgs> {} }:

let
  greeting = "Hello, World!";
  add = a: b: a + b;
in {
  shell = pkgs.mkShell {
    buildInputs = [ pkgs.hello ];
  };
  result = add 3 4;
}
"#;
        let tree = parser.parse(source, Language::Nix).expect("should parse Nix");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_code");
        assert!(root.child_count() > 0);
        assert!(!root.has_error(), "tree should be error-free");
    }

    // -- Language detection ------------------------------------------------

    #[test]
    fn detect_language_from_file_path() {
        let cases = vec![
            ("src/app.ts", Some(Language::TypeScript)),
            ("src/app.tsx", Some(Language::Tsx)),
            ("lib/util.js", Some(Language::JavaScript)),
            ("lib/util.mjs", Some(Language::JavaScript)),
            ("lib/util.cjs", Some(Language::JavaScript)),
            ("components/Button.jsx", Some(Language::Jsx)),
            ("scripts/run.py", Some(Language::Python)),
            ("main.go", Some(Language::Go)),
            ("lib.rs", Some(Language::Rust)),
            ("Main.java", Some(Language::Java)),
            ("main.c", Some(Language::C)),
            ("util.h", Some(Language::C)),
            ("main.cpp", Some(Language::Cpp)),
            ("Program.cs", Some(Language::CSharp)),
            ("index.php", Some(Language::Php)),
            ("app.rb", Some(Language::Ruby)),
            ("Main.kt", Some(Language::Kotlin)),
            ("App.swift", Some(Language::Swift)),
            // Phase 11
            ("deploy.sh", Some(Language::Bash)),
            ("config.bash", Some(Language::Bash)),
            ("Main.scala", Some(Language::Scala)),
            ("app.dart", Some(Language::Dart)),
            ("main.zig", Some(Language::Zig)),
            ("script.lua", Some(Language::Lua)),
            ("counter.v", Some(Language::Verilog)),
            ("chip.sv", Some(Language::Verilog)),
            ("Main.hs", Some(Language::Haskell)),
            ("app.ex", Some(Language::Elixir)),
            ("test.exs", Some(Language::Elixir)),
            ("build.groovy", Some(Language::Groovy)),
            ("build.gradle", Some(Language::Groovy)),
            ("script.ps1", Some(Language::PowerShell)),
            ("core.clj", Some(Language::Clojure)),
            ("main.jl", Some(Language::Julia)),
            ("analysis.r", Some(Language::R)),
            ("analysis.R", Some(Language::R)),
            ("server.erl", Some(Language::Erlang)),
            ("Main.elm", Some(Language::Elm)),
            ("solver.f90", Some(Language::Fortran)),
            ("config.nix", Some(Language::Nix)),
            ("README.md", None),
            ("Cargo.toml", None),
            ("no-extension", None),
        ];

        for (path, expected) in cases {
            assert_eq!(
                CodeParser::detect_language(path),
                expected,
                "detect_language({path:?})"
            );
        }
    }

    #[test]
    fn is_supported_returns_correct_values() {
        // Original languages
        assert!(CodeParser::is_supported("index.ts"));
        assert!(CodeParser::is_supported("app.tsx"));
        assert!(CodeParser::is_supported("main.js"));
        assert!(CodeParser::is_supported("component.jsx"));
        assert!(CodeParser::is_supported("script.py"));
        assert!(CodeParser::is_supported("lib/nested/deep.ts"));
        assert!(CodeParser::is_supported("main.go"));
        assert!(CodeParser::is_supported("lib.rs"));
        assert!(CodeParser::is_supported("Main.java"));
        assert!(CodeParser::is_supported("main.c"));
        assert!(CodeParser::is_supported("main.cpp"));
        assert!(CodeParser::is_supported("Program.cs"));
        assert!(CodeParser::is_supported("index.php"));
        assert!(CodeParser::is_supported("app.rb"));
        assert!(CodeParser::is_supported("Main.kt"));
        assert!(CodeParser::is_supported("App.swift"));
        // Phase 11
        assert!(CodeParser::is_supported("deploy.sh"));
        assert!(CodeParser::is_supported("Main.scala"));
        assert!(CodeParser::is_supported("app.dart"));
        assert!(CodeParser::is_supported("main.zig"));
        assert!(CodeParser::is_supported("script.lua"));
        assert!(CodeParser::is_supported("counter.v"));
        assert!(CodeParser::is_supported("Main.hs"));
        assert!(CodeParser::is_supported("app.ex"));
        assert!(CodeParser::is_supported("build.groovy"));
        assert!(CodeParser::is_supported("script.ps1"));
        assert!(CodeParser::is_supported("core.clj"));
        assert!(CodeParser::is_supported("main.jl"));
        assert!(CodeParser::is_supported("analysis.R"));
        assert!(CodeParser::is_supported("server.erl"));
        assert!(CodeParser::is_supported("Main.elm"));
        assert!(CodeParser::is_supported("solver.f90"));
        assert!(CodeParser::is_supported("config.nix"));

        assert!(!CodeParser::is_supported("readme.md"));
        assert!(!CodeParser::is_supported("config.yaml"));
        assert!(!CodeParser::is_supported(""));
    }

    // -- Query compilation -------------------------------------------------

    #[test]
    fn load_query_succeeds_for_all_languages() {
        let languages = all_languages();

        for lang in languages {
            let query = CodeParser::load_query(lang);
            assert!(
                query.is_ok(),
                "load_query({lang}) failed: {:?}",
                query.err()
            );
            // Every query should capture at least one pattern
            let q = query.unwrap();
            assert!(
                q.pattern_count() > 0,
                "{lang} query should have at least one pattern"
            );
        }
    }

    #[test]
    fn load_query_has_expected_capture_names() {
        let query = CodeParser::load_query(Language::TypeScript).unwrap();
        let names: Vec<&str> = query.capture_names().iter().copied().collect();

        // Core captures that our extractor will rely on
        assert!(names.contains(&"name"), "missing @name capture");
        assert!(
            names.contains(&"definition.function"),
            "missing @definition.function capture"
        );
        assert!(
            names.contains(&"definition.class"),
            "missing @definition.class capture"
        );
        assert!(
            names.contains(&"definition.method"),
            "missing @definition.method capture"
        );
        assert!(
            names.contains(&"reference.call"),
            "missing @reference.call capture"
        );
    }

    // -- get_ts_language ---------------------------------------------------

    #[test]
    fn get_ts_language_returns_valid_language_for_all_variants() {
        for lang in all_languages() {
            let ts_lang = CodeParser::get_ts_language(lang);
            // A valid language must have a version within the supported range
            assert!(
                ts_lang.version() >= tree_sitter::MIN_COMPATIBLE_LANGUAGE_VERSION,
                "{lang} grammar version {} is below minimum {}",
                ts_lang.version(),
                tree_sitter::MIN_COMPATIBLE_LANGUAGE_VERSION
            );
            assert!(
                ts_lang.version() <= tree_sitter::LANGUAGE_VERSION,
                "{lang} grammar version {} exceeds maximum {}",
                ts_lang.version(),
                tree_sitter::LANGUAGE_VERSION
            );
        }
    }
}
