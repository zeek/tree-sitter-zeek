# tree-sitter-zeek

[![Tests](https://github.com/ckreibich/tree-sitter-zeek/actions/workflows/test.yaml/badge.svg)](https://github.com/ckreibich/tree-sitter-zeek/actions/workflows/test.yaml)

A [Zeek](https://zeek.org) grammar for [tree-sitter](https://github.com/tree-sitter/tree-sitter).

## Background

This grammar parses scripts written in the [Zeek scripting
language](https://docs.zeek.org/en/master/script-reference/index.html).

The goal of this grammar is to facilitate tooling around Zeek
scripts. For that reason, its structure resembles Zeek's grammar but differs in
a number of ways. For example, it tracks newlines explicitly and relies more
strongly on precedence and associativity to resolve ambiguities. Like Zeek's
parser, this one currently doesn't name symbols deeply: for example, the grammar
features an `expr` rule that covers any kind of expression, but the choices
aren't currently broken down into, say, `addition_expr`, `or_expr`, and
similars.

## Usage

To use the generated parser directly (e.g. via any of tree-sitter's
[language bindings](https://tree-sitter.github.io/tree-sitter/#language-bindings)),
clone this repository recursively. We maintain a separate
[git repository](https://github.com/ckreibich/tree-sitter-zeek-src)
to track generated sources. You do not need the tree-sitter CLI to use
those sources.

## Building the parser

* Install [tree-sitter](https://tree-sitter.github.io/tree-sitter/creating-parsers#installation) on your machine.
* Generate the parser: run `tree-sitter generate`.

## Testing

There's currently no `tree-sitter test` testsuite. Instead, a test driver
clones the Zeek repository and runs on every Zeek script in the distribution.
