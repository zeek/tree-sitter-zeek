# tree-sitter-zeek

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
[git repository](https://github.com/zeek/tree-sitter-zeek-src)
to track generated sources. You do not need the tree-sitter CLI
to use those sources in your tooling, but you'll likely want it
anyway to explore the parser. For example, `tree-sitter parse <script>`
produces the script's syntax tree, and `tree-sitter highlight <script>`
shows syntax-highlighted sources.

## Building the parser

- Install [tree-sitter](https://tree-sitter.github.io/tree-sitter/creating-parsers#installation) on your machine.
- Generate the parser: run `tree-sitter generate`.

## Testing

There's currently no `tree-sitter test` testsuite. Instead, a test driver runs
the parser on every Zeek script in the Zeek distribution, reporting any
errors. For CI, a Github Action workflow additionally clones the Zeek tree prior
to running this test, to ensure that those Zeek scripts are available.

## Releasing a new version

To release a new version manually update the version number in the following
ecosystem-specific files:

- `package.json`: key `version`
  - `package-lock.json`: update `package.json` and run `npm install` to update the lock file.
- `pyproject.toml`: key `project.version`
- `Cargo.toml`: key `package.version`
- `tree-sitter.json`: key `metadata.version`
- `CMakeLists.txt`: `VERSION` in `project` call

Once all versions are consistently updated create a version tag `vX.Y.Z` and
push it. We trigger automatic publishing of releases for all tags.
