all: generate

generate:
	tree-sitter generate

test:
	$(MAKE) -C test $@

.PHONY : all generate test
