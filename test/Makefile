all: corpus test

corpus:
	(cd .. && tree-sitter test)

test:
	./parse-zeek-tree.sh

.PHONY : all test
