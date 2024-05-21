package tree_sitter_zeek_test

import (
	"testing"

	tree_sitter "github.com/smacker/go-tree-sitter"
	"github.com/tree-sitter/tree-sitter-zeek"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_zeek.Language())
	if language == nil {
		t.Errorf("Error loading Zeek grammar")
	}
}
