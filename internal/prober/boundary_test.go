package prober_test

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestImportBoundary enforces design §6.4 for the prober: it must not import
// internal/search, internal/scoring, or internal/importsvc — it speaks only the
// public HTTP contract and the tlevent schema. Test files are exempt.
func TestImportBoundary(t *testing.T) {
	forbidden := []string{"internal/search", "internal/scoring", "internal/importsvc"}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.Contains(p, bad) {
					t.Errorf("%s imports %q — forbidden by §6.4", name, p)
				}
			}
		}
	}
}
