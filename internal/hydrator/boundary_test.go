package hydrator_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestImportBoundary enforces design §6.4: the hydrator (and the shared tlevent
// package) must not import internal/search, internal/scoring, or
// internal/importsvc. The hydrator speaks only the public HTTP contract, so the
// coupling stays one-way. Test files are exempt (they may import anything).
func TestImportBoundary(t *testing.T) {
	forbidden := []string{"internal/search", "internal/scoring", "internal/importsvc"}
	dirs := []string{".", "../tlevent"}

	fset := token.NewFileSet()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", dir, name, err)
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbidden {
					if strings.Contains(p, bad) {
						t.Errorf("%s/%s imports %q — forbidden by §6.4", dir, name, p)
					}
				}
			}
		}
	}
}
