package server_test

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/importsvc"
	"github.com/agentnameservice/agent-trust-discovery/internal/search"
)

// specPath resolves to spec/api-spec-search.yaml relative to the repo root,
// letting this test run from anywhere in the tree (go test ./..., etc.).
func specPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}
	// Walk up until we find spec/api-spec-search.yaml.
	for range 6 {
		p := filepath.Join(dir, "spec", "api-spec-search.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("spec/api-spec-search.yaml not found from cwd")
	return ""
}

// The Go-side error-code constants and the spec's ProblemDetails.code enum
// must be the same set. A code that lives on one side but not the other is
// exactly the class of drift the spec-conformance pass is meant to trap —
// clients coded to the spec would panic on an unknown code from the server,
// or fail to handle a documented one the server never emits.
func TestErrorCodes_MatchSpec(t *testing.T) {
	b, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	// Decode just enough to reach components.schemas.ProblemDetails.properties.code.enum.
	var doc struct {
		Components struct {
			Schemas struct {
				ProblemDetails struct {
					Properties struct {
						Code struct {
							Enum []string `yaml:"enum"`
						} `yaml:"code"`
					} `yaml:"properties"`
				} `yaml:"ProblemDetails"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}

	specSet := make(map[string]bool, len(doc.Components.Schemas.ProblemDetails.Properties.Code.Enum))
	for _, c := range doc.Components.Schemas.ProblemDetails.Properties.Code.Enum {
		specSet[c] = true
	}
	if len(specSet) == 0 {
		t.Fatalf("spec ProblemDetails.code.enum is empty — did the schema move?")
	}

	// Every Go-side code the server actually emits must be in the spec.
	goCodes := map[string]string{
		"search.CodeNotFound":              search.CodeNotFound,
		"search.CodeInvalidRequest":        search.CodeInvalidRequest,
		"search.CodeInvalidValue":          search.CodeInvalidValue,
		"search.CodeUnknownProfile":        search.CodeUnknownProfile,
		"importsvc.CodeInvalidRequest":     importsvc.CodeInvalidRequest,
		"importsvc.CodeAgentNotFound":      importsvc.CodeAgentNotFound,
		"importsvc.CodeUnknownSignal":      importsvc.CodeUnknownSignal,
		"importsvc.CodeInvalidSignal":      importsvc.CodeInvalidSignal,
		"importsvc.CodeInvalidSignalValue": importsvc.CodeInvalidSignalValue,
		"importsvc.CodeUnauthorized":       importsvc.CodeUnauthorized,
	}
	for label, code := range goCodes {
		if !specSet[code] {
			t.Errorf("%s = %q is emitted by the server but not listed in spec's ProblemDetails.code.enum — a client coded to the spec would treat it as an unknown code", label, code)
		}
	}

	// Every spec-listed code must be emitted somewhere in the Go tree — the
	// spec must not advertise a code that the server never returns.
	goSet := make(map[string]bool, len(goCodes))
	for _, c := range goCodes {
		goSet[c] = true
	}
	for code := range specSet {
		if !goSet[code] {
			t.Errorf("spec advertises code %q but no Go-side constant is registered in this test — either add it to the Go constants (and this test) or remove it from the spec", code)
		}
	}
}
