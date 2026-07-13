package hydrator_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/hydrator"
)

func TestLoadConfig_ShippedYAML(t *testing.T) {
	s, err := hydrator.LoadConfig("../../config/hydrator.yaml")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !s.Mock {
		t.Error("Mock = false, want true (mode: mock)")
	}
	if s.TargetURL != "http://localhost:8080" {
		t.Errorf("TargetURL = %q", s.TargetURL)
	}
	if s.TLEventsDir != "fixtures/tl-events" || s.ObservationsDir != "fixtures/observations" {
		t.Errorf("dirs = %q / %q", s.TLEventsDir, s.ObservationsDir)
	}
	if s.AIMID != "did:web:demo-aim.local" {
		t.Errorf("AIMID = %q", s.AIMID)
	}
}

func TestLoadConfig_RealMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.yaml")
	if err := os.WriteFile(p, []byte("mode: real\ntarget:\n  url: http://x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := hydrator.LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if s.Mock {
		t.Error("Mock = true, want false (mode: real)")
	}
}

func TestLoadConfig_Errors(t *testing.T) {
	if _, err := hydrator.LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte("mode: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hydrator.LoadConfig(p); err == nil {
		t.Error("expected error for malformed YAML")
	}
}
