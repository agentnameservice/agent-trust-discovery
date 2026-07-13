package prober_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/prober"
)

func TestLoadConfig_ShippedYAML(t *testing.T) {
	s, err := prober.LoadConfig("../../config/prober.yaml")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if s.TargetURL != "http://localhost:8080" {
		t.Errorf("TargetURL = %q", s.TargetURL)
	}
	if s.TLEventsDir != "fixtures/tl-events" {
		t.Errorf("TLEventsDir = %q", s.TLEventsDir)
	}
	if s.Cadence != 0 {
		t.Errorf("Cadence = %v, want 0 (single pass)", s.Cadence)
	}
	if s.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", s.Timeout)
	}
	if s.AIMID != "did:web:demo-prober.local" {
		t.Errorf("AIMID = %q", s.AIMID)
	}
}

func TestLoadConfig_Errors(t *testing.T) {
	if _, err := prober.LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for a missing file")
	}
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte("probe:\n  timeout: not-a-duration\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prober.LoadConfig(p); err == nil {
		t.Error("expected error for an invalid timeout duration")
	}
}
