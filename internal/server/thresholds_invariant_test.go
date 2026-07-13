package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/config"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/engine"
)

// engine.DefaultThresholds() and config.defaultClassify() encode the same
// 20/50/80/90 constants in two packages that (by design) can't import each
// other — engine has no config dependency, and config has no domain-layer
// dependency. This test bridges them: it loads a minimal runtime.yaml so
// Load fills Classify with the config-side default, maps it via thresholdsOf
// (the same path the boot sequence takes), and asserts the result equals
// engine.DefaultThresholds() field-by-field. Drift in either default fails
// this test at build time instead of silently shipping a mismatched cascade.
func TestDefaultClassify_MatchesEngineDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime.yaml")
	if err := os.WriteFile(path, []byte("admin:\n  key: x\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	got := thresholdsOf(cfg)
	want := engine.DefaultThresholds()
	if got != want {
		t.Errorf("threshold drift between packages:\n  config.defaultClassify() → thresholdsOf = %+v\n  engine.DefaultThresholds()             = %+v\nboth must move together — see design §4.6 cascade",
			got, want)
	}
}
