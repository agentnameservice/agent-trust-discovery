package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/rasync"
)

func TestLoadConfig_ParsesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ra-sync.yaml")
	if err := os.WriteFile(path, []byte("raUrl: http://ra:18080\ntlUrl: http://tl:18081\nout: fixtures/ra-sync\npageSize: 200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.RABaseURL != "http://ra:18080" || cfg.TLBaseURL != "http://tl:18081" || cfg.OutDir != "fixtures/ra-sync" || cfg.PageSize != 200 {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestLoadConfig_MissingFileIsEmptyConfig(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("loadConfig missing: %v", err)
	}
	if cfg != (configZero()) {
		t.Errorf("expected zero config for missing file, got %+v", cfg)
	}
}

func configZero() rasync.Config { return rasync.Config{} }
