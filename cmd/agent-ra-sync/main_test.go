package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/rasync"
)

// tempStderr returns an *os.File the run() code can write diagnostics to, plus
// a reader that returns everything written so far. run() writes with
// fmt.Fprintln / flag output, which go straight to the fd, so a plain re-read
// of the file sees them.
func tempStderr(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr-*")
	if err != nil {
		t.Fatalf("create temp stderr: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(b)
}

func TestRun_MissingRequiredFieldsReturns1(t *testing.T) {
	// No config file (missing path → empty config) and no override flags, so
	// ra-url/tl-url/out are all empty: run must reject rather than dial.
	stderr := tempStderr(t)
	code := run([]string{"-config", filepath.Join(t.TempDir(), "absent.yaml")}, stderr)
	if code != 1 {
		t.Fatalf("run code = %d, want 1", code)
	}
	if out := readAll(t, stderr); !strings.Contains(out, "are required") {
		t.Errorf("stderr = %q, want it to mention the required flags", out)
	}
}

func TestRun_BadFlagReturns2(t *testing.T) {
	stderr := tempStderr(t)
	if code := run([]string{"-not-a-flag"}, stderr); code != 2 {
		t.Fatalf("run code = %d, want 2 (flag parse error)", code)
	}
}

func TestRun_MalformedConfigReturns1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ra-sync.yaml")
	if err := os.WriteFile(path, []byte("raUrl: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := tempStderr(t)
	if code := run([]string{"-config", path}, stderr); code != 1 {
		t.Fatalf("run code = %d, want 1 (config parse error)", code)
	}
}

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
