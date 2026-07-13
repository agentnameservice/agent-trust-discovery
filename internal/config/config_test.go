package config_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/config"
)

func TestLoad_ShippedRuntimeYAML(t *testing.T) {
	c, err := config.Load("../../config/runtime.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", c.ListenAddr)
	}
	if c.DBPath != "agent-trust-discovery.db" {
		t.Errorf("DBPath = %q, want agent-trust-discovery.db", c.DBPath)
	}
	if !c.AdminRequireKey {
		t.Error("AdminRequireKey = false, want true (secure default)")
	}
	if c.AdminKey != "" {
		t.Errorf("AdminKey = %q, want empty", c.AdminKey)
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", c.LogLevel)
	}
	want := config.Classify{Untrusted: 20, Transactional: 50, Fiduciary: 80, IdentityFiduciary: 90}
	if c.Classify != want {
		t.Errorf("Classify = %+v, want %+v", c.Classify, want)
	}
}

func TestLoad_ShippedDemoYAML(t *testing.T) {
	c, err := config.Load("../../config/demo.runtime.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AdminRequireKey {
		t.Error("demo AdminRequireKey = true, want false")
	}
	if c.DBPath != "/tmp/agent-trust-discovery-demo.db" {
		t.Errorf("DBPath = %q", c.DBPath)
	}
}

// ANS_ADMIN_KEY overrides admin.key from YAML so operators can inject the
// admin key from a container secret without editing the config on disk.
func TestLoad_AdminKeyEnvOverridesYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte("admin:\n  requireKey: true\n  key: yaml-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.AdminKeyEnv, "env-value")
	c, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AdminKey != "env-value" {
		t.Errorf("AdminKey = %q, want env-value (env should win over YAML)", c.AdminKey)
	}
}

// An empty ANS_ADMIN_KEY explicitly clears the YAML value — useful when the
// key must be unset in an environment that inherits a stray var.
func TestLoad_EmptyAdminKeyEnvClearsYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte("admin:\n  key: yaml-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.AdminKeyEnv, "")
	c, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AdminKey != "" {
		t.Errorf("AdminKey = %q, want empty (explicit empty env should clear YAML)", c.AdminKey)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := config.Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoad_BadYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte("listen: [not, a, mapping\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "min.yaml")
	// Only db.path set; everything else should default.
	if err := os.WriteFile(p, []byte("db:\n  path: x.db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want default :8080", c.ListenAddr)
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want default info", c.LogLevel)
	}
	want := config.Classify{Untrusted: 20, Transactional: 50, Fiduciary: 80, IdentityFiduciary: 90}
	if c.Classify != want {
		t.Errorf("Classify = %+v, want defaults %+v", c.Classify, want)
	}
}

// A complete, well-ordered classify block loads and overrides the defaults.
func TestLoad_ClassifyFullBlockOverrides(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	yaml := "classify:\n" +
		"  untrustedThreshold: 30\n" +
		"  transactionalThreshold: 55\n" +
		"  fiduciaryThreshold: 75\n" +
		"  identityFiduciaryThreshold: 95\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := config.Classify{Untrusted: 30, Transactional: 55, Fiduciary: 75, IdentityFiduciary: 95}
	if c.Classify != want {
		t.Errorf("Classify = %+v, want %+v", c.Classify, want)
	}
}

// A partial classify block used to silently zero-fill the omitted thresholds;
// it must now fail fast at load with a message naming the offending field.
func TestLoad_ClassifyPartialBlockRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte("classify:\n  untrustedThreshold: 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(p)
	if err == nil {
		t.Fatal("expected an error for a partial classify block")
	}
	if !strings.Contains(err.Error(), "transactionalThreshold") {
		t.Errorf("error should name the first zero-filled field, got %v", err)
	}
}

// A present-but-misordered classify block is rejected even when all four are
// nonzero — the cascade must strictly ascend.
func TestLoad_ClassifyMisorderedRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	yaml := "classify:\n" +
		"  untrustedThreshold: 50\n" +
		"  transactionalThreshold: 40\n" + // out of order
		"  fiduciaryThreshold: 80\n" +
		"  identityFiduciaryThreshold: 90\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(p)
	if err == nil {
		t.Fatal("expected an error for a misordered classify block")
	}
	if !strings.Contains(err.Error(), "ascend") && !strings.Contains(err.Error(), "greater") {
		t.Errorf("error should explain the ordering requirement, got %v", err)
	}
}

// An out-of-range threshold (>100) is rejected.
func TestLoad_ClassifyOutOfRangeRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	yaml := "classify:\n" +
		"  untrustedThreshold: 20\n" +
		"  transactionalThreshold: 50\n" +
		"  fiduciaryThreshold: 80\n" +
		"  identityFiduciaryThreshold: 130\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected an error for a threshold above 100")
	}
}

func TestSlogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		"WARN":  slog.LevelWarn, // case-insensitive
		"":      slog.LevelInfo, // default
		"bogus": slog.LevelInfo, // unknown → info
	}
	for in, want := range cases {
		if got := (config.Config{LogLevel: in}).SlogLevel(); got != want {
			t.Errorf("SlogLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
