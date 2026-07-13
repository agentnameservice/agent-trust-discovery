package hydrator_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/hydrator"
)

const obsFixture = `
agentId: agent-001
observations:
  - signalId: certtype
    observedAt: 2026-05-28T08:00:00Z
    value:
      type: DV
  - signalId: certfingerprint.server
    observedAt: 2026-05-28T08:00:00Z
    observed: "SHA256:server"
`

func TestParseObservationFile(t *testing.T) {
	f, err := hydrator.ParseObservationFile([]byte(obsFixture))
	if err != nil {
		t.Fatalf("ParseObservationFile: %v", err)
	}
	if f.AgentID != "agent-001" || len(f.Observations) != 2 {
		t.Fatalf("file = %+v", f)
	}
	if f.Observations[0].Value["type"] != "DV" {
		t.Errorf("raw value = %v", f.Observations[0].Value)
	}
	if f.Observations[1].Observed != "SHA256:server" {
		t.Errorf("drift observed = %q", f.Observations[1].Observed)
	}
}

func TestParseObservationFile_RequiresAgentID(t *testing.T) {
	if _, err := hydrator.ParseObservationFile([]byte("observations: []\n")); err == nil {
		t.Error("expected error when agentId is missing")
	}
}

func TestLoadObservations(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(obsFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.md"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := hydrator.LoadObservations(dir)
	if err != nil {
		t.Fatalf("LoadObservations: %v", err)
	}
	if len(files) != 1 || files[0].AgentID != "agent-001" {
		t.Errorf("files = %+v", files)
	}
}

func TestLoadObservations_MissingDir(t *testing.T) {
	if _, err := hydrator.LoadObservations(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected error for a missing dir")
	}
}

func TestParseObservationFile_BadYAML(t *testing.T) {
	if _, err := hydrator.ParseObservationFile([]byte("agentId: [unterminated\n")); err == nil {
		t.Error("expected error for malformed YAML")
	}
}

func TestLoadObservations_BadFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("observations: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hydrator.LoadObservations(dir); err == nil {
		t.Error("expected error for a file missing agentId")
	}
}
