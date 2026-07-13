package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/engine"
)

// Guards that the shipped config profiles parse and have valid dimension keys.
func TestLoadShippedProfiles(t *testing.T) {
	profiles, err := engine.LoadProfiles("../../../config/default-profile.yaml", "../../../config/profiles")
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	def, ok := profiles["default"]
	if !ok || def.DimensionWeights[domain.DimensionIntegrity] != 1.0 {
		t.Errorf("default profile wrong: %+v ok=%v", def, ok)
	}
	strict, ok := profiles["identity-strict"]
	if !ok || strict.DimensionWeights[domain.DimensionIdentity] != 1.0 {
		t.Errorf("identity-strict profile wrong: %+v ok=%v", strict, ok)
	}
}

func writeProfile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadProfileErrors(t *testing.T) {
	cases := map[string]string{
		"unknown dimension": "name: x\ndimensionWeights:\n  bogus: 1.0\n",
		"missing name":      "dimensionWeights:\n  integrity: 1.0\n",
		"bad yaml":          "name: [unterminated\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := engine.LoadProfile(writeProfile(t, content)); err == nil {
				t.Error("want error")
			}
		})
	}
	if _, err := engine.LoadProfile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file: want error")
	}
}

// In v1 a dimensionWeight is a pure on/off gate (§4.6 active-dimension rule);
// magnitude is inert until a cross-dimension aggregate exists. The loader
// rejects any value other than 0 or 1 so a fractional weight fails fast at boot
// rather than silently doing nothing.
func TestLoadProfileRejectsFractionalDimensionWeight(t *testing.T) {
	p := writeProfile(t, "name: x\ndimensionWeights:\n  integrity: 0.5\n")
	if _, err := engine.LoadProfile(p); err == nil {
		t.Error("fractional dimensionWeight: want error")
	}
}

// A negative signalWeight is almost certainly a typo — weightedAverage's
// weight>0 guard would silently drop it. Reject at boot so the operator sees
// the mistake instead of a mysterious dimension score.
func TestLoadProfileRejectsNegativeSignalWeight(t *testing.T) {
	p := writeProfile(t, "name: x\nsignalWeights:\n  certtype: -1\n")
	if _, err := engine.LoadProfile(p); err == nil {
		t.Error("negative signalWeight: want error")
	}
}

func TestLoadProfilesDuplicateName(t *testing.T) {
	dir := t.TempDir()
	for _, fn := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, fn), []byte("name: dup\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := engine.LoadProfiles(writeProfile(t, "name: default\n"), dir); err == nil {
		t.Error("duplicate name: want error")
	}
}

func TestLoadProfilesDefaultAndDir(t *testing.T) {
	if _, err := engine.LoadProfiles(filepath.Join(t.TempDir(), "none.yaml"), ""); err == nil {
		t.Error("missing default: want error")
	}
	def := writeProfile(t, "name: solo\n")
	got, err := engine.LoadProfiles(def, "")
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if len(got) != 1 || got["solo"].Name != "solo" {
		t.Errorf("got %v", got)
	}
	if _, err := engine.LoadProfiles(def, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing dir: want error")
	}
}

func TestValidateSignalWeights(t *testing.T) {
	known := map[domain.SignalID]bool{"certtype": true, "dnssecurity": true}
	ok := domain.ScoringProfile{Name: "ok", SignalWeights: map[domain.SignalID]float64{"certtype": 1}}
	if err := engine.ValidateSignalWeights(ok, known); err != nil {
		t.Errorf("known signal: %v", err)
	}
	bad := domain.ScoringProfile{Name: "bad", SignalWeights: map[domain.SignalID]float64{"nope": 1}}
	if err := engine.ValidateSignalWeights(bad, known); err == nil {
		t.Error("unknown signal: want error")
	}
}
