package scorecontainer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "score-signals.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSignals_OK(t *testing.T) {
	p := writeCfg(t, `
signals:
  - id: trustmodel.safety.score
    dimension: safety
    threshold: 70
  - id: agentgraph.safety.score
    dimension: safety
    threshold: 60
  - id: dnsofmoney.solvency.score
    dimension: solvency
`)
	sigs, err := LoadSignals(p)
	if err != nil {
		t.Fatalf("LoadSignals: %v", err)
	}
	if len(sigs) != 3 {
		t.Fatalf("want 3 signals, got %d", len(sigs))
	}
	byID := map[domain.SignalID]domain.Dimension{}
	for _, s := range sigs {
		byID[s.ID()] = s.Dimension()
	}
	if byID["agentgraph.safety.score"] != domain.DimensionSafety {
		t.Errorf("agentgraph dimension = %q", byID["agentgraph.safety.score"])
	}
	// zero/absent threshold falls back to the package default.
	for _, s := range sigs {
		if ss, ok := s.(ScoreSignal); ok && ss.ID() == "dnsofmoney.solvency.score" && ss.threshold != DefaultLowThreshold {
			t.Errorf("absent threshold should default, got %d", ss.threshold)
		}
	}
}

// A configured-but-missing path is a boot error (a set path is deliberate). The
// "no provider signals" case is expressed by not calling LoadSignals at all
// (server.Build skips it when the path is unset), not by a missing file.
func TestLoadSignals_MissingFileIsError(t *testing.T) {
	if _, err := LoadSignals(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("missing file should be an error")
	}
}

// An empty or fully-commented file is not a crash — it registers no signals, so
// an operator can switch providers off by commenting them out.
func TestLoadSignals_EmptyFileIsNoSignals(t *testing.T) {
	for _, body := range []string{"", "# everything commented out\n"} {
		sigs, err := LoadSignals(writeCfg(t, body))
		if err != nil {
			t.Errorf("empty/commented file should not error: %v", err)
		}
		if len(sigs) != 0 {
			t.Errorf("empty/commented file should yield no signals, got %d", len(sigs))
		}
	}
}

// An explicit threshold: 0 means "no backstop" and must survive as 0, not be
// coerced to the default; an omitted threshold falls back to the default.
func TestLoadSignals_ThresholdZeroVsAbsent(t *testing.T) {
	sigs, err := LoadSignals(writeCfg(t, `
signals:
  - id: acme.safety.score
    dimension: safety
    threshold: 0
  - id: beta.safety.score
    dimension: safety
`))
	if err != nil {
		t.Fatalf("LoadSignals: %v", err)
	}
	for _, s := range sigs {
		ss := s.(ScoreSignal)
		switch ss.ID() {
		case "acme.safety.score":
			if ss.threshold != 0 {
				t.Errorf("explicit 0 threshold = %d, want 0", ss.threshold)
			}
		case "beta.safety.score":
			if ss.threshold != DefaultLowThreshold {
				t.Errorf("absent threshold = %d, want default %d", ss.threshold, DefaultLowThreshold)
			}
		}
	}
}

// subject is parsed, defaults to agent when omitted, and rejects a non-token.
func TestLoadSignals_Subject(t *testing.T) {
	sigs, err := LoadSignals(writeCfg(t, `
signals:
  - id: agentgraph.safety.score
    dimension: safety
    subject: tool
  - id: beta.safety.score
    dimension: safety
`))
	if err != nil {
		t.Fatalf("LoadSignals: %v", err)
	}
	for _, s := range sigs {
		ss := s.(ScoreSignal)
		switch ss.ID() {
		case "agentgraph.safety.score":
			if ss.Subject() != "tool" {
				t.Errorf("subject = %q, want tool", ss.Subject())
			}
		case "beta.safety.score":
			if ss.Subject() != SubjectAgent {
				t.Errorf("omitted subject = %q, want %q", ss.Subject(), SubjectAgent)
			}
		}
	}
}

// A vendor segment may itself contain dots — e.g. a did:web authority, which
// the doc comment in the example config explicitly suggests as a vendor value,
// or a bare domain — so the format check must peel dimension.name off the right
// rather than require exactly three dot-separated parts. Both forms below were
// rejected before the fix.
func TestLoadSignals_DottedVendor(t *testing.T) {
	for _, id := range []string{
		"did:web:example.com.solvency.score", // did:web authority as vendor
		"dnsofmoney.com.solvency.score",      // bare domain as vendor
	} {
		t.Run(id, func(t *testing.T) {
			sigs, err := LoadSignals(writeCfg(t, "signals:\n  - id: "+id+"\n    dimension: solvency\n"))
			if err != nil {
				t.Fatalf("LoadSignals: %v", err)
			}
			if len(sigs) != 1 {
				t.Fatalf("want 1 signal, got %d", len(sigs))
			}
			if got := sigs[0].ID(); string(got) != id {
				t.Errorf("ID() = %q, want %q", got, id)
			}
			if got := sigs[0].Dimension(); got != domain.DimensionSolvency {
				t.Errorf("Dimension() = %q", got)
			}
		})
	}
}

func TestLoadSignals_Rejections(t *testing.T) {
	cases := map[string]string{
		"unknown dimension":      "signals:\n  - id: x.bogus.score\n    dimension: bogus\n",
		"segment mismatch":       "signals:\n  - id: x.safety.score\n    dimension: solvency\n",
		"not three segments":     "signals:\n  - id: safety\n    dimension: safety\n",
		"empty id":               "signals:\n  - id: \"\"\n    dimension: safety\n",
		"threshold out of range": "signals:\n  - id: x.safety.score\n    dimension: safety\n    threshold: 200\n",
		"bad subject":            "signals:\n  - id: x.safety.score\n    dimension: safety\n    subject: Tool!\n",
		"duplicate id":           "signals:\n  - id: x.safety.score\n    dimension: safety\n  - id: x.safety.score\n    dimension: safety\n",
		"unknown field":          "signals:\n  - id: x.safety.score\n    dimension: safety\n    weight: 1\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadSignals(writeCfg(t, body)); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}
