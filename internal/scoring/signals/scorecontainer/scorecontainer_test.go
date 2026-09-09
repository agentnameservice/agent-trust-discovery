package scorecontainer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func obs(v string) *domain.SignalObservation {
	return &domain.SignalObservation{Value: json.RawMessage(v)}
}

// ptr returns a *int for the threshold argument. nil means "use the default".
func ptr(n int) *int { return &n }

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestMetadataAndAbsence(t *testing.T) {
	s := New("trustmodel.safety.score", domain.DimensionSafety, nil)
	if s.ID() != "trustmodel.safety.score" {
		t.Errorf("id = %q", s.ID())
	}
	if s.Dimension() != domain.DimensionSafety {
		t.Errorf("dimension = %q", s.Dimension())
	}
	if s.Derived() {
		t.Error("Derived() = true, want false")
	}
	if s.AbsenceInformative() {
		t.Error("AbsenceInformative() = true, want false (absence is not informative)")
	}
}

func TestSubject(t *testing.T) {
	// New defaults the subject to agent.
	if got := New("trustmodel.safety.score", domain.DimensionSafety, nil).Subject(); got != SubjectAgent {
		t.Errorf("New subject = %q, want %q", got, SubjectAgent)
	}
	// NewWithSubject carries an explicit subject.
	if got := NewWithSubject("agentgraph.safety.score", domain.DimensionSafety, "tool", nil).Subject(); got != "tool" {
		t.Errorf("subject = %q, want tool", got)
	}
	// An empty subject falls back to agent.
	if got := NewWithSubject("x.safety.score", domain.DimensionSafety, "", nil).Subject(); got != SubjectAgent {
		t.Errorf("empty subject = %q, want %q", got, SubjectAgent)
	}
}

func TestEvaluate(t *testing.T) {
	s := New("trustmodel.safety.score", domain.DimensionSafety, nil)

	// nil obs -> 0 + vendor-scoped UNKNOWN
	r, _ := s.Evaluate(context.TODO(), domain.Agent{}, nil)
	if r.Raw != 0 || !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_UNKNOWN") {
		t.Errorf("nil: raw=%d codes=%v", r.Raw, r.RiskCodes)
	}

	// clean high score -> no codes
	r, _ = s.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":86}`))
	if r.Raw != 86 || len(r.RiskCodes) != 0 {
		t.Errorf("high: raw=%d codes=%v", r.Raw, r.RiskCodes)
	}

	// below threshold -> vendor-scoped backstop
	r, _ = s.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":40}`))
	if !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("low: codes=%v", r.RiskCodes)
	}

	// provider codes pass through with prefix filter; explanation surfaced
	r, _ = s.Evaluate(context.TODO(), domain.Agent{},
		obs(`{"score":30,"riskCodes":["SAFETY_PROMPT_INJECTION"],"explanation":"2/40 jailbroke"}`))
	if !contains(r.RiskCodes, "SAFETY_PROMPT_INJECTION") {
		t.Errorf("provider code dropped: %v", r.RiskCodes)
	}
	if r.Explanation != "2/40 jailbroke" {
		t.Errorf("explanation = %q", r.Explanation)
	}

	// a score of 0 is a real, evaluated score — not the missing-value sentinel
	r, _ = s.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":0}`))
	if r.Raw != 0 || !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("explicit 0: raw=%d codes=%v", r.Raw, r.RiskCodes)
	}
}

// A missing, null, or misspelled score must not decode to a real 0 — the worst
// score on the scale. All three are errors, in Validate (a 422 at import) and in
// Evaluate (a hard failure, never a silent 0).
func TestScoreRequired(t *testing.T) {
	s := New("trustmodel.safety.score", domain.DimensionSafety, nil)
	for _, body := range []string{`{}`, `{"score":null}`, `{"scores":50}`} {
		if err := s.Validate(json.RawMessage(body)); err == nil {
			t.Errorf("Validate(%s): expected error, got nil", body)
		}
		if _, err := s.Evaluate(context.TODO(), domain.Agent{}, obs(body)); err == nil {
			t.Errorf("Evaluate(%s): expected error, got nil", body)
		}
	}
}

// The backstop and UNKNOWN codes are scoped to the id's vendor segment, so two
// providers in the same dimension produce distinguishable codes.
func TestVendorScopedCodes(t *testing.T) {
	tm := New("trustmodel.safety.score", domain.DimensionSafety, ptr(70))
	ag := New("agentgraph.safety.score", domain.DimensionSafety, ptr(70))

	rt, _ := tm.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":10}`))
	ra, _ := ag.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":10}`))
	if !contains(rt.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("trustmodel backstop missing: %v", rt.RiskCodes)
	}
	if !contains(ra.RiskCodes, "SAFETY_AGENTGRAPH_SCORE_LOW") {
		t.Errorf("agentgraph backstop missing: %v", ra.RiskCodes)
	}
}

// A hyphenated vendor segment must still yield a backstop code that matches the
// risk-code shape (^[A-Z0-9_]+$) — the hyphen is normalised to an underscore.
func TestHyphenatedVendorSanitized(t *testing.T) {
	s := New("acme-labs.safety.score", domain.DimensionSafety, ptr(70))
	r, _ := s.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":10}`))
	if !contains(r.RiskCodes, "SAFETY_ACME_LABS_SCORE_LOW") {
		t.Errorf("hyphen not normalised: %v", r.RiskCodes)
	}
	for _, c := range r.RiskCodes {
		if !riskCodeRe.MatchString(c) {
			t.Errorf("emitted code %q does not match %s", c, riskCodeRe.String())
		}
	}
}

// A vendor segment may itself contain dots — a did:web authority, or a bare
// domain used as a vendor token — and must still be recognised as ONE vendor
// segment rather than being truncated at its first dot, and normalised whole
// into the backstop code.
func TestDottedVendorSanitized(t *testing.T) {
	s := New("did:web:example.com.safety.score", domain.DimensionSafety, ptr(70))
	if got := s.vendor; got != "DID_WEB_EXAMPLE_COM" {
		t.Fatalf("vendor = %q, want DID_WEB_EXAMPLE_COM", got)
	}
	r, _ := s.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":10}`))
	if !contains(r.RiskCodes, "SAFETY_DID_WEB_EXAMPLE_COM_SCORE_LOW") {
		t.Errorf("dotted vendor not kept whole: %v", r.RiskCodes)
	}
	for _, c := range r.RiskCodes {
		if !riskCodeRe.MatchString(c) {
			t.Errorf("emitted code %q does not match %s", c, riskCodeRe.String())
		}
	}
}

func TestValidate(t *testing.T) {
	s := New("trustmodel.behavior.score", domain.DimensionBehavior, nil)
	if err := s.Validate(json.RawMessage(`{"score":50}`)); err != nil {
		t.Errorf("valid rejected: %v", err)
	}
	if err := s.Validate(json.RawMessage(`{"score":101}`)); err == nil {
		t.Error("expected out-of-range error")
	}
	if err := s.Validate(json.RawMessage(`{"score":50,"riskCodes":["bad-code"]}`)); err == nil {
		t.Error("expected malformed risk-code error")
	}
	// A well-formed code for the wrong dimension is rejected at import, not
	// silently dropped later.
	if err := s.Validate(json.RawMessage(`{"score":50,"riskCodes":["SAFETY_PROMPT_INJECTION"]}`)); err == nil {
		t.Error("expected wrong-dimension prefix error")
	}
	// A correctly-prefixed code validates.
	if err := s.Validate(json.RawMessage(`{"score":50,"riskCodes":["BEHAVIOR_STALE"]}`)); err != nil {
		t.Errorf("correctly-prefixed code rejected: %v", err)
	}
	codes := make([]string, maxRiskCodes+1)
	for i := range codes {
		codes[i] = "BEHAVIOR_X"
	}
	body, _ := json.Marshal(map[string]any{"score": 50, "riskCodes": codes})
	if err := s.Validate(body); err == nil {
		t.Error("expected count-cap error")
	}
}

func TestThresholdConfigurable(t *testing.T) {
	strict := New("trustmodel.safety.score", domain.DimensionSafety, ptr(90))
	r, _ := strict.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":85}`))
	if !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("threshold 90: score 85 should trip backstop, got %v", r.RiskCodes)
	}

	// nil threshold falls back to the package default.
	if New("x.safety.score", domain.DimensionSafety, nil).threshold != DefaultLowThreshold {
		t.Error("nil threshold should fall back to DefaultLowThreshold")
	}

	// An explicit 0 means "no backstop": a score can never be below 0, so the
	// SCORE_LOW code is never emitted — the opposite of the old <=0 -> 70 rule.
	noBackstop := New("x.safety.score", domain.DimensionSafety, ptr(0))
	if noBackstop.threshold != 0 {
		t.Errorf("explicit 0 threshold = %d, want 0", noBackstop.threshold)
	}
	r, _ = noBackstop.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":0}`))
	for _, c := range r.RiskCodes {
		if strings.HasSuffix(c, "_SCORE_LOW") {
			t.Errorf("threshold 0 should emit no backstop, got %v", r.RiskCodes)
		}
	}
}
