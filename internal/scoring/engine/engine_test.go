package engine_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/engine"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/registry"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

type fakeStore struct {
	obs map[domain.SignalID]*domain.SignalObservation
	err error
}

func (f fakeStore) LatestObservation(_ context.Context, _ domain.AgentID, sid domain.SignalID) (*domain.SignalObservation, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.obs[sid], nil
}

func obs(v string) *domain.SignalObservation {
	return &domain.SignalObservation{Value: json.RawMessage(v)}
}

func defaultProfile() domain.ScoringProfile {
	return domain.ScoringProfile{
		Name: "default",
		DimensionWeights: map[domain.Dimension]float64{
			domain.DimensionIntegrity: 0.5,
			domain.DimensionIdentity:  0.5,
		},
		SignalWeights: map[domain.SignalID]float64{
			"certtype": 1, "dnssecurity": 1, "agentage": 1, "versionstability": 1,
			"certfingerprint.server": 1, "certfingerprint.identity": 1,
			"dnsrecord.ans": 1, "dnsrecord.ans-badge": 1,
		},
	}
}

func newRegistry(t *testing.T, clock func() time.Time) *registry.Registry {
	t.Helper()
	r := registry.New()
	for _, s := range signals.BuiltIns(clock) {
		if err := r.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.ID(), err)
		}
	}
	return r
}

func findDim(t *testing.T, ev domain.TrustEvaluation, dim domain.Dimension) domain.DimensionScore {
	t.Helper()
	for _, d := range ev.Dimensions {
		if d.Dimension == dim {
			return d
		}
	}
	t.Fatalf("dimension %s missing from evaluation", dim)
	return domain.DimensionScore{}
}

// Reproduces the §5.1 worked example exactly.
func TestEvaluateReproducesWorkedExample(t *testing.T) {
	at := time.Date(2026, 6, 4, 8, 0, 0, 0, time.UTC)
	clock := func() time.Time { return at }

	matched := `{"expected":"x","observed":"x","matched":true,"expectedSource":"tl_attestation"}`
	store := fakeStore{obs: map[domain.SignalID]*domain.SignalObservation{
		"certtype":                 obs(`{"type":"DV"}`),
		"dnssecurity":              obs(`{"dnssec":true,"caa":true}`),
		"versionstability":         obs(`{"versionChanges30d":2}`),
		"certfingerprint.server":   obs(matched),
		"certfingerprint.identity": obs(matched),
		"dnsrecord.ans":            obs(matched),
		"dnsrecord.ans-badge":      obs(matched),
		// agentage is derived — no observation.
	}}

	eng := engine.New(store, newRegistry(t, clock), engine.DefaultThresholds(), clock)
	agent := domain.Agent{ID: "agent-001", FirstSeen: at.AddDate(0, 0, -163)}

	ev, err := eng.Evaluate(context.Background(), agent, defaultProfile())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if ev.TrustVector != (domain.TrustVector{Integrity: 89, Identity: 40}) {
		t.Errorf("trustVector = %+v, want {89,40,0,0,0}", ev.TrustVector)
	}
	if ev.RecommendedProfile != domain.ProfileReadOnly {
		t.Errorf("recommendedProfile = %s, want READ_ONLY", ev.RecommendedProfile)
	}
	if len(ev.RiskFactors) != 1 || ev.RiskFactors[0] != signals.RiskCertDVOnly {
		t.Errorf("riskFactors = %v, want [%s]", ev.RiskFactors, signals.RiskCertDVOnly)
	}
	if ev.ScoringProfile != "default" || !ev.EvaluationTime.Equal(at) || ev.VerificationTier != domain.TierUnset {
		t.Errorf("meta: profile=%s time=%v tier=%q", ev.ScoringProfile, ev.EvaluationTime, ev.VerificationTier)
	}
	if len(ev.Dimensions) != 5 {
		t.Fatalf("dimensions = %d, want 5", len(ev.Dimensions))
	}

	integrity := findDim(t, ev, domain.DimensionIntegrity)
	if integrity.Score != 89 || len(integrity.SignalScores) != 7 {
		t.Errorf("integrity: score=%d signals=%d, want 89/7", integrity.Score, len(integrity.SignalScores))
	}
	for _, s := range integrity.SignalScores {
		isDrift := s.SignalID == "certfingerprint.server" || s.SignalID == "certfingerprint.identity" ||
			s.SignalID == "dnsrecord.ans" || s.SignalID == "dnsrecord.ans-badge"
		if isDrift && s.Attestation != domain.AttestationTLAttested {
			t.Errorf("%s attestation = %s, want tl_attested", s.SignalID, s.Attestation)
		}
	}

	if id := findDim(t, ev, domain.DimensionIdentity); id.Score != 40 || len(id.SignalScores) != 1 {
		t.Errorf("identity: score=%d signals=%d, want 40/1", id.Score, len(id.SignalScores))
	}
	for _, dim := range []domain.Dimension{domain.DimensionSolvency, domain.DimensionBehavior, domain.DimensionSafety} {
		d := findDim(t, ev, dim)
		if d.Score != 0 || len(d.SignalScores) != 0 {
			t.Errorf("%s should be empty: score=%d signals=%d", dim, d.Score, len(d.SignalScores))
		}
	}
}

func TestEvaluateWeightZeroDropsScoreAndRisk(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC) }
	store := fakeStore{obs: map[domain.SignalID]*domain.SignalObservation{
		"certtype": obs(`{"type":"DV"}`),
	}}
	// identity-strict-like: certtype weighted 0, so identity has no weighted
	// signal → score 0 and its DV risk is dropped.
	profile := domain.ScoringProfile{
		Name:             "id-zero",
		DimensionWeights: map[domain.Dimension]float64{domain.DimensionIdentity: 1},
		SignalWeights:    map[domain.SignalID]float64{"certtype": 0},
	}
	eng := engine.New(store, newRegistry(t, clock), engine.DefaultThresholds(), clock)
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, profile)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if ev.TrustVector.Identity != 0 {
		t.Errorf("identity score = %d, want 0 (weight 0)", ev.TrustVector.Identity)
	}
	for _, rf := range ev.RiskFactors {
		if rf == signals.RiskCertDVOnly {
			t.Error("IDENTITY_CERT_DV_ONLY should be dropped for a weight-0 signal")
		}
	}
}

func TestEvaluateRiskFactorsAlwaysNonNil(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC) }
	store := fakeStore{obs: map[domain.SignalID]*domain.SignalObservation{
		"certtype": obs(`{"type":"EV"}`), "dnssecurity": obs(`{"dnssec":true,"caa":true}`),
	}}
	eng := engine.New(store, newRegistry(t, clock), engine.DefaultThresholds(), clock)
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a", FirstSeen: clock().AddDate(0, 0, -200)}, defaultProfile())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if ev.RiskFactors == nil {
		t.Error("RiskFactors is nil, want empty slice")
	}
}

func TestEvaluatePropagatesStoreError(t *testing.T) {
	clock := time.Now
	store := fakeStore{err: errors.New("boom")}
	eng := engine.New(store, newRegistry(t, clock), engine.DefaultThresholds(), clock)
	if _, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, defaultProfile()); err == nil {
		t.Error("store error: want propagated error")
	}
}

// TestEvaluateDegradesOnSignalError guards the extension-boundary policy:
// one signal returning an error must not abort the entire evaluation. The
// failing signal degrades to Raw=0 Unattested and emits
// SIGNAL_EVALUATION_FAILED, and the rest of the run proceeds normally.
func TestEvaluateDegradesOnSignalError(t *testing.T) {
	clock := time.Now
	store := fakeStore{obs: map[domain.SignalID]*domain.SignalObservation{
		"certtype":    obs(`not-json`), // certtype.Evaluate will fail to decode
		"dnssecurity": obs(`{"dnssec":true,"caa":true}`),
	}}
	eng := engine.New(store, newRegistry(t, clock), engine.DefaultThresholds(), clock)
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, defaultProfile())
	if err != nil {
		t.Fatalf("Evaluate: want nil err (degrade), got %v", err)
	}

	// SIGNAL_EVALUATION_FAILED should be present in the risk factors.
	found := false
	for _, rf := range ev.RiskFactors {
		if rf == engine.RiskSignalEvaluationFailed {
			found = true
		}
	}
	if !found {
		t.Errorf("riskFactors = %v, want to contain %s", ev.RiskFactors, engine.RiskSignalEvaluationFailed)
	}

	// The failing signal should have Raw=0 in the dimension scores.
	id := findDim(t, ev, domain.DimensionIdentity)
	for _, s := range id.SignalScores {
		if s.SignalID == "certtype" && s.RawScore != 0 {
			t.Errorf("certtype degrade: raw=%d, want 0", s.RawScore)
		}
	}
}

// TestEvaluateClampsRawOutOfRange asserts that a signal returning Raw < 0
// or > 100 does not corrupt the weighted dimension score. This uses a spy
// signal — the v1 built-ins are all pure and stay in range.
func TestEvaluateClampsRawOutOfRange(t *testing.T) {
	high := &clampSpy{returnRaw: 250}
	low := &clampSpy{returnRaw: -50, id: "low"}
	// Rebuild a registry with only the two spies so their scores dominate.
	// The test asserts the RawScore surfaced in the dimension breakdown is
	// clamped to [0,100].
	r := registry.New()
	if err := r.Register(high); err != nil {
		t.Fatalf("register high: %v", err)
	}
	if err := r.Register(low); err != nil {
		t.Fatalf("register low: %v", err)
	}
	eng := engine.New(fakeStore{}, r, engine.DefaultThresholds(), time.Now)
	prof := domain.ScoringProfile{
		Name:             "clamp",
		DimensionWeights: map[domain.Dimension]float64{domain.DimensionIntegrity: 1},
		SignalWeights:    map[domain.SignalID]float64{"high": 1, "low": 1},
	}
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, prof)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	dim := findDim(t, ev, domain.DimensionIntegrity)
	byID := map[domain.SignalID]int{}
	for _, s := range dim.SignalScores {
		byID[s.SignalID] = s.RawScore
	}
	if byID["high"] != 100 {
		t.Errorf("high raw=%d, want 100 (clamped from 250)", byID["high"])
	}
	if byID["low"] != 0 {
		t.Errorf("low raw=%d, want 0 (clamped from -50)", byID["low"])
	}
	// Dimension score is average of clamped Raw values: (100+0)/2 = 50.
	if dim.Score != 50 {
		t.Errorf("integrity score=%d, want 50 (average of clamped raws)", dim.Score)
	}
}

type clampSpy struct {
	id        domain.SignalID
	returnRaw int
}

func (c clampSpy) ID() domain.SignalID {
	if c.id == "" {
		return "high"
	}
	return c.id
}
func (clampSpy) Dimension() domain.Dimension    { return domain.DimensionIntegrity }
func (clampSpy) Derived() bool                  { return false }
func (clampSpy) Validate(json.RawMessage) error { return nil }
func (c clampSpy) Evaluate(context.Context, domain.Agent, *domain.SignalObservation) (port.SignalResult, error) {
	return port.SignalResult{Raw: c.returnRaw}, nil
}

// ctxSpy is a Signal whose only job is to record the ctx it was called with,
// so we can assert the engine hands its ctx down to signals (Signal.Evaluate
// contract).
type ctxSpy struct{ seen chan context.Context }

func (ctxSpy) ID() domain.SignalID            { return "ctxspy" }
func (ctxSpy) Dimension() domain.Dimension    { return domain.DimensionIntegrity }
func (ctxSpy) Derived() bool                  { return false }
func (ctxSpy) Validate(json.RawMessage) error { return nil }
func (s ctxSpy) Evaluate(ctx context.Context, _ domain.Agent, _ *domain.SignalObservation) (port.SignalResult, error) {
	// Non-blocking send; the test buffers one slot.
	select {
	case s.seen <- ctx:
	default:
	}
	return port.SignalResult{Raw: 100, Explanation: "spy"}, nil
}

func TestEvaluatePropagatesContextToSignals(t *testing.T) {
	spy := ctxSpy{seen: make(chan context.Context, 1)}
	r := registry.New()
	if err := r.Register(spy); err != nil {
		t.Fatalf("register spy: %v", err)
	}
	eng := engine.New(fakeStore{}, r, engine.DefaultThresholds(), time.Now)

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")
	prof := domain.ScoringProfile{
		Name:             "spy",
		DimensionWeights: map[domain.Dimension]float64{domain.DimensionIntegrity: 1},
		SignalWeights:    map[domain.SignalID]float64{"ctxspy": 1},
	}
	if _, err := eng.Evaluate(ctx, domain.Agent{ID: "a"}, prof); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	got := <-spy.seen
	if v, _ := got.Value(ctxKey{}).(string); v != "marker" {
		t.Fatalf("ctx not propagated to signal: want marker, got %v", got.Value(ctxKey{}))
	}
}

func TestNewDefaultsClock(t *testing.T) {
	// nil clock must not panic and must stamp a recent time.
	eng := engine.New(fakeStore{}, newRegistry(t, time.Now), engine.DefaultThresholds(), nil)
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, defaultProfile())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if ev.EvaluationTime.IsZero() {
		t.Error("EvaluationTime is zero; nil clock should default to time.Now")
	}
}

// absenceSpy is a test signal for the issue #13(a) absent-observation policy.
// It implements the optional port.AbsenceAware interface so a test can toggle
// whether a missing observation is informative.
type absenceSpy struct {
	id          domain.SignalID
	dim         domain.Dimension
	raw         int
	informative bool
}

func (s absenceSpy) ID() domain.SignalID            { return s.id }
func (s absenceSpy) Dimension() domain.Dimension    { return s.dim }
func (s absenceSpy) Derived() bool                  { return false }
func (s absenceSpy) Validate(json.RawMessage) error { return nil }
func (s absenceSpy) AbsenceInformative() bool       { return s.informative }
func (s absenceSpy) Evaluate(_ context.Context, _ domain.Agent, _ *domain.SignalObservation) (port.SignalResult, error) {
	return port.SignalResult{Raw: s.raw, Attestation: domain.AttestationUnattested}, nil
}

func registerAll(t *testing.T, sigs ...port.Signal) *registry.Registry {
	t.Helper()
	r := registry.New()
	for _, s := range sigs {
		if err := r.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.ID(), err)
		}
	}
	return r
}

// The #13 scenario: two providers in one dimension, one has scored the agent
// and one never has. The absent provider (absence non-informative) must be
// EXCLUDED, so the dimension reads the covering provider's score, not the
// average with a zero.
func TestAbsentNonInformativeSignalExcluded(t *testing.T) {
	covered := absenceSpy{id: "prov.a", dim: domain.DimensionSolvency, raw: 100, informative: false}
	uncovered := absenceSpy{id: "prov.b", dim: domain.DimensionSolvency, raw: 0, informative: false}
	r := registerAll(t, covered, uncovered)
	store := fakeStore{obs: map[domain.SignalID]*domain.SignalObservation{"prov.a": obs(`{}`)}}
	eng := engine.New(store, r, engine.DefaultThresholds(), time.Now)
	prof := domain.ScoringProfile{
		Name:             "solv",
		DimensionWeights: map[domain.Dimension]float64{domain.DimensionSolvency: 1},
		SignalWeights:    map[domain.SignalID]float64{"prov.a": 1, "prov.b": 1},
	}
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, prof)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	dim := findDim(t, ev, domain.DimensionSolvency)
	if dim.Score != 100 {
		t.Errorf("solvency = %d, want 100 (absent provider excluded, not averaged to 50)", dim.Score)
	}
	for _, s := range dim.SignalScores {
		if s.SignalID == "prov.b" {
			t.Errorf("absent non-informative prov.b must be excluded, got entry %+v", s)
		}
	}
}

// When every signal in a dimension is absent + non-informative, the dimension
// carries no signal scores (inactive/unknown), not a misleading active-0.
func TestAllAbsentDimensionCarriesNoScores(t *testing.T) {
	only := absenceSpy{id: "prov.a", dim: domain.DimensionSafety, raw: 0, informative: false}
	eng := engine.New(fakeStore{}, registerAll(t, only), engine.DefaultThresholds(), time.Now)
	prof := domain.ScoringProfile{
		Name:             "safety",
		DimensionWeights: map[domain.Dimension]float64{domain.DimensionSafety: 1},
		SignalWeights:    map[domain.SignalID]float64{"prov.a": 1},
	}
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, prof)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	dim := findDim(t, ev, domain.DimensionSafety)
	if len(dim.SignalScores) != 0 {
		t.Errorf("fully-uncovered dimension should carry no signal scores, got %+v", dim.SignalScores)
	}
}

// A signal that does NOT opt out (absence informative) keeps the v1 behavior:
// a missing observation scores 0 and counts. This preserves the integrity
// built-ins, where a missing observation is itself meaningful.
func TestAbsentInformativeSignalStillCountsZero(t *testing.T) {
	informativeAbsent := absenceSpy{id: "prov.c", dim: domain.DimensionIntegrity, raw: 0, informative: true}
	covered := absenceSpy{id: "prov.d", dim: domain.DimensionIntegrity, raw: 80, informative: true}
	r := registerAll(t, informativeAbsent, covered)
	store := fakeStore{obs: map[domain.SignalID]*domain.SignalObservation{"prov.d": obs(`{}`)}}
	eng := engine.New(store, r, engine.DefaultThresholds(), time.Now)
	prof := domain.ScoringProfile{
		Name:             "intg",
		DimensionWeights: map[domain.Dimension]float64{domain.DimensionIntegrity: 1},
		SignalWeights:    map[domain.SignalID]float64{"prov.c": 1, "prov.d": 1},
	}
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, prof)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	dim := findDim(t, ev, domain.DimensionIntegrity)
	if dim.Score != 40 { // (0 + 80) / 2 — informative absence still counts
		t.Errorf("integrity = %d, want 40 (informative absence scores 0 and counts)", dim.Score)
	}
}

// gateSpy is a Signal that can act as a gate: it returns a fixed Raw and an
// optional DimensionCap, and declares whether its absence is informative so the
// #14 interaction can be exercised.
type gateSpy struct {
	id                 domain.SignalID
	dim                domain.Dimension
	raw                int
	cap                *int
	absenceInformative bool
}

func (g gateSpy) ID() domain.SignalID          { return g.id }
func (g gateSpy) Dimension() domain.Dimension  { return g.dim }
func (gateSpy) Derived() bool                  { return false }
func (gateSpy) Validate(json.RawMessage) error { return nil }
func (g gateSpy) AbsenceInformative() bool     { return g.absenceInformative }
func (g gateSpy) Evaluate(context.Context, domain.Agent, *domain.SignalObservation) (port.SignalResult, error) {
	return port.SignalResult{Raw: g.raw, DimensionCap: g.cap}, nil
}

func capPtr(n int) *int { return &n }

// evalSafety registers the given signals, evaluates one agent with safety
// weighted, and returns the safety dimension score.
func evalSafety(t *testing.T, store engine.ObservationReader, weights map[domain.SignalID]float64, sigs ...port.Signal) domain.DimensionScore {
	t.Helper()
	r := registry.New()
	for _, s := range sigs {
		if err := r.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.ID(), err)
		}
	}
	eng := engine.New(store, r, engine.DefaultThresholds(), time.Now)
	prof := domain.ScoringProfile{
		Name:             "gate",
		DimensionWeights: map[domain.Dimension]float64{domain.DimensionSafety: 1},
		SignalWeights:    weights,
	}
	ev, err := eng.Evaluate(context.Background(), domain.Agent{ID: "a"}, prof)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return findDim(t, ev, domain.DimensionSafety)
}

// A gating signal caps its dimension: a hard block (Raw 0, cap 0) beside a
// signal scoring 100 yields 0, not the 50 the average would give — blocked is a
// verdict, not a term (issue #13(b)).
func TestEvaluateGatingCapsDimension(t *testing.T) {
	gate := gateSpy{id: "gate", dim: domain.DimensionSafety, raw: 0, cap: capPtr(0), absenceInformative: true}
	good := gateSpy{id: "good", dim: domain.DimensionSafety, raw: 100, absenceInformative: true}
	dim := evalSafety(t, fakeStore{}, map[domain.SignalID]float64{"gate": 1, "good": 1}, gate, good)
	if dim.Score != 0 {
		t.Errorf("gated safety score = %d, want 0 (cap beats the 50 average)", dim.Score)
	}
}

// The cap composes with the absent-observation policy (#14): an absent,
// non-informative gating signal is skipped before Evaluate, so it produces no
// cap — only a present gate caps. Here the block never fires because it has no
// observation, and the co-signal's 100 stands uncapped.
func TestEvaluateGatingCapComposesWithAbsence(t *testing.T) {
	absentGate := gateSpy{id: "gate", dim: domain.DimensionSafety, raw: 0, cap: capPtr(0), absenceInformative: false}
	good := gateSpy{id: "good", dim: domain.DimensionSafety, raw: 100, absenceInformative: true}
	// fakeStore has no observation for either signal.
	dim := evalSafety(t, fakeStore{}, map[domain.SignalID]float64{"gate": 1, "good": 1}, absentGate, good)
	if dim.Score != 100 {
		t.Errorf("absent gate should not cap: score = %d, want 100", dim.Score)
	}
}

// A weight-0 (inactive) gating signal does not cap — zeroing its weight disables
// the gate, consistent with risk-code handling.
func TestEvaluateWeightZeroGateDoesNotCap(t *testing.T) {
	gate := gateSpy{id: "gate", dim: domain.DimensionSafety, raw: 0, cap: capPtr(0), absenceInformative: true}
	good := gateSpy{id: "good", dim: domain.DimensionSafety, raw: 100, absenceInformative: true}
	dim := evalSafety(t, fakeStore{}, map[domain.SignalID]float64{"gate": 0, "good": 1}, gate, good)
	if dim.Score != 100 {
		t.Errorf("weight-0 gate should not cap: score = %d, want 100", dim.Score)
	}
}

// A cap above the weighted average is a no-op: caps only pull a dimension down.
func TestEvaluateGatingCapOnlyLowers(t *testing.T) {
	gate := gateSpy{id: "gate", dim: domain.DimensionSafety, raw: 60, cap: capPtr(80), absenceInformative: true}
	good := gateSpy{id: "good", dim: domain.DimensionSafety, raw: 40, absenceInformative: true}
	dim := evalSafety(t, fakeStore{}, map[domain.SignalID]float64{"gate": 1, "good": 1}, gate, good)
	if dim.Score != 50 {
		t.Errorf("cap above average should be a no-op: score = %d, want 50", dim.Score)
	}
}
