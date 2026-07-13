package search_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/adapter/sqlitestore"
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/engine"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/registry"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
	"github.com/agentnameservice/agent-trust-discovery/internal/search"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

// fixedNow pins the evaluation clock (and agentage's clock) so trust scores are
// deterministic. It matches the design §5.1 worked-example evaluationTime.
func fixedNow() time.Time { return time.Date(2026, 6, 4, 8, 0, 0, 0, time.UTC) }

func newService(t *testing.T) (*search.Service, *sqlitestore.DB) {
	t.Helper()
	db, err := sqlitestore.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := registry.New()
	for _, s := range signals.BuiltIns(fixedNow) {
		if err := reg.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.ID(), err)
		}
	}
	eng := engine.New(db, reg, engine.DefaultThresholds(), fixedNow)
	profiles, err := engine.LoadProfiles("../../config/default-profile.yaml", "../../config/profiles")
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	return search.New(db, db, eng, profiles), db
}

func seedAgent(t *testing.T, store port.AgentStore, id string, firstSeen time.Time) {
	t.Helper()
	a := domain.Agent{
		ID:          domain.AgentID(id),
		DNSName:     "ans://v1.0.0." + id + ".example.com",
		DisplayName: "Agent " + id,
		ProviderID:  "godaddy",
		Status:      domain.StatusActive,
		Protocols:   []string{"A2A"},
		FirstSeen:   firstSeen,
		LastUpdated: fixedNow(),
	}
	if err := store.UpsertAgent(context.Background(), a); err != nil {
		t.Fatalf("seed agent %q: %v", id, err)
	}
}

func appendObs(t *testing.T, store port.AgentStore, agentID, signalID, value string) {
	t.Helper()
	o := domain.SignalObservation{
		AgentID:    domain.AgentID(agentID),
		SignalID:   domain.SignalID(signalID),
		ObservedAt: fixedNow(),
		Value:      json.RawMessage(value),
	}
	if err := store.AppendObservation(context.Background(), o); err != nil {
		t.Fatalf("append obs %s/%s: %v", agentID, signalID, err)
	}
}

func assertWebError(t *testing.T, err error, status int, code string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var we *web.Error
	if !errors.As(err, &we) {
		t.Fatalf("error %v is not a *web.Error", err)
	}
	if we.Status != status {
		t.Errorf("status = %d, want %d", we.Status, status)
	}
	if we.Code != code {
		t.Errorf("code = %q, want %q", we.Code, code)
	}
}

func TestDetail_NotFound(t *testing.T) {
	svc, _ := newService(t)
	_, _, err := svc.Detail(context.Background(), "ghost", "default")
	assertWebError(t, err, http.StatusNotFound, search.CodeNotFound)
}

func TestDetail_UnknownProfile(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "a1", fixedNow())
	_, _, err := svc.Detail(context.Background(), "a1", "no-such-profile")
	assertWebError(t, err, http.StatusUnprocessableEntity, search.CodeUnknownProfile)
}

func TestDetail_DefaultProfileEvaluates(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "a1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	appendObs(t, store, "a1", "certtype", `{"type":"DV"}`)

	agent, eval, err := svc.Detail(context.Background(), "a1", "")
	if err != nil {
		t.Fatalf("Detail: %v", err)
	}
	if agent.ID != "a1" {
		t.Errorf("agent.ID = %q", agent.ID)
	}
	if eval.ScoringProfile != "default" {
		t.Errorf("scoringProfile = %q, want default (empty → default)", eval.ScoringProfile)
	}
	if eval.TrustVector.Identity != 40 {
		t.Errorf("identity = %d, want 40 (DV cert)", eval.TrustVector.Identity)
	}
	if !eval.EvaluationTime.Equal(fixedNow()) {
		t.Errorf("evaluationTime = %v, want %v", eval.EvaluationTime, fixedNow())
	}
	if eval.VerificationTier != domain.TierUnset {
		t.Errorf("verificationTier = %q, want unset", eval.VerificationTier)
	}
	if len(eval.Dimensions) != len(domain.AllDimensions()) {
		t.Errorf("dimensions len = %d, want %d", len(eval.Dimensions), len(domain.AllDimensions()))
	}
}

func TestDetail_ProfileReweightsClassification(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "a1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	appendObs(t, store, "a1", "certtype", `{"type":"EV"}`)                 // identity → 100
	appendObs(t, store, "a1", "dnssecurity", `{"dnssec":true,"caa":true}`) // one integrity signal high; others unobserved → 0

	_, def, err := svc.Detail(context.Background(), "a1", "default")
	if err != nil {
		t.Fatalf("default Detail: %v", err)
	}
	_, strict, err := svc.Detail(context.Background(), "a1", "identity-strict")
	if err != nil {
		t.Fatalf("identity-strict Detail: %v", err)
	}

	// default weighs integrity (dragged down by unobserved drift signals) AND
	// identity → READ_ONLY; identity-strict excludes integrity → identity 100
	// alone clears the fiduciary bar.
	if def.RecommendedProfile != domain.ProfileReadOnly {
		t.Errorf("default recommendedProfile = %q, want READ_ONLY", def.RecommendedProfile)
	}
	if strict.RecommendedProfile != domain.ProfileFiduciary {
		t.Errorf("identity-strict recommendedProfile = %q, want FIDUCIARY", strict.RecommendedProfile)
	}
	if def.ScoringProfile != "default" || strict.ScoringProfile != "identity-strict" {
		t.Errorf("scoringProfile names = %q / %q", def.ScoringProfile, strict.ScoringProfile)
	}
}

func TestSearch_Delegates(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "a1", fixedNow())
	seedAgent(t, store, "a2", fixedNow())

	page, err := svc.Search(context.Background(), port.SearchQuery{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Items) != 2 {
		t.Errorf("items = %d, want 2", len(page.Items))
	}
}

func TestSearch_IndexErrorIs500(t *testing.T) {
	reg := registry.New()
	eng := engine.New(failingStore{}, reg, engine.DefaultThresholds(), fixedNow)
	svc := search.New(failingStore{}, failingStore{}, eng, nil)
	_, err := svc.Search(context.Background(), port.SearchQuery{})
	if err == nil {
		t.Fatal("expected an error")
	}
	var we *web.Error
	if errors.As(err, &we) {
		t.Errorf("index error must NOT be a *web.Error (→500), got %+v", we)
	}
}

func TestDetail_StoreErrorIs500(t *testing.T) {
	reg := registry.New()
	eng := engine.New(failingStore{}, reg, engine.DefaultThresholds(), fixedNow)
	profiles := map[string]domain.ScoringProfile{"default": {Name: "default"}}
	svc := search.New(failingStore{}, failingStore{}, eng, profiles)
	_, _, err := svc.Detail(context.Background(), "a1", "default")
	if err == nil {
		t.Fatal("expected an error")
	}
	var we *web.Error
	if errors.As(err, &we) {
		t.Errorf("store error must NOT be a *web.Error (→500), got %+v", we)
	}
}

// fakeEvaluator satisfies search.Evaluator without pulling in the full engine.
// It lets Detail be exercised in isolation, confirming Service does not depend
// on the concrete *engine.Engine.
type fakeEvaluator struct {
	sawProfile string
	sawAgentID domain.AgentID
	returnErr  error
	returnEval domain.TrustEvaluation
}

func (f *fakeEvaluator) Evaluate(_ context.Context, a domain.Agent, p domain.ScoringProfile) (domain.TrustEvaluation, error) {
	f.sawAgentID = a.ID
	f.sawProfile = p.Name
	if f.returnErr != nil {
		return domain.TrustEvaluation{}, f.returnErr
	}
	return f.returnEval, nil
}

// TestDetail_UsesEvaluatorInterface asserts search.Service accepts any
// Evaluator implementation, not just *engine.Engine. This is the whole point
// of the Evaluator abstraction — Detail can be tested without the engine.
func TestDetail_UsesEvaluatorInterface(t *testing.T) {
	db, err := sqlitestore.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedAgent(t, db, "a1", fixedNow().AddDate(0, 0, -10))

	eval := &fakeEvaluator{
		returnEval: domain.TrustEvaluation{ScoringProfile: "spy", TrustVector: domain.TrustVector{Integrity: 42}},
	}
	profiles := map[string]domain.ScoringProfile{"default": {Name: "default"}}
	svc := search.New(db, db, eval, profiles)

	_, got, err := svc.Detail(context.Background(), "a1", "")
	if err != nil {
		t.Fatalf("Detail: %v", err)
	}
	if eval.sawAgentID != "a1" || eval.sawProfile != "default" {
		t.Errorf("evaluator saw agentID=%q profile=%q, want a1/default", eval.sawAgentID, eval.sawProfile)
	}
	if got.TrustVector.Integrity != 42 {
		t.Errorf("returned evaluation not from fake evaluator: got %+v", got)
	}
}

// failingStore satisfies port.AgentStore and port.Index, failing every call so
// the service surfaces an unexpected (→500) error.
type failingStore struct{}

func (failingStore) UpsertAgent(context.Context, domain.Agent) error { return errors.New("boom") }
func (failingStore) UpsertAgents(context.Context, []domain.Agent) error {
	return errors.New("boom")
}
func (failingStore) GetAgent(context.Context, domain.AgentID) (domain.Agent, bool, error) {
	return domain.Agent{}, false, errors.New("boom")
}
func (failingStore) AppendObservation(context.Context, domain.SignalObservation) error {
	return errors.New("boom")
}
func (failingStore) AppendObservations(context.Context, []domain.SignalObservation) error {
	return errors.New("boom")
}
func (failingStore) LatestObservation(context.Context, domain.AgentID, domain.SignalID) (*domain.SignalObservation, error) {
	return nil, errors.New("boom")
}
func (failingStore) Search(context.Context, port.SearchQuery) (port.SearchPage, error) {
	return port.SearchPage{}, errors.New("boom")
}

var (
	_ port.AgentStore = failingStore{}
	_ port.Index      = failingStore{}
)
