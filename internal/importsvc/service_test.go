package importsvc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/adapter/sqlitestore"
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/importsvc"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/registry"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

const hex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// newService wires the import service against the real SQLite store and the
// real signal registry (built-ins). Real components, no mocks — only the
// infra-failure tests below substitute a failing store.
func newService(t *testing.T) (*importsvc.Service, *sqlitestore.DB) {
	t.Helper()
	db, err := sqlitestore.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := registry.New()
	for _, s := range signals.BuiltIns(nil) {
		if err := reg.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.ID(), err)
		}
	}
	return importsvc.New(db, reg), db
}

func seedAgent(t *testing.T, store port.AgentStore, id string) {
	t.Helper()
	a := domain.Agent{
		ID:          domain.AgentID(id),
		DNSName:     "ans://v1.0.0." + id + ".example.com",
		DisplayName: "Agent " + id,
		Status:      domain.StatusActive,
		FirstSeen:   time.Date(2025, 12, 23, 10, 0, 0, 0, time.UTC),
		LastUpdated: time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC),
	}
	if err := store.UpsertAgent(context.Background(), a); err != nil {
		t.Fatalf("seed agent %q: %v", id, err)
	}
}

func obs(agentID, signalID, value string) domain.SignalObservation {
	return domain.SignalObservation{
		AgentID:    domain.AgentID(agentID),
		SignalID:   domain.SignalID(signalID),
		ObservedAt: time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC),
		Value:      json.RawMessage(value),
	}
}

func assertWebError(t *testing.T, err error, status int, code string) *web.Error {
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
	return we
}

func TestImportObservations_Valid(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "agent-1")
	ctx := context.Background()

	err := svc.ImportObservations(ctx, []domain.SignalObservation{
		obs("agent-1", "certtype", `{"type":"EV"}`),
	})
	if err != nil {
		t.Fatalf("ImportObservations: %v", err)
	}
	got, err := store.LatestObservation(ctx, "agent-1", "certtype")
	if err != nil {
		t.Fatalf("LatestObservation: %v", err)
	}
	if got == nil {
		t.Fatal("observation was not persisted")
	}
}

func TestImportObservations_AgentNotFound(t *testing.T) {
	svc, _ := newService(t)
	err := svc.ImportObservations(context.Background(), []domain.SignalObservation{
		obs("ghost", "certtype", `{"type":"EV"}`),
	})
	assertWebError(t, err, http.StatusUnprocessableEntity, importsvc.CodeAgentNotFound)
}

func TestImportObservations_UnknownSignal(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "agent-1")
	err := svc.ImportObservations(context.Background(), []domain.SignalObservation{
		obs("agent-1", "not-a-signal", `{}`),
	})
	assertWebError(t, err, http.StatusUnprocessableEntity, importsvc.CodeUnknownSignal)
}

func TestImportObservations_DerivedSignalRejected(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "agent-1")
	err := svc.ImportObservations(context.Background(), []domain.SignalObservation{
		obs("agent-1", "agentage", `{}`),
	})
	assertWebError(t, err, http.StatusUnprocessableEntity, importsvc.CodeInvalidSignal)
}

func TestImportObservations_InvalidValue(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "agent-1")
	err := svc.ImportObservations(context.Background(), []domain.SignalObservation{
		obs("agent-1", "certtype", `{"type":"BOGUS"}`),
	})
	we := assertWebError(t, err, http.StatusUnprocessableEntity, importsvc.CodeInvalidSignalValue)
	// §5.2.1: detail must carry signalId + agentId + the Validate error string.
	for _, want := range []string{"certtype", "agent-1"} {
		if !strings.Contains(we.Detail, want) {
			t.Errorf("detail %q missing %q", we.Detail, want)
		}
	}
}

func TestImportObservations_BatchAtomic_NothingPersistedOnFailure(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "agent-1")
	ctx := context.Background()

	// First row is valid; second row fails (unknown signal). The whole batch
	// must be rejected and the valid row must NOT be persisted (§5.2.1:
	// validate-all-before-persist-any).
	err := svc.ImportObservations(ctx, []domain.SignalObservation{
		obs("agent-1", "certtype", `{"type":"EV"}`),
		obs("agent-1", "totally-unknown", `{}`),
	})
	if err == nil {
		t.Fatal("expected the batch to be rejected")
	}
	got, _ := store.LatestObservation(ctx, "agent-1", "certtype")
	if got != nil {
		t.Errorf("valid row was persisted despite batch failure: %+v", got)
	}
}

func TestImportObservations_Supersede(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "agent-1")
	ctx := context.Background()

	older := obs("agent-1", "certtype", `{"type":"DV"}`)
	older.ObservedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := obs("agent-1", "certtype", `{"type":"EV"}`)
	newer.ObservedAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	if err := svc.ImportObservations(ctx, []domain.SignalObservation{older}); err != nil {
		t.Fatalf("import older: %v", err)
	}
	if err := svc.ImportObservations(ctx, []domain.SignalObservation{newer}); err != nil {
		t.Fatalf("import newer: %v", err)
	}

	got, _ := store.LatestObservation(ctx, "agent-1", "certtype")
	if got == nil {
		t.Fatal("no observation found")
	}
	var v struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(got.Value, &v)
	if v.Type != "EV" {
		t.Errorf("latest type = %q, want EV (newer should supersede)", v.Type)
	}
}

func TestImportObservations_ProvenancePersisted(t *testing.T) {
	svc, store := newService(t)
	seedAgent(t, store, "agent-1")
	ctx := context.Background()

	o := obs("agent-1", "certfingerprint.server",
		`{"expected":"SHA256:`+hex64+`","observed":"SHA256:`+hex64+`","matched":true,"expectedSource":"tl_attestation","observedSource":"fixture"}`)
	o.Provenance = &domain.Provenance{AIMID: "did:web:demo-aim.local", EvidenceURL: "https://demo-aim.local/f.json"}

	if err := svc.ImportObservations(ctx, []domain.SignalObservation{o}); err != nil {
		t.Fatalf("ImportObservations: %v", err)
	}
	got, _ := store.LatestObservation(ctx, "agent-1", "certfingerprint.server")
	if got == nil || got.Provenance == nil {
		t.Fatal("provenance was not persisted")
	}
	if got.Provenance.AIMID != "did:web:demo-aim.local" {
		t.Errorf("aimId = %q", got.Provenance.AIMID)
	}
}

func TestImportObservations_StoreErrorIs500(t *testing.T) {
	reg := registry.New()
	for _, s := range signals.BuiltIns(nil) {
		_ = reg.Register(s)
	}
	svc := importsvc.New(failingStore{}, reg)

	err := svc.ImportObservations(context.Background(), []domain.SignalObservation{
		obs("agent-1", "certtype", `{"type":"EV"}`),
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	var we *web.Error
	if errors.As(err, &we) {
		t.Errorf("infra error must NOT be a *web.Error (so it maps to 500), got %+v", we)
	}
}

func TestImportAgents_PersistsBatch(t *testing.T) {
	svc, store := newService(t)
	ctx := context.Background()

	agents := []domain.Agent{
		{ID: "a1", DNSName: "ans://a1", DisplayName: "A1", Status: domain.StatusActive,
			FirstSeen: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), LastUpdated: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ID: "a2", DNSName: "ans://a2", DisplayName: "A2", Status: domain.StatusRevoked,
			FirstSeen: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), LastUpdated: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	if err := svc.ImportAgents(ctx, agents); err != nil {
		t.Fatalf("ImportAgents: %v", err)
	}
	for _, id := range []domain.AgentID{"a1", "a2"} {
		if _, found, _ := store.GetAgent(ctx, id); !found {
			t.Errorf("agent %q not persisted", id)
		}
	}
}

func TestImportAgents_UpsertMovesFirstSeen(t *testing.T) {
	svc, store := newService(t)
	ctx := context.Background()

	a := domain.Agent{ID: "a1", DNSName: "ans://a1", DisplayName: "A1", Status: domain.StatusActive,
		FirstSeen: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), LastUpdated: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := svc.ImportAgents(ctx, []domain.Agent{a}); err != nil {
		t.Fatalf("first import: %v", err)
	}

	moved := a
	moved.FirstSeen = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC) // re-import moves agentage input (§5.2.1)
	if err := svc.ImportAgents(ctx, []domain.Agent{moved}); err != nil {
		t.Fatalf("re-import: %v", err)
	}

	got, _, _ := store.GetAgent(ctx, "a1")
	if !got.FirstSeen.Equal(moved.FirstSeen) {
		t.Errorf("firstSeen = %v, want %v (upsert should replace)", got.FirstSeen, moved.FirstSeen)
	}
}

func TestImportAgents_StoreErrorIs500(t *testing.T) {
	reg := registry.New()
	svc := importsvc.New(failingStore{}, reg)
	err := svc.ImportAgents(context.Background(), []domain.Agent{
		{ID: "a1", DNSName: "ans://a1", DisplayName: "A1", Status: domain.StatusActive,
			FirstSeen: time.Now(), LastUpdated: time.Now()},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	var we *web.Error
	if errors.As(err, &we) {
		t.Errorf("infra error must NOT be a *web.Error, got %+v", we)
	}
}

// failingStore satisfies port.AgentStore but fails the read/write paths so the
// service surfaces an unexpected (→500) error rather than a typed *web.Error.
type failingStore struct{}

func (failingStore) UpsertAgent(context.Context, domain.Agent) error {
	return errors.New("boom: upsert failed")
}

func (failingStore) UpsertAgents(context.Context, []domain.Agent) error {
	return errors.New("boom: upsert failed")
}

func (failingStore) GetAgent(context.Context, domain.AgentID) (domain.Agent, bool, error) {
	return domain.Agent{}, false, errors.New("boom: lookup failed")
}

func (failingStore) AppendObservation(context.Context, domain.SignalObservation) error {
	return errors.New("boom: append failed")
}

func (failingStore) AppendObservations(context.Context, []domain.SignalObservation) error {
	return errors.New("boom: append failed")
}

func (failingStore) LatestObservation(context.Context, domain.AgentID, domain.SignalID) (*domain.SignalObservation, error) {
	return nil, errors.New("boom: latest failed")
}

var _ port.AgentStore = failingStore{}

// appendFailingStore reports the agent as present (so validation passes) but
// fails the append — exercising the service's persist-loop error path (→ 500).
type appendFailingStore struct{ failingStore }

func (appendFailingStore) GetAgent(context.Context, domain.AgentID) (domain.Agent, bool, error) {
	return domain.Agent{ID: "a1", Status: domain.StatusActive}, true, nil
}

func TestImportObservations_AppendErrorIs500(t *testing.T) {
	reg := registry.New()
	for _, s := range signals.BuiltIns(nil) {
		_ = reg.Register(s)
	}
	svc := importsvc.New(appendFailingStore{}, reg)

	err := svc.ImportObservations(context.Background(), []domain.SignalObservation{
		obs("a1", "certtype", `{"type":"EV"}`),
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	var we *web.Error
	if errors.As(err, &we) {
		t.Errorf("append failure must NOT be a *web.Error (→500), got %+v", we)
	}
}
