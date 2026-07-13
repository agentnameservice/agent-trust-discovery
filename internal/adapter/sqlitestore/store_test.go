package sqlitestore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/adapter/sqlitestore"
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func newStore(t *testing.T) *sqlitestore.DB {
	t.Helper()
	db, err := sqlitestore.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func sampleAgent(id string) domain.Agent {
	return domain.Agent{
		ID:           domain.AgentID(id),
		DNSName:      "ans://v1.0.0." + id + ".example.com",
		DisplayName:  "Booking " + id,
		Description:  "Hotel booking agent",
		ProviderID:   "godaddy",
		Status:       domain.StatusActive,
		Protocols:    []string{"A2A", "MCP"},
		Transports:   []string{"HTTP"},
		Tags:         []string{"travel", "booking"},
		Capabilities: []string{"search-hotels", "book-hotel"},
		FirstSeen:    time.Date(2025, 12, 23, 10, 0, 0, 0, time.UTC),
		LastUpdated:  time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC),
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func assertAgentEqual(t *testing.T, got, want domain.Agent) {
	t.Helper()
	if got.ID != want.ID || got.DNSName != want.DNSName || got.DisplayName != want.DisplayName ||
		got.Description != want.Description || got.ProviderID != want.ProviderID || got.Status != want.Status {
		t.Errorf("scalar mismatch:\n got=%+v\nwant=%+v", got, want)
	}
	if !sameStrings(got.Protocols, want.Protocols) || !sameStrings(got.Transports, want.Transports) ||
		!sameStrings(got.Tags, want.Tags) || !sameStrings(got.Capabilities, want.Capabilities) {
		t.Errorf("slice mismatch:\n got=%+v\nwant=%+v", got, want)
	}
	if !got.FirstSeen.Equal(want.FirstSeen) || !got.LastUpdated.Equal(want.LastUpdated) {
		t.Errorf("time mismatch: firstSeen %v/%v lastUpdated %v/%v",
			got.FirstSeen, want.FirstSeen, got.LastUpdated, want.LastUpdated)
	}
}

func TestUpsertAndGetAgentRoundTrip(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	want := sampleAgent("agent-001")
	if err := db.UpsertAgent(ctx, want); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	got, found, err := db.GetAgent(ctx, want.ID)
	if err != nil || !found {
		t.Fatalf("GetAgent: found=%v err=%v", found, err)
	}
	assertAgentEqual(t, got, want)
}

func TestGetAgentMissing(t *testing.T) {
	db := newStore(t)
	_, found, err := db.GetAgent(context.Background(), "nope")
	if err != nil {
		t.Fatalf("GetAgent err: %v", err)
	}
	if found {
		t.Fatal("found = true for missing agent")
	}
}

func TestUpsertReplacesAndResyncsFTS(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	a := sampleAgent("agent-001")
	if err := db.UpsertAgent(ctx, a); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	// Replace with a new display name + status; the FTS index must follow.
	a.DisplayName = "Concierge unique-token"
	a.Status = domain.StatusRevoked
	a.Tags = []string{"luxury"}
	if err := db.UpsertAgent(ctx, a); err != nil {
		t.Fatalf("UpsertAgent replace: %v", err)
	}

	got, found, err := db.GetAgent(ctx, a.ID)
	if err != nil || !found {
		t.Fatalf("GetAgent: found=%v err=%v", found, err)
	}
	if got.DisplayName != "Concierge unique-token" || got.Status != domain.StatusRevoked {
		t.Errorf("replace not reflected: %+v", got)
	}
	if !sameStrings(got.Tags, []string{"luxury"}) {
		t.Errorf("tags not replaced: %v", got.Tags)
	}
}

func TestUpsertAgentEmptySlicesNormalize(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	a := sampleAgent("agent-001")
	a.Protocols, a.Transports, a.Tags, a.Capabilities = nil, nil, nil, nil
	if err := db.UpsertAgent(ctx, a); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	got, _, err := db.GetAgent(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if len(got.Protocols) != 0 || len(got.Transports) != 0 || len(got.Tags) != 0 || len(got.Capabilities) != 0 {
		t.Errorf("nil slices did not normalize to empty: %+v", got)
	}
}

func TestAppendAndLatestObservation(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	older := domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype",
		ObservedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Value:      json.RawMessage(`{"type":"DV"}`),
	}
	newer := domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype",
		ObservedAt: time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC),
		Value:      json.RawMessage(`{"type":"EV"}`),
		Provenance: &domain.Provenance{AIMID: "did:web:demo-aim.local", EvidenceURL: "https://x/find.json"},
	}
	if err := db.AppendObservation(ctx, older); err != nil {
		t.Fatalf("append older: %v", err)
	}
	if err := db.AppendObservation(ctx, newer); err != nil {
		t.Fatalf("append newer: %v", err)
	}

	got, err := db.LatestObservation(ctx, "agent-001", "certtype")
	if err != nil {
		t.Fatalf("LatestObservation: %v", err)
	}
	if got == nil {
		t.Fatal("LatestObservation = nil, want newest")
	}
	if string(got.Value) != `{"type":"EV"}` {
		t.Errorf("latest value = %s, want EV", got.Value)
	}
	if got.Provenance == nil || got.Provenance.AIMID != "did:web:demo-aim.local" {
		t.Errorf("provenance not round-tripped: %+v", got.Provenance)
	}
	if !got.ObservedAt.Equal(newer.ObservedAt) {
		t.Errorf("observedAt = %v, want %v", got.ObservedAt, newer.ObservedAt)
	}
}

func TestLatestObservationNone(t *testing.T) {
	db := newStore(t)
	got, err := db.LatestObservation(context.Background(), "agent-001", "certtype")
	if err != nil {
		t.Fatalf("LatestObservation: %v", err)
	}
	if got != nil {
		t.Errorf("LatestObservation = %+v, want nil", got)
	}
}

func TestAppendObservationUnknownAgentFails(t *testing.T) {
	db := newStore(t)
	err := db.AppendObservation(context.Background(), domain.SignalObservation{
		AgentID: "ghost", SignalID: "certtype",
		ObservedAt: time.Now(), Value: json.RawMessage(`{"type":"DV"}`),
	})
	if err == nil {
		t.Fatal("append for unknown agent: want FK error, got nil")
	}
}

// TestLatestObservationOrdersByObservedAt guards that observations one second
// apart order strictly by real time. It also guards a historical bug: an
// earlier RFC3339Nano encoding trimmed trailing zeros, so a whole-second
// value "…00:00Z" (byte 0x5A) sorted greater than a fractional value
// "…00:00.5Z" (byte 0x2E) and DESC returned the older row.
func TestLatestObservationOrdersByObservedAt(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	base := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	older := domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype",
		ObservedAt: base,
		Value:      json.RawMessage(`{"type":"DV"}`),
	}
	// One second apart so encode.formatTime (whole-second precision) yields
	// distinct observed_at strings and both rows survive dedup.
	newer := domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype",
		ObservedAt: base.Add(1 * time.Second),
		Value:      json.RawMessage(`{"type":"EV"}`),
	}
	if err := db.AppendObservation(ctx, older); err != nil {
		t.Fatalf("append older: %v", err)
	}
	if err := db.AppendObservation(ctx, newer); err != nil {
		t.Fatalf("append newer: %v", err)
	}

	got, err := db.LatestObservation(ctx, "agent-001", "certtype")
	if err != nil {
		t.Fatalf("LatestObservation: %v", err)
	}
	if got == nil || string(got.Value) != `{"type":"EV"}` {
		t.Fatalf("latest = %+v, want newer EV observation", got)
	}
}

func TestObservationWithoutProvenance(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := db.AppendObservation(ctx, domain.SignalObservation{
		AgentID: "agent-001", SignalID: "dnssecurity",
		ObservedAt: time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC),
		Value:      json.RawMessage(`{"dnssec":true,"caa":true}`),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := db.LatestObservation(ctx, "agent-001", "dnssecurity")
	if err != nil {
		t.Fatalf("LatestObservation: %v", err)
	}
	if got == nil || got.Provenance != nil {
		t.Errorf("expected non-nil obs with nil provenance, got %+v", got)
	}
}

func TestMigrateIdempotentOnReopen(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ans.db"
	ctx := context.Background()
	db1, err := sqlitestore.Open(ctx, path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := db1.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Re-open the same file: migrations already applied must be a no-op and data persists.
	db2, err := sqlitestore.Open(ctx, path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	if _, found, err := db2.GetAgent(ctx, "agent-001"); err != nil || !found {
		t.Fatalf("agent not persisted across reopen: found=%v err=%v", found, err)
	}
}
