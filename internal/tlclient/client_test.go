package tlclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFetch_MapsProdTLResponseToEvent(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/agent.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	const ansID = "a11c5ca5-0000-0000-0000-000000000001"
	ev, err := New(srv.Client()).Fetch(context.Background(), srv.URL, ansID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if want := "/v1/agents/" + ansID; gotPath != want {
		t.Fatalf("path: got %q, want %q", gotPath, want)
	}
	if ev.ANSID != ansID {
		t.Fatalf("ansId: got %q, want %q", ev.ANSID, ansID)
	}
	if ev.Agent.Host != "ans-agent.godaddy.com" {
		t.Fatalf("host: got %q", ev.Agent.Host)
	}
	if !strings.HasPrefix(ev.Attestations.ServerCert.Fingerprint, "SHA256:c0c0") {
		t.Fatalf("serverCert.fingerprint: got %q", ev.Attestations.ServerCert.Fingerprint)
	}
	if !strings.HasPrefix(ev.Attestations.IdentityCert.Fingerprint, "SHA256:1d1d") {
		t.Fatalf("identityCert.fingerprint: got %q", ev.Attestations.IdentityCert.Fingerprint)
	}
	if !strings.HasPrefix(ev.Attestations.DNSRecordsProvisioned.ANS, "v=ans1;") {
		t.Fatalf("_ans: got %q", ev.Attestations.DNSRecordsProvisioned.ANS)
	}
	if !strings.HasPrefix(ev.Attestations.DNSRecordsProvisioned.ANSBadge, "v=ans-badge1;") {
		t.Fatalf("_ans-badge: got %q", ev.Attestations.DNSRecordsProvisioned.ANSBadge)
	}
	if ev.Status != "ACTIVE" {
		t.Fatalf("status: got %q, want ACTIVE (from response root)", ev.Status)
	}
	// firstSeen comes from event.issuedAt; lastUpdated from event.timestamp.
	// Sub-second precision must be stripped so the tlevent RFC3339 validator
	// accepts the timestamp.
	if ev.FirstSeen != "2026-03-23T19:20:59Z" {
		t.Fatalf("firstSeen: got %q", ev.FirstSeen)
	}
	if ev.LastUpdated != "2026-03-23T19:32:40Z" {
		t.Fatalf("lastUpdated: got %q", ev.LastUpdated)
	}
}

func TestNormalizeRFC3339(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"", ""},
		{"2026-03-23T19:20:59Z", "2026-03-23T19:20:59Z"},
		{"2026-03-23T19:20:59.356812Z", "2026-03-23T19:20:59Z"},
		{"2026-03-23T19:20:59.000+07:00", "2026-03-23T19:20:59+07:00"},
		{"2026-03-23T19:20:59-05:00", "2026-03-23T19:20:59-05:00"},
		{"2026-03-23T19:20:59.5", "2026-03-23T19:20:59"}, // no tz: the validator rejects the result anyway
	}
	for _, tc := range tests {
		if got := normalizeRFC3339(tc.in); got != tc.want {
			t.Fatalf("normalizeRFC3339(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFetch_MissingDNSRecordsForHostBecomeEmpty(t *testing.T) {
	t.Parallel()

	// Same shape as testdata/agent.json but with mismatched DNS keys —
	// simulates the (defensive) case where the FQDN doesn't match the host.
	const body = `{
		"status": "ACTIVE",
		"payload": {"producer": {"event": {
			"ansId":"x",
			"issuedAt":"2026-05-01T00:00:00Z", "timestamp":"2026-06-15T12:00:00Z",
			"agent": {"host":"a.example.com","version":"v1","name":"X"},
			"attestations": {
				"serverCert": {"fingerprint":"SHA256:aa"},
				"identityCert": {"fingerprint":"SHA256:bb"},
				"dnsRecordsProvisioned": {
					"_ans.other.example.com": "v=ans1; nope",
					"_ans-badge.other.example.com": "v=ans-badge1; nope"
				}
			}
		}}}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	ev, err := New(srv.Client()).Fetch(context.Background(), srv.URL, "x")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ev.Attestations.DNSRecordsProvisioned.ANS != "" ||
		ev.Attestations.DNSRecordsProvisioned.ANSBadge != "" {
		t.Fatalf("unresolved DNS keys should map to empty strings, got %+v",
			ev.Attestations.DNSRecordsProvisioned)
	}
}

func TestFetch_RejectsEmptyANSID(t *testing.T) {
	t.Parallel()
	_, err := New(nil).Fetch(context.Background(), "http://example.invalid", "")
	if err == nil || !strings.Contains(err.Error(), "ansId is required") {
		t.Fatalf("want ansId-required error, got %v", err)
	}
}

func TestFetch_InvalidBaseURL(t *testing.T) {
	t.Parallel()
	_, err := New(nil).Fetch(context.Background(), "://bad", "x")
	if err == nil {
		t.Fatalf("want parse error, got nil")
	}
}

func TestFetch_PropagatesNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.Client()).Fetch(context.Background(), srv.URL, "missing")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 error, got %v", err)
	}
}

func TestFetch_DecodeError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.Client()).Fetch(context.Background(), srv.URL, "x")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("want decode error, got %v", err)
	}
}

// TestFetch_ResponseBodyCap rejects a success body over the size cap rather
// than decoding it fully into memory — the bounded-read pattern shared with
// atdclient, applied at every external read point (PR #5 review, @chou-godaddy).
func TestFetch_ResponseBodyCap(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Valid JSON envelope wrapping a huge padding string that pushes the
		// total body past the 32 MiB cap.
		_, _ = w.Write([]byte(`{"status":"ACTIVE","payload":{"producer":{"event":{"ansId":"x","pad":"`))
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = 'x'
		}
		for range 33 { // 33 MiB > 32 MiB cap
			_, _ = w.Write(buf)
		}
		_, _ = w.Write([]byte(`"}}}}`))
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.Client()).Fetch(context.Background(), srv.URL, "x")
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}
