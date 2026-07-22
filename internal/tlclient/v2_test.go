package tlclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestFetch_MapsV1ProdFixtureToEvent pins the V1 (prod) decode path against a
// real captured badge response — it must keep working byte-for-byte as the V2
// path is added alongside it.
func TestFetch_MapsV1ProdFixtureToEvent(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/badge_v1_prod.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	const ansID = "121072b1-79d5-4d2f-8eba-298addcb53d3"
	ev, err := New(srv.Client()).Fetch(context.Background(), srv.URL, ansID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if ev.ANSID != ansID {
		t.Fatalf("ansId: got %q, want %q", ev.ANSID, ansID)
	}
	if ev.Status != "EXPIRED" {
		t.Fatalf("status: got %q, want EXPIRED (from response root)", ev.Status)
	}
	if ev.FirstSeen != "2026-03-23T19:20:59Z" {
		t.Fatalf("firstSeen: got %q", ev.FirstSeen)
	}
	if ev.LastUpdated != "2026-03-23T19:32:40Z" {
		t.Fatalf("lastUpdated: got %q", ev.LastUpdated)
	}
	if ev.Agent.Host != "corn-futures.aginttest.net" {
		t.Fatalf("agent.host: got %q", ev.Agent.Host)
	}
	if ev.Agent.Version != "v1.0.0" {
		t.Fatalf("agent.version: got %q", ev.Agent.Version)
	}
	if ev.Agent.Name != "Corn Futures" {
		t.Fatalf("agent.name: got %q", ev.Agent.Name)
	}
	if want := "SHA256:2ed286d0c5ab2a9c0fa13c47785ee6409a25a9492219c44b26ae0dcbaa169d30"; ev.Attestations.ServerCert.Fingerprint != want {
		t.Fatalf("serverCert.fingerprint: got %q, want %q", ev.Attestations.ServerCert.Fingerprint, want)
	}
	if want := "SHA256:fa2bbcdada9d2f6cc8b3034cac67cec07144f7aaa87933127a5e6067d0c64991"; ev.Attestations.IdentityCert.Fingerprint != want {
		t.Fatalf("identityCert.fingerprint: got %q, want %q", ev.Attestations.IdentityCert.Fingerprint, want)
	}
	if want := "v=ans1; version=v1.0.0; p=a2a; mode=direct; url=https://corn-futures.aginttest.net/"; ev.Attestations.DNSRecordsProvisioned.ANS != want {
		t.Fatalf("_ans: got %q, want %q", ev.Attestations.DNSRecordsProvisioned.ANS, want)
	}
	if want := "v=ans-badge1; version=v1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/121072b1-79d5-4d2f-8eba-298addcb53d3"; ev.Attestations.DNSRecordsProvisioned.ANSBadge != want {
		t.Fatalf("_ans-badge: got %q, want %q", ev.Attestations.DNSRecordsProvisioned.ANSBadge, want)
	}
}

// TestFetch_MapsV2ReferenceFixtureToEvent asserts the reference ans-tl's V2
// badge shape (plural cert arrays, array-shaped DNS records) decodes into the
// exact same tlevent.Event fields the V1 path produces.
func TestFetch_MapsV2ReferenceFixtureToEvent(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/badge_v2_reference.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	const ansID = "73020903-9917-4e5e-972f-36f76f3c7e1a"
	ev, err := New(srv.Client()).Fetch(context.Background(), srv.URL, ansID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if ev.ANSID != ansID {
		t.Fatalf("ansId: got %q, want %q", ev.ANSID, ansID)
	}
	if ev.Status != "ACTIVE" {
		t.Fatalf("status: got %q, want ACTIVE (from response root)", ev.Status)
	}
	if ev.FirstSeen != "2026-07-21T15:11:26Z" {
		t.Fatalf("firstSeen: got %q", ev.FirstSeen)
	}
	if ev.LastUpdated != "2026-07-21T15:11:26Z" {
		t.Fatalf("lastUpdated: got %q", ev.LastUpdated)
	}
	if ev.Agent.Host != "demo-819792fd.example.com" {
		t.Fatalf("agent.host: got %q", ev.Agent.Host)
	}
	if ev.Agent.Version != "1.0.0" {
		t.Fatalf("agent.version: got %q", ev.Agent.Version)
	}
	if ev.Agent.Name != "demo-agent" {
		t.Fatalf("agent.name: got %q", ev.Agent.Name)
	}
	if want := "SHA256:c15286f12f34d1231b49a02963b8c7d0cfbd957b9f64641fdcc5fc7219343389"; ev.Attestations.ServerCert.Fingerprint != want {
		t.Fatalf("serverCert.fingerprint (from serverCerts[0]): got %q, want %q", ev.Attestations.ServerCert.Fingerprint, want)
	}
	if want := "SHA256:56237c3e19206707ccd0f4d1effa6fbf1a4a784e34cdf74ae6320517ceead1b3"; ev.Attestations.IdentityCert.Fingerprint != want {
		t.Fatalf("identityCert.fingerprint (from identityCerts[0]): got %q, want %q", ev.Attestations.IdentityCert.Fingerprint, want)
	}
	if want := "v=ans1; version=v1.0.0; p=mcp; mode=direct; url=https://demo-819792fd.example.com/mcp"; ev.Attestations.DNSRecordsProvisioned.ANS != want {
		t.Fatalf("_ans (resolved from array): got %q, want %q", ev.Attestations.DNSRecordsProvisioned.ANS, want)
	}
	if want := "v=ans-badge1; version=v1.0.0; url=https://localhost:18081/v1/agents/73020903-9917-4e5e-972f-36f76f3c7e1a"; ev.Attestations.DNSRecordsProvisioned.ANSBadge != want {
		t.Fatalf("_ans-badge (resolved from array): got %q, want %q", ev.Attestations.DNSRecordsProvisioned.ANSBadge, want)
	}
}

// TestPrimaryCertFingerprint exercises the newest-notAfter cert-selection
// helper in isolation: multi-entry arrays, tie/unparseable fallback to the
// first entry, and the empty-array case.
func TestPrimaryCertFingerprint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		certs []tlCertV2
		want  string
	}{
		{
			name:  "empty array yields empty fingerprint",
			certs: nil,
			want:  "",
		},
		{
			name:  "single entry",
			certs: []tlCertV2{{Fingerprint: "A", NotAfter: "2026-01-01T00:00:00Z"}},
			want:  "A",
		},
		{
			name: "picks newest notAfter regardless of order",
			certs: []tlCertV2{
				{Fingerprint: "OLD", NotAfter: "2026-01-01T00:00:00Z"},
				{Fingerprint: "NEWEST", NotAfter: "2027-06-15T00:00:00Z"},
				{Fingerprint: "MID", NotAfter: "2026-06-15T00:00:00Z"},
			},
			want: "NEWEST",
		},
		{
			name: "tie among newest keeps the first newest entry",
			certs: []tlCertV2{
				{Fingerprint: "FIRST", NotAfter: "2027-01-01T00:00:00Z"},
				{Fingerprint: "TIED", NotAfter: "2027-01-01T00:00:00Z"},
			},
			want: "FIRST",
		},
		{
			// certs[0] is NOT among the newest, and the two newest tie. The
			// result must be the first of the newest (NEW_FIRST), never certs[0].
			name: "tie among newest ignores an older certs[0]",
			certs: []tlCertV2{
				{Fingerprint: "OLD", NotAfter: "2026-01-01T00:00:00Z"},
				{Fingerprint: "NEW_FIRST", NotAfter: "2027-06-15T00:00:00Z"},
				{Fingerprint: "NEW_SECOND", NotAfter: "2027-06-15T00:00:00Z"},
			},
			want: "NEW_FIRST",
		},
		{
			name: "all unparseable falls back to first entry",
			certs: []tlCertV2{
				{Fingerprint: "FIRST", NotAfter: "not-a-time"},
				{Fingerprint: "SECOND", NotAfter: ""},
			},
			want: "FIRST",
		},
		{
			name: "unparseable entries are skipped in favor of a parseable one",
			certs: []tlCertV2{
				{Fingerprint: "BAD", NotAfter: "not-a-time"},
				{Fingerprint: "GOOD", NotAfter: "2026-01-01T00:00:00Z"},
			},
			want: "GOOD",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := primaryCertFingerprint(tc.certs); got != tc.want {
				t.Fatalf("primaryCertFingerprint() = %q, want %q", got, tc.want)
			}
		})
	}
}
