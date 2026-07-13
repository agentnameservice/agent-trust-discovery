package tlevent_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

const validEvent = `
ansId: agent-001
status: ACTIVE
providerId: godaddy
firstSeen: 2025-12-23T10:00:00Z
lastUpdated: 2026-05-28T08:00:00Z
agent:
  host: booking.example.com
  version: v1.0.0
  name: Booking
  description: Hotel booking agent
  tags: [travel, booking]
  capabilities: [search-hotels]
  endpoints:
    - protocol: A2A
      transport: HTTP
      url: https://booking.example.com/a2a
    - protocol: MCP
      transport: HTTP
      url: https://booking.example.com/mcp
attestations:
  serverCert:
    fingerprint: "SHA256:d2b71bc0"
  identityCert:
    fingerprint: "SHA256:a1c30099"
  dnsRecordsProvisioned:
    _ans: "v=ans1; version=v1.0.0; url=https://booking.example.com"
    _ans-badge: "v=ans-badge1; level=gold"
  dnssecStatus: signed
`

func TestParseEvent_Valid(t *testing.T) {
	e, err := tlevent.ParseEvent([]byte(validEvent))
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if e.ANSID != "agent-001" {
		t.Errorf("ansId = %q", e.ANSID)
	}
	if e.Agent.Host != "booking.example.com" || e.Agent.Version != "v1.0.0" || e.Agent.Name != "Booking" {
		t.Errorf("agent = %+v", e.Agent)
	}
	if len(e.Agent.Endpoints) != 2 || e.Agent.Endpoints[0].Protocol != "A2A" {
		t.Errorf("endpoints = %+v", e.Agent.Endpoints)
	}
	if e.Attestations.ServerCert.Fingerprint != "SHA256:d2b71bc0" {
		t.Errorf("serverCert = %q", e.Attestations.ServerCert.Fingerprint)
	}
	if e.Attestations.DNSRecordsProvisioned.ANS == "" || e.Attestations.DNSRecordsProvisioned.ANSBadge == "" {
		t.Errorf("dns records = %+v", e.Attestations.DNSRecordsProvisioned)
	}
}

func TestParseEvent_Errors(t *testing.T) {
	cases := map[string]string{
		"missing ansId":   "status: ACTIVE\nfirstSeen: 2025-12-23T10:00:00Z\nlastUpdated: 2026-05-28T08:00:00Z\nagent:\n  host: h\n  version: v1\n  name: n\n",
		"missing host":    "ansId: a\nstatus: ACTIVE\nfirstSeen: 2025-12-23T10:00:00Z\nlastUpdated: 2026-05-28T08:00:00Z\nagent:\n  version: v1\n  name: n\n",
		"missing version": "ansId: a\nstatus: ACTIVE\nfirstSeen: 2025-12-23T10:00:00Z\nlastUpdated: 2026-05-28T08:00:00Z\nagent:\n  host: h\n  name: n\n",
		"missing name":    "ansId: a\nstatus: ACTIVE\nfirstSeen: 2025-12-23T10:00:00Z\nlastUpdated: 2026-05-28T08:00:00Z\nagent:\n  host: h\n  version: v1\n",
		"invalid status":  "ansId: a\nstatus: BOGUS\nfirstSeen: 2025-12-23T10:00:00Z\nlastUpdated: 2026-05-28T08:00:00Z\nagent:\n  host: h\n  version: v1\n  name: n\n",
		"bad firstSeen":   "ansId: a\nstatus: ACTIVE\nfirstSeen: nope\nlastUpdated: 2026-05-28T08:00:00Z\nagent:\n  host: h\n  version: v1\n  name: n\n",
		"missing times":   "ansId: a\nstatus: ACTIVE\nagent:\n  host: h\n  version: v1\n  name: n\n",
		"malformed yaml":  "ansId: [unterminated\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tlevent.ParseEvent([]byte(src)); err == nil {
				t.Errorf("expected an error for %q", name)
			}
		})
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("b.yaml", validEvent)
	a := "ansId: agent-000\nstatus: ACTIVE\nfirstSeen: 2025-12-23T10:00:00Z\nlastUpdated: 2026-05-28T08:00:00Z\nagent:\n  host: a.example.com\n  version: v1.0.0\n  name: A\n"
	write("a.yaml", a)
	write("ignore.txt", "not yaml")

	events, err := tlevent.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("loaded %d events, want 2", len(events))
	}
	// Sorted by filename → a.yaml (agent-000) before b.yaml (agent-001).
	if events[0].ANSID != "agent-000" || events[1].ANSID != "agent-001" {
		t.Errorf("order = %q, %q; want agent-000, agent-001", events[0].ANSID, events[1].ANSID)
	}
}

func TestLoadDir_Errors(t *testing.T) {
	if _, err := tlevent.LoadDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected error for missing dir")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("ansId: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tlevent.LoadDir(dir); err == nil {
		t.Error("expected error for a malformed event file")
	}
}
