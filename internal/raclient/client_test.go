package raclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchEvents_ParsesPageAndSendsParams(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/events" {
			t.Errorf("path = %q, want /v1/agents/events", r.URL.Path)
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items": [
				{"logId":"L1","eventType":"AGENT_REGISTERED","createdAt":"2026-07-01T00:00:00Z",
				 "agentId":"a1","ansName":"ans://v1.0.0.x.example.com","agentHost":"x.example.com",
				 "version":"v1.0.0","agentDisplayName":"X","agentDescription":"desc",
				 "endpoints":[{"agentUrl":"https://x.example.com","protocol":"A2A","transports":["HTTP"]}]}
			],
			"lastLogId": "L1"
		}`))
	}))
	defer srv.Close()

	page, err := New(srv.Client()).FetchEvents(context.Background(), srv.URL, "L0", 50)
	if err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}
	if gotQuery != "lastLogId=L0&limit=50" {
		t.Errorf("query = %q, want lastLogId=L0&limit=50", gotQuery)
	}
	if len(page.Items) != 1 || page.Items[0].AgentID != "a1" || page.LastLogID != "L1" {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.Items[0].Endpoints[0].Protocol != "A2A" || page.Items[0].Endpoints[0].Transports[0] != "HTTP" {
		t.Errorf("endpoint not parsed: %+v", page.Items[0].Endpoints)
	}
}

func TestFetchEvents_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := New(srv.Client()).FetchEvents(context.Background(), srv.URL, "", 100); err == nil {
		t.Fatal("expected error on 503, got nil")
	}
}

func TestFetchEvents_OmitsCursorWhenEmpty(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"items":[],"lastLogId":""}`))
	}))
	defer srv.Close()
	if _, err := New(srv.Client()).FetchEvents(context.Background(), srv.URL, "", 100); err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}
	if gotQuery != "limit=100" {
		t.Errorf("query = %q, want limit=100 (no lastLogId)", gotQuery)
	}
}
