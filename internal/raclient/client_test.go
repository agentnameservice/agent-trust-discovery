package raclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestNew_NilClientFallsBackToDefault covers New's nil-httpClient guard: the
// returned Client must use http.DefaultClient and still perform a real fetch.
func TestNew_NilClientFallsBackToDefault(t *testing.T) {
	c := New(nil)
	if c.httpClient != http.DefaultClient {
		t.Fatalf("New(nil).httpClient = %v, want http.DefaultClient", c.httpClient)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"items":[],"lastLogId":""}`)
	}))
	defer srv.Close()
	if _, err := c.FetchEvents(context.Background(), srv.URL, "", 10); err != nil {
		t.Fatalf("FetchEvents with default client: %v", err)
	}
}

// TestFetchEvents_ServerBodyErrors covers the two 200-response failure branches:
// a body over the size cap must surface ErrResponseTooLarge, and a malformed
// JSON body must surface a (non-sentinel) decode error.
func TestFetchEvents_ServerBodyErrors(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		wantIs error // sentinel to match with errors.Is; nil means "any error"
	}{
		{
			name:   "oversized body exceeds cap",
			body:   strings.Repeat("a", maxResponseBodyBytes+1),
			wantIs: ErrResponseTooLarge,
		},
		{
			name: "malformed json body",
			body: "{",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			_, err := New(srv.Client()).FetchEvents(context.Background(), srv.URL, "", 100)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Fatalf("error = %v, want errors.Is %v", err, tt.wantIs)
			}
		})
	}
}

// TestFetchEvents_BadBaseURLIsError covers buildURL's parse-error branch: a
// malformed baseURL must fail before any request is issued.
func TestFetchEvents_BadBaseURLIsError(t *testing.T) {
	if _, err := New(nil).FetchEvents(context.Background(), "://bad", "", 10); err == nil {
		t.Fatal("expected error on bad base URL, got nil")
	}
}
