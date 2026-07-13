package server

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/agentnameservice/agent-trust-discovery/internal/importsvc"
	"github.com/agentnameservice/agent-trust-discovery/internal/search"
)

// newRouter mounts the implemented routes only (design §2.2: a registered route
// is a committed contract; unimplemented = unregistered → 404). Global
// middleware: requestID. Public read routes wrap the request logger around
// recoverer; admin routes wrap audit around recoverer so both loggers observe
// the final (500) status after a panic, and the mandatory admin audit line
// still fires on a panicking handler (design §5.6).
func newRouter(searchH *search.Handler, importH *importsvc.Handler, adminAuth func(http.Handler) http.Handler, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(requestID(logger))

	// Liveness probe: always open, intentionally unlogged (design §5.3).
	// recoverer wraps it as a safety net — Health should never panic, but if
	// it did we'd rather log + 500 than crash the process.
	r.Get("/health", recoverer(http.HandlerFunc(searchH.Health)).ServeHTTP)

	r.Group(func(read chi.Router) {
		read.Use(requestLogger)
		read.Use(recoverer)
		read.Get("/v1/ans/registered-agents", searchH.SearchByQuery)
		read.Post("/v1/ans/search-registered-agents", searchH.SearchByBody)
		read.Get("/v1/ans/registered-agents/{agentId}", detailBridge(searchH))
	})

	r.Group(func(admin chi.Router) {
		admin.Use(audit)
		admin.Use(recoverer)
		admin.Use(adminAuth)
		admin.Post("/v1/internal/agents/import", importH.ImportAgents)
		admin.Post("/v1/internal/observations/import", importH.ImportObservations)
	})

	return r
}

// detailBridge copies chi's route param into the stdlib PathValue slot the
// search handler reads, so the handler stays router-agnostic.
func detailBridge(h *search.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("agentId", chi.URLParam(r, "agentId"))
		h.Detail(w, r)
	}
}
