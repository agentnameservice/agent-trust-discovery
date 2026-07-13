package importsvc

import (
	"encoding/json"
	"net/http"

	"github.com/agentnameservice/agent-trust-discovery/internal/auditctx"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

// Handler is the HTTP adapter for the import service. Its methods are mounted on
// the admin routes (behind the admin-key middleware) during server wiring
// (design §5.3, Phase 7); they are plain http.HandlerFunc so they test directly
// with httptest.
type Handler struct {
	svc *Service
}

// NewHandler constructs a Handler over the given service.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// importAck is the 200 response body — a minimal acknowledgement of how many
// rows were accepted. The spec leaves the 200 body unspecified; this is an
// additive convenience for the curl walkthrough.
type importAck struct {
	Imported int `json:"imported"`
}

// ImportAgents handles POST /v1/internal/agents/import: decode, convert (400 on
// malformed request), upsert the batch (500 on storage failure), ack with 200.
func (h *Handler) ImportAgents(w http.ResponseWriter, r *http.Request) {
	var req importAgentsRequest
	if err := decodeJSON(r, &req); err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	agents, err := req.toDomain()
	if err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	if err := h.svc.ImportAgents(r.Context(), agents); err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	if info := auditctx.From(r.Context()); info != nil {
		info.Accepted = len(agents)
	}
	web.WriteJSON(w, http.StatusOK, importAck{Imported: len(agents)})
}

// ImportObservations handles POST /v1/internal/observations/import: decode,
// convert (400), validate + append the batch atomically (422 on a bad row, 500
// on storage failure), ack with 200.
func (h *Handler) ImportObservations(w http.ResponseWriter, r *http.Request) {
	var req importObservationsRequest
	if err := decodeJSON(r, &req); err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	observations, err := req.toDomain()
	if err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	if err := h.svc.ImportObservations(r.Context(), observations); err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	if info := auditctx.From(r.Context()); info != nil {
		info.Accepted = len(observations)
	}
	web.WriteJSON(w, http.StatusOK, importAck{Imported: len(observations)})
}

// decodeJSON decodes the request body into dst, mapping any parse failure to
// a 400 INVALID_REQUEST (§5.2.1). Body-too-large is enforced upstream by the
// audit middleware, so by the time we reach the handler the body is bounded.
func decodeJSON(r *http.Request, dst any) error {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return errInvalidRequest("request body is not valid JSON: " + err.Error())
	}
	return nil
}
