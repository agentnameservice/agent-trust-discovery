package search

import (
	"fmt"
	"net/http"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

// Problem-Details codes returned by the read endpoints (design §5.4). Clients
// switch on these. The status split follows the same rule the import service
// uses (design §5.2 error table): 400 for *syntactic* failures the request
// could not even parse into a well-formed shape (bad JSON, non-integer where
// an integer was required, non-boolean), and 422 for *semantic* failures
// where the request was parseable but the values don't validate — enum
// mismatches, size caps, references to resources that don't exist.
const (
	CodeNotFound       = "AGENT_NOT_FOUND" // 404 — detail for an unknown agentId
	CodeInvalidRequest = "INVALID_REQUEST" // 400 — malformed JSON / non-int / non-bool / missing path param
	CodeInvalidValue   = "INVALID_VALUE"   // 422 — well-formed input failed enum / cap / range validation
	CodeUnknownProfile = "UNKNOWN_PROFILE" // 422 — ?profile names a profile this binary did not load
)

func errAgentNotFound(id domain.AgentID) *web.Error {
	return web.NewError(http.StatusNotFound, CodeNotFound, fmt.Sprintf("agent %q not found", id))
}

func errUnknownProfile(name string) *web.Error {
	return web.NewError(http.StatusUnprocessableEntity, CodeUnknownProfile, fmt.Sprintf("unknown scoring profile %q", name))
}

// errInvalidRequest is a 400 — the caller sent something the server couldn't
// parse into a well-formed request (bad JSON, non-integer where int expected).
func errInvalidRequest(detail string) *web.Error {
	return web.NewError(http.StatusBadRequest, CodeInvalidRequest, detail)
}

// errInvalidValue is a 422 — the request parsed cleanly, but a value inside it
// failed semantic validation (enum mismatch, per-filter cap, out-of-range).
// This matches the design §5.2 rule the import service already follows.
func errInvalidValue(detail string) *web.Error {
	return web.NewError(http.StatusUnprocessableEntity, CodeInvalidValue, detail)
}
