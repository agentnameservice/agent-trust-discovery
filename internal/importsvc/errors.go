package importsvc

import (
	"fmt"
	"net/http"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

// Problem-Details codes returned by the import endpoints (design §5.2.1 table,
// §5.3). Clients switch on these; they are part of the API contract.
const (
	CodeAgentNotFound      = "AGENT_NOT_FOUND"      // 422 — agentId absent from the agents table
	CodeUnknownSignal      = "UNKNOWN_SIGNAL"       // 422 — signalId not registered in this binary
	CodeInvalidSignal      = "INVALID_SIGNAL"       // 422 — signalId is a derived signal (rejects imports)
	CodeInvalidSignalValue = "INVALID_SIGNAL_VALUE" // 422 — value failed signal.Validate
	CodeInvalidRequest     = "INVALID_REQUEST"      // 400 — malformed JSON / bad RFC 3339 / missing field
	CodeUnauthorized       = "UNAUTHORIZED"         // 401 — missing or wrong admin bearer key
)

func errAgentNotFound(id domain.AgentID) *web.Error {
	return web.NewError(http.StatusUnprocessableEntity, CodeAgentNotFound,
		fmt.Sprintf("agent %q not found", id))
}

func errUnknownSignal(id domain.SignalID) *web.Error {
	return web.NewError(http.StatusUnprocessableEntity, CodeUnknownSignal,
		fmt.Sprintf("signal %q is not registered in this binary", id))
}

func errDerivedSignal(id domain.SignalID) *web.Error {
	return web.NewError(http.StatusUnprocessableEntity, CodeInvalidSignal,
		fmt.Sprintf("signal %q is derived and does not accept imported observations", id))
}

// errInvalidSignalValue carries signalId, agentId, and the Validate error in
// detail so the caller can correct and retry (design §5.2.1).
func errInvalidSignalValue(agentID domain.AgentID, signalID domain.SignalID, cause error) *web.Error {
	return web.NewError(http.StatusUnprocessableEntity, CodeInvalidSignalValue,
		fmt.Sprintf("observation value for signal %q on agent %q is invalid: %v", signalID, agentID, cause))
}

func errInvalidRequest(detail string) *web.Error {
	return web.NewError(http.StatusBadRequest, CodeInvalidRequest, detail)
}
