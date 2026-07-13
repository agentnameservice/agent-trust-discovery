package domain

import "time"

// AgentID uniquely identifies a registered agent.
type AgentID string

// Status mirrors the ans-search-api lifecycle states verbatim (design §3.1
// decision #7). The Trust Index spec §4.4 names only ACTIVE/DEPRECATED/REVOKED
// for Status Tokens; the additional values are search-side lifecycle states,
// not trust-vector inputs.
type Status string

const (
	StatusActive     Status = "ACTIVE"
	StatusWarning    Status = "WARNING"
	StatusDeprecated Status = "DEPRECATED"
	StatusExpired    Status = "EXPIRED"
	StatusRevoked    Status = "REVOKED"
)

// Valid reports whether s is one of the five known statuses. Used at the import
// boundary; the storage CHECK constraint mirrors this set (design §7).
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusWarning, StatusDeprecated, StatusExpired, StatusRevoked:
		return true
	default:
		return false
	}
}

// Agent is a registered AI agent as indexed by agent-trust-discovery.
type Agent struct {
	ID           AgentID
	DNSName      string // e.g. ans://v1.0.0.booking.example.com
	DisplayName  string
	Description  string
	ProviderID   string
	Status       Status
	Protocols    []string // A2A, MCP, HTTP-API, ACP
	Transports   []string // HTTP, SSE, JSON-RPC, REST, STREAMABLE-HTTP
	Tags         []string
	Capabilities []string
	FirstSeen    time.Time
	LastUpdated  time.Time
}
