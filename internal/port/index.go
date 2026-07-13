package port

import (
	"context"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// SearchQuery is the parsed, transport-agnostic search request the Index
// consumes. The search handlers (Phase 6) map HTTP query params / JSON bodies
// (design §5.1) onto this; the sqlitestore Index (Phase 3) executes it against
// FTS5 + equality filters. Empty filter slices mean "no constraint."
type SearchQuery struct {
	Text         string // free-text MATCH; empty means match-all
	ProviderIDs  []string
	Statuses     []domain.Status
	AgentDomains []string
	Protocols    []string
	Transports   []string
	Tags         []string
	Capabilities []string

	// Pagination. Page is 1-based; PageToken drives cursor traversal (mutually
	// exclusive with Page at the handler layer — pageToken wins). The store
	// owns token opacity and mechanics.
	//
	// PageTokenDirection is validated but not honoured by the current sqlite
	// index — the token encodes an absolute page number, so a "backward" walk
	// is a no-op today. The field is kept on the wire and in the type for
	// parity with the sibling ans-search-api; a v2 cursor implementation
	// (opaque keyset over lastUpdated) will consume it.
	Page               int
	PageSize           int
	PageToken          string
	PageTokenDirection string // "forward" | "backward" | ""  (v2: honored)
	TotalRequired      bool   // compute TotalItems/TotalPages when true
}

// SearchPage is one page of search results plus the pagination metadata needed
// to build the response envelope (design §5.1). TotalItems/TotalPages are only
// meaningful when the query set TotalRequired.
type SearchPage struct {
	Items      []domain.Agent
	TotalItems int
	TotalPages int
	PrevToken  string // empty when there is no previous page
	NextToken  string // empty when there is no next page
}

// Index is the search contract over the indexed agents (design §2.1). The
// sqlitestore adapter implements it alongside AgentStore.
type Index interface {
	Search(ctx context.Context, q SearchQuery) (SearchPage, error)
}
