// Package auditctx carries a mutable audit record on a request Context so
// handlers can surface what they processed (batch size, outcome flags) to the
// audit middleware without either side knowing the other's wire shape. The
// audit middleware installs the record before the handler runs and reads it
// in a deferred log line; the handler mutates its Accepted field once
// processing succeeds.
package auditctx

import "context"

// Info is the per-request audit record. Only the audit middleware creates
// one; handlers mutate through the pointer returned by From. All fields are
// optional — a zero-valued Info is a valid state ("no handler reported").
type Info struct {
	// Accepted is the number of rows the handler accepted for persistence
	// (e.g. len(agents), len(observations)). Reporting this is idempotent —
	// setting it to zero means "nothing accepted", not "handler did not run".
	Accepted int
}

type ctxKey int

const infoKey ctxKey = iota

// With attaches a fresh, mutable Info to ctx and returns both. The returned
// pointer is shared: the audit middleware holds it to read Accepted on the
// way out; downstream handlers write to it after a successful import.
func With(ctx context.Context) (context.Context, *Info) {
	i := &Info{}
	return context.WithValue(ctx, infoKey, i), i
}

// From returns the audit Info attached by With, or nil if none is present.
// Handlers should treat a nil return as "no audit in flight" and skip
// reporting rather than panic — the middleware may be absent in tests.
func From(ctx context.Context) *Info {
	if i, ok := ctx.Value(infoKey).(*Info); ok {
		return i
	}
	return nil
}
