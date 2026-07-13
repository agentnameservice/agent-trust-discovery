// Package ctxlog carries a request-scoped *slog.Logger on a context.Context.
// The request-id middleware in the server package attaches the correlated
// logger; downstream packages (search, importsvc, web) fetch it to emit lines
// with the same requestId, without importing server.
package ctxlog

import (
	"context"
	"log/slog"
)

type ctxKey int

const loggerKey ctxKey = iota

// With returns ctx annotated with logger. Callers typically wrap the base
// logger with correlating fields (requestId, agentId) before storing it.
func With(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// From returns the logger previously stored via With, or slog.Default() when
// none is present. Never returns nil.
func From(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
