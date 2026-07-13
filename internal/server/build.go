package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/agentnameservice/agent-trust-discovery/internal/adapter/sqlitestore"
	"github.com/agentnameservice/agent-trust-discovery/internal/config"
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/importsvc"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/engine"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/registry"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
	"github.com/agentnameservice/agent-trust-discovery/internal/search"
)

// Build is the composition root: it opens the store (migrations run on Open),
// registers the built-in signals, loads + validates the scoring profiles, wires
// the import and search services behind the §5.6 observability stack, and
// returns the ready HTTP handler plus the store to close on shutdown.
//
// It fails fast (returns an error the caller treats as a boot failure) on a bad
// store, an unloadable/invalid profile set, or an admin-key misconfiguration
// (requireKey with an empty key). The returned *sqlitestore.DB is non-nil only
// on success; the caller owns Close.
func Build(ctx context.Context, cfg config.Config, profileDefaultPath, profileDir string, logger *slog.Logger) (http.Handler, *sqlitestore.DB, error) {
	db, err := sqlitestore.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, nil, fmt.Errorf("server: open store: %w", err)
	}
	// Single cleanup site — flipped to false on the successful path just before
	// returning. Any early return from a fallible step below runs Close via the
	// defer, so a future contributor adding a step in the middle can't leak the
	// DB file descriptor by forgetting to add a manual Close call.
	success := false
	defer func() {
		if !success {
			_ = db.Close()
		}
	}()

	reg := registry.New()
	for _, s := range signals.BuiltIns(nil) {
		if err := reg.Register(s); err != nil {
			return nil, nil, fmt.Errorf("server: register signal: %w", err)
		}
	}

	profiles, err := engine.LoadProfiles(profileDefaultPath, profileDir)
	if err != nil {
		return nil, nil, fmt.Errorf("server: load profiles: %w", err)
	}
	known := knownSignals(reg)
	for _, p := range profiles {
		if err := engine.ValidateSignalWeights(p, known); err != nil {
			return nil, nil, fmt.Errorf("server: %w", err)
		}
	}

	eng := engine.New(db, reg, thresholdsOf(cfg), nil)

	adminAuth, err := importsvc.NewAdminAuth(
		importsvc.AdminAuthConfig{RequireKey: cfg.AdminRequireKey, Key: cfg.AdminKey}, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("server: admin auth: %w", err)
	}

	importH := importsvc.NewHandler(importsvc.New(db, reg))
	searchH := search.NewHandler(search.New(db, db, eng, profiles))

	logBoot(logger, cfg)
	success = true
	return newRouter(searchH, importH, adminAuth, logger), db, nil
}

func thresholdsOf(cfg config.Config) engine.Thresholds {
	return engine.Thresholds{
		Untrusted:         cfg.Classify.Untrusted,
		Transactional:     cfg.Classify.Transactional,
		Fiduciary:         cfg.Classify.Fiduciary,
		IdentityFiduciary: cfg.Classify.IdentityFiduciary,
	}
}

func knownSignals(reg port.SignalRegistry) map[domain.SignalID]bool {
	known := make(map[domain.SignalID]bool)
	for _, s := range reg.All() {
		known[s.ID()] = true
	}
	return known
}

// logBoot emits the one-time boot lines (design §5.6 boot level): the resolved
// configuration, plus the loud warning when the admin routes run unauthenticated.
func logBoot(logger *slog.Logger, cfg config.Config) {
	logger.Info("boot: configuration resolved",
		"listenAddr", cfg.ListenAddr,
		"dbPath", cfg.DBPath,
		"logLevel", cfg.LogLevel,
		"adminRequireKey", cfg.AdminRequireKey)
	if !cfg.AdminRequireKey {
		logger.Warn(importsvc.UnauthenticatedWarning)
	}
}
