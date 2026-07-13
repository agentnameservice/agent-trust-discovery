// Command agent-trust-discovery is the Trust Index reference search API. It loads a
// runtime config, builds the server (store, signals, scoring profiles, import +
// search routes, observability), and serves until interrupted. All real wiring
// lives in internal/server.Build so it can be tested without a process.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/config"
	"github.com/agentnameservice/agent-trust-discovery/internal/server"
)

func main() {
	os.Exit(run())
}

// run holds main's body so its defers (signal stop, store Close) run before the
// process exits — main only translates the result into an exit code.
func run() int {
	configPath := flag.String("config", "config/runtime.yaml", "path to the runtime config YAML")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Bootstrap logger at info until the configured level is known.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.ErrorContext(ctx, "boot: load config", "error", err, "path", *configPath)
		return 1
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.SlogLevel()}))

	// Profiles live next to the runtime config (default-profile.yaml + profiles/).
	dir := filepath.Dir(*configPath)
	handler, db, err := server.Build(ctx, cfg,
		filepath.Join(dir, "default-profile.yaml"), filepath.Join(dir, "profiles"), logger)
	if err != nil {
		logger.ErrorContext(ctx, "boot: build server", "error", err)
		return 1
	}
	defer func() { _ = db.Close() }()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// A listen failure (bind error, port already in use) must surface as a
	// non-zero exit so supervisors and CI see the process crash — otherwise
	// stop() cancels ctx, Shutdown on the never-started server returns nil, and
	// run() returns 0, indistinguishable from a clean shutdown.
	listenErr := make(chan error, 1)
	go func() {
		logger.InfoContext(ctx, "listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.ErrorContext(ctx, "server: listen", "error", err)
			listenErr <- err
			stop()
			return
		}
		listenErr <- nil
	}()

	<-ctx.Done()
	logger.InfoContext(context.Background(), "shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "server: shutdown", "error", err)
		return 1
	}
	if err := <-listenErr; err != nil {
		return 1
	}
	return 0
}
