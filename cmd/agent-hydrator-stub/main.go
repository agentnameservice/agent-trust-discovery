// Command agent-hydrator-stub is the Bootstrap-archetype signal hydrator (design
// §6.3): a single offline pass that reads TL-event and observation fixtures and
// POSTs the projected agents and observations to agent-trust-discovery. All logic lives in
// internal/hydrator so it can be tested without a process.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/agentnameservice/agent-trust-discovery/internal/hydrator"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "config/hydrator.yaml", "path to the hydrator config YAML")
	flag.Parse()

	// Match the sibling command binaries: SIGINT/SIGTERM cancels in-flight POSTs
	// cleanly rather than aborting the http.Client mid-flush.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	s, err := hydrator.LoadConfig(*configPath)
	if err != nil {
		logger.ErrorContext(ctx, "hydrator: load config", "error", err, "path", *configPath)
		return 1
	}

	events, err := tlevent.LoadDir(s.TLEventsDir)
	if err != nil {
		logger.ErrorContext(ctx, "hydrator: load tl-events", "error", err)
		return 1
	}

	var obs []hydrator.ObservationFile
	if s.Mock {
		obs, err = hydrator.LoadObservations(s.ObservationsDir)
		if err != nil {
			logger.ErrorContext(ctx, "hydrator: load observations", "error", err)
			return 1
		}
	}

	h := hydrator.New(hydrator.Config{BaseURL: s.TargetURL, AdminKey: s.AdminKey, AIMID: s.AIMID}, nil)
	summary, err := h.Run(ctx, events, obs, s.Mock)
	if err != nil {
		logger.ErrorContext(ctx, "hydrator: run", "error", err)
		return 1
	}

	logger.InfoContext(ctx, "hydration complete",
		"mock", s.Mock,
		"agentsImported", summary.AgentsImported,
		"observationsImported", summary.ObservationsImported)
	return 0
}
