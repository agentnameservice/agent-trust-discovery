// Command agent-ra-sync captures a fixture snapshot from a (private) ANS RA's
// public event feed (GET /v1/agents/events) and the Transparency Log, writing
// the tl-events/ fixture YAML the existing agent-hydrator-stub and agent-prober
// consume unchanged. All orchestration lives in internal/rasync; this file is
// thin wiring: CLI parsing, config-file merge, and process lifecycle.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/raclient"
	"github.com/agentnameservice/agent-trust-discovery/internal/rasync"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlclient"
)

const (
	httpTimeout = 30 * time.Second
	runTimeout  = 5 * time.Minute
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent-ra-sync", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", "config/ra-sync.yaml", "path to the ra-sync config YAML")
	raURL := fs.String("ra-url", "", "RA event-feed base URL (override config)")
	tlURL := fs.String("tl-url", "", "Transparency Log base URL (override config)")
	out := fs.String("out", "", "output directory for fixture YAML (override config)")
	pageSize := fs.Int("page-size", 0, "feed page size 1..200 (default 100)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *raURL != "" {
		cfg.RABaseURL = *raURL
	}
	if *tlURL != "" {
		cfg.TLBaseURL = *tlURL
	}
	if *out != "" {
		cfg.OutDir = *out
	}
	if *pageSize > 0 {
		cfg.PageSize = *pageSize
	}
	if cfg.RABaseURL == "" || cfg.TLBaseURL == "" || cfg.OutDir == "" {
		fmt.Fprintln(stderr, "agent-ra-sync: --ra-url, --tl-url, and --out are required (via config or flag)")
		return 1
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	httpClient := &http.Client{Timeout: httpTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	if _, err := rasync.Run(ctx, raclient.New(httpClient), tlclient.New(httpClient), cfg, logger); err != nil {
		logger.ErrorContext(ctx, "rasync: run failed", "error", err)
		return 1
	}
	return 0
}

// configFile is the on-disk schema for config/ra-sync.yaml. CLI flags override.
type configFile struct {
	RAURL    string `yaml:"raUrl"`
	TLURL    string `yaml:"tlUrl"`
	Out      string `yaml:"out"`
	PageSize int    `yaml:"pageSize"`
}

func loadConfig(path string) (rasync.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rasync.Config{}, nil // config optional when all flags are set
		}
		return rasync.Config{}, fmt.Errorf("agent-ra-sync: read config %s: %w", path, err)
	}
	var cf configFile
	if err := yaml.Unmarshal(b, &cf); err != nil {
		return rasync.Config{}, fmt.Errorf("agent-ra-sync: parse config %s: %w", path, err)
	}
	return rasync.Config{RABaseURL: cf.RAURL, TLBaseURL: cf.TLURL, OutDir: cf.Out, PageSize: cf.PageSize}, nil
}
