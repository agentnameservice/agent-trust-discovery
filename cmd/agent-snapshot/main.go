// Command agent-snapshot captures a fixture snapshot from the production
// agent-trust-discovery Search API and the production Transparency Log (plan §3). All
// orchestration lives in internal/snapshot; this file is thin wiring: CLI
// parsing, config-file merge, and process lifecycle.
//
// The output is fixture YAML the existing agent-hydrator-stub and agent-prober
// consume unchanged — see config/hydrator.snapshot.yaml and
// config/prober.snapshot.yaml.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/atdclient"
	"github.com/agentnameservice/agent-trust-discovery/internal/snapshot"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlclient"
)

const httpTimeout = 30 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, _, stderr *os.File) int {
	fs := flag.NewFlagSet("agent-snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", "config/snapshot.yaml", "path to the snapshot config YAML")
	searchURL := fs.String("search-url", "", "Search API base URL (override config)")
	tlURL := fs.String("tl-url", "", "Transparency Log base URL (override config)")
	out := fs.String("out", "", "output directory for fixture YAML (override config)")
	query := fs.String("query", "", "free-text search")
	keywordExtraction := fs.Bool("keyword-extraction", false, "enable keyword extraction (requires --query)")
	keywordAlgorithm := fs.String("keyword-algorithm", "", "SIMPLE | RAKE | TEXTRANK")
	profile := fs.String("profile", "", "scoring profile (default: default)")
	pageSize := fs.Int("page-size", 0, "1–100, default 20")
	limit := fs.Int("limit", 0, "cap on agents captured (default from config)")

	var providers, domains, protocols, transports, tags, capabilities multiFlag
	fs.Var(&providers, "provider", "providerIds[] (repeatable)")
	fs.Var(&domains, "domain", "agentDomains[] (repeatable)")
	fs.Var(&protocols, "protocol", "protocols[] (repeatable)")
	fs.Var(&transports, "transport", "transports[] (repeatable)")
	fs.Var(&tags, "tag", "tags[] (repeatable)")
	fs.Var(&capabilities, "capability", "capabilities[] (repeatable)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	// CLI overrides config; flag values default to "" / 0 so the test for
	// "set on CLI" is "non-zero / non-empty".
	if *searchURL != "" {
		cfg.SearchBaseURL = *searchURL
	}
	if *tlURL != "" {
		cfg.TLBaseURL = *tlURL
	}
	if *out != "" {
		cfg.OutDir = *out
	}
	opts := cfg.SearchOpts
	if *query != "" {
		opts.Query = *query
	}
	if *keywordExtraction {
		opts.KeywordExtraction = true
	}
	if *keywordAlgorithm != "" {
		opts.KeywordAlgorithm = *keywordAlgorithm
	}
	if *profile != "" {
		opts.Profile = *profile
	}
	if *pageSize > 0 {
		opts.PageSize = *pageSize
	}
	if *limit > 0 {
		opts.Limit = *limit
	}
	opts.ProviderIDs = append(opts.ProviderIDs, providers...)
	opts.AgentDomains = append(opts.AgentDomains, domains...)
	opts.Protocols = append(opts.Protocols, protocols...)
	opts.Transports = append(opts.Transports, transports...)
	opts.Tags = append(opts.Tags, tags...)
	opts.Capabilities = append(opts.Capabilities, capabilities...)
	cfg.SearchOpts = opts

	if cfg.SearchBaseURL == "" || cfg.TLBaseURL == "" || cfg.OutDir == "" {
		fmt.Fprintln(stderr, "agent-snapshot: --search-url, --tl-url, and --out are required (via config or flag)")
		return 1
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	httpClient := &http.Client{Timeout: httpTimeout}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_, err = snapshot.Run(ctx,
		atdclient.New(httpClient),
		tlclient.New(httpClient),
		cfg, logger)
	if err != nil {
		logger.ErrorContext(ctx, "snapshot: run failed", "error", err)
		return 1
	}
	return 0
}

// configFile is the on-disk schema for config/snapshot.yaml. CLI flags
// override these values.
type configFile struct {
	SearchURL string `yaml:"searchUrl"`
	TLURL     string `yaml:"tlUrl"`
	Out       string `yaml:"out"`
	Search    struct {
		Query             string   `yaml:"query"`
		KeywordExtraction bool     `yaml:"keywordExtraction"`
		KeywordAlgorithm  string   `yaml:"keywordAlgorithm"`
		Profile           string   `yaml:"profile"`
		PageSize          int      `yaml:"pageSize"`
		Limit             int      `yaml:"limit"`
		ProviderIDs       []string `yaml:"providerIds"`
		AgentDomains      []string `yaml:"agentDomains"`
		Protocols         []string `yaml:"protocols"`
		Transports        []string `yaml:"transports"`
		Tags              []string `yaml:"tags"`
		Capabilities      []string `yaml:"capabilities"`
	} `yaml:"search"`
}

func loadConfig(path string) (snapshot.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot.Config{}, nil // config is optional when all flags are set
		}
		return snapshot.Config{}, fmt.Errorf("agent-snapshot: read config %s: %w", path, err)
	}
	var cf configFile
	if err := yaml.Unmarshal(b, &cf); err != nil {
		return snapshot.Config{}, fmt.Errorf("agent-snapshot: parse config %s: %w", path, err)
	}
	return snapshot.Config{
		SearchBaseURL: cf.SearchURL,
		TLBaseURL:     cf.TLURL,
		OutDir:        cf.Out,
		SearchOpts: atdclient.SearchOpts{
			Query:             cf.Search.Query,
			KeywordExtraction: cf.Search.KeywordExtraction,
			KeywordAlgorithm:  cf.Search.KeywordAlgorithm,
			Profile:           cf.Search.Profile,
			PageSize:          cf.Search.PageSize,
			Limit:             cf.Search.Limit,
			ProviderIDs:       cf.Search.ProviderIDs,
			AgentDomains:      cf.Search.AgentDomains,
			Protocols:         cf.Search.Protocols,
			Transports:        cf.Search.Transports,
			Tags:              cf.Search.Tags,
			Capabilities:      cf.Search.Capabilities,
		},
	}, nil
}

// multiFlag is a flag.Value backing repeatable --foo=bar flags.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
