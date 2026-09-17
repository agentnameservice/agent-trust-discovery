// Package config loads the runtime configuration (config/runtime.yaml, design
// §5.3/§5.6) into a plain struct. It depends only on the standard library and a
// YAML parser; the server package maps it onto the engine/import types so this
// loader stays free of domain coupling.
package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Classify holds the recommendedProfile cascade thresholds (design §4.6). The
// defaults mirror engine.DefaultThresholds; they are duplicated here only so the
// loader needs no scoring-engine import.
type Classify struct {
	Untrusted         int
	Transactional     int
	Fiduciary         int
	IdentityFiduciary int
}

// Config is the resolved runtime configuration.
type Config struct {
	ListenAddr      string
	DBPath          string
	AdminRequireKey bool
	AdminKey        string
	LogLevel        string
	Classify        Classify
	// ScoreSignalsPath points at a provider-signal config (see scorecontainer.
	// LoadSignals). Empty = no provider signals. A provider listed there
	// registers with a config entry + a hydrator and no Go code. A relative path
	// is resolved against the config file's directory (like the profile paths).
	// A set-but-missing path is a boot error, not a silent no-op — see
	// LoadSignals — so "none" is expressed by leaving this empty, not by pointing
	// at a file that isn't there.
	ScoreSignalsPath string
}

// defaultClassify mirrors engine.DefaultThresholds (20 / 50 / 80 / 90).
func defaultClassify() Classify {
	return Classify{Untrusted: 20, Transactional: 50, Fiduciary: 80, IdentityFiduciary: 90}
}

// yamlConfig is the on-disk shape. Pointers distinguish "absent" (apply a
// default) from an explicit zero where that matters.
type yamlConfig struct {
	Listen struct {
		Addr string `yaml:"addr"`
	} `yaml:"listen"`
	DB struct {
		Path string `yaml:"path"`
	} `yaml:"db"`
	Admin struct {
		RequireKey *bool  `yaml:"requireKey"`
		Key        string `yaml:"key"`
	} `yaml:"admin"`
	Log struct {
		Level string `yaml:"level"`
	} `yaml:"log"`
	Signals struct {
		Path string `yaml:"path"`
	} `yaml:"signals"`
	Classify *struct {
		Untrusted         int `yaml:"untrustedThreshold"`
		Transactional     int `yaml:"transactionalThreshold"`
		Fiduciary         int `yaml:"fiduciaryThreshold"`
		IdentityFiduciary int `yaml:"identityFiduciaryThreshold"`
	} `yaml:"classify"`
}

// AdminKeyEnv is the environment variable that overrides admin.key from the
// YAML. Set for container/Kubernetes deployments so the admin key can be
// injected from a Secret / SSM parameter without editing config files.
const AdminKeyEnv = "ANS_ADMIN_KEY"

// Load reads and resolves the config at path, applying defaults for any omitted
// field. admin.requireKey defaults to true (secure by default, §5.3). The
// ANS_ADMIN_KEY environment variable, when set, overrides admin.key from YAML
// so operators can inject the secret without editing the config on disk.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	var yc yamlConfig
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&yc); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	c := Config{
		ListenAddr:       orDefault(yc.Listen.Addr, ":8080"),
		DBPath:           orDefault(yc.DB.Path, "agent-trust-discovery.db"),
		AdminRequireKey:  yc.Admin.RequireKey == nil || *yc.Admin.RequireKey, // default true
		AdminKey:         yc.Admin.Key,
		LogLevel:         orDefault(yc.Log.Level, "info"),
		Classify:         defaultClassify(),
		ScoreSignalsPath: yc.Signals.Path,
	}
	if v, ok := os.LookupEnv(AdminKeyEnv); ok {
		c.AdminKey = v
	}
	// Resolve a relative signals.path against the config file's directory, the
	// same way main.go resolves default-profile.yaml and profiles/. Without this
	// the path resolved against the process working directory while profiles
	// resolved against the config dir, so `--config /etc/atd/runtime.yaml` with
	// `signals.path: config/score-signals.yaml` hunted for the signals file
	// wherever the supervisor happened to start. An absolute path is used as-is.
	if c.ScoreSignalsPath != "" && !filepath.IsAbs(c.ScoreSignalsPath) {
		c.ScoreSignalsPath = filepath.Join(filepath.Dir(path), c.ScoreSignalsPath)
	}
	if yc.Classify != nil {
		cl := Classify{
			Untrusted:         yc.Classify.Untrusted,
			Transactional:     yc.Classify.Transactional,
			Fiduciary:         yc.Classify.Fiduciary,
			IdentityFiduciary: yc.Classify.IdentityFiduciary,
		}
		// A present classify block replaces the defaults wholesale — the inner
		// fields are plain ints, so a partial block would otherwise silently
		// zero-fill the omitted thresholds (e.g. only untrustedThreshold set
		// yields {30,0,0,0}). Reject that: all four must be present (>0) and
		// strictly ascending, matching the cascade the engine expects (§4.6).
		if err := cl.validate(); err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", path, err)
		}
		c.Classify = cl
	}
	return c, nil
}

// validate enforces that an operator-supplied classify block is complete and
// well-ordered: every threshold must be a positive score in (0,100] and the
// four must strictly ascend (untrusted < transactional < fiduciary <
// identityFiduciary). This turns a partial or misordered block into a
// fail-fast load error rather than a silently zero-filled cascade.
func (c Classify) validate() error {
	steps := []struct {
		name string
		val  int
	}{
		{"untrustedThreshold", c.Untrusted},
		{"transactionalThreshold", c.Transactional},
		{"fiduciaryThreshold", c.Fiduciary},
		{"identityFiduciaryThreshold", c.IdentityFiduciary},
	}
	prev := 0
	for _, s := range steps {
		if s.val <= 0 || s.val > 100 {
			return fmt.Errorf("classify.%s = %d, must be in (0,100] (a partial classify block zero-fills omitted thresholds)", s.name, s.val)
		}
		if s.val <= prev {
			return fmt.Errorf("classify.%s = %d must be strictly greater than the preceding threshold (%d); thresholds must ascend", s.name, s.val, prev)
		}
		prev = s.val
	}
	return nil
}

// SlogLevel maps the configured level name (case-insensitive) to a slog.Level,
// defaulting to Info for empty or unrecognized values.
func (c Config) SlogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
