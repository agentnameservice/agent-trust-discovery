package prober

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Settings is the resolved agent-prober configuration (config/prober.yaml,
// design §6.6). Cadence 0 means a single pass; >0 loops every Cadence.
type Settings struct {
	TargetURL   string
	AdminKey    string
	TLEventsDir string
	Cadence     time.Duration
	Timeout     time.Duration
	AIMID       string
}

type configFile struct {
	Target struct {
		URL      string `yaml:"url"`
		AdminKey string `yaml:"adminKey"`
	} `yaml:"target"`
	Source struct {
		TLEventsDir string `yaml:"tlEventsDir"`
	} `yaml:"source"`
	Probe struct {
		Cadence int    `yaml:"cadence"` // seconds; 0 = single pass
		Timeout string `yaml:"timeout"` // Go duration, e.g. "5s"
	} `yaml:"probe"`
	Provenance struct {
		AIMID string `yaml:"aimId"`
	} `yaml:"provenance"`
}

// LoadConfig reads the prober config from path.
func LoadConfig(path string) (Settings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, fmt.Errorf("prober: read config %s: %w", path, err)
	}
	var cf configFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cf); err != nil {
		return Settings{}, fmt.Errorf("prober: parse config %s: %w", path, err)
	}

	timeout := 5 * time.Second
	if cf.Probe.Timeout != "" {
		d, err := time.ParseDuration(cf.Probe.Timeout)
		if err != nil {
			return Settings{}, fmt.Errorf("prober: invalid probe.timeout %q: %w", cf.Probe.Timeout, err)
		}
		timeout = d
	}
	return Settings{
		TargetURL:   cf.Target.URL,
		AdminKey:    cf.Target.AdminKey,
		TLEventsDir: cf.Source.TLEventsDir,
		Cadence:     time.Duration(cf.Probe.Cadence) * time.Second,
		Timeout:     timeout,
		AIMID:       cf.Provenance.AIMID,
	}, nil
}
