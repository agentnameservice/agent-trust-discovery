package hydrator

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Settings is the resolved agent-hydrator-stub configuration (config/hydrator.yaml,
// design §6.3). Mock is true unless mode is explicitly "real".
type Settings struct {
	Mock            bool
	TargetURL       string
	AdminKey        string
	TLEventsDir     string
	ObservationsDir string
	AIMID           string
}

type configFile struct {
	Mode   string `yaml:"mode"`
	Target struct {
		URL      string `yaml:"url"`
		AdminKey string `yaml:"adminKey"`
	} `yaml:"target"`
	Source struct {
		TLEventsDir     string `yaml:"tlEventsDir"`
		ObservationsDir string `yaml:"observationsDir"`
	} `yaml:"source"`
	Provenance struct {
		AIMID string `yaml:"aimId"`
	} `yaml:"provenance"`
}

// LoadConfig reads the hydrator config from path.
func LoadConfig(path string) (Settings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, fmt.Errorf("hydrator: read config %s: %w", path, err)
	}
	var cf configFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cf); err != nil {
		return Settings{}, fmt.Errorf("hydrator: parse config %s: %w", path, err)
	}
	return Settings{
		Mock:            cf.Mode != "real", // default mock
		TargetURL:       cf.Target.URL,
		AdminKey:        cf.Target.AdminKey,
		TLEventsDir:     cf.Source.TLEventsDir,
		ObservationsDir: cf.Source.ObservationsDir,
		AIMID:           cf.Provenance.AIMID,
	}, nil
}
