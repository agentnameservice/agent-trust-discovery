package hydrator

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ObservationFile is one fixture file of observations for a single agent
// (design §8.4). Raw-signal entries carry a full Value; drift-signal entries
// carry only the live-side Observed value (the hydrator supplies the sealed
// baseline from the matching TL event).
type ObservationFile struct {
	AgentID      string             `yaml:"agentId"`
	Observations []ObservationEntry `yaml:"observations"`
}

// ObservationEntry is one observation. Value is set for raw signals; Observed
// is set for drift-verdict signals.
type ObservationEntry struct {
	SignalID   string         `yaml:"signalId"`
	ObservedAt string         `yaml:"observedAt"`
	Value      map[string]any `yaml:"value"`
	Observed   string         `yaml:"observed"`
}

// ParseObservationFile parses one observation fixture from YAML bytes.
// Unknown fields are rejected — the snapshot binary writes these and humans
// edit them, so a mistyped field (`observd` instead of `observed`) surfaces
// at load rather than silently dropping to the zero value.
func ParseObservationFile(b []byte) (ObservationFile, error) {
	var f ObservationFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return ObservationFile{}, fmt.Errorf("hydrator: parse observations: %w", err)
	}
	if f.AgentID == "" {
		return ObservationFile{}, errors.New("hydrator: observation file: agentId is required")
	}
	return f, nil
}

// LoadObservations reads every *.yaml observation fixture in dir, sorted by
// filename.
func LoadObservations(dir string) ([]ObservationFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("hydrator: read observations dir %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	files := make([]ObservationFile, 0, len(names))
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("hydrator: read %s: %w", name, err)
		}
		f, err := ParseObservationFile(b)
		if err != nil {
			return nil, fmt.Errorf("hydrator: %s: %w", name, err)
		}
		files = append(files, f)
	}
	return files, nil
}
