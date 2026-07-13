package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// profileFile is the on-disk YAML shape of a scoring profile (design §4.5).
type profileFile struct {
	Name             string             `yaml:"name"`
	DimensionWeights map[string]float64 `yaml:"dimensionWeights"`
	SignalWeights    map[string]float64 `yaml:"signalWeights"`
}

// LoadProfile reads and validates one scoring-profile YAML file. Dimension keys
// are checked against the five known dimensions; signal keys are validated
// later against the registry (ValidateSignalWeights), since this loader is
// decoupled from which signals a binary registers.
func LoadProfile(path string) (domain.ScoringProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return domain.ScoringProfile{}, fmt.Errorf("profile: read %s: %w", path, err)
	}
	var pf profileFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&pf); err != nil {
		return domain.ScoringProfile{}, fmt.Errorf("profile: parse %s: %w", path, err)
	}
	if pf.Name == "" {
		return domain.ScoringProfile{}, fmt.Errorf("profile %s: name is required", path)
	}

	dims := make(map[domain.Dimension]float64, len(pf.DimensionWeights))
	for k, v := range pf.DimensionWeights {
		d := domain.Dimension(k)
		if !d.Valid() {
			return domain.ScoringProfile{}, fmt.Errorf("profile %q: unknown dimension %q", pf.Name, k)
		}
		// A dimensionWeight is a pure on/off gate in v1 (§4.6 active-dimension
		// rule): only its sign is read. Magnitude is reserved for a future
		// cross-dimension aggregate (compositeScore is declined, design §5.5),
		// so reject anything but 0 or 1 rather than accept a fractional weight
		// that would silently do nothing.
		if v != 0 && v != 1 {
			return domain.ScoringProfile{}, fmt.Errorf("profile %q: dimension %q weight %v: v1 supports only 0 or 1 (magnitude is reserved for a future cross-dimension aggregate)", pf.Name, k, v)
		}
		dims[d] = v
	}
	sigs := make(map[domain.SignalID]float64, len(pf.SignalWeights))
	for k, v := range pf.SignalWeights {
		// A negative weight is almost certainly a typo (weightedAverage's
		// weight>0 guard would silently drop it, so it would degrade to a
		// no-op the operator wouldn't see) — reject it at boot instead.
		if v < 0 {
			return domain.ScoringProfile{}, fmt.Errorf("profile %q: signal %q weight %v must be >= 0", pf.Name, k, v)
		}
		sigs[domain.SignalID(k)] = v
	}
	return domain.ScoringProfile{Name: pf.Name, DimensionWeights: dims, SignalWeights: sigs}, nil
}

// LoadProfiles loads the default profile plus every *.yaml under dir (if dir is
// non-empty), keyed by profile name. Duplicate names are an error.
func LoadProfiles(defaultPath, dir string) (map[string]domain.ScoringProfile, error) {
	out := make(map[string]domain.ScoringProfile)
	def, err := LoadProfile(defaultPath)
	if err != nil {
		return nil, err
	}
	out[def.Name] = def

	if dir == "" {
		return out, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("profile: read dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p, err := LoadProfile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if _, dup := out[p.Name]; dup {
			return nil, fmt.Errorf("profile: duplicate profile name %q", p.Name)
		}
		out[p.Name] = p
	}
	return out, nil
}

// ValidateSignalWeights rejects a profile that weights a signal the binary does
// not register (design §4.3 rollout safety; "unknown signal → boot error").
func ValidateSignalWeights(p domain.ScoringProfile, known map[domain.SignalID]bool) error {
	for id := range p.SignalWeights {
		if !known[id] {
			return fmt.Errorf("profile %q: unknown signal %q", p.Name, id)
		}
	}
	return nil
}
