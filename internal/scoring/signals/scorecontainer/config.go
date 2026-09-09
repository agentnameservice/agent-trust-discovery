package scorecontainer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// signalEntry is one config-declared score signal. Threshold is a pointer so an
// omitted threshold (nil -> package default) is distinct from an explicit 0
// (which means "no low-score backstop"). Subject is optional and defaults to
// SubjectAgent when omitted.
type signalEntry struct {
	ID        string `yaml:"id"`
	Dimension string `yaml:"dimension"`
	Subject   string `yaml:"subject"`
	Threshold *int   `yaml:"threshold"`
}

// subjectRe constrains a config-supplied subject to an open lowercase token
// (letter-led, letters/digits/underscores): "agent", "tool", "org",
// "mcp_server", or whatever a future provider needs. Open on purpose — a new
// subject class is a config value, not a core change.
var subjectRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// signalsFile is the on-disk shape of the provider-signal config.
type signalsFile struct {
	Signals []signalEntry `yaml:"signals"`
}

// LoadSignals reads a provider-signal config and returns one scorecontainer
// signal per entry. This is the config-driven registration path: a provider
// registers a dimension score with a config entry plus a hydrator and touches
// no Go code. Each entry is instantiated with New, so it gets the same generic
// container, validation, prefix-scoped risk codes, backstop, and absence
// semantics as a code-registered one.
//
// Validation is strict (unknown YAML fields rejected): every id must follow the
// vendor.dimension.name convention with its dimension segment matching the
// declared dimension, the dimension must be one of the five, an explicit
// threshold must be in [0,100] (omit for the package default; 0 means no
// backstop), an explicit subject must be a lowercase token (omit for the agent
// default), and ids must be unique within the file.
//
// A configured path that does not exist IS an error — a score-signals path is
// set deliberately, and a supervisor that starts the process from an unexpected
// working directory should fail loudly rather than register nothing and leave
// the provider's hydrator to eat 422s. "No provider signals" is expressed by
// leaving signals.path unset (the caller skips LoadSignals entirely), not by a
// path to a missing file. An empty or fully-commented file is treated as no
// signals, so switching providers off by commenting them out doesn't crash boot.
func LoadSignals(path string) ([]port.Signal, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("score-signals: read %s: %w", path, err)
	}

	var sf signalsFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&sf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil // empty or fully-commented file: no signals, not a crash
		}
		return nil, fmt.Errorf("score-signals: parse %s: %w", path, err)
	}

	seen := make(map[string]bool, len(sf.Signals))
	out := make([]port.Signal, 0, len(sf.Signals))
	for i, e := range sf.Signals {
		where := fmt.Sprintf("%s[%d]", path, i)
		if e.ID == "" {
			return nil, fmt.Errorf("score-signals: %s: id is required", where)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("score-signals: %s: duplicate id %q", where, e.ID)
		}
		dim := domain.Dimension(e.Dimension)
		if !dim.Valid() {
			return nil, fmt.Errorf("score-signals: %s (%s): unknown dimension %q", where, e.ID, e.Dimension)
		}
		// vendor.dimension.name, with the dimension segment matching Dimension().
		// dimension and name are single tokens by construction, so they're peeled
		// off from the right; everything before them is the vendor, even if the
		// vendor itself contains dots (e.g. a did:web authority).
		dimSeg, ok := dimensionSegment(e.ID)
		if !ok {
			return nil, fmt.Errorf("score-signals: %s: id %q must be vendor.dimension.name", where, e.ID)
		}
		if dimSeg != e.Dimension {
			return nil, fmt.Errorf("score-signals: %s: id %q dimension segment %q must match dimension %q",
				where, e.ID, dimSeg, e.Dimension)
		}
		if e.Threshold != nil && (*e.Threshold < 0 || *e.Threshold > 100) {
			return nil, fmt.Errorf("score-signals: %s (%s): threshold must be in [0,100], got %d", where, e.ID, *e.Threshold)
		}
		if e.Subject != "" && !subjectRe.MatchString(e.Subject) {
			return nil, fmt.Errorf("score-signals: %s (%s): subject %q must match %s", where, e.ID, e.Subject, subjectRe.String())
		}
		seen[e.ID] = true
		out = append(out, NewWithSubject(domain.SignalID(e.ID), dim, e.Subject, e.Threshold))
	}
	return out, nil
}

// dimensionSegment returns the dimension segment of a vendor.dimension.name id
// by peeling name and dimension off the right, so a vendor segment containing
// dots of its own (e.g. a did:web authority like "did:web:example.com") does
// not defeat the format check the way a plain 3-part strings.Split would.
// ok is false unless the id has at least two dots and all three resulting
// segments (vendor, dimension, name) are non-empty.
func dimensionSegment(id string) (string, bool) {
	i := strings.LastIndexByte(id, '.')
	if i < 0 {
		return "", false
	}
	name, rest := id[i+1:], id[:i]
	j := strings.LastIndexByte(rest, '.')
	if j < 0 {
		return "", false
	}
	dim, vendor := rest[j+1:], rest[:j]
	if vendor == "" || dim == "" || name == "" {
		return "", false
	}
	return dim, true
}
