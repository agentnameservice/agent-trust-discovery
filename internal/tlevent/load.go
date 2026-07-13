package tlevent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadDir reads and validates every *.yaml file in dir (sorted by filename for
// deterministic ordering), skipping non-YAML entries and subdirectories.
func LoadDir(dir string) ([]Event, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("tlevent: read dir %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	events := make([]Event, 0, len(names))
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("tlevent: read %s: %w", name, err)
		}
		e, err := ParseEvent(b)
		if err != nil {
			return nil, fmt.Errorf("tlevent: %s: %w", name, err)
		}
		events = append(events, e)
	}
	return events, nil
}
