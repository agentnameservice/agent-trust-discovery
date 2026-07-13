package sqlitestore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// marshalStrings encodes a string slice as a JSON array, normalizing nil/empty
// to "[]" (never "null") so the column's NOT NULL DEFAULT '[]' invariant holds.
func marshalStrings(s []string) (string, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("sqlitestore: marshal string slice: %w", err)
	}
	return string(b), nil
}

// unmarshalStrings decodes a JSON array column back to a string slice.
func unmarshalStrings(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("sqlitestore: unmarshal string slice: %w", err)
	}
	return out, nil
}

// formatTime encodes to fixed-length RFC3339 (whole-second precision), so
// stored strings compare correctly under lexicographic ORDER BY: RFC3339Nano
// trims trailing zeros, so "…00Z" (0x5A) would sort greater than "…00.5Z"
// (0x2E) at the sub-second boundary and DESC would return the older row.
// Sub-second producer precision is truncated on write; the ORDER BY tie-break
// on obs_id preserves insert order within a single second.
func formatTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// parseTime stays tolerant to RFC3339Nano-shaped strings so legacy rows written
// before the fixed-length format still round-trip.
func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("sqlitestore: parse time %q: %w", s, err)
	}
	return t.UTC(), nil
}

// provenanceJSON is the on-disk shape of domain.Provenance. The domain type has
// no JSON tags by design (§3); storage/wire shapes live in adapters.
type provenanceJSON struct {
	AIMID       string `json:"aimId"`
	EvidenceURL string `json:"evidenceUrl,omitempty"`
}

// marshalProvenance returns a NULL NullString for absent provenance, else the
// JSON-encoded block. The result is a valid SQL arg in both cases.
func marshalProvenance(p *domain.Provenance) (sql.NullString, error) {
	if p == nil {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(provenanceJSON{AIMID: p.AIMID, EvidenceURL: p.EvidenceURL})
	if err != nil {
		return sql.NullString{}, fmt.Errorf("sqlitestore: marshal provenance: %w", err)
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

func unmarshalProvenance(ns sql.NullString) (*domain.Provenance, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil //nolint:nilnil // absent provenance is legitimately (nil, nil)
	}
	var pj provenanceJSON
	if err := json.Unmarshal([]byte(ns.String), &pj); err != nil {
		return nil, fmt.Errorf("sqlitestore: unmarshal provenance: %w", err)
	}
	return &domain.Provenance{AIMID: pj.AIMID, EvidenceURL: pj.EvidenceURL}, nil
}
