package domain_test

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func TestStatusValid(t *testing.T) {
	for _, s := range []domain.Status{
		domain.StatusActive, domain.StatusWarning, domain.StatusDeprecated,
		domain.StatusExpired, domain.StatusRevoked,
	} {
		if !s.Valid() {
			t.Errorf("Status(%q).Valid() = false, want true", s)
		}
	}
	for _, s := range []domain.Status{"", "active", "ACTIVE ", "UNKNOWN", "Revoked"} {
		if s.Valid() {
			t.Errorf("Status(%q).Valid() = true, want false", s)
		}
	}
}

// The status strings are a wire contract; pin them so an accidental edit fails.
func TestStatusValues(t *testing.T) {
	pins := map[domain.Status]string{
		domain.StatusActive:     "ACTIVE",
		domain.StatusWarning:    "WARNING",
		domain.StatusDeprecated: "DEPRECATED",
		domain.StatusExpired:    "EXPIRED",
		domain.StatusRevoked:    "REVOKED",
	}
	for s, want := range pins {
		if string(s) != want {
			t.Errorf("status const = %q, want %q", string(s), want)
		}
	}
}
