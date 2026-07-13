package domain_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// AllDimensions and TrustVector must stay in lockstep. AllDimensions is
// iterated by the engine to build every DimensionScore; TrustVector is the
// fixed-shape aggregate that rides the wire. Adding a dimension to the list
// without a matching field on TrustVector would leave the new dimension
// scored but never surfaced in the trust vector — a silent gap. This test
// traps that drift at build time.
func TestTrustVector_FieldsMatchAllDimensions(t *testing.T) {
	tv := reflect.TypeOf(domain.TrustVector{})

	fieldsLower := make(map[string]bool, tv.NumField())
	for i := range tv.NumField() {
		fieldsLower[strings.ToLower(tv.Field(i).Name)] = true
	}
	dimsLower := make(map[string]bool, len(domain.AllDimensions()))
	for _, d := range domain.AllDimensions() {
		dimsLower[strings.ToLower(string(d))] = true
	}

	// Every dimension must have a TrustVector field (case-insensitive match on
	// the const value like "integrity" vs the field name "Integrity").
	for _, d := range domain.AllDimensions() {
		if !fieldsLower[strings.ToLower(string(d))] {
			t.Errorf("AllDimensions contains %q but TrustVector has no matching field; the dimension will be scored but never rides the wire", d)
		}
	}
	// And every TrustVector field must be one of the known dimensions — an
	// orphan field would silently zero on every evaluation.
	for i := range tv.NumField() {
		name := tv.Field(i).Name
		if !dimsLower[strings.ToLower(name)] {
			t.Errorf("TrustVector has field %q with no matching dimension in AllDimensions; the field will always be zero", name)
		}
	}
}
