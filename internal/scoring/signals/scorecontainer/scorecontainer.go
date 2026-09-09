// Package scorecontainer is the neutral, reusable score container for
// provider-fed Trust Index dimensions (solvency, behavior, safety, and any
// future dimension whose evidence a provider hydrates rather than the engine
// computing it from public DNS/certs).
//
// It exists so no single vendor "owns" the container shape. A provider registers
// a dimension score by instantiating New(id, dimension, threshold) — it does not
// re-implement validation, risk-code handling, or the low-score backstop, and it
// does not add anything to core. Multiple providers can each register their own
// vendor.dimension.name signal against the same container:
//
//	scorecontainer.New("trustmodel.safety.score",  domain.DimensionSafety,   70)
//	scorecontainer.New("agentgraph.safety.score",  domain.DimensionSafety,   70)
//	scorecontainer.New("acme.behavior.score",      domain.DimensionBehavior, 60)
//
// The observation value is a generic 0..100 score plus provider-asserted,
// dimension-scoped risk codes and an optional explanation:
//
//	{ "score": 0, "riskCodes": ["SAFETY_..."], "explanation": "…" }
//
// Provenance/attestation (an evidence URL, a signed receipt, a ledger anchor,
// an Ed25519/JWS blob) rides the observation's provenance envelope, not this
// value, so the score stays opinion-free and any evidence model composes.
package scorecontainer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// ScoreSignal implements both port.Signal and port.AbsenceAware. The compile
// guard keeps the pairing honest: the container's absence semantics (absent !=
// scored-0) only take effect once the engine honours port.AbsenceAware, so this
// package must be built against a tree that defines it. If AbsenceAware is not
// present, this line fails to compile rather than silently reverting a covered
// dimension to a 0 roll-up.
var (
	_ port.Signal       = ScoreSignal{}
	_ port.AbsenceAware = ScoreSignal{}
)

// DefaultLowThreshold is the score below which the generic
// {DIMENSION}_<VENDOR>_SCORE_LOW backstop risk code is emitted. It is a
// per-signal field (see New) so it can be tuned in configuration rather than
// baked in as a magic constant.
const DefaultLowThreshold = 70

// maxRiskCodes caps how many provider risk codes one observation may carry, so
// a hostile or buggy hydrator can't balloon the evaluation payload.
const maxRiskCodes = 16

// SubjectAgent is the default subject class: the observation scores the agent
// itself. A provider that scores a *different* entity in the same dimension —
// a tool / MCP server, or the controlling organization — declares its own
// subject so a Trust Index never silently averages, e.g., a tool's safety into
// an agent's safety. Subject is an open lowercase token (not a fixed enum) so a
// new subject class needs no core change; the engine buckets by value.
const SubjectAgent = "agent"

// riskCodeRe is the risk-code shape (§7.3): uppercase, digits, underscores.
var riskCodeRe = regexp.MustCompile(`^[A-Z0-9_]+$`)

// scoreValue is the observation shape decoded from the import. It is internal:
// providers emit JSON of this shape from their hydrator; they do not construct
// the Go struct. A bare {"score": N} is valid — you then get only the backstop,
// so a minimal hydrator still works.
//
// Score is a *int, not an int, so the three ways a hydrator can fail to send a
// score are all distinguishable from a real 0 (the worst score on the scale):
// an absent field ({}), an explicit null ({"score":null}), and — paired with
// DisallowUnknownFields in decodeScore — a misspelled field ({"scores":50}).
// All three become a 422 at import instead of silently punishing the agent.
type scoreValue struct {
	Score       *int     `json:"score"`                 // 0..100, required
	RiskCodes   []string `json:"riskCodes,omitempty"`   // provider-asserted, {DIMENSION}_-prefixed
	Explanation string   `json:"explanation,omitempty"` // optional; surfaced in the API response
}

// decodeScore is the single strict decode used by both Validate and Evaluate.
// DisallowUnknownFields turns a field-name typo into an error rather than a
// silently-dropped value, and the explicit nil check turns an absent/null score
// into an error rather than a real 0.
func decodeScore(raw json.RawMessage) (scoreValue, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v scoreValue
	if err := dec.Decode(&v); err != nil {
		return scoreValue{}, err
	}
	if v.Score == nil {
		return scoreValue{}, errors.New("score is required")
	}
	return v, nil
}

// ScoreSignal is a generic provider-score signal for one dimension. Construct
// with New (subject = agent) or NewWithSubject. It implements port.Signal and
// port.AbsenceAware.
type ScoreSignal struct {
	id        domain.SignalID
	dimension domain.Dimension
	vendor    string
	subject   string
	threshold int
}

// New builds a ScoreSignal that scores the agent (subject = SubjectAgent). See
// NewWithSubject for the vendor/threshold semantics.
func New(id domain.SignalID, dim domain.Dimension, threshold *int) ScoreSignal {
	return NewWithSubject(id, dim, SubjectAgent, threshold)
}

// NewWithSubject builds a ScoreSignal for a vendor.dimension.name id that scores
// the given subject class. The id's vendor segment prefixes the generic backstop
// code (e.g. "trustmodel" -> SAFETY_TRUSTMODEL_SCORE_LOW).
//
// subject records what entity the score is about (SubjectAgent, "tool", "org",
// …) so an index can keep, e.g., a tool-safety score in a different bucket from
// an agent-safety score rather than averaging across subjects. An empty subject
// defaults to SubjectAgent.
//
// threshold is a *int so 0 is a usable value: nil applies DefaultLowThreshold,
// while an explicit 0 means "no low-score backstop" (a score can never be below
// 0, so the {DIMENSION}_<VENDOR>_SCORE_LOW code is never emitted). Previously a
// <= 0 threshold silently became 70, so an operator asking for "no backstop"
// got the opposite.
func NewWithSubject(id domain.SignalID, dim domain.Dimension, subject string, threshold *int) ScoreSignal {
	t := DefaultLowThreshold
	if threshold != nil {
		t = *threshold
	}
	if subject == "" {
		subject = SubjectAgent
	}
	// Normalise the vendor segment to the risk-code charset (^[A-Z0-9_]+$) so a
	// hyphenated vendor like "acme-labs" yields SAFETY_ACME_LABS_SCORE_LOW, a
	// valid code, rather than SAFETY_ACME-LABS_SCORE_LOW, which would fail the
	// very shape check we enforce on provider-supplied codes.
	vendor := sanitizeSegment(vendorSegment(string(id)))
	return ScoreSignal{id: id, dimension: dim, vendor: vendor, subject: subject, threshold: t}
}

// vendorSegment returns the vendor segment of a vendor.dimension.name id: the
// id with its trailing ".dimension.name" removed, or the whole id if it
// carries fewer than two dots. Peeling from the right (rather than splitting
// on the first dot) means a vendor segment that itself contains dots — a
// did:web authority, say — keeps its dots rather than being truncated at the
// first one; sanitizeSegment normalises them afterward.
func vendorSegment(id string) string {
	i := strings.LastIndexByte(id, '.')
	if i < 0 {
		return id
	}
	rest := id[:i]
	if j := strings.LastIndexByte(rest, '.'); j >= 0 {
		return rest[:j]
	}
	return rest
}

// sanitizeSegment uppercases a segment and maps any character outside
// [A-Z0-9_] to '_', so the generated backstop code always matches riskCodeRe.
func sanitizeSegment(s string) string {
	up := strings.ToUpper(s)
	var b strings.Builder
	b.Grow(len(up))
	for _, r := range up {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func (s ScoreSignal) ID() domain.SignalID         { return s.id }
func (s ScoreSignal) Dimension() domain.Dimension { return s.dimension }
func (s ScoreSignal) Derived() bool               { return false }

// Subject reports the entity class this signal's score is about (SubjectAgent by
// default). A Trust Index can group/filter by subject before aggregating, so a
// tool-safety score and an agent-safety score in the same dimension are never
// silently averaged together.
func (s ScoreSignal) Subject() string { return s.subject }

// AbsenceInformative reports false: a missing observation for a provider-fed
// dimension means no provider has covered the agent yet, not that it scored
// badly. The engine excludes the signal from the roll-up when absent rather than
// scoring it 0 (issue #13).
func (s ScoreSignal) AbsenceInformative() bool { return false }

// prefix is the required {DIMENSION}_ prefix for this signal's risk codes, e.g.
// "SAFETY_". Provider codes without it are dropped in Evaluate so a signal can't
// leak a code into a dimension it doesn't own.
func (s ScoreSignal) prefix() string {
	return strings.ToUpper(string(s.dimension)) + "_"
}

// Validate enforces the container schema before the observation is persisted:
// a required score in range, each risk code well-formed AND prefixed for this
// signal's dimension, and the count capped. Rejecting a wrong-dimension code
// here (rather than dropping it in Evaluate) means a hydrator that emits
// "SAFTEY_..." for a safety signal — a typo, or a code meant for another
// dimension — gets a 422 telling it why, instead of the code silently vanishing
// from the score with no feedback.
func (s ScoreSignal) Validate(value json.RawMessage) error {
	v, err := decodeScore(value)
	if err != nil {
		return fmt.Errorf("%s: invalid value: %w", s.id, err)
	}
	if *v.Score < 0 || *v.Score > 100 {
		return fmt.Errorf("%s: score must be in [0,100], got %d", s.id, *v.Score)
	}
	if len(v.RiskCodes) > maxRiskCodes {
		return fmt.Errorf("%s: too many riskCodes (%d > %d)", s.id, len(v.RiskCodes), maxRiskCodes)
	}
	prefix := s.prefix()
	for _, c := range v.RiskCodes {
		if !riskCodeRe.MatchString(c) {
			return fmt.Errorf("%s: risk code %q must match %s", s.id, c, riskCodeRe.String())
		}
		if !strings.HasPrefix(c, prefix) {
			return fmt.Errorf("%s: risk code %q must be prefixed %q (the signal's dimension)", s.id, c, prefix)
		}
	}
	return nil
}

// Evaluate maps the container onto a SignalResult: Raw is the score; RiskCodes
// are the provider's dimension-scoped codes (codes prefixed for another
// dimension are dropped) plus the normalized {DIMENSION}_<VENDOR>_SCORE_LOW
// backstop when the score is below the configured threshold. The provider's
// explanation is surfaced.
func (s ScoreSignal) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	prefix := s.prefix()
	if obs == nil {
		return port.SignalResult{
			Raw:         0,
			Explanation: fmt.Sprintf("no %s observation recorded for %s", s.dimension, s.id),
			Attestation: domain.AttestationUnattested,
			RiskCodes:   []string{prefix + s.vendor + "_UNKNOWN"},
		}, nil
	}
	v, err := decodeScore(obs.Value)
	if err != nil {
		return port.SignalResult{}, fmt.Errorf("%s: %w", s.id, err)
	}

	// Validate already rejects wrong-dimension codes at import, so this filter is
	// a defence-in-depth pass for observations stored before that check existed.
	codes := make([]string, 0, len(v.RiskCodes)+1)
	for _, c := range v.RiskCodes {
		if strings.HasPrefix(c, prefix) {
			codes = append(codes, c)
		}
	}
	if *v.Score < s.threshold {
		codes = append(codes, prefix+s.vendor+"_SCORE_LOW")
	}

	explanation := v.Explanation
	if explanation == "" {
		explanation = fmt.Sprintf("%s score %d/100", s.id, *v.Score)
	}
	return port.SignalResult{
		Raw:         *v.Score,
		Explanation: explanation,
		Attestation: domain.AttestationUnattested,
		RiskCodes:   codes,
	}, nil
}
