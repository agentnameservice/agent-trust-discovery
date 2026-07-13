package search

import (
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// Wire response shapes. Field names follow spec/api-spec-search.yaml
// (RegisteredAgent, SearchResults, Link, AgentDetail, TrustEvaluation, …). The
// collection envelope is byte-compatible with ans-search-api (design §5.5);
// trustEvaluation, the per-dimension breakdown, and signalScore.attestation are
// RI additions. compositeScore is deliberately not emitted (spec §2.4).

type registeredAgentDTO struct {
	AgentID      string   `json:"agentId"`
	DNSName      string   `json:"dnsName"`
	DisplayName  string   `json:"displayName"`
	Description  string   `json:"description,omitempty"`
	ProviderID   string   `json:"providerId,omitempty"`
	Status       string   `json:"status"`
	Protocols    []string `json:"protocols,omitempty"`
	Transports   []string `json:"transports,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	FirstSeen    string   `json:"firstSeen"`
	LastUpdated  string   `json:"lastUpdated"`
}

func newRegisteredAgentDTO(a domain.Agent) registeredAgentDTO {
	return registeredAgentDTO{
		AgentID:      string(a.ID),
		DNSName:      a.DNSName,
		DisplayName:  a.DisplayName,
		Description:  a.Description,
		ProviderID:   a.ProviderID,
		Status:       string(a.Status),
		Protocols:    a.Protocols,
		Transports:   a.Transports,
		Tags:         a.Tags,
		Capabilities: a.Capabilities,
		FirstSeen:    a.FirstSeen.UTC().Format(time.RFC3339),
		LastUpdated:  a.LastUpdated.UTC().Format(time.RFC3339),
	}
}

type linkDTO struct {
	Rel    string `json:"rel"`
	Method string `json:"method"`
	Href   string `json:"href"`
}

// searchResultsDTO is the collection envelope. items and links are always
// present; totalItems/totalPages appear only when the query set totalRequired.
type searchResultsDTO struct {
	Items      []registeredAgentDTO `json:"items"`
	Links      []linkDTO            `json:"links"`
	TotalItems *int                 `json:"totalItems,omitempty"`
	TotalPages *int                 `json:"totalPages,omitempty"`
}

func newSearchResultsDTO(items []registeredAgentDTO, links []linkDTO, page port.SearchPage, totalRequired bool) searchResultsDTO {
	res := searchResultsDTO{Items: items, Links: links}
	if totalRequired {
		ti, tp := page.TotalItems, page.TotalPages
		res.TotalItems = &ti
		res.TotalPages = &tp
	}
	return res
}

type trustVectorDTO struct {
	Integrity int `json:"integrity"`
	Identity  int `json:"identity"`
	Solvency  int `json:"solvency"`
	Behavior  int `json:"behavior"`
	Safety    int `json:"safety"`
}

type signalScoreDTO struct {
	SignalID    string  `json:"signalId"`
	RawScore    int     `json:"rawScore"`
	Weight      float64 `json:"weight"`
	Attestation string  `json:"attestation"`
	Explanation string  `json:"explanation"`
}

type dimensionScoreDTO struct {
	Dimension    string           `json:"dimension"`
	Score        int              `json:"score"`
	SignalScores []signalScoreDTO `json:"signalScores"`
}

// trustEvaluationDTO is the spec Appendix B payload plus the RI dimensions[]
// breakdown. verificationTier is rendered (as null in v1) rather than omitted,
// matching the design §5.1 example; compositeScore is not present.
type trustEvaluationDTO struct {
	AgentID            string              `json:"agentId"`
	EvaluationTime     string              `json:"evaluationTime"`
	TrustVector        trustVectorDTO      `json:"trustVector"`
	RecommendedProfile string              `json:"recommendedProfile"`
	VerificationTier   *string             `json:"verificationTier"`
	RiskFactors        []string            `json:"riskFactors"`
	ScoringProfile     string              `json:"scoringProfile"`
	Dimensions         []dimensionScoreDTO `json:"dimensions"`
}

type agentDetailDTO struct {
	registeredAgentDTO
	TrustEvaluation trustEvaluationDTO `json:"trustEvaluation"`
}

func newTrustEvaluationDTO(e domain.TrustEvaluation) trustEvaluationDTO {
	dims := make([]dimensionScoreDTO, 0, len(e.Dimensions))
	for _, d := range e.Dimensions {
		scores := make([]signalScoreDTO, 0, len(d.SignalScores))
		for _, s := range d.SignalScores {
			scores = append(scores, signalScoreDTO{
				SignalID:    string(s.SignalID),
				RawScore:    s.RawScore,
				Weight:      s.Weight,
				Attestation: string(s.Attestation),
				Explanation: s.Explanation,
			})
		}
		dims = append(dims, dimensionScoreDTO{
			Dimension:    string(d.Dimension),
			Score:        d.Score,
			SignalScores: scores,
		})
	}

	var tier *string
	if e.VerificationTier != domain.TierUnset {
		t := string(e.VerificationTier)
		tier = &t
	}

	return trustEvaluationDTO{
		AgentID:        string(e.AgentID),
		EvaluationTime: e.EvaluationTime.UTC().Format(time.RFC3339),
		TrustVector: trustVectorDTO{
			Integrity: e.TrustVector.Integrity,
			Identity:  e.TrustVector.Identity,
			Solvency:  e.TrustVector.Solvency,
			Behavior:  e.TrustVector.Behavior,
			Safety:    e.TrustVector.Safety,
		},
		RecommendedProfile: string(e.RecommendedProfile),
		VerificationTier:   tier,
		// Copy so the wire value is always a non-nil [] and never aliases the engine's slice.
		RiskFactors:    append([]string{}, e.RiskFactors...),
		ScoringProfile: e.ScoringProfile,
		Dimensions:     dims,
	}
}
