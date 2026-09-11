package risk

import (
	"fmt"

	"github.com/szey/Aegis_Router/internal/models"
)

type Scorer struct {
	config models.PolicyConfig
}

func New(cfg models.PolicyConfig) *Scorer {
	return &Scorer{config: cfg}
}

// Assess produces optional advisory metadata. Its numeric result is not a
// policy input and must never decide authorization, obligations, Permit
// issuance, or executor selection.
func (s *Scorer) Assess(req models.Request) models.RiskAssessment {
	score := 0
	var signals []string
	action := req.EffectiveAction()
	authority := req.EffectiveAuthority()

	if resource, ok := s.config.Resources[action.TargetResource]; ok {
		points := map[string]int{"low": 0, "medium": 20, "high": 35, "critical": 50}[resource.Sensitivity]
		score += points
		if points > 0 {
			signals = append(signals, fmt.Sprintf("%s resource sensitivity (+%d)", resource.Sensitivity, points))
		}
		for _, required := range resource.Scopes {
			if !contains(authority.Scopes, required) {
				score += 35
				signals = append(signals, "delegated scope mismatch (+35)")
				break
			}
		}
	} else {
		score += 50
		signals = append(signals, "unclassified resource (+50)")
	}

	if contains(s.config.SensitiveActions, action.Capability) {
		score += 20
		signals = append(signals, "sensitive capability (+20)")
	}
	if contains(s.config.ProhibitedActions, action.Capability) {
		score += 60
		signals = append(signals, "prohibited capability (+60)")
	}
	if action.Destination != nil && action.Destination.External {
		score += 25
		signals = append(signals, "external trust-boundary crossing (+25)")
	}
	if action.SideEffect != "" && action.SideEffect != "none" && action.SideEffect != "read_only" {
		score += 15
		signals = append(signals, "side-effecting operation (+15)")
	}
	if req.DataAccess != nil && req.DataAccess.Protected {
		score += 10
		signals = append(signals, "protected data class (+10)")
	}

	if score > 100 {
		score = 100
	}
	level := "low"
	if score >= 70 {
		level = "high"
	} else if score >= 35 {
		level = "medium"
	}
	if len(signals) == 0 {
		signals = []string{"no elevated risk signals"}
	}
	return models.RiskAssessment{Score: score, Level: level, Signals: signals}
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
