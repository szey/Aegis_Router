package detection

import (
	"fmt"
	"strings"
	"sync"

	"github.com/szey/Aegis_Router/internal/models"
)

// Engine correlates privacy-preserving request metadata within one process.
// It does not claim to observe activity that bypasses the Router or an adapter.
type Engine struct {
	mu       sync.Mutex
	controls models.SessionControls
	sessions map[string]*sessionState
}

type sessionState struct {
	events         map[string]eventSummary
	order          []string
	cumulativeRisk int
	protectedReads int
}

type eventSummary struct {
	parentID      string
	sensitiveRead bool
	poisonedInput bool
}

type Result struct {
	Findings []models.SecurityFinding
	Context  models.CausalContext
	// RecommendedRoute and RiskDelta are deprecated advisory compatibility
	// signals. The Permit authorization path must not consume either value.
	RecommendedRoute models.Route
	RiskDelta        int
}

func New(controls models.SessionControls) *Engine {
	if controls.PrivacyReadBudget < 1 {
		controls.PrivacyReadBudget = 3
	}
	if controls.CumulativeRiskLimit < 1 {
		controls.CumulativeRiskLimit = 80
	}
	if len(controls.EgressCapabilities) == 0 {
		controls.EgressCapabilities = []string{"external_request", "send_data", "upload_file", "exfiltrate_data"}
	}
	if len(controls.SideEffectCapabilities) == 0 {
		controls.SideEffectCapabilities = []string{"write_config", "run_limited_commands", "external_request", "invoke_admin_tool"}
	}
	if len(controls.InjectionRiskSignals) == 0 {
		controls.InjectionRiskSignals = []string{"instruction_like_content", "tool_directive", "policy_override", "credential_request"}
	}
	return &Engine{controls: controls, sessions: make(map[string]*sessionState)}
}

func (e *Engine) Evaluate(req models.Request, baseRisk int) Result {
	e.mu.Lock()
	defer e.mu.Unlock()

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = req.RequestID
	}
	state := e.sessions[sessionID]
	if state == nil {
		state = &sessionState{events: make(map[string]eventSummary)}
		e.sessions[sessionID] = state
	}

	ancestors := causalAncestors(state, req.ParentEventID)
	candidates := ancestors
	if len(candidates) == 0 {
		candidates = recent(state.order, 12)
	}

	action := req.EffectiveAction()
	tool := req.EffectiveTool()
	sensitiveRead := isSensitiveRead(req)
	poisonedInput := hasPoisonedInput(req.InputSources, e.controls.InjectionRiskSignals)
	egress := action.Destination != nil && action.Destination.External || contains(e.controls.EgressCapabilities, action.Capability)
	sideEffect := egress || contains(e.controls.SideEffectCapabilities, action.Capability) || (action.SideEffect != "" && action.SideEffect != "none" && action.SideEffect != "read_only")

	result := Result{Findings: []models.SecurityFinding{}}
	if sensitiveRead {
		state.protectedReads++
		result.RiskDelta += 10
		result.Findings = append(result.Findings, finding(req.RequestID, "sensitive_read_request", "medium", "data.protected_read_requested",
			"the attempted action declares a protected file read; no runtime execution is inferred from this request metadata",
			[]string{fmt.Sprintf("operation=%s", req.DataAccess.Operation), "path_class=" + safeValue(req.DataAccess.PathClass, "protected"), "content_recorded=false"}))
	}

	if poisonedInput {
		severity := "high"
		route := models.RouteSandbox
		points := 35
		if sideEffect {
			severity, route, points = "critical", models.RouteDeny, 60
		}
		result.RiskDelta += points
		result.RecommendedRoute = stronger(result.RecommendedRoute, route)
		result.Findings = append(result.Findings, finding(req.RequestID, "indirect_prompt_injection", severity, "input.indirect_prompt_injection",
			"untrusted retrieved content contains instruction-like signals before a tool action",
			inputEvidence(req)))
	}

	if schemaMismatch(&tool) {
		result.RiskDelta += 50
		result.RecommendedRoute = stronger(result.RecommendedRoute, models.RouteDeny)
		result.Findings = append(result.Findings, finding(req.RequestID, "tool_schema_drift", "critical", "tool.schema_hash_mismatch",
			"the invoked tool schema does not match the approved schema hash",
			[]string{"tool=" + tool.Name, "provider=" + safeValue(tool.Provider, "unknown"), "schema_hash_match=false"}))
	}

	crossToolFound := false
	if egress {
		if sourceEventID, ok := protectedInputSource(req.InputSources); ok {
			crossToolFound = true
			result.RiskDelta += 50
			result.RecommendedRoute = stronger(result.RecommendedRoute, models.RouteDeny)
			result.Findings = append(result.Findings, finding(req.RequestID, "cross_tool_exfiltration", "critical", "sequence.protected_read_context_then_egress",
				"a protected-read provenance claim is followed by an external-boundary action",
				[]string{"source_event=" + safeValue(sourceEventID, req.ParentEventID), "destination=" + destinationClass(req), "content_recorded=false"}))
		}
	}
	for _, eventID := range candidates {
		if eventID == req.RequestID {
			continue
		}
		prior, ok := state.events[eventID]
		if !ok {
			continue
		}
		if !crossToolFound && prior.sensitiveRead && egress {
			result.RiskDelta += 50
			result.RecommendedRoute = stronger(result.RecommendedRoute, models.RouteDeny)
			result.Findings = append(result.Findings, finding(req.RequestID, "cross_tool_exfiltration", "critical", "sequence.protected_read_context_then_egress",
				"a prior protected-read request is followed by an external-boundary action in the same causal session",
				[]string{"source_event=" + eventID, "destination=" + destinationClass(req), "content_recorded=false"}))
			crossToolFound = true
			break
		}
	}
	for _, eventID := range candidates {
		if eventID == req.RequestID {
			continue
		}
		prior, ok := state.events[eventID]
		if ok && prior.poisonedInput && sideEffect {
			result.RiskDelta += 45
			result.RecommendedRoute = stronger(result.RecommendedRoute, models.RouteDeny)
			result.Findings = append(result.Findings, finding(req.RequestID, "poisoned_input_tool_chain", "critical", "sequence.poisoned_input_then_side_effect",
				"a prior poisoned-input event causally precedes a side-effecting tool action",
				[]string{"source_event=" + eventID, "capability=" + action.Capability}))
			break
		}
	}

	remaining := e.controls.PrivacyReadBudget - state.protectedReads
	if remaining < 0 {
		remaining = 0
	}
	if state.protectedReads > e.controls.PrivacyReadBudget {
		result.RiskDelta += 30
		result.RecommendedRoute = stronger(result.RecommendedRoute, models.RouteEscalate)
		result.Findings = append(result.Findings, finding(req.RequestID, "privacy_budget_exceeded", "high", "data.privacy_read_request_budget",
			"the session exceeded its protected-read request budget",
			[]string{fmt.Sprintf("budget=%d", e.controls.PrivacyReadBudget), fmt.Sprintf("observed_reads=%d", state.protectedReads)}))
	}

	contribution := baseRisk/4 + result.RiskDelta
	if contribution < 1 {
		contribution = 1
	}
	state.cumulativeRisk = clamp(state.cumulativeRisk+contribution, 0, 100)
	if state.cumulativeRisk >= e.controls.CumulativeRiskLimit && result.RecommendedRoute != models.RouteDeny {
		result.RecommendedRoute = stronger(result.RecommendedRoute, models.RouteEscalate)
		result.Findings = append(result.Findings, finding(req.RequestID, "cumulative_risk_limit", "high", "session.cumulative_risk_limit",
			"the session cumulative-risk limit was reached",
			[]string{fmt.Sprintf("risk=%d", state.cumulativeRisk), fmt.Sprintf("limit=%d", e.controls.CumulativeRiskLimit)}))
	}

	state.events[req.RequestID] = eventSummary{parentID: req.ParentEventID, sensitiveRead: sensitiveRead, poisonedInput: poisonedInput}
	state.order = append(state.order, req.RequestID)
	if len(state.order) > 128 {
		delete(state.events, state.order[0])
		state.order = state.order[1:]
	}
	result.Context = models.CausalContext{
		SessionID: sessionID, EventID: req.RequestID, ParentEventID: req.ParentEventID,
		Ancestors: nonNil(ancestors), CumulativeRisk: state.cumulativeRisk, PrivacyBudgetRemaining: remaining,
	}
	return result
}

func protectedInputSource(sources []models.InputSource) (string, bool) {
	for _, source := range sources {
		if (source.Kind == "protected_read" || source.Kind == "protected_data") && source.Trust != "untrusted" {
			return source.EventID, true
		}
	}
	return "", false
}

func isSensitiveRead(req models.Request) bool {
	if req.DataAccess == nil || !req.DataAccess.Protected {
		return false
	}
	op := strings.ToLower(req.DataAccess.Operation)
	return op == "open" || op == "read"
}

func hasPoisonedInput(sources []models.InputSource, accepted []string) bool {
	for _, source := range sources {
		if source.Kind != "retrieval" || (source.Trust != "untrusted" && source.Trust != "external") {
			continue
		}
		for _, signal := range source.RiskSignals {
			if contains(accepted, signal) {
				return true
			}
		}
	}
	return false
}

func schemaMismatch(tool *models.ToolIdentity) bool {
	return tool != nil && tool.ExpectedSchemaSHA256 != "" && tool.ExpectedSchemaSHA256 != tool.SchemaSHA256
}

func causalAncestors(state *sessionState, parentID string) []string {
	ancestors := []string{}
	seen := map[string]bool{}
	for parentID != "" && !seen[parentID] && len(ancestors) < 16 {
		seen[parentID] = true
		ancestors = append(ancestors, parentID)
		prior, ok := state.events[parentID]
		if !ok {
			break
		}
		parentID = prior.parentID
	}
	return ancestors
}

func recent(items []string, limit int) []string {
	if len(items) <= limit {
		return append([]string(nil), items...)
	}
	return append([]string(nil), items[len(items)-limit:]...)
}

func inputEvidence(req models.Request) []string {
	action := req.EffectiveAction()
	tool := req.EffectiveTool()
	evidence := []string{"capability=" + action.Capability, "content_recorded=false"}
	if tool.Name != "" {
		evidence = append(evidence, "tool="+tool.Name)
	}
	for _, source := range req.InputSources {
		if source.Kind == "retrieval" && (source.Trust == "untrusted" || source.Trust == "external") {
			evidence = append(evidence, "input_kind="+source.Kind, "input_trust="+source.Trust, "uri_class="+safeValue(source.URIClass, "external"))
			break
		}
	}
	return evidence
}

func destinationClass(req models.Request) string {
	destination := req.EffectiveAction().Destination
	if destination == nil {
		return "external"
	}
	return safeValue(destination.Kind, "external")
}

func finding(eventID, category, severity, rule, summary string, evidence []string) models.SecurityFinding {
	return models.SecurityFinding{ID: eventID + ":" + rule, Category: category, Severity: severity, Rule: rule, Summary: summary, Evidence: nonNil(evidence)}
}

func stronger(current, candidate models.Route) models.Route {
	rank := map[models.Route]int{"": 0, models.RouteAllow: 1, models.RouteRestrict: 2, models.RouteSandbox: 3, models.RouteEscalate: 4, models.RouteDeny: 5}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func safeValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func nonNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}
