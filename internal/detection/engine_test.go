package detection_test

import (
	"testing"

	"github.com/szey/Aegis_Router/internal/detection"
	"github.com/szey/Aegis_Router/internal/models"
)

func TestIndirectPromptInjectionBeforeToolActionIsDenied(t *testing.T) {
	engine := detection.New(models.SessionControls{})
	result := engine.Evaluate(models.Request{
		RequestID: "evt-injection", SessionID: "session-injection", RequestedCapability: "run_limited_commands",
		InputSources: []models.InputSource{{Kind: "retrieval", Trust: "untrusted", URIClass: "web", RiskSignals: []string{"tool_directive"}}},
		ToolIdentity: &models.ToolIdentity{Name: "shell", SchemaSHA256: "approved", ExpectedSchemaSHA256: "approved"},
	}, 10)
	if result.RecommendedRoute != models.RouteDeny || !hasRule(result.Findings, "input.indirect_prompt_injection") {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestSensitiveReadThenEgressIsCorrelated(t *testing.T) {
	engine := detection.New(models.SessionControls{})
	first := engine.Evaluate(models.Request{
		RequestID: "evt-read", SessionID: "session-chain", RequestedCapability: "read_config",
		DataAccess: &models.DataAccess{Operation: "read", PathClass: "company_config", Protected: true, Sensitivity: "high"},
	}, 40)
	if !hasRule(first.Findings, "data.protected_read_requested") {
		t.Fatalf("sensitive read not detected: %#v", first)
	}
	second := engine.Evaluate(models.Request{
		RequestID: "evt-send", SessionID: "session-chain", ParentEventID: "evt-read", RequestedCapability: "external_request",
		Destination: &models.Destination{Kind: "https_api", TrustBoundary: "internet", External: true},
	}, 20)
	if second.RecommendedRoute != models.RouteDeny || !hasRule(second.Findings, "sequence.protected_read_context_then_egress") {
		t.Fatalf("cross-tool chain not denied: %#v", second)
	}
	if len(second.Context.Ancestors) != 1 || second.Context.Ancestors[0] != "evt-read" {
		t.Fatalf("causal ancestors = %#v", second.Context.Ancestors)
	}
}

func TestProtectedReadProvenanceCanTriggerCrossToolRule(t *testing.T) {
	engine := detection.New(models.SessionControls{})
	result := engine.Evaluate(models.Request{
		RequestID: "evt-send", SessionID: "session-adapter", ParentEventID: "evt-read", RequestedCapability: "external_request",
		InputSources: []models.InputSource{{EventID: "evt-read", Kind: "protected_read", Trust: "observer_recorded"}},
		Destination:  &models.Destination{Kind: "https_api", External: true},
	}, 20)
	if result.RecommendedRoute != models.RouteDeny || !hasRule(result.Findings, "sequence.protected_read_context_then_egress") {
		t.Fatalf("adapter provenance was not enforced: %#v", result)
	}
}

func TestSchemaHashMismatchIsDenied(t *testing.T) {
	engine := detection.New(models.SessionControls{})
	result := engine.Evaluate(models.Request{
		RequestID: "evt-schema", RequestedCapability: "read_safe_files",
		ToolIdentity: &models.ToolIdentity{Name: "filesystem", SchemaSHA256: "changed", ExpectedSchemaSHA256: "approved"},
	}, 0)
	if result.RecommendedRoute != models.RouteDeny || !hasRule(result.Findings, "tool.schema_hash_mismatch") {
		t.Fatalf("schema mismatch was not denied: %#v", result)
	}
}

func TestMissingReportedSchemaHashFailsClosed(t *testing.T) {
	engine := detection.New(models.SessionControls{})
	result := engine.Evaluate(models.Request{
		RequestID: "evt-schema-missing", RequestedCapability: "read_safe_files",
		ToolIdentity: &models.ToolIdentity{Name: "filesystem", ExpectedSchemaSHA256: "approved"},
	}, 0)
	if result.RecommendedRoute != models.RouteDeny || !hasRule(result.Findings, "tool.schema_hash_mismatch") {
		t.Fatalf("missing schema hash did not fail closed: %#v", result)
	}
}

func TestPrivacyBudgetEscalatesRepeatedProtectedReads(t *testing.T) {
	engine := detection.New(models.SessionControls{PrivacyReadBudget: 1, CumulativeRiskLimit: 100})
	request := models.Request{RequestID: "evt-1", SessionID: "session-budget", RequestedCapability: "read_config", DataAccess: &models.DataAccess{Operation: "read", Protected: true}}
	engine.Evaluate(request, 0)
	request.RequestID = "evt-2"
	result := engine.Evaluate(request, 0)
	if result.RecommendedRoute != models.RouteEscalate || !hasRule(result.Findings, "data.privacy_read_request_budget") {
		t.Fatalf("privacy budget did not escalate: %#v", result)
	}
}

func TestRepeatedEventIDDoesNotBecomeItsOwnCausalParent(t *testing.T) {
	engine := detection.New(models.SessionControls{})
	req := models.Request{
		RequestID: "evt-repeat", SessionID: "session-repeat", RequestedCapability: "run_limited_commands",
		InputSources: []models.InputSource{{Kind: "retrieval", Trust: "untrusted", RiskSignals: []string{"tool_directive"}}},
	}
	engine.Evaluate(req, 0)
	result := engine.Evaluate(req, 0)
	if hasRule(result.Findings, "sequence.poisoned_input_then_side_effect") {
		t.Fatalf("event correlated with itself: %#v", result)
	}
}

func hasRule(findings []models.SecurityFinding, rule string) bool {
	for _, finding := range findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}
