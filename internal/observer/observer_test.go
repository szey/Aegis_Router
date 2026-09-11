package observer_test

import (
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/observer"
)

func TestRuntimeEventInsidePermitIsAllowed(t *testing.T) {
	result := evaluate(validEvent())
	if !result.Accepted || !result.WithinEnvelope || result.Terminated || result.Verdict != "PERMITTED_RUNTIME_EVENT" {
		t.Fatalf("evaluation = %#v", result)
	}
}

func TestSecretAccessOutsidePermitIsViolation(t *testing.T) {
	event := validEvent()
	event.SecretAccess = true
	result := evaluate(event)
	assertBoundaryViolation(t, result, "envelope.secret_access_denied")
}

func TestWriteOutsideReadOnlyPermitIsViolation(t *testing.T) {
	event := validEvent()
	event.Operation = "write"
	result := evaluate(event)
	assertBoundaryViolation(t, result, "envelope.write_access_denied")
}

func TestExternalEgressWhenDeniedIsViolation(t *testing.T) {
	event := validEvent()
	event.External = true
	event.DestinationClass = "PUBLIC_INTERNET"
	result := evaluate(event)
	assertBoundaryViolation(t, result, "envelope.network_egress_denied")
}

func TestExpiredPermitRejectsRuntimeEvent(t *testing.T) {
	permit := validPermit()
	event := validEvent()
	now := permit.ExpiresAt.Add(time.Second)
	result := observer.New(models.PolicyConfig{}).Evaluate(permit, event, now)
	assertRejected(t, result, "runtime.permit_expired")
}

func TestWrongAgentOrRequestBindingIsRejected(t *testing.T) {
	tests := []struct {
		name string
		edit func(*models.RuntimeEvent)
		rule string
	}{
		{name: "wrong agent", edit: func(event *models.RuntimeEvent) { event.AgentID = "other-agent" }, rule: "runtime.agent_binding_mismatch"},
		{name: "wrong request", edit: func(event *models.RuntimeEvent) { event.RequestID = "req-other" }, rule: "runtime.request_binding_mismatch"},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			event := validEvent()
			item.edit(&event)
			assertRejected(t, evaluate(event), item.rule)
		})
	}
}

func TestDemoAndSelfReportedTelemetryRemainExplicitlyLabeled(t *testing.T) {
	tests := []struct {
		source models.RuntimeEventSource
		trust  models.RuntimeTrustLevel
	}{
		{source: models.RuntimeSourceSimulatedDemo, trust: models.RuntimeTrustSimulated},
		{source: models.RuntimeSourceAgentSelfReported, trust: models.RuntimeTrustSelfReported},
	}
	for _, item := range tests {
		event := validEvent()
		event.Source, event.TrustLevel = item.source, item.trust
		result := evaluate(event)
		if !result.Accepted || !result.WithinEnvelope {
			t.Fatalf("source=%s trust=%s evaluation=%#v", item.source, item.trust, result)
		}
		if event.Source != item.source || event.TrustLevel != item.trust {
			t.Fatal("observer changed the evidence label")
		}
	}
}

func TestFalseEvidenceTrustLabelIsRejected(t *testing.T) {
	event := validEvent()
	event.Source = models.RuntimeSourceAgentSelfReported
	event.TrustLevel = models.RuntimeTrustIndependentSensor
	assertRejected(t, evaluate(event), "runtime.source_trust_mismatch")
}

func evaluate(event models.RuntimeEvent) models.RuntimeEventEvaluation {
	permit := validPermit()
	return observer.New(models.PolicyConfig{}).Evaluate(permit, event, permit.IssuedAt.Add(time.Second))
}

func validPermit() models.AuthorizationEnvelope {
	issued := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	return models.AuthorizationEnvelope{
		PermitID: "permit-01", RequestID: "req-01", PrincipalID: "user-01", AgentID: "coder-agent", WorkloadID: "coder-workload-v1",
		AllowedCapability: "read_config", AllowedTool: "config_reader", AllowedResource: "protected_config",
		AllowedOperations: []string{"read"}, IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute),
		Constraints: models.AuthorizationConstraints{
			NetworkEgress: "deny", SecretAccess: "deny", WriteAccess: "deny", AllowedSideEffects: []string{}, MaxBytes: 4096,
		},
	}
}

func validEvent() models.RuntimeEvent {
	return models.RuntimeEvent{
		EventID: "event-01", PermitID: "permit-01", RequestID: "req-01", AgentID: "coder-agent", WorkloadID: "coder-workload-v1",
		Source: models.RuntimeSourceInstrumentedAdapter, TrustLevel: models.RuntimeTrustAdapterReported,
		Capability: "read_config", Tool: "config_reader", Operation: "read", Resource: "protected_config", Bytes: 1024,
	}
}

func assertBoundaryViolation(t *testing.T, result models.RuntimeEventEvaluation, rule string) {
	t.Helper()
	if !result.Accepted || result.WithinEnvelope || !result.Terminated || result.Verdict != "AUTHORIZATION_BOUNDARY_VIOLATION" {
		t.Fatalf("evaluation = %#v", result)
	}
	if !hasViolation(result, rule) {
		t.Fatalf("violations = %#v, want %s", result.Violations, rule)
	}
}

func assertRejected(t *testing.T, result models.RuntimeEventEvaluation, rule string) {
	t.Helper()
	if result.Accepted || result.WithinEnvelope || !result.Terminated || result.Verdict != "RUNTIME_EVENT_REJECTED" {
		t.Fatalf("evaluation = %#v", result)
	}
	if !hasViolation(result, rule) {
		t.Fatalf("violations = %#v, want %s", result.Violations, rule)
	}
}

func hasViolation(result models.RuntimeEventEvaluation, rule string) bool {
	for _, item := range result.Violations {
		if item.Rule == rule {
			return true
		}
	}
	return false
}
