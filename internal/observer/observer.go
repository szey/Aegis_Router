package observer

import (
	"fmt"
	"strings"
	"time"

	"github.com/szey/Aegis_Router/internal/models"
)

type Observer struct{}

func New(_ models.PolicyConfig) *Observer {
	return &Observer{}
}

// Evaluate compares independently supplied runtime metadata with the issued
// authorization envelope. It never treats an agent plan as a security boundary.
func (o *Observer) Evaluate(permit models.AuthorizationEnvelope, event models.RuntimeEvent, evaluatedAt time.Time) models.RuntimeEventEvaluation {
	result := models.RuntimeEventEvaluation{
		EventID: event.EventID, PermitID: event.PermitID, Accepted: true,
		WithinEnvelope: true, Verdict: "PERMITTED_RUNTIME_EVENT", Violations: []models.AuthorizationViolation{},
	}

	reject := func(rule, summary, expected, actual string) {
		result.Accepted = false
		result.WithinEnvelope = false
		result.Terminated = true
		result.Violations = append(result.Violations, violation(rule, summary, expected, actual))
	}
	boundary := func(rule, summary, expected, actual string) {
		result.WithinEnvelope = false
		result.Terminated = true
		result.Violations = append(result.Violations, violation(rule, summary, expected, actual))
	}

	if event.EventID == "" {
		reject("runtime.event_id_missing", "runtime event has no event identifier", "non-empty event_id", "empty")
	}
	if expectedTrust, ok := trustForSource(event.Source); !ok {
		reject("runtime.source_unknown", "runtime event evidence source is not recognized", "known evidence source", string(event.Source))
	} else if expectedTrust != event.TrustLevel {
		reject("runtime.source_trust_mismatch", "runtime evidence trust label does not match its source", string(expectedTrust), string(event.TrustLevel))
	}
	if permit.PermitID == "" || event.PermitID != permit.PermitID {
		reject("runtime.permit_binding_mismatch", "runtime event is bound to the wrong execution permit", permit.PermitID, event.PermitID)
	}
	if event.RequestID != permit.RequestID {
		reject("runtime.request_binding_mismatch", "runtime event is bound to the wrong request", permit.RequestID, event.RequestID)
	}
	if event.AgentID != permit.AgentID {
		reject("runtime.agent_binding_mismatch", "runtime event is bound to the wrong agent", permit.AgentID, event.AgentID)
	}
	if event.WorkloadID != "" && event.WorkloadID != permit.WorkloadID {
		reject("runtime.workload_binding_mismatch", "runtime event is bound to the wrong workload", permit.WorkloadID, event.WorkloadID)
	}
	if !permit.ExpiresAt.After(evaluatedAt) || (!event.Timestamp.IsZero() && event.Timestamp.After(permit.ExpiresAt)) {
		reject("runtime.permit_expired", "runtime event was received outside the permit lifetime", permit.ExpiresAt.UTC().Format(time.RFC3339Nano), evaluatedAt.UTC().Format(time.RFC3339Nano))
	}

	// Binding and evidence failures are rejected before their action metadata is
	// considered trustworthy enough for boundary evaluation.
	if !result.Accepted {
		result.Verdict = "RUNTIME_EVENT_REJECTED"
		return result
	}

	if event.Capability != permit.AllowedCapability {
		boundary("envelope.capability_exceeded", "runtime capability exceeds the authorization envelope", permit.AllowedCapability, event.Capability)
	}
	if event.Tool != permit.AllowedTool {
		boundary("envelope.tool_exceeded", "runtime tool exceeds the authorization envelope", permit.AllowedTool, event.Tool)
	}
	if event.Resource != permit.AllowedResource {
		boundary("envelope.resource_exceeded", "runtime resource exceeds the authorization envelope", permit.AllowedResource, event.Resource)
	}
	if !contains(permit.AllowedOperations, event.Operation) {
		boundary("envelope.operation_exceeded", "runtime operation exceeds the authorization envelope", strings.Join(permit.AllowedOperations, ","), event.Operation)
	}
	if event.External && permit.Constraints.NetworkEgress != "allow" {
		boundary("envelope.network_egress_denied", "runtime action crossed an external trust boundary while egress was denied", "network_egress=deny", destination(event))
	}
	if event.SecretAccess && permit.Constraints.SecretAccess != "allow" {
		boundary("envelope.secret_access_denied", "runtime action accessed a secret while secret access was denied", "secret_access=deny", "secret_access=true")
	}
	if models.IsWriteOperation(event.Operation) && permit.Constraints.WriteAccess != "allow" {
		boundary("envelope.write_access_denied", "runtime write exceeded a read-only authorization envelope", "write_access=deny", "operation="+event.Operation)
	}
	if event.SideEffect != "" && event.SideEffect != "none" && event.SideEffect != "read_only" && !contains(permit.Constraints.AllowedSideEffects, event.SideEffect) {
		boundary("envelope.side_effect_denied", "runtime side effect was not granted by the authorization envelope", strings.Join(permit.Constraints.AllowedSideEffects, ","), event.SideEffect)
	}
	if permit.Constraints.MaxBytes > 0 && event.Bytes > permit.Constraints.MaxBytes {
		boundary("envelope.max_bytes_exceeded", "runtime byte count exceeded the authorization envelope", fmt.Sprintf("<=%d", permit.Constraints.MaxBytes), fmt.Sprintf("%d", event.Bytes))
	}
	if permit.Constraints.MaxDurationMS > 0 && !event.Timestamp.IsZero() {
		elapsed := event.Timestamp.Sub(permit.IssuedAt).Milliseconds()
		if elapsed > permit.Constraints.MaxDurationMS {
			boundary("envelope.max_duration_exceeded", "runtime event exceeded the authorization duration limit", fmt.Sprintf("<=%dms", permit.Constraints.MaxDurationMS), fmt.Sprintf("%dms", elapsed))
		}
	}

	if !result.WithinEnvelope {
		result.Verdict = "AUTHORIZATION_BOUNDARY_VIOLATION"
	}
	return result
}

func trustForSource(source models.RuntimeEventSource) (models.RuntimeTrustLevel, bool) {
	switch source {
	case models.RuntimeSourceGatewayEnforced:
		return models.RuntimeTrustEnforced, true
	case models.RuntimeSourceInstrumentedAdapter:
		return models.RuntimeTrustAdapterReported, true
	case models.RuntimeSourceAgentSelfReported:
		return models.RuntimeTrustSelfReported, true
	case models.RuntimeSourceOSSensor, models.RuntimeSourceNetworkSensor:
		return models.RuntimeTrustIndependentSensor, true
	case models.RuntimeSourceSimulatedDemo:
		return models.RuntimeTrustSimulated, true
	default:
		return "", false
	}
}

func violation(rule, summary, expected, actual string) models.AuthorizationViolation {
	return models.AuthorizationViolation{Rule: rule, Summary: summary, Expected: expected, Actual: actual}
}

func destination(event models.RuntimeEvent) string {
	if event.DestinationClass == "" {
		return "external"
	}
	return event.DestinationClass
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
