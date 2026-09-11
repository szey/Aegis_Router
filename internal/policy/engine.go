package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/szey/Aegis_Router/internal/models"
)

type Engine struct {
	config models.PolicyConfig
	clock  func() time.Time
}

func New(cfg models.PolicyConfig) *Engine {
	return &Engine{config: cfg, clock: time.Now}
}

// Evaluate is the sole authorization authority for execution-permit issuance.
// It uses deterministic policy inputs only; advisory risk or detection output
// is neither accepted nor consulted here.
func (e *Engine) Evaluate(req models.Request) models.PolicyDecision {
	principal := req.EffectivePrincipal()
	agentIdentity := req.EffectiveAgent()
	authority := req.EffectiveAuthority()
	tool := req.EffectiveTool()
	action := req.EffectiveAction()

	if !req.UsesStructuredContext() && !e.config.Compatibility.AllowLegacyFlatRequests {
		return deny("request.legacy_not_allowed", "the flat legacy request shape is disabled; structured security context is required")
	}
	agent, ok := e.config.Agents[agentIdentity.AgentID]
	if !ok {
		return deny("identity.unknown_agent", fmt.Sprintf("agent %q has no authorization policy", agentIdentity.AgentID))
	}
	if len(agent.WorkloadIDs) > 0 && !contains(agent.WorkloadIDs, agentIdentity.WorkloadID) {
		return deny("identity.workload_not_granted", fmt.Sprintf("workload %q is not registered for agent %q", agentIdentity.WorkloadID, agentIdentity.AgentID))
	}
	if authority.Subject != "" && principal.PrincipalID != "" && authority.Subject != principal.PrincipalID {
		return deny("delegation.subject_mismatch", "delegated authority subject does not match the acting principal")
	}
	if authority.ExpiresAt != nil && !authority.ExpiresAt.After(e.clock()) {
		return deny("delegation.expired", "delegated authority has expired")
	}
	resource, ok := e.config.Resources[action.TargetResource]
	if !ok {
		return deny("resource.unknown", fmt.Sprintf("resource %q is not classified", action.TargetResource))
	}
	if contains(e.config.ProhibitedActions, action.Capability) {
		return deny("capability.prohibited", "the requested capability is globally prohibited")
	}
	if contains(agent.DeniedResources, action.TargetResource) {
		return deny("resource.agent_denylist", "the agent policy explicitly denies this resource")
	}

	capability, ok := agent.Capabilities[action.Capability]
	if !ok {
		if contains(agent.AllowedCapabilities, action.Capability) {
			capability = legacyGrant(action.TargetResource, resource)
			ok = true
		}
	}
	if !ok {
		return deny("capability.not_granted", "the agent was not granted the requested capability")
	}
	resourceGrant, ok := capability.Resources[action.TargetResource]
	if !ok {
		return deny("resource.not_granted", "the capability is not granted against the requested resource")
	}

	matchedTool := firstNonEmpty(tool.Name, tool.ToolID)
	if matchedTool == "" && !req.UsesStructuredContext() && e.config.Compatibility.AllowMissingTool && len(capability.AllowedTools) > 0 {
		matchedTool = capability.AllowedTools[0]
	}
	if matchedTool == "" || !contains(capability.AllowedTools, matchedTool) {
		return deny("tool.not_granted", fmt.Sprintf("tool %q is not allowed for capability %q", matchedTool, action.Capability))
	}

	operation := action.Operation
	if operation == "" && !req.UsesStructuredContext() && e.config.Compatibility.AllowMissingOperation && len(resourceGrant.AllowedOperations) > 0 {
		operation = resourceGrant.AllowedOperations[0]
	}
	if operation == "" || !contains(resourceGrant.AllowedOperations, operation) {
		return deny("resource.operation_not_granted", fmt.Sprintf("operation %q is not allowed on resource %q", operation, action.TargetResource))
	}

	requiredScopes := unique(append(append(copyStrings(resource.Scopes), capability.RequiredScopes...), resourceGrant.RequiredScopes...))
	missing := missingScopes(authority.Scopes, requiredScopes)
	if len(missing) > 0 {
		return deny("scope.mismatch", fmt.Sprintf("delegated authority is missing required scopes: %v", missing))
	}

	constraints := mergeConstraints(capability.Constraints, resourceGrant.Constraints)
	if action.Destination != nil && action.Destination.External && constraints.NetworkEgress != "allow" {
		return deny("constraint.network_egress_denied", "the authorization grant denies external network egress")
	}
	if requestsSecret(action) && constraints.SecretAccess != "allow" {
		return deny("constraint.secret_access_denied", "the authorization grant denies secret access")
	}
	if models.IsWriteOperation(operation) && constraints.WriteAccess != "allow" {
		return deny("constraint.write_access_denied", "the authorization grant is read-only")
	}
	if sideEffect := strings.TrimSpace(action.SideEffect); sideEffect != "" && sideEffect != "none" && sideEffect != "read_only" && !contains(constraints.AllowedSideEffects, sideEffect) {
		return deny("constraint.side_effect_not_granted", fmt.Sprintf("side effect %q is not allowed", sideEffect))
	}
	if constraints.MaxBytes > 0 && action.Bytes > constraints.MaxBytes {
		return deny("constraint.max_bytes_exceeded", fmt.Sprintf("requested byte count %d exceeds grant limit %d", action.Bytes, constraints.MaxBytes))
	}

	route := capability.Route
	if route == "" {
		route = models.RouteAllow
	}
	status := models.AuthorizationStatusAuthorized
	authorized := true
	switch route {
	case models.RouteDeny:
		status = models.AuthorizationStatusDenied
		authorized = false
	case models.RouteEscalate:
		status = models.AuthorizationStatusRequiresApproval
		authorized = false
	}
	return models.PolicyDecision{
		Authorized: authorized,
		Status:     status,
		Route:      route,
		Reasons: []string{
			"principal, workload, delegated scopes, capability, tool, resource, operation, and constraints match",
		},
		Rules: []string{"identity.agent_and_workload_match", "delegation.scopes_match", "authorization.explicit_grant"},
		Grant: &models.MatchedAuthorizationGrant{
			AgentID: agentIdentity.AgentID, WorkloadID: agentIdentity.WorkloadID,
			Capability: action.Capability, Tool: matchedTool, Resource: action.TargetResource,
			AllowedOperations: copyStrings(resourceGrant.AllowedOperations), RequiredScopes: requiredScopes,
			Constraints: constraints,
		},
	}
}

func deny(rule, reason string) models.PolicyDecision {
	return models.PolicyDecision{Authorized: false, Status: models.AuthorizationStatusDenied, Route: models.RouteDeny, Reasons: []string{reason}, Rules: []string{rule}}
}

func legacyGrant(resourceID string, resource models.ResourcePolicy) models.CapabilityGrant {
	return models.CapabilityGrant{
		AllowedTools: []string{"legacy-unspecified"},
		Resources: map[string]models.ResourceGrant{
			resourceID: {AllowedOperations: []string{"legacy-unspecified"}, RequiredScopes: copyStrings(resource.Scopes)},
		},
		Constraints: models.AuthorizationConstraints{NetworkEgress: "deny", SecretAccess: "deny", WriteAccess: "deny"},
	}
}

func mergeConstraints(base, resource models.AuthorizationConstraints) models.AuthorizationConstraints {
	result := base
	if result.NetworkEgress == "" {
		result.NetworkEgress = "deny"
	}
	if result.SecretAccess == "" {
		result.SecretAccess = "deny"
	}
	if result.WriteAccess == "" {
		result.WriteAccess = "deny"
	}
	if result.AllowedSideEffects == nil {
		result.AllowedSideEffects = []string{}
	}
	if resource.NetworkEgress != "" {
		result.NetworkEgress = resource.NetworkEgress
	}
	if resource.SecretAccess != "" {
		result.SecretAccess = resource.SecretAccess
	}
	if resource.WriteAccess != "" {
		result.WriteAccess = resource.WriteAccess
	}
	if resource.AllowedSideEffects != nil {
		result.AllowedSideEffects = copyStrings(resource.AllowedSideEffects)
	}
	if resource.MaxBytes > 0 {
		result.MaxBytes = resource.MaxBytes
	}
	if resource.MaxDurationMS > 0 {
		result.MaxDurationMS = resource.MaxDurationMS
	}
	if resource.ExecutorProfile != "" {
		result.ExecutorProfile = resource.ExecutorProfile
	}
	return result
}

func requestsSecret(action models.ActionRequest) bool {
	value := strings.ToLower(action.SideEffect + " " + action.Capability + " " + action.TargetResource)
	return strings.Contains(value, "secret") || strings.Contains(value, "credential")
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func missingScopes(actual, required []string) []string {
	missing := []string{}
	for _, scope := range required {
		if !contains(actual, scope) {
			missing = append(missing, scope)
		}
	}
	return missing
}

func unique(items []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func copyStrings(items []string) []string {
	return append([]string(nil), items...)
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if item != "" {
			return item
		}
	}
	return ""
}
