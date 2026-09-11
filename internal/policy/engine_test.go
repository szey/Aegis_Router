package policy_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/config"
	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/policy"
)

func TestUnknownAgentFailsClosed(t *testing.T) {
	req := safeRequest()
	req.Agent.AgentID = "unregistered-agent"
	assertDeniedBy(t, evaluate(t, req), "identity.unknown_agent")
}

func TestUnknownWorkloadFailsClosed(t *testing.T) {
	req := safeRequest()
	req.Agent.WorkloadID = "unregistered-workload"
	assertDeniedBy(t, evaluate(t, req), "identity.workload_not_granted")
}

func TestMissingDelegatedScopeFailsClosed(t *testing.T) {
	req := safeRequest()
	req.Authority.Scopes = nil
	assertDeniedBy(t, evaluate(t, req), "scope.mismatch")
}

func TestUngrantedCapabilityFailsClosed(t *testing.T) {
	req := safeRequest()
	req.Action.Capability = "read_finance_data"
	req.Action.TargetResource = "finance_data"
	req.Action.Operation = "read"
	req.Tool.Name = "finance_reader"
	assertDeniedBy(t, evaluate(t, req), "capability.not_granted")
}

func TestToolNotAllowedFailsClosed(t *testing.T) {
	req := safeRequest()
	req.Tool.Name = "shell.exec"
	assertDeniedBy(t, evaluate(t, req), "tool.not_granted")
}

func TestResourceOperationNotAllowedFailsClosed(t *testing.T) {
	req := safeRequest()
	req.Action.Operation = "write"
	assertDeniedBy(t, evaluate(t, req), "resource.operation_not_granted")
}

func TestSafeRequestMatchesExplicitGrant(t *testing.T) {
	decision := evaluate(t, safeRequest())
	if !decision.Authorized || decision.Route != models.RouteAllow || decision.Grant == nil {
		t.Fatalf("decision = %#v, want authorized allow with grant", decision)
	}
	if decision.Grant.Tool != "coder" || decision.Grant.Resource != "public_workspace" {
		t.Fatalf("matched grant = %#v", decision.Grant)
	}
}

func TestLegacyCompatibilityPolicyEvaluationRemainsAvailable(t *testing.T) {
	request := models.Request{
		UserID: "user-01", AgentID: "coder-agent", TokenScopes: []string{"code.read"},
		RequestedCapability: "generate_code", TargetResource: "public_workspace",
	}
	decision := evaluate(t, request)
	if !decision.Authorized || decision.Grant == nil || decision.Grant.WorkloadID != "coder-agent" || decision.Grant.Tool != "coder" {
		t.Fatalf("legacy compatibility policy decision = %#v", decision)
	}
}

func TestClaimedIntentDoesNotGrantAuthority(t *testing.T) {
	req := safeRequest()
	req.Action.Capability = "read_finance_data"
	req.Action.TargetResource = "finance_data"
	req.Action.Operation = "read"
	req.Tool.Name = "finance_reader"
	req.ClaimedIntent = "administrator_approved"
	assertDeniedBy(t, evaluate(t, req), "capability.not_granted")
}

func TestExpiredDelegatedAuthorityFailsClosed(t *testing.T) {
	req := safeRequest()
	expired := time.Now().Add(-time.Minute)
	req.Authority.ExpiresAt = &expired
	assertDeniedBy(t, evaluate(t, req), "delegation.expired")
}

func evaluate(t *testing.T, req models.Request) models.PolicyDecision {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return policy.New(cfg).Evaluate(req)
}

func safeRequest() models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "coder-agent", WorkloadID: "coder-workload-v1"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Scopes:                []string{"code.read"}, Subject: "user-01",
		},
		Tool:   models.ToolContext{Name: "coder"},
		Action: models.ActionRequest{Capability: "generate_code", Operation: "generate", TargetResource: "public_workspace", SideEffect: "none"},
	}
}

func assertDeniedBy(t *testing.T, decision models.PolicyDecision, rule string) {
	t.Helper()
	if decision.Authorized || decision.Route != models.RouteDeny {
		t.Fatalf("decision = %#v, want deterministic deny", decision)
	}
	if len(decision.Rules) != 1 || decision.Rules[0] != rule {
		t.Fatalf("rules = %v, want [%s]", decision.Rules, rule)
	}
}
