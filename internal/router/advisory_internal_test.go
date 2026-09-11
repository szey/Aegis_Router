package router

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"agent-governance-gateway/internal/audit"
	"agent-governance-gateway/internal/config"
	"agent-governance-gateway/internal/intake"
	"agent-governance-gateway/internal/models"
)

func TestDisabledAdvisoryEnginesDoNotChangeAuthorization(t *testing.T) {
	cfg, err := config.Load("../../configs/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 2, 0, 0, 0, time.UTC)
	newTestRouter := func() *Router {
		store, storeErr := audit.NewStore("")
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		return NewWithClock(cfg, store, func() time.Time { return now })
	}
	request := models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "finance-agent", WorkloadID: "finance-workload-v1"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("b", 64), Scopes: []string{"payment.transfer"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "payment.send"},
		Action: models.ActionRequest{
			Capability: "payment_transfer", Operation: "transfer", TargetResource: "account-123",
			Arguments:  json.RawMessage(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`),
			SideEffect: "financial_transaction",
		},
	}
	seal := func() intake.Authorization {
		authorization, sealErr := intake.NewTrustedAuthorization(request, intake.IdentityContext{
			Principal: request.Principal, Agent: request.Agent, DelegatedAuthority: request.Authority,
			WorkloadBinding: intake.WorkloadBinding{KeyID: "advisory-test-workload-key", PublicKeyThumbprint: "sha256:" + strings.Repeat("e", 64)},
		}, "router-internal-test", now)
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		return authorization
	}

	withAdvisory := newTestRouter()
	withResult, err := withAdvisory.AuthorizeTrustedAction(seal())
	if err != nil {
		t.Fatal(err)
	}
	withoutAdvisory := newTestRouter()
	withoutAdvisory.risk = nil
	withoutAdvisory.detection = nil
	withoutResult, err := withoutAdvisory.AuthorizeTrustedAction(seal())
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(withResult.Decision.PolicyDecision, withoutResult.Decision.PolicyDecision) ||
		!reflect.DeepEqual(withResult.Decision.Obligations, withoutResult.Decision.Obligations) ||
		(withResult.Permit == nil) != (withoutResult.Permit == nil) {
		t.Fatalf("disabling advisory engines changed authorization: with=%#v without=%#v", withResult.Decision, withoutResult.Decision)
	}
	if withResult.Decision.AuthorizationEnvelope.ActionDigest != withoutResult.Decision.AuthorizationEnvelope.ActionDigest {
		t.Fatal("disabling advisory engines changed the bound action")
	}
	if withoutResult.Decision.AdvisorySignals.RiskAssessment.Level != "not_evaluated" ||
		!withoutResult.Decision.AdvisorySignals.RiskAssessment.AdvisoryOnly {
		t.Fatalf("disabled advisory state is not explicit: %#v", withoutResult.Decision.AdvisorySignals)
	}
}
