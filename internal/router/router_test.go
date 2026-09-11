package router_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"agent-governance-gateway/internal/audit"
	"agent-governance-gateway/internal/canonicalaction"
	"agent-governance-gateway/internal/config"
	"agent-governance-gateway/internal/intake"
	"agent-governance-gateway/internal/models"
	"agent-governance-gateway/internal/permit"
	"agent-governance-gateway/internal/router"
	"agent-governance-gateway/internal/scenario"
)

func TestDemoScenariosHaveExpectedDispatch(t *testing.T) {
	cfg := loadConfig(t)
	scenarios, err := scenario.LoadDirectory(filepath.Join("..", "..", "examples"))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := audit.NewStore("")
	r := router.New(cfg, store)

	for _, item := range scenarios {
		item := item
		t.Run(item.ID, func(t *testing.T) {
			record, err := authorizeSyntheticRecord(t, r, item.Request)
			if err != nil {
				t.Fatal(err)
			}
			if record.DispatchDecision.Route != item.Expected {
				t.Fatalf("dispatch = %q, want %q; policy=%#v risk=%#v", record.DispatchDecision.Route, item.Expected, record.PolicyDecision, record.RiskAssessment)
			}
			if record.RequestID == "" {
				t.Fatal("request ID was not generated")
			}
			if record.AuthorizationContext == nil || record.AuthorizationContext.Source != "server_owned_fixture" || record.AuthorizationContext.Assurance != "simulated_demo" {
				t.Fatalf("synthetic demo provenance = %#v", record.AuthorizationContext)
			}
		})
	}

	if got := len(store.Recent(20)); got != len(scenarios) {
		t.Fatalf("stored %d audit records, want %d", got, len(scenarios))
	}
}

func TestSafeRequestAllowsAndIssuesLeastPrivilegePermit(t *testing.T) {
	r, store, now := testRouter(t)
	req := safeRequest()
	req.RequestedAction = "do not persist this prompt-like text"
	record, err := authorizeRecord(t, r, req)
	if err != nil {
		t.Fatal(err)
	}
	if !record.PolicyDecision.Authorized || record.PolicyDecision.Route != models.RouteAllow || record.DispatchDecision.Route != models.RouteAllow {
		t.Fatalf("record = %#v", record)
	}
	permit := record.AuthorizationEnvelope
	if permit == nil {
		t.Fatal("allowed request did not receive a permit")
	}
	if permit.AllowedCapability != "generate_code" || permit.AllowedTool != "coder" || permit.AllowedResource != "public_workspace" {
		t.Fatalf("permit = %#v", permit)
	}
	if len(permit.AllowedOperations) != 1 || permit.AllowedOperations[0] != "generate" {
		t.Fatalf("permit operations = %v", permit.AllowedOperations)
	}
	if permit.ExpiresAt.Sub(now) != 30*time.Second {
		t.Fatalf("permit expiry = %s, want the policy max duration", permit.ExpiresAt)
	}
	if record.Request.RequestedAction != "" {
		t.Fatal("prompt-like legacy requested_action leaked into audit")
	}
	if got, ok := store.Get(record.RequestID); !ok || got.AuthorizationEnvelope == nil {
		t.Fatal("authorization chain was not stored")
	}
}

func TestSignedPermitCredentialStaysOutsideAuditAndIsSingleUse(t *testing.T) {
	r, store, _ := testRouter(t)
	req := paymentSemanticRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
	result, err := authorizeAction(t, r, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Permit == nil || result.Permit.PermitToken == "" {
		t.Fatal("authorized action did not receive a permit credential")
	}
	stored, ok := store.Get(result.Decision.RequestID)
	if !ok {
		t.Fatal("authorization audit was not stored")
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(result.Permit.PermitToken)) {
		t.Fatal("permit token leaked into audit")
	}
	if bytes.Contains(encoded, []byte("merchant-456")) {
		t.Fatal("raw action arguments leaked into audit")
	}
	first, err := r.VerifyRequestAndConsume(result.Permit.PermitToken, req)
	if err != nil || !first.Verified || first.Outcome != "VERIFIED" {
		t.Fatalf("first verification = %#v, err = %v", first, err)
	}
	second, err := r.VerifyRequestAndConsume(result.Permit.PermitToken, req)
	if err != nil || second.Verified || second.Outcome != "REPLAYED" {
		t.Fatalf("second verification = %#v, err = %v", second, err)
	}
}

func TestRevokedSignedPermitIsRejected(t *testing.T) {
	r, _, _ := testRouter(t)
	req := paymentSemanticRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
	result, err := authorizeAction(t, r, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.RevokePermit(result.Permit.PermitID); err != nil {
		t.Fatal(err)
	}
	verification, err := r.VerifyRequestAndConsume(result.Permit.PermitToken, req)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Verified || verification.Outcome != "REVOKED" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestValidationRejectsRawDelegatedCredential(t *testing.T) {
	req := safeRequest()
	req.Authority.CredentialFingerprint = "Bearer-real-secret-must-never-enter-audit"
	if err := router.Validate(req); err == nil {
		t.Fatal("raw delegated credential was accepted as a fingerprint")
	}
}

func TestRejectedRawDelegatedCredentialNeverReachesAudit(t *testing.T) {
	marker := "Bearer-secret-delegated-token-marker"
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(loadConfig(t), store)
	request := paymentSemanticRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
	request.Authority.CredentialFingerprint = marker
	authorization := trustedAuthorization(t, request)
	if _, err := r.AuthorizeTrustedAction(authorization); err == nil {
		t.Fatal("raw delegated credential was accepted")
	}
	encoded, err := json.Marshal(store.Recent(100))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(marker)) {
		t.Fatal("raw delegated credential reached the in-memory audit")
	}
	if persisted, err := os.ReadFile(path); err == nil && bytes.Contains(persisted, []byte(marker)) {
		t.Fatal("raw delegated credential reached the persisted audit")
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestDigestShapedDelegatedInputIsReboundBeforeAudit(t *testing.T) {
	marker := strings.Repeat("0123456789abcdef", 4)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(loadConfig(t), store)
	request := safeRequest()
	request.Authority.CredentialFingerprint = marker
	result, err := authorizeAction(t, r, request)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := canonicalaction.BindDelegatedAuthorityFingerprint(marker)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.Request.Authority.CredentialFingerprint != bound || result.Decision.AuthorizationEnvelope.DelegatedCredentialFingerprint != bound {
		t.Fatalf("delegated fingerprint was not rebound: %#v", result.Decision)
	}
	encoded, err := json.Marshal(store.Recent(100))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(marker)) {
		t.Fatal("digest-shaped delegated input reached the in-memory audit verbatim")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted, []byte(marker)) {
		t.Fatal("digest-shaped delegated input reached the persisted audit verbatim")
	}
}

func TestPolicyDenialIsIndependentOfAdvisoryRiskLevel(t *testing.T) {
	tests := []struct {
		name      string
		request   models.Request
		riskLevel string
	}{
		{
			name: "low risk",
			request: func() models.Request {
				req := safeRequest()
				req.Action.Capability = "not_granted"
				return req
			}(),
			riskLevel: "low",
		},
		{
			name: "high risk",
			request: func() models.Request {
				req := safeRequest()
				req.Action = models.ActionRequest{Capability: "read_finance_data", Operation: "read", TargetResource: "finance_data", SideEffect: "read_only"}
				req.Tool.Name = "finance_reader"
				return req
			}(),
			riskLevel: "high",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, _, _ := testRouter(t)
			record, err := authorizeRecord(t, r, test.request)
			if err != nil {
				t.Fatal(err)
			}
			if record.PolicyDecision.Authorized || record.PolicyDecision.Route != models.RouteDeny || record.AuthorizationStatus != models.AuthorizationStatusDenied {
				t.Fatalf("authorization failure was overridden: %#v", record)
			}
			if record.AuthorizationEnvelope != nil || record.AdvisorySignals.RiskAssessment.Level != test.riskLevel {
				t.Fatalf("denial/diagnostic mismatch: %#v", record)
			}
		})
	}
}

func TestHighRiskRemainsAdvisoryAndCannotAddPermitObligations(t *testing.T) {
	r, _, _ := testRouter(t)
	req := safeRequest()
	req.Agent = models.AgentIdentity{AgentID: "finance-agent", WorkloadID: "finance-workload-v1"}
	req.Authority.Scopes = []string{"finance.read"}
	req.Tool.Name = "finance_reader"
	req.Action = models.ActionRequest{Capability: "read_finance_data", Operation: "read", TargetResource: "finance_data", SideEffect: "read_only"}
	record, err := authorizeRecord(t, r, req)
	if err != nil {
		t.Fatal(err)
	}
	if !record.PolicyDecision.Authorized || record.PolicyDecision.Route != models.RouteAllow {
		t.Fatalf("policy decision = %#v, want explicit authorization", record.PolicyDecision)
	}
	if record.AdvisorySignals.RiskAssessment.Level != "high" || !record.AdvisorySignals.RiskAssessment.AdvisoryOnly || record.AuthorizationEnvelope == nil {
		t.Fatalf("advisory/permit = %#v / %#v", record.AdvisorySignals, record.AuthorizationEnvelope)
	}
	if record.AuthorizationEnvelope.Obligations.EnhancedAuditRequired || record.AuthorizationEnvelope.Obligations.IsolationRequired {
		t.Fatalf("advisory risk changed signed obligations: %#v", record.AuthorizationEnvelope.Obligations)
	}
	if record.DispatchDecision.ExecutorInvoked {
		t.Fatalf("authorization claimed execution: %#v", record.DispatchDecision)
	}
}

func TestRuntimeEventInsidePermitUpdatesAudit(t *testing.T) {
	r, store, _ := testRouter(t)
	record, err := authorizeRecord(t, r, safeRequest())
	if err != nil {
		t.Fatal(err)
	}
	event := eventFor(record)
	evaluation, err := r.IngestRuntimeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if !evaluation.Accepted || !evaluation.WithinEnvelope {
		t.Fatalf("evaluation = %#v", evaluation)
	}
	updated, _ := store.Get(record.RequestID)
	if len(updated.RuntimeObservation.Events) != 1 || updated.RuntimeObservation.Coverage.ToolEvents != "adapter_reported" {
		t.Fatalf("runtime observation = %#v", updated.RuntimeObservation)
	}
}

func TestTerminatingBoundaryViolationRevokesPermit(t *testing.T) {
	r, store, _ := testRouter(t)
	record, _ := authorizeRecord(t, r, safeRequest())
	event := eventFor(record)
	event.EventID = "event-secret"
	event.SecretAccess = true
	first, err := r.IngestRuntimeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if first.Verdict != "AUTHORIZATION_BOUNDARY_VIOLATION" || !first.Terminated {
		t.Fatalf("first evaluation = %#v", first)
	}
	event.EventID = "event-after-termination"
	second, err := r.IngestRuntimeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if second.Accepted || !hasViolation(second, "runtime.permit_unknown") {
		t.Fatalf("revoked permit accepted another event: %#v", second)
	}
	updated, _ := store.Get(record.RequestID)
	if updated.FinalVerdict != "AUTHORIZATION_BOUNDARY_VIOLATION" {
		t.Fatalf("final verdict = %q", updated.FinalVerdict)
	}
}

func TestRejectedBoundEventRevokesPermit(t *testing.T) {
	r, _, _ := testRouter(t)
	record, _ := authorizeRecord(t, r, safeRequest())
	event := eventFor(record)
	event.AgentID = "other-agent"
	first, _ := r.IngestRuntimeEvent(event)
	if first.Accepted || !hasViolation(first, "runtime.agent_binding_mismatch") {
		t.Fatalf("binding mismatch = %#v", first)
	}
	event.AgentID = record.AuthorizationEnvelope.AgentID
	event.EventID = "event-after-rejection"
	second, _ := r.IngestRuntimeEvent(event)
	if second.Accepted || !hasViolation(second, "runtime.permit_unknown") {
		t.Fatalf("permit was not revoked: %#v", second)
	}
}

func TestCompletionRevokesPermit(t *testing.T) {
	r, _, now := testRouter(t)
	record, _ := authorizeRecord(t, r, safeRequest())
	completed, err := r.CompleteExecution(models.ExecutionCompletion{
		RequestID: record.RequestID, PermitID: record.AuthorizationEnvelope.PermitID, Status: "completed", CompletedAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.FinalVerdict != "COMPLETED_WITHOUT_BOUNDARY_VERIFICATION" {
		t.Fatalf("completion = %#v", completed)
	}
	event := eventFor(record)
	event.EventID = "event-after-completion"
	evaluation, _ := r.IngestRuntimeEvent(event)
	if evaluation.Accepted || !hasViolation(evaluation, "runtime.permit_unknown") {
		t.Fatalf("completed permit accepted event: %#v", evaluation)
	}
}

func TestCompletionAfterPermitExpiryIsAudited(t *testing.T) {
	store, err := audit.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	current := time.Date(2026, 9, 3, 2, 0, 0, 0, time.UTC)
	r := router.NewWithClock(loadConfig(t), store, func() time.Time { return current })
	record, err := authorizeRecord(t, r, safeRequest())
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(31 * time.Second)
	completed, err := r.CompleteExecution(models.ExecutionCompletion{
		RequestID: record.RequestID, PermitID: record.AuthorizationEnvelope.PermitID, Status: "completed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.FinalVerdict != "PERMIT_EXPIRED" || len(completed.RuntimeObservation.AuthorizationViolations) != 1 {
		t.Fatalf("expired completion = %#v", completed)
	}
}

func TestValidationMakesClaimedIntentOptional(t *testing.T) {
	req := safeRequest()
	req.ClaimedIntent = ""
	if err := router.Validate(req); err != nil {
		t.Fatalf("optional claimed_intent rejected: %v", err)
	}
}

func TestValidationRejectsRawPathInMetadata(t *testing.T) {
	req := safeRequest()
	req.DataAccess = &models.DataAccess{Operation: "read", PathClass: `C:\\Users\\person\\secret.txt`, Protected: true}
	if err := router.Validate(req); err == nil {
		t.Fatal("expected raw path metadata to be rejected")
	}
}

func TestLegacyValidationRejectsRawPathInAuditFields(t *testing.T) {
	req := models.Request{
		UserID: "user-01", AgentID: "coder-agent", TokenScopes: []string{"code.read"},
		RequestedCapability: "read_safe_files", TargetResource: `C:\\Users\\someone\\secrets.txt`,
	}
	if err := router.Validate(req); err == nil {
		t.Fatal("legacy request accepted a raw local path as target_resource")
	}
}

func TestPublicRequestShapeRejectsSimulatedActions(t *testing.T) {
	decoder := json.NewDecoder(bytes.NewBufferString(`{
		"principal":{"principal_id":"user-01","principal_type":"human"},
		"simulated_actions":["read_secret"]
	}`))
	decoder.DisallowUnknownFields()
	var req models.Request
	if err := decoder.Decode(&req); err == nil {
		t.Fatal("simulated_actions unexpectedly remained in the public request model")
	}
}

func TestRouterExposesNoRawRequestAuthorizationShortcut(t *testing.T) {
	routerType := reflect.TypeOf((*router.Router)(nil))
	for _, method := range []string{"AuthorizeAction", "Authorize", "Process"} {
		if _, exists := routerType.MethodByName(method); exists {
			t.Fatalf("Router still exposes raw models.Request authorization method %s", method)
		}
	}
}

func TestRouterRequiresSealedTrustedAuthorization(t *testing.T) {
	r, _, _ := testRouter(t)
	if _, err := r.AuthorizeTrustedAction(intake.Authorization{}); err == nil {
		t.Fatal("zero-value unsealed authorization was accepted")
	}
	result, err := r.AuthorizeTrustedAction(trustedAuthorization(t, paymentSemanticRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)))
	if err != nil || result.Permit == nil {
		t.Fatalf("explicitly sealed in-process authorization failed: result=%#v err=%v", result, err)
	}
}

func TestTrustedExecutionRejectsSealedLegacyAuthorizationBeforePermitIssuance(t *testing.T) {
	r, store, _ := testRouter(t)
	authorization := sealedLegacyAuthorization(t, "finance-workload-v1")
	result, err := r.AuthorizeTrustedAction(authorization)
	if !errors.Is(err, router.ErrStructuredExecutionContextRequired) {
		t.Fatalf("error = %v, want structured-context rejection", err)
	}
	if result.Permit != nil || len(r.ListPermits()) != 0 || len(store.Recent(10)) != 0 {
		t.Fatalf("legacy authorization produced execution evidence: result=%#v permits=%d audits=%d", result, len(r.ListPermits()), len(store.Recent(10)))
	}
}

func TestLegacyIntakeCannotExploitAgentDerivedWorkloadFallback(t *testing.T) {
	r, _, _ := testRouter(t)
	authorization := sealedLegacyAuthorization(t, "attacker-workload")
	degraded := authorization.Request()
	if degraded.UsesStructuredContext() || degraded.EffectiveAgent().WorkloadID != "finance-agent" {
		t.Fatalf("test did not reproduce legacy workload degradation: %#v", degraded)
	}
	result, err := r.AuthorizeTrustedAction(authorization)
	if !errors.Is(err, router.ErrStructuredExecutionContextRequired) || result.Permit != nil || len(r.ListPermits()) != 0 {
		t.Fatalf("agent-derived workload fallback reached execution issuance: result=%#v err=%v", result, err)
	}
}

func TestLegacyIntakeCannotLoseDelegationFingerprintIntoPermit(t *testing.T) {
	r, _, _ := testRouter(t)
	authorization := sealedLegacyAuthorization(t, "finance-workload-v1")
	degraded := authorization.Request()
	if degraded.EffectiveAuthority().CredentialFingerprint != "" {
		t.Fatalf("test did not reproduce legacy fingerprint loss: %#v", degraded.EffectiveAuthority())
	}
	result, err := r.AuthorizeTrustedAction(authorization)
	if !errors.Is(err, router.ErrStructuredExecutionContextRequired) || result.Permit != nil || len(r.ListPermits()) != 0 {
		t.Fatalf("fingerprint-free legacy context reached execution issuance: result=%#v err=%v", result, err)
	}
}

func TestRiskAndDetectionConfigurationCannotChangeAuthorization(t *testing.T) {
	baseline := loadConfig(t)
	adversarial := loadConfig(t)
	resource := adversarial.Resources["public_workspace"]
	resource.Sensitivity = "critical"
	adversarial.Resources["public_workspace"] = resource
	adversarial.SensitiveActions = append(adversarial.SensitiveActions, "generate_code")
	adversarial.SuspiciousActions = append(adversarial.SuspiciousActions, "generate_code")
	adversarial.SessionControls.CumulativeRiskLimit = 1

	newRouter := func(cfg models.PolicyConfig) *router.Router {
		store, err := audit.NewStore("")
		if err != nil {
			t.Fatal(err)
		}
		return router.NewWithClock(cfg, store, func() time.Time {
			return time.Date(2026, 9, 3, 2, 0, 0, 0, time.UTC)
		})
	}
	first, err := newRouter(baseline).AuthorizeTrustedAction(trustedAuthorization(t, safeRequest()))
	if err != nil {
		t.Fatal(err)
	}
	second, err := newRouter(adversarial).AuthorizeTrustedAction(trustedAuthorization(t, safeRequest()))
	if err != nil {
		t.Fatal(err)
	}
	if first.Decision.AuthorizationStatus != second.Decision.AuthorizationStatus ||
		(first.Permit == nil) != (second.Permit == nil) ||
		!reflect.DeepEqual(first.Decision.Obligations, second.Decision.Obligations) {
		t.Fatalf("advisory configuration changed authorization: first=%#v second=%#v", first.Decision, second.Decision)
	}
	if first.Decision.AdvisorySignals.RiskAssessment.Score == second.Decision.AdvisorySignals.RiskAssessment.Score {
		t.Fatal("test setup did not actually change advisory risk output")
	}
}

func TestDetectionFindingsCannotCreateAuthorizationGrant(t *testing.T) {
	r, _, _ := testRouter(t)
	request := safeRequest()
	request.Agent.AgentID = "unknown-agent"
	request.Agent.WorkloadID = "unknown-workload"
	request.InputSources = []models.InputSource{{
		EventID: "retrieval-1", Kind: "retrieval", Trust: "untrusted",
		RiskSignals: []string{"policy_override"},
	}}
	result, err := authorizeAction(t, r, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.AuthorizationStatus != models.AuthorizationStatusDenied || result.Permit != nil {
		t.Fatalf("detection finding created a grant: %#v", result)
	}
	if len(result.Decision.AdvisorySignals.DetectionFindings) == 0 {
		t.Fatal("test setup did not produce advisory detection findings")
	}
}

func TestLegacyRouteProjectionDoesNotGatePermitIssuance(t *testing.T) {
	tests := []struct {
		name       string
		request    models.Request
		obligation func(models.ExecutionObligations) bool
	}{
		{
			name: "restrict",
			request: func() models.Request {
				req := safeRequest()
				req.Tool.Name = "shell.exec"
				req.Action = models.ActionRequest{Capability: "run_limited_commands", Operation: "execute", TargetResource: "public_workspace", SideEffect: "process_execution"}
				return req
			}(),
			obligation: func(value models.ExecutionObligations) bool { return value.EnhancedAuditRequired },
		},
		{
			name: "sandbox",
			request: func() models.Request {
				req := safeRequest()
				req.Authority.Scopes = []string{"config.read"}
				req.Tool.Name = "config_reader"
				req.Action = models.ActionRequest{Capability: "read_config", Operation: "read", TargetResource: "protected_config", SideEffect: "read_only"}
				return req
			}(),
			obligation: func(value models.ExecutionObligations) bool { return value.IsolationRequired },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, _, _ := testRouter(t)
			result, err := authorizeAction(t, r, test.request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Permit == nil || result.Decision.AuthorizationStatus != models.AuthorizationStatusAuthorized {
				t.Fatalf("deterministic grant did not issue a Permit: %#v", result)
			}
			if !result.Decision.DispatchDecision.LegacyCompatibilityOnly || !test.obligation(result.Decision.Obligations) {
				t.Fatalf("legacy projection or policy obligation missing: %#v", result.Decision)
			}
		})
	}
}

func trustedAuthorization(t *testing.T, request models.Request) intake.Authorization {
	t.Helper()
	authorization, err := intake.NewTrustedAuthorization(request, intake.IdentityContext{
		Principal: request.EffectivePrincipal(), Agent: request.EffectiveAgent(),
		DelegatedAuthority: request.EffectiveAuthority(),
		WorkloadBinding:    intake.WorkloadBinding{KeyID: "router-test-workload-key", PublicKeyThumbprint: "sha256:" + strings.Repeat("e", 64)},
	}, "router-test-trusted-integration", time.Date(2026, 9, 3, 1, 59, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func sealedLegacyAuthorization(t *testing.T, trustedWorkload string) intake.Authorization {
	t.Helper()
	proposal := models.Request{
		UserID: "forged-user", AgentID: "finance-agent", TokenScopes: []string{"payment.transfer"},
		RequestedCapability: "payment_transfer", TargetResource: "account-123",
	}
	authorization, err := intake.NewTrustedAuthorization(proposal, intake.IdentityContext{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "finance-agent", WorkloadID: trustedWorkload},
		DelegatedAuthority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("b", 64), Scopes: []string{"payment.transfer"}, Subject: "user-01",
		},
		WorkloadBinding: intake.WorkloadBinding{KeyID: "router-test-workload-key", PublicKeyThumbprint: "sha256:" + strings.Repeat("e", 64)},
	}, "router-test-trusted-integration", time.Date(2026, 9, 3, 1, 59, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func authorizeAction(t *testing.T, r *router.Router, request models.Request) (models.ActionAuthorizationResponse, error) {
	t.Helper()
	tool := request.EffectiveTool().Name
	if tool == "" {
		tool = request.EffectiveTool().ToolID
	}
	if tool != "payment.send" && tool != "workspace.write" {
		return r.AuthorizeSyntheticDemoAction(request, 0)
	}
	return r.AuthorizeTrustedAction(trustedAuthorization(t, request))
}

func authorizeRecord(t *testing.T, r *router.Router, request models.Request) (models.AuditRecord, error) {
	t.Helper()
	result, err := authorizeAction(t, r, request)
	return result.Decision, err
}

func authorizeSyntheticRecord(t *testing.T, r *router.Router, request models.Request) (models.AuditRecord, error) {
	t.Helper()
	result, err := r.AuthorizeSyntheticDemoAction(request, 0)
	return result.Decision, err
}

func TestSyntheticDemoPermitCannotReachExecutionVerifier(t *testing.T) {
	r, _, _ := testRouter(t)
	request := paymentSemanticRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
	authorized, err := r.AuthorizeSyntheticDemoAction(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Permit == nil {
		t.Fatal("synthetic demo authorization did not issue a permit")
	}

	verification, err := r.VerifyRequestAndConsume(authorized.Permit.PermitToken, request)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Verified {
		t.Fatalf("synthetic demo permit crossed the normal execution boundary: %#v", verification)
	}
	if verification.Outcome != "WRONG_PERMIT_CLASS" || verification.PermitClass != "simulation" {
		t.Fatalf("synthetic demo rejection did not identify its purpose: %#v", verification)
	}
	record, ok := r.GetPermit(authorized.Permit.PermitID)
	if !ok || record.State != permit.StateIssued {
		t.Fatalf("wrong-purpose attempt consumed permit: %#v", record)
	}
	accepted, err := r.VerifySyntheticDemoRequest(authorized.Permit.PermitToken, request)
	if err != nil || !accepted.Verified {
		t.Fatalf("simulation permit was not reusable at its intended boundary: result=%#v err=%v", accepted, err)
	}
}

func TestPaymentSendV1SemanticPolicyControlsPermitIssuance(t *testing.T) {
	t.Run("valid boundary amount", func(t *testing.T) {
		r, _, _ := testRouter(t)
		request := paymentSemanticRequest(`{"recipient":"merchant-456","currency":"USD","amount_minor":10000}`)
		authorized, err := authorizeAction(t, r, request)
		if err != nil {
			t.Fatal(err)
		}
		if authorized.Permit == nil || authorized.Permit.ProfileID != "payment.send/v1" || authorized.Permit.Audience != "mcp://local-payment-sandbox" {
			t.Fatalf("payment permit missing server bindings: %#v", authorized)
		}
		verification, err := r.VerifyRequestAndConsume(authorized.Permit.PermitToken, request)
		if err != nil || !verification.Verified {
			t.Fatalf("valid normalized payment did not verify: result=%#v err=%v", verification, err)
		}
	})

	tests := []struct {
		name            string
		mutate          func(*models.Request)
		code            string
		validationError bool
	}{
		{"amount exceeds limit", func(request *models.Request) {
			request.Action.Arguments = json.RawMessage(`{"amount_minor":10001,"currency":"USD","recipient":"merchant-456"}`)
		}, "PAYMENT_AMOUNT_EXCEEDS_LIMIT", false},
		{"currency denied", func(request *models.Request) {
			request.Action.Arguments = json.RawMessage(`{"amount_minor":100,"currency":"EUR","recipient":"merchant-456"}`)
		}, "PAYMENT_CURRENCY_NOT_ALLOWED", false},
		{"recipient denied", func(request *models.Request) {
			request.Action.Arguments = json.RawMessage(`{"amount_minor":100,"currency":"USD","recipient":"merchant-999"}`)
		}, "PAYMENT_RECIPIENT_NOT_ALLOWED", false},
		{"invalid arguments", func(request *models.Request) {
			request.Action.Arguments = json.RawMessage(`{"amount_minor":"100","currency":"USD","recipient":"merchant-456"}`)
		}, "PAYMENT_ARGUMENTS_INVALID", false},
		{"missing tool cannot use legacy fallback", func(request *models.Request) { request.Tool.Name = "" }, "", true},
		{"missing operation cannot use legacy fallback", func(request *models.Request) { request.Action.Operation = "" }, "", true},
		{"profile conflict", func(request *models.Request) { request.Action.ProfileID = "payment.send/v2" }, "PAYMENT_PROFILE_MISMATCH", false},
		{"audience conflict", func(request *models.Request) { request.Action.Audience = "mcp://attacker" }, "PAYMENT_AUDIENCE_MISMATCH", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, _, _ := testRouter(t)
			request := paymentSemanticRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
			test.mutate(&request)
			result, err := authorizeAction(t, r, request)
			if test.validationError {
				if err == nil || result.Permit != nil {
					t.Fatalf("legacy missing field bypassed validation: result=%#v err=%v", result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Permit != nil || result.Decision.AuthorizationStatus != models.AuthorizationStatusDenied || !containsString(result.Decision.PolicyDecision.Reasons, test.code) {
				t.Fatalf("semantic rejection=%#v, want %s and no permit", result, test.code)
			}
		})
	}

	t.Run("mapping missing", func(t *testing.T) {
		cfg := loadConfig(t)
		cfg.SemanticActions = models.SemanticActionsConfig{}
		store, _ := audit.NewStore("")
		r := router.New(cfg, store)
		result, err := authorizeAction(t, r, paymentSemanticRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`))
		if err != nil {
			t.Fatal(err)
		}
		if result.Permit != nil || !containsString(result.Decision.PolicyDecision.Reasons, "PAYMENT_TOOL_UNMAPPED") {
			t.Fatalf("missing mapping did not fail closed: %#v", result)
		}
	})
}

func TestWorkspaceWriteV1UsesTheSharedExecutionPermitCore(t *testing.T) {
	t.Run("valid semantic action", func(t *testing.T) {
		r, store, _ := testRouter(t)
		request := workspaceSemanticRequest(`{"content":"hello","path":"reports/result.txt"}`)
		authorized, err := authorizeAction(t, r, request)
		if err != nil {
			t.Fatal(err)
		}
		if authorized.Permit == nil || authorized.Permit.ProfileID != "workspace.write/v1" || authorized.Permit.Audience != "mcp://local-workspace-sandbox" {
			t.Fatalf("workspace Permit missing server bindings: %#v", authorized)
		}
		verification, err := r.VerifyRequestAndConsume(authorized.Permit.PermitToken, workspaceSemanticRequest(`{"path":"reports/result.txt","content":"hello"}`))
		if err != nil || !verification.Verified || verification.Outcome != "VERIFIED" {
			t.Fatalf("workspace verification=%#v err=%v", verification, err)
		}
		persisted, _ := json.Marshal(store.Recent(10))
		if bytes.Contains(persisted, []byte("hello")) {
			t.Fatal("raw workspace content entered audit persistence")
		}
	})

	tests := []struct {
		name   string
		mutate func(*models.Request)
		code   string
	}{
		{"invalid path", func(request *models.Request) {
			request.Action.Arguments = json.RawMessage(`{"path":"../secret.txt","content":"hello"}`)
		}, "WORKSPACE_PATH_INVALID"},
		{"oversized content", func(request *models.Request) {
			request.Action.Arguments = json.RawMessage(`{"path":"reports/a.txt","content":"` + strings.Repeat("x", 4097) + `"}`)
		}, "WORKSPACE_CONTENT_TOO_LARGE"},
		{"profile conflict", func(request *models.Request) { request.Action.ProfileID = "workspace.write/v2" }, "WORKSPACE_PROFILE_MISMATCH"},
		{"audience conflict", func(request *models.Request) { request.Action.Audience = "mcp://attacker" }, "WORKSPACE_AUDIENCE_MISMATCH"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, _, _ := testRouter(t)
			request := workspaceSemanticRequest(`{"path":"reports/a.txt","content":"hello"}`)
			test.mutate(&request)
			result, err := authorizeAction(t, r, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Permit != nil || result.Decision.AuthorizationStatus != models.AuthorizationStatusDenied || !containsString(result.Decision.PolicyDecision.Reasons, test.code) {
				t.Fatalf("workspace semantic rejection=%#v, want %s", result, test.code)
			}
		})
	}
}

func TestUnknownSemanticToolCannotReceiveExecutionPermit(t *testing.T) {
	r, _, _ := testRouter(t)
	request := safeRequest()
	result, err := r.AuthorizeTrustedAction(trustedAuthorization(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if result.Permit != nil || result.Decision.AuthorizationStatus != models.AuthorizationStatusDenied ||
		!containsString(result.Decision.PolicyDecision.Reasons, "SEMANTIC_TOOL_UNMAPPED") {
		t.Fatalf("unknown semantic tool did not fail closed: %#v", result)
	}
}

func testRouter(t *testing.T) (*router.Router, *audit.Store, time.Time) {
	t.Helper()
	store, err := audit.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 2, 0, 0, 0, time.UTC)
	return router.NewWithClock(loadConfig(t), store, func() time.Time { return now }), store, now
}

func loadConfig(t *testing.T) models.PolicyConfig {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func safeRequest() models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human", Tenant: "demo", Environment: "local"},
		Agent:     models.AgentIdentity{AgentID: "coder-agent", WorkloadID: "coder-workload-v1", Owner: "engineering", Environment: "demo"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Issuer:                "demo-idp", Scopes: []string{"code.read"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "coder", Provider: "instrumented-demo"},
		Action: models.ActionRequest{
			Capability: "generate_code", Operation: "generate", TargetResource: "public_workspace", SideEffect: "none",
		},
		ClaimedIntent: "code_generation",
	}
}

func paymentSemanticRequest(arguments string) models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human", Environment: "local"},
		Agent:     models.AgentIdentity{AgentID: "finance-agent", WorkloadID: "finance-workload-v1", Environment: "demo"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("b", 64), Issuer: "demo-idp",
			Scopes: []string{"payment.transfer"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "payment.send", Provider: "mcp"},
		Action: models.ActionRequest{
			Capability: "payment_transfer", Operation: "transfer", TargetResource: "account-123",
			Arguments: json.RawMessage(arguments), SideEffect: "financial_transaction",
		},
	}
}

func workspaceSemanticRequest(arguments string) models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human", Environment: "local"},
		Agent:     models.AgentIdentity{AgentID: "workspace-agent", WorkloadID: "workspace-workload-v1", Environment: "demo"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("e", 64), Issuer: "demo-idp",
			Scopes: []string{"workspace.write"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "workspace.write", Provider: "mcp"},
		Action: models.ActionRequest{
			Capability: "workspace_write", Operation: "write", TargetResource: "demo-workspace",
			Arguments: json.RawMessage(arguments), SideEffect: "logical_workspace_write",
		},
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func eventFor(record models.AuditRecord) models.RuntimeEvent {
	permit := record.AuthorizationEnvelope
	return models.RuntimeEvent{
		EventID: "event-01", PermitID: permit.PermitID, RequestID: permit.RequestID, SessionID: permit.SessionID,
		AgentID: permit.AgentID, WorkloadID: permit.WorkloadID,
		Source: models.RuntimeSourceInstrumentedAdapter, TrustLevel: models.RuntimeTrustAdapterReported,
		Capability: permit.AllowedCapability, Tool: permit.AllowedTool, Operation: permit.AllowedOperations[0], Resource: permit.AllowedResource,
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
