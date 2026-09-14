package verifier_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/permit"
	"github.com/szey/Aegis_Router/internal/verifier"
)

func TestRequiredObligationsRejectBeforePermitAndNonceConsumption(t *testing.T) {
	for _, test := range []struct {
		name        string
		obligations permit.Obligations
	}{
		{"read_only", permit.Obligations{ReadOnly: true}},
		{"network_egress_denied", permit.Obligations{NetworkEgressDenied: true}},
		{"enhanced_audit_required", permit.Obligations{EnhancedAuditRequired: true}},
		{"isolation_required", permit.Obligations{IsolationRequired: true}},
		{"human_approval_required", permit.Obligations{HumanApprovalRequired: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixtureWithClass(t, time.Minute, permit.ClassExecution, test.obligations)
			proof := executionProof(t, fixture)
			for range 2 {
				result := fixture.verifier.VerifyExecutionAndConsume(fixture.issued.Token(), proof, fixture.action, "POST", "/mcp")
				if string(result.Outcome) != "UNSATISFIED_OBLIGATION" || result.Allowed() {
					t.Errorf("required %s: outcome=%s allowed=%v; want unconsumed rejection", test.name, result.Outcome, result.Allowed())
				}
				assertIssued(t, fixture)
				if len(result.ConstraintChecks) != 1 || result.ConstraintChecks[0].Requirement != test.name {
					t.Fatalf("missing constraint diagnostic: %#v", result.ConstraintChecks)
				}
			}
		})
	}
}

func TestUnknownSignedObligationCannotDisappearDuringDecode(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	parts := strings.Split(fixture.issued.Token(), ".")
	var claims map[string]any
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["obligations"] = map[string]bool{"future_requirement": true}
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.privateKey, []byte(input)))
	proof := executionProof(t, fixture)
	result := fixture.verifier.VerifyExecutionAndConsume(token, proof, fixture.action, "POST", "/mcp")
	assertOutcome(t, result, verifier.OutcomeInvalidPermit)
	assertIssued(t, fixture)
	// Rejection of the malformed token did not burn the proof nonce either.
	assertOutcome(t, fixture.verifier.VerifyExecutionAndConsume(fixture.issued.Token(), proof, fixture.action, "POST", "/mcp"), verifier.OutcomeVerified)
}

func TestConstraintRejectionDoesNotOverrideAuthenticationFailure(t *testing.T) {
	fixture := newFixtureWithClass(t, time.Minute, permit.ClassExecution, permit.Obligations{IsolationRequired: true})
	result := fixture.verifier.VerifyExecutionAndConsume(fixture.issued.Token(), "", fixture.action, "POST", "/mcp")
	assertOutcome(t, result, verifier.OutcomeWrongExecutor)
	if len(result.ConstraintChecks) != 0 {
		t.Fatal("constraints evaluated before workload authentication")
	}
	assertIssued(t, fixture)
}
