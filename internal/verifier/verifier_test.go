package verifier_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
	"github.com/szey/Aegis_Router/internal/executionproof"
	"github.com/szey/Aegis_Router/internal/keyprovider"
	"github.com/szey/Aegis_Router/internal/permit"
	"github.com/szey/Aegis_Router/internal/verifier"
)

func TestValidPermitVerifiesAndIsConsumed(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	result := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	if result.Outcome != verifier.OutcomeVerified || !result.Allowed() || result.State != permit.StateConsumed {
		t.Fatalf("VerifyExecutionAndConsume = %#v", result)
	}
	if result.PermitID != fixture.issued.PermitID || result.Claims == nil || result.Claims.ActionDigest == "" {
		t.Fatalf("safe result metadata missing: %#v", result)
	}
}

func TestCheckExecutionCannotConsumeOrAuthorizeWithoutProof(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	for range 2 {
		result := fixture.verifier.CheckExecution(fixture.issued.Token(), fixture.action)
		assertOutcome(t, result, verifier.OutcomeValidNotConsumed)
		if result.Verified || result.State != permit.StateIssued {
			t.Fatalf("non-consuming check looked executable: %#v", result)
		}
		assertIssued(t, fixture)
	}
	result := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	assertOutcome(t, result, verifier.OutcomeVerified)
}

func TestExecutionEntryRequiresProofBeforeConsumption(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	missing := fixture.verifier.VerifyExecutionAndConsume(fixture.issued.Token(), "", fixture.action, "POST", "/mcp")
	assertOutcome(t, missing, verifier.OutcomeWrongExecutor)
	assertIssued(t, fixture)

	accepted := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	assertOutcome(t, accepted, verifier.OutcomeVerified)
}

func TestInvalidSignatureIsRejected(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forgedToken, err := permit.SignToken(otherPrivateKey, fixture.issued.Claims.SigningKeyID, fixture.issued.Claims)
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.verifier.VerifyExecutionAndConsume(forgedToken, "", fixture.action, "POST", "/mcp")
	assertOutcome(t, result, verifier.OutcomeInvalidSignature)
	assertIssued(t, fixture)
}

func TestPermitClassBoundariesRejectWithoutConsumption(t *testing.T) {
	t.Run("simulation cannot execute", func(t *testing.T) {
		fixture := newFixtureWithClass(t, time.Minute, permit.ClassSimulation)
		assertOutcome(t, fixture.verifier.VerifyExecutionAndConsume(fixture.issued.Token(), "", fixture.action, "POST", "/mcp"), verifier.OutcomeWrongPermitClass)
		assertIssued(t, fixture)
		assertOutcome(t, fixture.verifier.VerifySimulationAndConsume(fixture.issued.Token(), fixture.action), verifier.OutcomeVerified)
	})

	t.Run("execution cannot simulate", func(t *testing.T) {
		fixture := newFixture(t, time.Minute)
		assertOutcome(t, fixture.verifier.VerifySimulationAndConsume(fixture.issued.Token(), fixture.action), verifier.OutcomeWrongPermitClass)
		assertIssued(t, fixture)
		assertOutcome(t, verifyExecution(t, fixture, fixture.verifier, fixture.action), verifier.OutcomeVerified)
	})
}

func TestPermitClassTamperingAndInvalidValuesAreRejected(t *testing.T) {
	t.Run("tampered class breaks signature", func(t *testing.T) {
		fixture := newFixture(t, time.Minute)
		value := string(permit.ClassSimulation)
		token := rewritePermitClass(t, fixture.issued.Token(), fixture.privateKey, &value, false)
		assertOutcome(t, fixture.verifier.VerifyExecutionAndConsume(token, "", fixture.action, "POST", "/mcp"), verifier.OutcomeInvalidSignature)
		assertIssued(t, fixture)
	})

	for _, test := range []struct {
		name  string
		value *string
	}{
		{name: "missing"},
		{name: "unknown", value: stringPointer("diagnostic")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, time.Minute)
			token := rewritePermitClass(t, fixture.issued.Token(), fixture.privateKey, test.value, true)
			assertOutcome(t, fixture.verifier.VerifyExecutionAndConsume(token, "", fixture.action, "POST", "/mcp"), verifier.OutcomeInvalidPermit)
			assertIssued(t, fixture)
		})
	}
}

func TestExpiredPermitIsRejected(t *testing.T) {
	fixture := newFixture(t, 5*time.Second)
	fixture.now = fixture.issued.Claims.ExpiresTime()
	result := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	assertOutcome(t, result, verifier.OutcomeExpired)
}

func TestPermitThatExpiresDuringVerificationIsRejectedAtConsumeBoundary(t *testing.T) {
	fixture := newFixture(t, 5*time.Second)
	var calls atomic.Int32
	boundaryVerifier, err := verifier.New(fixture.keyProvider, "aegis-router", fixture.store, verifier.WithClock(func() time.Time {
		if calls.Add(1) == 1 {
			return fixture.issued.Claims.IssuedTime()
		}
		return fixture.issued.Claims.ExpiresTime()
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := boundaryVerifier.RegisterWorkloadPublicKey(fixture.workloadKeyID, fixture.workloadPrivateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	result := verifyExecution(t, fixture, boundaryVerifier, fixture.action)
	assertOutcome(t, result, verifier.OutcomeExpired)
}

func TestWrongActionBindingsAreRejectedWithoutConsumption(t *testing.T) {
	tests := []struct {
		name    string
		outcome verifier.Outcome
		mutate  func(*canonicalaction.Action)
	}{
		{"principal", verifier.OutcomeWrongPrincipal, func(action *canonicalaction.Action) { action.PrincipalID = "user-02" }},
		{"agent", verifier.OutcomeWrongAgent, func(action *canonicalaction.Action) { action.AgentID = "other-agent" }},
		{"workload", verifier.OutcomeWrongWorkload, func(action *canonicalaction.Action) { action.WorkloadID = "other-workload" }},
		{"delegation", verifier.OutcomeWrongDelegation, func(action *canonicalaction.Action) {
			action.DelegatedAuthorityFingerprint = "sha256:" + strings.Repeat("b", 64)
		}},
		{"tool", verifier.OutcomeWrongTool, func(action *canonicalaction.Action) { action.Tool = "payment.admin_send" }},
		{"capability", verifier.OutcomeWrongCapability, func(action *canonicalaction.Action) { action.Capability = "payment.refund" }},
		{"resource", verifier.OutcomeWrongResource, func(action *canonicalaction.Action) { action.Resource = "account-999" }},
		{"operation", verifier.OutcomeWrongOperation, func(action *canonicalaction.Action) { action.Operation = "refund" }},
		{"profile", verifier.OutcomeWrongProfile, func(action *canonicalaction.Action) { action.ProfileID = "payment.send/v2" }},
		{"audience", verifier.OutcomeWrongAudience, func(action *canonicalaction.Action) { action.Audience = "mcp://other-upstream" }},
		{"arguments", verifier.OutcomeActionMismatch, func(action *canonicalaction.Action) {
			action.Arguments = json.RawMessage(`{"amount":10000,"currency":"USD","recipient":"merchant-456"}`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, time.Minute)
			action := fixture.action
			test.mutate(&action)
			result := verifyExecution(t, fixture, fixture.verifier, action)
			assertOutcome(t, result, test.outcome)
			assertIssued(t, fixture)
		})
	}
}

func TestPermitReplayIsRejected(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	first := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	second := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	assertOutcome(t, first, verifier.OutcomeVerified)
	assertOutcome(t, second, verifier.OutcomeReplayed)
}

func TestConcurrentReplayExactlyOneSucceeds(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	const attempts = 2
	start := make(chan struct{})
	results := make(chan verifier.Result, attempts)
	var ready sync.WaitGroup
	ready.Add(attempts)
	proofs := make([]string, attempts)
	for index := range attempts {
		proofs[index] = executionProof(t, fixture)
	}
	for index := range attempts {
		proof := proofs[index]
		go func() {
			ready.Done()
			<-start
			results <- fixture.verifier.VerifyExecutionAndConsume(fixture.issued.Token(), proof, fixture.action, "POST", "/mcp")
		}()
	}
	ready.Wait()
	close(start)

	var verified, replayed atomic.Int32
	for range attempts {
		result := <-results
		switch result.Outcome {
		case verifier.OutcomeVerified:
			verified.Add(1)
		case verifier.OutcomeReplayed:
			replayed.Add(1)
		default:
			t.Fatalf("unexpected concurrent outcome %#v", result)
		}
	}
	if verified.Load() != 1 || replayed.Load() != 1 {
		t.Fatalf("verified=%d replayed=%d, want exactly one each", verified.Load(), replayed.Load())
	}
}

func TestRevokedPermitIsRejected(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	if _, err := fixture.store.Revoke(fixture.issued.PermitID, fixture.now); err != nil {
		t.Fatal(err)
	}
	result := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	assertOutcome(t, result, verifier.OutcomeRevoked)
}

func TestIssuerAndStoreBindingsAreRejected(t *testing.T) {
	fixture := newFixture(t, time.Minute)

	t.Run("wrong issuer", func(t *testing.T) {
		other, err := verifier.New(fixture.keyProvider, "other-issuer", fixture.store, verifier.WithClock(func() time.Time { return fixture.now }))
		if err != nil {
			t.Fatal(err)
		}
		assertOutcome(t, other.VerifyExecutionAndConsume(fixture.issued.Token(), "", fixture.action, "POST", "/mcp"), verifier.OutcomeInvalidIssuer)
	})

	t.Run("unknown permit", func(t *testing.T) {
		emptyStore := permit.NewMemoryStore()
		other, err := verifier.New(fixture.keyProvider, "aegis-router", emptyStore, verifier.WithClock(func() time.Time { return fixture.now }))
		if err != nil {
			t.Fatal(err)
		}
		assertOutcome(t, other.VerifyExecutionAndConsume(fixture.issued.Token(), "", fixture.action, "POST", "/mcp"), verifier.OutcomeUnknownPermit)
	})

	t.Run("store claim mismatch", func(t *testing.T) {
		mismatchedStore := permit.NewMemoryStore()
		claims := fixture.issued.Claims
		claims.PolicyVersion = "different-policy"
		if err := mismatchedStore.Register(claims); err != nil {
			t.Fatal(err)
		}
		other, err := verifier.New(fixture.keyProvider, "aegis-router", mismatchedStore, verifier.WithClock(func() time.Time { return fixture.now }))
		if err != nil {
			t.Fatal(err)
		}
		assertOutcome(t, other.VerifyExecutionAndConsume(fixture.issued.Token(), "", fixture.action, "POST", "/mcp"), verifier.OutcomeInvalidPermit)
	})
}

func TestVerificationResultNeverLeaksTokenOrRawArguments(t *testing.T) {
	fixture := newFixture(t, time.Minute)
	result := verifyExecution(t, fixture, fixture.verifier, fixture.action)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{fixture.issued.Token(), "permit_token", "super-secret-recipient", "arguments"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("verification result leaked %q: %s", forbidden, encoded)
		}
	}
}

type fixture struct {
	now                time.Time
	privateKey         ed25519.PrivateKey
	workloadPrivateKey ed25519.PrivateKey
	workloadKeyID      string
	proofNonce         atomic.Uint64
	keyProvider        *keyprovider.Static
	store              *permit.MemoryStore
	issued             permit.IssuedPermit
	action             canonicalaction.Action
	verifier           *verifier.Verifier
}

func newFixture(t *testing.T, ttl time.Duration) *fixture {
	return newFixtureWithClass(t, ttl, permit.ClassExecution)
}

func newFixtureWithClass(t *testing.T, ttl time.Duration, permitClass permit.Class) *fixture {
	t.Helper()
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := canonicalaction.Action{
		PrincipalID: "user-01", AgentID: "finance-agent", WorkloadID: "finance-agent-v3",
		DelegatedAuthorityFingerprint: "sha256:" + strings.Repeat("a", 64),
		Tool:                          "payment.send", Capability: "payment.transfer", Resource: "account-123", Operation: "transfer",
		ProfileID: "payment.send/v1", Audience: "mcp://test-payment-upstream",
		Arguments: json.RawMessage(`{"amount":100,"currency":"USD","recipient":"super-secret-recipient"}`),
	}
	digest, err := action.Digest()
	if err != nil {
		t.Fatal(err)
	}
	store := permit.NewMemoryStore()
	keyProvider, err := keyprovider.NewStatic("test-ed25519-01", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := permit.NewIssuer("aegis-router", keyProvider, store, permit.WithIssuerClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	_, workloadPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	executorThumbprint := ""
	executorKeyID := ""
	if permitClass == permit.ClassExecution {
		executorKeyID = "workload-key-01"
		executorThumbprint, err = executionproof.Thumbprint(workloadPrivateKey.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
	}
	issued, err := issuer.Issue(permit.IssueRequest{
		PermitID: "p_fixture", PermitClass: permitClass, RequestID: "request-01", PrincipalID: action.PrincipalID,
		AgentID: action.AgentID, WorkloadID: action.WorkloadID,
		ExecutorKeyID:                 executorKeyID,
		ExecutorKeyThumbprint:         executorThumbprint,
		DelegatedAuthorityFingerprint: action.DelegatedAuthorityFingerprint,
		Tool:                          action.Tool, Capability: action.Capability, Resource: action.Resource, Operation: action.Operation,
		ProfileID: action.ProfileID, Audience: action.Audience,
		ActionDigest: digest, PolicyVersion: "policy-v7", TTL: ttl,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = publicKey
	fixture := &fixture{
		now: now, privateKey: privateKey, workloadPrivateKey: workloadPrivateKey, workloadKeyID: executorKeyID,
		keyProvider: keyProvider, store: store, issued: issued, action: action,
	}
	result, err := verifier.New(keyProvider, "aegis-router", store, verifier.WithClock(func() time.Time { return fixture.now }))
	if err != nil {
		t.Fatal(err)
	}
	if permitClass == permit.ClassExecution {
		if err := result.RegisterWorkloadPublicKey(executorKeyID, workloadPrivateKey.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
	fixture.verifier = result
	return fixture
}

func executionProof(t *testing.T, fixture *fixture) string {
	t.Helper()
	proof, err := executionproof.Sign(fixture.workloadPrivateKey, fixture.workloadKeyID, executionproof.Claims{
		PermitID: fixture.issued.PermitID, ActionDigest: fixture.issued.Claims.ActionDigest,
		HTTPMethod: "POST", HTTPPath: "/mcp", IssuedAt: fixture.now.Unix(),
		Nonce: fmt.Sprintf("proof-%d", fixture.proofNonce.Add(1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func verifyExecution(t *testing.T, fixture *fixture, target *verifier.Verifier, action canonicalaction.Action) verifier.Result {
	t.Helper()
	return target.VerifyExecutionAndConsume(fixture.issued.Token(), executionProof(t, fixture), action, "POST", "/mcp")
}

func rewritePermitClass(t *testing.T, token string, privateKey ed25519.PrivateKey, permitClass *string, resign bool) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if permitClass == nil {
		delete(claims, "permit_class")
	} else {
		claims["permit_class"] = *permitClass
	}
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	if resign {
		signingInput := parts[0] + "." + parts[1]
		parts[2] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signingInput)))
	}
	return strings.Join(parts, ".")
}

func stringPointer(value string) *string { return &value }

func assertOutcome(t *testing.T, result verifier.Result, want verifier.Outcome) {
	t.Helper()
	if result.Outcome != want {
		t.Fatalf("outcome = %s, want %s (result=%#v)", result.Outcome, want, result)
	}
	if want != verifier.OutcomeVerified && result.Allowed() {
		t.Fatalf("rejected result reports Allowed: %#v", result)
	}
}

func assertIssued(t *testing.T, fixture *fixture) {
	t.Helper()
	record, ok := fixture.store.Get(fixture.issued.PermitID, fixture.now)
	if !ok || record.State != permit.StateIssued {
		t.Fatalf("binding failure consumed permit: record=%#v exists=%v", record, ok)
	}
}
