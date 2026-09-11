package canonicalaction_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
)

func TestArgumentOrderDoesNotChangeDigest(t *testing.T) {
	first := testAction(json.RawMessage(`{"amount":100,"currency":"USD","recipient":{"id":"merchant-456","kind":"merchant"}}`))
	second := testAction(json.RawMessage(`{"recipient":{"kind":"merchant","id":"merchant-456"},"currency":"USD","amount":100}`))

	firstDigest := mustDigest(t, first)
	secondDigest := mustDigest(t, second)
	if firstDigest != secondDigest {
		t.Fatalf("equivalent objects produced different digests:\n%s\n%s", firstDigest, secondDigest)
	}
}

func TestSameSemanticActionCreatesSameDigest(t *testing.T) {
	first := testAction(json.RawMessage(`{"amount":100.0,"tags":["approved","finance"]}`))
	second := testAction(json.RawMessage(`{"tags":["approved","finance"],"amount":1e2}`))
	if mustDigest(t, first) != mustDigest(t, second) {
		t.Fatal("exactly equivalent numeric values or key ordering changed the digest")
	}
}

func TestSecurityRelevantMutationsChangeDigest(t *testing.T) {
	base := testAction(json.RawMessage(`{"amount":100,"currency":"USD"}`))
	tests := map[string]canonicalaction.Action{
		"amount":    withArguments(base, `{"amount":10000,"currency":"USD"}`),
		"resource":  withResource(base, "account-999"),
		"tool":      withTool(base, "payment.admin_send"),
		"operation": withOperation(base, "refund"),
	}
	want := mustDigest(t, base)
	for name, mutated := range tests {
		t.Run(name, func(t *testing.T) {
			if got := mustDigest(t, mutated); got == want {
				t.Fatalf("%s mutation did not change digest %s", name, got)
			}
		})
	}
}

func TestDelegatedFingerprintBindingIsStableAndDoesNotRetainInput(t *testing.T) {
	input := strings.Repeat("Ab", 32)
	first, err := canonicalaction.BindDelegatedAuthorityFingerprint(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalaction.BindDelegatedAuthorityFingerprint(strings.ToLower(input))
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, "sha256:") || strings.Contains(first, input) {
		t.Fatalf("unexpected delegated fingerprint binding: first=%q second=%q", first, second)
	}
}

func TestCanonicalJSONRejectsDuplicateKeys(t *testing.T) {
	action := testAction(json.RawMessage(`{"amount":100,"amount":10000}`))
	_, err := action.Digest()
	if !errors.Is(err, canonicalaction.ErrDuplicateObjectKey) {
		t.Fatalf("Digest error = %v, want ErrDuplicateObjectKey", err)
	}
}

func TestCanonicalJSONRejectsLossyStringEncodings(t *testing.T) {
	tests := map[string]json.RawMessage{
		"unpaired high surrogate": json.RawMessage(`{"value":"\ud800"}`),
		"unpaired low surrogate":  json.RawMessage(`{"value":"\udc00"}`),
		"invalid UTF-8":           json.RawMessage([]byte{'{', '"', 'v', '"', ':', '"', 0xff, '"', '}'}),
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := testAction(arguments).Digest(); !errors.Is(err, canonicalaction.ErrInvalidJSON) {
				t.Fatalf("Digest error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func TestCanonicalJSONPreservesArrayOrder(t *testing.T) {
	first := testAction(json.RawMessage(`{"steps":["read","write"]}`))
	second := testAction(json.RawMessage(`{"steps":["write","read"]}`))
	if mustDigest(t, first) == mustDigest(t, second) {
		t.Fatal("array reordering did not change digest")
	}
}

func TestCanonicalJSONDoesNotContainUnqualifiedRawFormatting(t *testing.T) {
	action := testAction(json.RawMessage("{\n  \"secret_ref\": \"vault:item-1\", \"amount\": 100.00\n}"))
	canonical, err := action.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), "\n") || strings.Contains(string(canonical), "100.00") {
		t.Fatalf("CanonicalJSON retained formatting differences: %s", canonical)
	}
	if digest := mustDigest(t, action); !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		t.Fatalf("unexpected digest format %q", digest)
	}
}

func testAction(arguments json.RawMessage) canonicalaction.Action {
	return canonicalaction.Action{
		PrincipalID:                   "user-01",
		AgentID:                       "finance-agent",
		WorkloadID:                    "finance-agent-v3",
		DelegatedAuthorityFingerprint: "sha256:" + strings.Repeat("d", 64),
		Tool:                          "payment.send",
		Capability:                    "payment.transfer",
		Resource:                      "account-123",
		Operation:                     "transfer",
		Arguments:                     arguments,
	}
}

func mustDigest(t *testing.T, action canonicalaction.Action) string {
	t.Helper()
	digest, err := action.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func withArguments(action canonicalaction.Action, arguments string) canonicalaction.Action {
	action.Arguments = json.RawMessage(arguments)
	return action
}

func withResource(action canonicalaction.Action, resource string) canonicalaction.Action {
	action.Resource = resource
	return action
}

func withTool(action canonicalaction.Action, tool string) canonicalaction.Action {
	action.Tool = tool
	return action
}

func withOperation(action canonicalaction.Action, operation string) canonicalaction.Action {
	action.Operation = operation
	return action
}
