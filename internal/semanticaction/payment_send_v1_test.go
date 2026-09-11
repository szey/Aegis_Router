package semanticaction_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/semanticaction"
)

func TestPaymentSendV1ValidatesAndNormalizesExactSemantics(t *testing.T) {
	profile := testProfile(t)
	first, err := profile.Resolve(validInput(`{"amount_minor":10000,"currency":"USD","recipient":"merchant-456"}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := profile.Resolve(validInput(`{"recipient":"merchant-456","currency":"USD","amount_minor":10000}`))
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := first.Action.Digest()
	secondDigest, _ := second.Action.Digest()
	if firstDigest != secondDigest || string(first.NormalizedArguments) != `{"amount_minor":10000,"currency":"USD","recipient":"merchant-456"}` {
		t.Fatalf("normalization mismatch: %s / %s / %s", firstDigest, secondDigest, first.NormalizedArguments)
	}
	if first.Action.ProfileID != semanticaction.PaymentSendV1ID || first.Action.Audience != "mcp://test-payment-upstream" {
		t.Fatalf("server binding missing: %#v", first.Action)
	}
}

func TestPaymentSendV1RejectsInvalidBusinessArguments(t *testing.T) {
	profile := testProfile(t)
	tests := []struct {
		name string
		raw  string
		code semanticaction.RejectionCode
	}{
		{"over limit", `{"amount_minor":10001,"currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectAmountExceedsLimit},
		{"zero", `{"amount_minor":0,"currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectAmountInvalid},
		{"negative", `{"amount_minor":-1,"currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectAmountInvalid},
		{"overflow", `{"amount_minor":9223372036854775808,"currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectArgumentsInvalid},
		{"string amount", `{"amount_minor":"100","currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectArgumentsInvalid},
		{"floating amount", `{"amount_minor":100.0,"currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectArgumentsInvalid},
		{"missing amount", `{"currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectArgumentsInvalid},
		{"unknown field", `{"amount_minor":100,"currency":"USD","recipient":"merchant-456","memo":"unbound"}`, semanticaction.RejectArgumentsInvalid},
		{"currency", `{"amount_minor":100,"currency":"EUR","recipient":"merchant-456"}`, semanticaction.RejectCurrencyNotAllowed},
		{"currency case is not coerced", `{"amount_minor":100,"currency":"usd","recipient":"merchant-456"}`, semanticaction.RejectCurrencyNotAllowed},
		{"recipient", `{"amount_minor":100,"currency":"USD","recipient":"merchant-999"}`, semanticaction.RejectRecipientNotAllowed},
		{"duplicate field", `{"amount_minor":100,"amount_minor":200,"currency":"USD","recipient":"merchant-456"}`, semanticaction.RejectArgumentsInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := profile.Resolve(validInput(test.raw))
			if err == nil || semanticaction.Code(err) != test.code {
				t.Fatalf("error=%v code=%s, want %s", err, semanticaction.Code(err), test.code)
			}
		})
	}
}

func TestPaymentSendV1RejectsCallerBindingConflicts(t *testing.T) {
	profile := testProfile(t)
	tests := []struct {
		name   string
		mutate func(*semanticaction.Input)
		code   semanticaction.RejectionCode
	}{
		{"unknown tool", func(input *semanticaction.Input) { input.Tool = "payment.admin" }, semanticaction.RejectToolUnmapped},
		{"missing operation", func(input *semanticaction.Input) { input.Operation = "" }, semanticaction.RejectBindingConflict},
		{"capability", func(input *semanticaction.Input) { input.Capability = "payment.unlimited" }, semanticaction.RejectBindingConflict},
		{"resource", func(input *semanticaction.Input) { input.Resource = "account-999" }, semanticaction.RejectBindingConflict},
		{"profile", func(input *semanticaction.Input) { input.ProfileID = "payment.send/v2" }, semanticaction.RejectProfileMismatch},
		{"audience", func(input *semanticaction.Input) { input.Audience = "mcp://attacker" }, semanticaction.RejectAudienceMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validInput(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
			test.mutate(&input)
			_, err := profile.Resolve(input)
			if err == nil || semanticaction.Code(err) != test.code {
				t.Fatalf("error=%v code=%s, want %s", err, semanticaction.Code(err), test.code)
			}
		})
	}
}

func testProfile(t *testing.T) *semanticaction.PaymentSendV1 {
	t.Helper()
	profile, err := semanticaction.NewPaymentSendV1(models.PaymentSendV1Config{
		ProfileID: semanticaction.PaymentSendV1ID, MCPTool: "payment.send", Capability: "payment_transfer",
		Resource: "account-123", Operation: "transfer", Audience: "mcp://test-payment-upstream",
		UpstreamURL: "http://127.0.0.1:3001/mcp", AllowedCurrencies: []string{"USD", "CNY"},
		MaxAmountMinorByCurrency: map[string]int64{"USD": 10000, "CNY": 50000},
		AllowedRecipients:        []string{"merchant-456"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func validInput(raw string) semanticaction.Input {
	return semanticaction.Input{
		PrincipalID: "user-01", AgentID: "finance-agent", WorkloadID: "finance-workload-v1",
		DelegatedAuthorityFingerprint: "sha256:" + strings.Repeat("a", 64),
		Tool:                          "payment.send", Capability: "payment_transfer", Resource: "account-123", Operation: "transfer",
		Arguments: json.RawMessage(raw),
	}
}
