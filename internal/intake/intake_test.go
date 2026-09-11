package intake_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/intake"
	"github.com/szey/Aegis_Router/internal/models"
)

func TestStaticIntakeOverwritesCallerSuppliedSecurityIdentity(t *testing.T) {
	trusted := intake.IdentityContext{
		Principal: models.PrincipalContext{PrincipalID: "trusted-user", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "trusted-agent", WorkloadID: "trusted-workload"},
		DelegatedAuthority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("a", 64), Scopes: []string{"code.read"}, Subject: "trusted-user",
		},
		WorkloadBinding: testWorkloadBinding(),
	}
	provider, err := intake.NewStatic(trusted, "test-auth-middleware")
	if err != nil {
		t.Fatal(err)
	}
	proposal := models.Request{
		Principal: models.PrincipalContext{PrincipalID: "forged-user"},
		Agent:     models.AgentIdentity{AgentID: "forged-agent", WorkloadID: "forged-workload"},
		Authority: models.DelegatedAuthority{CredentialFingerprint: strings.Repeat("b", 64)},
		Tool:      models.ToolContext{Name: "coder"},
		Action:    models.ActionRequest{Capability: "generate_code", Operation: "generate", TargetResource: "public_workspace"},
	}
	authorization, err := provider.Resolve(httptest.NewRequest("POST", "/api/actions/authorize", nil), proposal)
	if err != nil {
		t.Fatal(err)
	}
	resolved := authorization.Request()
	if resolved.Principal.PrincipalID != "trusted-user" || resolved.Agent.AgentID != "trusted-agent" || resolved.Agent.WorkloadID != "trusted-workload" {
		t.Fatalf("caller identity was not overwritten: %#v", resolved)
	}
	if resolved.Authority.CredentialFingerprint != strings.Repeat("a", 64) || authorization.Provenance().Assurance != intake.AssuranceAuthenticated {
		t.Fatalf("trusted authority/provenance missing: %#v / %#v", resolved.Authority, authorization.Provenance())
	}
}

func TestDevelopmentBodyIntakeIsLoopbackOnlyAndExplicitlyLowAssurance(t *testing.T) {
	provider, err := intake.NewLoopbackDevelopment("local-test", testWorkloadBinding())
	if err != nil {
		t.Fatal(err)
	}
	proposal := models.Request{
		Principal: models.PrincipalContext{PrincipalID: "developer", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "dev-agent", WorkloadID: "dev-workload"},
	}
	remote := httptest.NewRequest("POST", "/api/actions/authorize", nil)
	remote.RemoteAddr = "192.0.2.10:1234"
	if _, err := provider.Resolve(remote, proposal); err == nil {
		t.Fatal("non-loopback peer was accepted by development intake")
	}
	local := httptest.NewRequest("POST", "/api/actions/authorize", nil)
	local.RemoteAddr = "127.0.0.1:1234"
	authorization, err := provider.Resolve(local, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Provenance().Source != intake.SourceLocalDevelopment || authorization.Provenance().Assurance != intake.AssuranceDevelopmentOnly {
		t.Fatalf("development provenance = %#v", authorization.Provenance())
	}
	if authorization.WorkloadBinding() != testWorkloadBinding() {
		t.Fatalf("development workload binding = %#v", authorization.WorkloadBinding())
	}
}

func TestTrustedProxyOverwritesForgedBodyIdentityAndRecordsProvenance(t *testing.T) {
	provider, err := intake.NewTrustedProxy([]string{"127.0.0.1/32", "::1/128"}, "local-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	proposal := models.Request{
		Principal: models.PrincipalContext{PrincipalID: "admin", PrincipalType: "service", Metadata: map[string]string{"role": "root"}},
		Agent:     models.AgentIdentity{AgentID: "attacker-agent", WorkloadID: "attacker-workload", Owner: "attacker"},
		Authority: models.DelegatedAuthority{CredentialFingerprint: strings.Repeat("a", 64), Scopes: []string{"payment.unlimited"}, Subject: "admin"},
		Tool:      models.ToolContext{Name: "payment.send"},
		Action:    models.ActionRequest{Capability: "payment_transfer", Operation: "transfer", TargetResource: "account-123"},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	setTrustedProxyHeaders(request.Header)
	request.Header.Set(intake.HeaderDelegatedScopes, "payment.transfer, finance.read")
	before := time.Now().UTC()
	authorization, err := provider.Resolve(request, proposal)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	resolved := authorization.Request()
	if resolved.Principal.PrincipalID != "user-01" || resolved.Principal.PrincipalType != "human" || len(resolved.Principal.Metadata) != 0 {
		t.Fatalf("trusted principal did not replace forged body: %#v", resolved.Principal)
	}
	if resolved.Agent.AgentID != "finance-agent" || resolved.Agent.WorkloadID != "finance-workload-v1" || resolved.Agent.Owner != "" {
		t.Fatalf("trusted Agent did not replace forged body: %#v", resolved.Agent)
	}
	if resolved.Authority.Subject != "user-01" || resolved.Authority.Issuer != "local-auth-gateway" || resolved.Authority.CredentialFingerprint != strings.Repeat("b", 64) {
		t.Fatalf("trusted delegation did not replace forged body: %#v", resolved.Authority)
	}
	if got := strings.Join(resolved.Authority.Scopes, ","); got != "finance.read,payment.transfer" {
		t.Fatalf("sorted scopes = %q", got)
	}
	provenance := authorization.Provenance()
	if provenance.Source != intake.SourceTrustedIntegration || provenance.ProviderID != "local-auth-gateway" || provenance.Assurance != intake.AssuranceAuthenticated || provenance.EstablishedAt.Before(before) || provenance.EstablishedAt.After(after) {
		t.Fatalf("trusted proxy provenance = %#v", provenance)
	}
	binding := authorization.WorkloadBinding()
	if binding.KeyID != "workload-key-01" || binding.PublicKeyThumbprint != "sha256:"+strings.Repeat("e", 64) {
		t.Fatalf("trusted workload binding = %#v", binding)
	}
}

func TestTrustedProxySupportsIPv6DirectPeerCIDR(t *testing.T) {
	provider, err := intake.NewTrustedProxy([]string{"2001:db8::/32"}, "ipv6-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", nil)
	request.RemoteAddr = "[2001:db8::42]:443"
	setTrustedProxyHeaders(request.Header)
	if _, err := provider.Resolve(request, models.Request{}); err != nil {
		t.Fatalf("IPv6 trusted peer was rejected: %v", err)
	}
}

func TestTrustedProxyNeverTrustsForwardedPeerHeaders(t *testing.T) {
	provider, err := intake.NewTrustedProxy([]string{"10.0.0.0/8"}, "edge-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", nil)
	request.RemoteAddr = "192.0.2.10:443"
	setTrustedProxyHeaders(request.Header)
	request.Header.Set("X-Forwarded-For", "10.1.2.3")
	request.Header.Set("Forwarded", "for=10.1.2.3")
	request.Header.Set("X-Real-IP", "10.1.2.3")
	if _, err := provider.Resolve(request, models.Request{}); err == nil {
		t.Fatal("forwarded-address headers allowed an untrusted direct peer")
	}
}

func TestTrustedProxyFailsClosedOnMalformedTrustInput(t *testing.T) {
	provider, err := intake.NewTrustedProxy([]string{"127.0.0.1/32"}, "local-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"untrusted peer", func(request *http.Request) { request.RemoteAddr = "192.0.2.10:443" }},
		{"malformed remote address", func(request *http.Request) { request.RemoteAddr = "127.0.0.1" }},
		{"missing workload", func(request *http.Request) { request.Header.Del(intake.HeaderWorkloadID) }},
		{"duplicate principal", func(request *http.Request) { request.Header.Add(intake.HeaderAuthenticatedPrincipal, "user-02") }},
		{"surrounding whitespace", func(request *http.Request) { request.Header.Set(intake.HeaderAgentID, " finance-agent ") }},
		{"oversized identity", func(request *http.Request) { request.Header.Set(intake.HeaderWorkloadID, strings.Repeat("a", 129)) }},
		{"control character", func(request *http.Request) { request.Header.Set(intake.HeaderAgentID, "finance\x01agent") }},
		{"invalid fingerprint", func(request *http.Request) { request.Header.Set(intake.HeaderDelegationFingerprint, "Bearer secret") }},
		{"missing workload key", func(request *http.Request) { request.Header.Del(intake.HeaderWorkloadKeyID) }},
		{"uppercase workload thumbprint", func(request *http.Request) {
			request.Header.Set(intake.HeaderWorkloadKeyThumbprint, "sha256:"+strings.Repeat("A", 64))
		}},
		{"empty scope", func(request *http.Request) {
			request.Header.Set(intake.HeaderDelegatedScopes, "payment.transfer,,finance.read")
		}},
		{"duplicate scope", func(request *http.Request) {
			request.Header.Set(intake.HeaderDelegatedScopes, "payment.transfer,payment.transfer")
		}},
		{"alternative scope syntax", func(request *http.Request) {
			request.Header.Set(intake.HeaderDelegatedScopes, "payment.transfer finance.read")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", nil)
			request.RemoteAddr = "127.0.0.1:43210"
			setTrustedProxyHeaders(request.Header)
			test.mutate(request)
			if _, err := provider.Resolve(request, models.Request{}); err == nil {
				t.Fatal("malformed trusted-proxy request was accepted")
			}
		})
	}
}

func TestTrustedProxyRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      []string
		providerID string
	}{
		{"missing CIDR", nil, "auth-gateway"},
		{"invalid CIDR", []string{"127.0.0.1"}, "auth-gateway"},
		{"duplicate CIDR", []string{"127.0.0.1/32", "127.0.0.1/32"}, "auth-gateway"},
		{"missing provider", []string{"127.0.0.1/32"}, ""},
		{"provider whitespace", []string{"127.0.0.1/32"}, " auth-gateway"},
		{"provider punctuation", []string{"127.0.0.1/32"}, "auth/gateway"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := intake.NewTrustedProxy(test.cidrs, test.providerID); err == nil {
				t.Fatal("invalid trusted-proxy configuration was accepted")
			}
		})
	}
}

func setTrustedProxyHeaders(header http.Header) {
	header.Set(intake.HeaderAuthenticatedPrincipal, "user-01")
	header.Set(intake.HeaderAgentID, "finance-agent")
	header.Set(intake.HeaderWorkloadID, "finance-workload-v1")
	header.Set(intake.HeaderDelegatedScopes, "payment.transfer")
	header.Set(intake.HeaderDelegationFingerprint, strings.Repeat("b", 64))
	header.Set(intake.HeaderWorkloadKeyID, "workload-key-01")
	header.Set(intake.HeaderWorkloadKeyThumbprint, "sha256:"+strings.Repeat("e", 64))
}

func testWorkloadBinding() intake.WorkloadBinding {
	return intake.WorkloadBinding{KeyID: "workload-key-01", PublicKeyThumbprint: "sha256:" + strings.Repeat("e", 64)}
}
