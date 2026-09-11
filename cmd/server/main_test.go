package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"

	"agent-governance-gateway/internal/audit"
	"agent-governance-gateway/internal/config"
	"agent-governance-gateway/internal/executionproof"
	"agent-governance-gateway/internal/intake"
	"agent-governance-gateway/internal/router"
)

func TestConfigureAuthorizationIntakeSelectsOneExplicitMode(t *testing.T) {
	tests := []struct {
		name        string
		development bool
		cidrs       []string
		providerID  string
		mode        string
		kind        any
	}{
		{"secure default", false, nil, "", "reject_all", intake.RejectAll{}},
		{"development", true, nil, "", "loopback_development", (*intake.LoopbackDevelopment)(nil)},
		{"trusted proxy", false, []string{"127.0.0.1/32", "::1/128"}, "local-auth-gateway", "trusted_proxy", (*intake.TrustedProxy)(nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var binding []intake.WorkloadBinding
			if test.development {
				binding = []intake.WorkloadBinding{{KeyID: "development-key", PublicKeyThumbprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
			}
			provider, mode, err := configureAuthorizationIntake(test.development, test.cidrs, test.providerID, binding...)
			if err != nil {
				t.Fatal(err)
			}
			if mode != test.mode {
				t.Fatalf("mode = %q, want %q", mode, test.mode)
			}
			switch test.kind.(type) {
			case intake.RejectAll:
				if _, ok := provider.(intake.RejectAll); !ok {
					t.Fatalf("provider = %T, want RejectAll", provider)
				}
			case *intake.LoopbackDevelopment:
				if _, ok := provider.(*intake.LoopbackDevelopment); !ok {
					t.Fatalf("provider = %T, want LoopbackDevelopment", provider)
				}
			case *intake.TrustedProxy:
				if _, ok := provider.(*intake.TrustedProxy); !ok {
					t.Fatalf("provider = %T, want TrustedProxy", provider)
				}
			}
		})
	}
}

func TestRegisterWorkloadPublicKeysUsesStrictEd25519Base64URL(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(cfg, store)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 7)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	bindings, err := registerWorkloadPublicKeys(r, []string{"workload-key-01=" + encoded})
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings=%#v err=%v", bindings, err)
	}
	thumbprint, _ := executionproof.Thumbprint(publicKey)
	if bindings[0] != (intake.WorkloadBinding{KeyID: "workload-key-01", PublicKeyThumbprint: thumbprint}) {
		t.Fatalf("binding=%#v", bindings[0])
	}
	for _, invalid := range []string{"missing-separator", "key=***", "key=AA"} {
		if _, err := registerWorkloadPublicKeys(r, []string{invalid}); err == nil {
			t.Fatalf("invalid workload key %q accepted", invalid)
		}
	}
}

func TestConfigureAuthorizationIntakeRejectsAmbiguousOrPartialProxyConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		development bool
		cidrs       []string
		providerID  string
	}{
		{"development and trusted proxy", true, []string{"127.0.0.1/32"}, "local-auth-gateway"},
		{"development and provider only", true, nil, "local-auth-gateway"},
		{"CIDR without provider", false, []string{"127.0.0.1/32"}, ""},
		{"provider without CIDR", false, nil, "local-auth-gateway"},
		{"whitespace provider without CIDR", false, nil, "   "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := configureAuthorizationIntake(test.development, test.cidrs, test.providerID); err == nil {
				t.Fatal("invalid authorization intake configuration was accepted")
			}
		})
	}
}
