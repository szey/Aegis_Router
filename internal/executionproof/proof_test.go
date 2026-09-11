package executionproof_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-governance-gateway/internal/executionproof"
)

func TestEd25519ExecutionProofRoundTripAndTamperRejection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := executionproof.Claims{
		PermitID: "p_test", ActionDigest: "sha256:" + strings.Repeat("a", 64),
		HTTPMethod: "POST", HTTPPath: "/mcp", IssuedAt: time.Now().Unix(), Nonce: "proof-nonce-01",
	}
	token, err := executionproof.Sign(privateKey, "workload-key-01", claims)
	if err != nil {
		t.Fatal(err)
	}
	if keyID, err := executionproof.TokenKeyID(token); err != nil || keyID != "workload-key-01" {
		t.Fatalf("key id=%q err=%v", keyID, err)
	}
	verified, err := executionproof.Verify(publicKey, token)
	if err != nil || verified != claims {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}

	parts := strings.Split(token, ".")
	last := "A"
	if strings.HasSuffix(parts[1], last) {
		last = "B"
	}
	parts[1] = parts[1][:len(parts[1])-1] + last
	if _, err := executionproof.Verify(publicKey, strings.Join(parts, ".")); !errors.Is(err, executionproof.ErrInvalidSignature) {
		t.Fatalf("tampered proof error=%v", err)
	}
}

func TestNonceStoreAllowsExactlyOneConcurrentUse(t *testing.T) {
	store := executionproof.NewNonceStore()
	now := time.Now().Unix()
	start := make(chan struct{})
	var ready sync.WaitGroup
	var successes atomic.Int32
	ready.Add(20)
	var workers sync.WaitGroup
	workers.Add(20)
	for range 20 {
		go func() {
			defer workers.Done()
			ready.Done()
			<-start
			if store.Use("workload-key-01", "same-nonce", now, now+30) {
				successes.Add(1)
			}
		}()
	}
	ready.Wait()
	close(start)
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatalf("nonce successes=%d, want 1", successes.Load())
	}
}

func TestThumbprintUsesLowercaseQualifiedSHA256(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := executionproof.Thumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !executionproof.ValidThumbprint(thumbprint) || len(thumbprint) != 71 {
		t.Fatalf("thumbprint=%q", thumbprint)
	}
}
