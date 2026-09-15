// Package executionbinding_test is an isolated contract experiment. Nothing in
// this package is linked into cmd/server. Its mock controller does not prove
// Docker, VM, filesystem, network isolation, or remote attestation properties.
package executionbinding_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type objectVersion struct {
	Namespace, ObjectID string
	Generation          uint64
}
type leaseVersion struct {
	ID, Executor, Scope, PolicyDigest string
	Generation                        uint64
	ExpiresAt                         int64
}
type grant struct {
	ActionDigest string
	Object       objectVersion
	Lease        leaseVersion
}
type signedGrant struct{ payload, signature []byte }

type finalWriter struct {
	mu           sync.Mutex
	object       objectVersion
	lease        leaseVersion
	actionDigest string
	writes       int
}

func issue(t *testing.T, key ed25519.PrivateKey, writer *finalWriter) signedGrant {
	t.Helper()
	writer.mu.Lock()
	defer writer.mu.Unlock()
	payload, err := json.Marshal(grant{writer.actionDigest, writer.object, writer.lease})
	if err != nil {
		t.Fatal(err)
	}
	return signedGrant{payload, ed25519.Sign(key, payload)}
}

// The final mutation and comparison share one lock. Reading versions at the
// Router and then writing unconditionally here would leave the gap open.
func (w *finalWriter) apply(key ed25519.PublicKey, signed signedGrant, now time.Time, compareVersions bool) error {
	if !ed25519.Verify(key, signed.payload, signed.signature) {
		return errors.New("invalid controller signature")
	}
	var allowed grant
	if err := json.Unmarshal(signed.payload, &allowed); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if allowed.ActionDigest != w.actionDigest {
		return errors.New("action mismatch")
	}
	if compareVersions && (allowed.Object != w.object || allowed.Lease != w.lease ||
		allowed.Lease.Scope != w.object.Namespace || now.Unix() >= allowed.Lease.ExpiresAt) {
		return errors.New("object or execution lease changed")
	}
	w.writes++
	w.object.Generation++
	return nil
}

func newWriter(now time.Time) *finalWriter {
	return &finalWriter{
		object:       objectVersion{"workspace-A", "object-1", 1},
		lease:        leaseVersion{ID: "lease-1", Executor: "broker-key-1", Scope: "workspace-A", PolicyDigest: "network-none-policy", Generation: 1, ExpiresAt: now.Add(time.Minute).Unix()},
		actionDigest: "synthetic-authorized-action-digest",
	}
}

func TestFinalExecutorVersionAndLeaseContract(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		change func(*finalWriter)
		delay  time.Duration
	}{
		{"same-name replacement", func(w *finalWriter) { w.object.ObjectID = "object-2" }, 0},
		{"new resource generation", func(w *finalWriter) { w.object.Generation++ }, 0},
		{"different namespace", func(w *finalWriter) { w.object.Namespace = "workspace-B" }, 0},
		{"resumed lease", func(w *finalWriter) { w.lease.Generation++ }, 0},
		{"different executor", func(w *finalWriter) { w.lease.Executor = "broker-key-2" }, 0},
		{"different scope", func(w *finalWriter) { w.lease.Scope = "workspace-B" }, 0},
		{"changed environment policy", func(w *finalWriter) { w.lease.PolicyDigest = "network-open-policy" }, 0},
		{"expired lease", func(*finalWriter) {}, time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Control: authenticating an unchanged action alone admits a write
			// after the target/controller state changes.
			baseline := newWriter(now)
			before := issue(t, private, baseline)
			test.change(baseline)
			if err := baseline.apply(public, before, now.Add(test.delay), false); err != nil || baseline.writes != 1 {
				t.Fatal("control did not reproduce the gap")
			}
			guarded := newWriter(now)
			permit := issue(t, private, guarded)
			test.change(guarded)
			if err := guarded.apply(public, permit, now.Add(test.delay), true); err == nil || guarded.writes != 0 {
				t.Fatal("changed object/lease produced a write")
			}
		})
	}
	w := newWriter(now)
	signed := issue(t, private, w)
	if err := w.apply(public, signed, now, true); err != nil || w.writes != 1 {
		t.Fatal("valid versions did not commit exactly one mutation")
	}
	if err := w.apply(public, signed, now, true); err == nil || w.writes != 1 {
		t.Fatal("stale generation was reused")
	}
	signed.payload[0] ^= 1
	if err := w.apply(public, signed, now, true); err == nil {
		t.Fatal("tampered controller grant accepted")
	}
}

func TestCompetingWritesUseOneResourceGeneration(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	w := newWriter(now)
	signed := issue(t, private, w)
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() { defer group.Done(); <-start; _ = w.apply(public, signed, now, true) }()
	}
	close(start)
	group.Wait()
	if w.writes != 1 {
		t.Fatalf("writes=%d; want one atomic conditional write", w.writes)
	}
}
