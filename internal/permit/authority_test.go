package permit_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/szey/Aegis_Router/internal/permit"
)

func boundClaims(id string) permit.Claims {
	claims := claimsForStore(id)
	claims.ExecutionBinding = "sha256:" + strings.Repeat("b", 64)
	claims.AuthorityEpoch = 1
	return claims
}

func TestAuthorityEpochClosesIssuanceAndConsumptionWindows(t *testing.T) {
	store := permit.NewMemoryStore()
	old := boundClaims("old")
	now := old.IssuedTime()
	key := old.AuthorityKey()
	if err := store.Register(old); err != nil {
		t.Fatal(err)
	}
	state, err := store.SetAuthorityEnabled(key, false, now)
	if err != nil || state.Enabled || state.Epoch != 2 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if got := store.Consume(old.PermitID, now); got.Outcome != permit.ConsumeRevoked {
		t.Fatalf("old consume=%s", got.Outcome)
	}
	stale := old
	stale.PermitID = "stale-policy-decision"
	if err := store.Register(stale); !errors.Is(err, permit.ErrAuthorityChanged) {
		t.Fatalf("stale registration=%v", err)
	}
	stale.AuthorityEpoch = state.Epoch
	if err := store.Register(stale); !errors.Is(err, permit.ErrAuthorityChanged) {
		t.Fatalf("disabled registration=%v", err)
	}
	state, err = store.SetAuthorityEnabled(key, true, now)
	if err != nil || !state.Enabled || state.Epoch != 3 {
		t.Fatalf("reenabled=%+v err=%v", state, err)
	}
	if got := store.Consume(old.PermitID, now); got.Outcome != permit.ConsumeRevoked {
		t.Fatal("re-enable restored an old permit")
	}
	stale.AuthorityEpoch = state.Epoch
	if err := store.Register(stale); err != nil {
		t.Fatal(err)
	}
	if got := store.Consume(stale.PermitID, now); got.Outcome != permit.ConsumeSucceeded {
		t.Fatal(got.Outcome)
	}
	// A different authority's epoch is unaffected.
	other := old
	other.PermitID = "other"
	other.WorkloadID = "another-workload"
	if err := store.Register(other); err != nil {
		t.Fatal(err)
	}
}

func TestRevocationAndConsumptionHaveOneLinearizationOrder(t *testing.T) {
	for i := 0; i < 64; i++ {
		store := permit.NewMemoryStore()
		claims := boundClaims(fmt.Sprintf("race-%d", i))
		if err := store.Register(claims); err != nil {
			t.Fatal(err)
		}
		now := claims.IssuedTime()
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		var consumed permit.ConsumeResult
		var revokeErr error
		go func() { defer group.Done(); <-start; consumed = store.Consume(claims.PermitID, now) }()
		go func() {
			defer group.Done()
			<-start
			_, revokeErr = store.SetAuthorityEnabled(claims.AuthorityKey(), false, now)
		}()
		close(start)
		group.Wait()
		if revokeErr != nil {
			t.Fatal(revokeErr)
		}
		record, _ := store.Get(claims.PermitID, now)
		switch consumed.Outcome {
		case permit.ConsumeSucceeded:
			if record.State != permit.StateConsumed {
				t.Fatal("revocation rewrote admitted work")
			}
		case permit.ConsumeRevoked:
			if record.State != permit.StateRevoked {
				t.Fatal("revocation lost its state")
			}
		default:
			t.Fatal(consumed.Outcome)
		}
		if got := store.Consume(claims.PermitID, now); got.Outcome == permit.ConsumeSucceeded {
			t.Fatal("execution admitted after completed revocation")
		}
	}
}
