package semanticaction_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/szey/Aegis_Router/internal/semanticaction"
)

func TestPreparedExecutionOwnsItsArguments(t *testing.T) {
	registry, err := semanticaction.NewRegistry(testProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	input := validInput(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
	prepared, err := registry.Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	original := prepared.Arguments()
	wantDigest, _ := prepared.Action().Digest()
	input.Arguments[0] = '['
	arguments := prepared.Arguments()
	arguments[0] = '['
	action := prepared.Action()
	action.Arguments[0] = '['
	action.ExecutionBinding = ""
	gotDigest, err := prepared.Action().Digest()
	if err != nil || gotDigest != wantDigest || !bytes.Equal(prepared.Arguments(), original) {
		t.Fatal("caller mutation changed the prepared execution")
	}
	if prepared.Action().ExecutionBinding == "" || prepared.UpstreamURL() != "http://127.0.0.1:3001/mcp" || prepared.CredentialMode() != "anonymous" {
		t.Fatal("prepared execution lost a server-owned binding")
	}
	if string(prepared.Arguments()) != `{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}` {
		t.Fatal("digest canonicalization changed the typed dispatch encoding")
	}
}

type inconsistentProfile struct {
	*semanticaction.PaymentSendV1
	change func(*semanticaction.Resolved)
}

func (p inconsistentProfile) Resolve(input semanticaction.Input) (semanticaction.Resolved, error) {
	resolved, err := p.PaymentSendV1.Resolve(input)
	if err == nil {
		p.change(&resolved)
	}
	return resolved, err
}

func TestPreparationRejectsAProfileWithTwoExecutionMeanings(t *testing.T) {
	for _, change := range []func(*semanticaction.Resolved){
		func(r *semanticaction.Resolved) { r.Action.PrincipalID = "another-user" },
		func(r *semanticaction.Resolved) { r.Action.Resource = "another-account" },
		func(r *semanticaction.Resolved) { r.UpstreamURL = "http://127.0.0.1:9999/other" },
		func(r *semanticaction.Resolved) {
			r.NormalizedArguments = json.RawMessage(`{"amount_minor":200,"currency":"USD","recipient":"merchant-456"}`)
		},
	} {
		registry, err := semanticaction.NewRegistry(inconsistentProfile{testProfile(t), change})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := registry.Prepare(validInput(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)); err == nil {
			t.Fatal("inconsistent semantic profile became executable")
		}
	}
}
