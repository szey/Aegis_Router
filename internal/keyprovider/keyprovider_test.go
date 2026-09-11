package keyprovider_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/szey/Aegis_Router/internal/keyprovider"
)

func TestEphemeralProviderKeepsOneProcessLocalKeyAndKeyID(t *testing.T) {
	provider, err := keyprovider.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.CurrentSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.CurrentSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID == "" || first.KeyID != second.KeyID || string(first.PublicKey()) != string(second.PublicKey()) {
		t.Fatalf("ephemeral provider was not stable within the process: %#v / %#v", first.KeyID, second.KeyID)
	}
	first.PrivateKey[0] ^= 0xff
	third, _ := provider.CurrentSigningKey()
	if string(first.PrivateKey) == string(third.PrivateKey) {
		t.Fatal("provider returned mutable private-key storage")
	}
}

func TestStaticProviderSupportsExternallyLoadedPersistentKeyAndExactKIDLookup(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := keyprovider.NewStatic("local-signing-2026-09", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := provider.VerificationKey("local-signing-2026-09")
	if err != nil || string(resolved) != string(publicKey) {
		t.Fatalf("verification key = %x, err=%v", resolved, err)
	}
	if _, err := provider.VerificationKey("local-signing-unknown"); !errors.Is(err, keyprovider.ErrUnknownKeyID) {
		t.Fatalf("unknown kid error = %v", err)
	}
}

func TestSigningKeyFormattingAndJSONRedactPrivateKey(t *testing.T) {
	provider, err := keyprovider.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	key, err := provider.CurrentSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := string(key.PrivateKey)
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), fmt.Sprintf("%v", key), fmt.Sprintf("%+v", key), fmt.Sprintf("%#v", key)} {
		if strings.Contains(output, secret) || !strings.Contains(output, "redacted") {
			t.Fatalf("signing key formatting was not redacted: %q", output)
		}
	}
}
