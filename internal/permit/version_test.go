package permit_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/permit"
)

func TestV2ExecutionBindingCannotBeAddedOrDroppedByVersionDowngrade(t *testing.T) {
	public, private := keyPair(t)
	issuer, err := permit.NewIssuer("aegis-router", staticProvider(t, private), permit.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	for _, bound := range []bool{false, true} {
		request := issueRequest("version-test", 30*time.Second)
		if bound {
			request.PermitID = "bound-version-test"
			request.ExecutionBinding = "sha256:" + strings.Repeat("a", 64)
			request.AuthorityEpoch = 1
		}
		issued, err := issuer.Issue(request)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(issued.Token(), ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var header map[string]any
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatal(err)
		}
		want := float64(1)
		if bound {
			want = 2
		}
		if header["v"] != want {
			t.Fatalf("header version=%v want %v", header["v"], want)
		}
		if claims, err := permit.VerifyToken(public, issued.Token()); err != nil || claims.ExecutionBinding != request.ExecutionBinding {
			t.Fatalf("binding round trip failed: %v", err)
		}
		// A correctly re-signed token with the wrong version must still reject.
		// This tests semantic downgrade protection rather than signature checks.
		header["v"] = float64(3) - want
		raw, _ = json.Marshal(header)
		parts[0] = base64.RawURLEncoding.EncodeToString(raw)
		input := parts[0] + "." + parts[1]
		changed := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
		if _, err := permit.VerifyToken(public, changed); err == nil {
			t.Fatal("accepted incompatible token version and binding")
		}
	}
}
