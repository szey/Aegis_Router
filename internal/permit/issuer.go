package permit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"agent-governance-gateway/internal/keyprovider"
)

const (
	DefaultTTL = 30 * time.Second
	MaxTTL     = 15 * time.Minute
)

type IssueRequest struct {
	PermitID                      string
	PermitClass                   Class
	RequestID                     string
	PrincipalID                   string
	AgentID                       string
	WorkloadID                    string
	ExecutorKeyID                 string
	ExecutorKeyThumbprint         string
	DelegatedAuthorityFingerprint string
	Tool                          string
	Capability                    string
	Resource                      string
	Operation                     string
	ProfileID                     string
	Audience                      string
	ActionDigest                  string
	PolicyVersion                 string
	Obligations                   Obligations
	TTL                           time.Duration
}

// IssuedPermit keeps its credential private from JSON and fmt's default struct
// formatting. Call Token only when returning the credential to its executor.
type IssuedPermit struct {
	PermitID string `json:"permit_id"`
	Claims   Claims `json:"claims"`
	token    string
}

func (p IssuedPermit) Token() string { return p.token }

// String and GoString prevent accidental credential disclosure through common
// structured logging and diagnostic formatting.
func (p IssuedPermit) String() string {
	return fmt.Sprintf("IssuedPermit{PermitID:%q, Token:<redacted>}", p.PermitID)
}

func (p IssuedPermit) GoString() string { return p.String() }

type IssuerOption func(*Issuer)

func WithIssuerClock(clock func() time.Time) IssuerOption {
	return func(issuer *Issuer) {
		if clock != nil {
			issuer.clock = clock
		}
	}
}

type Issuer struct {
	name        string
	keyProvider keyprovider.Provider
	store       Store
	clock       func() time.Time
}

func NewIssuer(name string, provider keyprovider.Provider, store Store, options ...IssuerOption) (*Issuer, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidClaims)
	}
	if provider == nil {
		return nil, ErrInvalidKey
	}
	if _, err := provider.CurrentSigningKey(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: permit store is required", ErrInvalidClaims)
	}
	issuer := &Issuer{
		name: name, keyProvider: provider, store: store, clock: time.Now,
	}
	for _, option := range options {
		option(issuer)
	}
	return issuer, nil
}

func (i *Issuer) Issue(request IssueRequest) (IssuedPermit, error) {
	signingKey, err := i.keyProvider.CurrentSigningKey()
	if err != nil {
		return IssuedPermit{}, fmt.Errorf("load current signing key: %w", err)
	}
	ttl := request.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Second || ttl > MaxTTL || ttl%time.Second != 0 {
		return IssuedPermit{}, fmt.Errorf("%w: TTL must be whole seconds between 1s and %s", ErrInvalidClaims, MaxTTL)
	}
	permitID := request.PermitID
	if permitID == "" {
		var err error
		permitID, err = newPermitID()
		if err != nil {
			return IssuedPermit{}, err
		}
	}
	now := i.clock().UTC().Truncate(time.Second)
	claims := Claims{
		PermitID: permitID, SigningKeyID: signingKey.KeyID, PermitClass: request.PermitClass, RequestID: request.RequestID,
		PrincipalID: request.PrincipalID, AgentID: request.AgentID, WorkloadID: request.WorkloadID,
		ExecutorKeyID:                 request.ExecutorKeyID,
		ExecutorKeyThumbprint:         request.ExecutorKeyThumbprint,
		DelegatedAuthorityFingerprint: request.DelegatedAuthorityFingerprint,
		Tool:                          request.Tool, Capability: request.Capability, Resource: request.Resource, Operation: request.Operation,
		ProfileID: request.ProfileID, Audience: request.Audience,
		ActionDigest: request.ActionDigest, PolicyVersion: request.PolicyVersion, Obligations: request.Obligations,
		Issuer: i.name, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), SingleUse: true,
	}
	if err := claims.Validate(); err != nil {
		return IssuedPermit{}, err
	}
	token, err := SignToken(signingKey.PrivateKey, signingKey.KeyID, claims)
	if err != nil {
		return IssuedPermit{}, err
	}
	if err := i.store.Register(claims); err != nil {
		return IssuedPermit{}, err
	}
	return IssuedPermit{PermitID: permitID, Claims: claims, token: token}, nil
}

func (i *Issuer) PublicKey() ed25519.PublicKey {
	key, err := i.keyProvider.CurrentSigningKey()
	if err != nil {
		return nil
	}
	return key.PublicKey()
}

func (i *Issuer) KeyID() string {
	key, err := i.keyProvider.CurrentSigningKey()
	if err != nil {
		return ""
	}
	return key.KeyID
}

func newPermitID() (string, error) {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate permit identifier: %w", err)
	}
	return "p_" + base64.RawURLEncoding.EncodeToString(random), nil
}
