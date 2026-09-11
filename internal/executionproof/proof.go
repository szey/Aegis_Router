// Package executionproof implements the Ed25519 proof of possession presented
// by an authenticated workload at the MCP execution boundary.
package executionproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"agent-governance-gateway/internal/canonicalaction"
	"agent-governance-gateway/internal/keyprovider"
)

const (
	TokenType      = "AEGIS-EXECUTION-PROOF"
	TokenAlgorithm = "EdDSA"
	TokenVersion   = 1
	MaxTokenBytes  = 16 * 1024
	MaxNonceBytes  = 256
)

var (
	ErrMalformedToken   = errors.New("malformed execution proof")
	ErrInvalidSignature = errors.New("invalid execution proof signature")
	ErrInvalidClaims    = errors.New("invalid execution proof claims")
)

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
	Version   int    `json:"v"`
}

// Claims bind a fresh workload signature to one Permit and one HTTP execution
// boundary. IssuedAt is a UTC Unix timestamp in seconds.
type Claims struct {
	PermitID     string `json:"permit_id"`
	ActionDigest string `json:"action_digest"`
	HTTPMethod   string `json:"http_method"`
	HTTPPath     string `json:"http_path"`
	IssuedAt     int64  `json:"issued_at"`
	Nonce        string `json:"nonce"`
}

func (claims Claims) Validate() error {
	if claims.PermitID == "" || len(claims.PermitID) > 160 {
		return fmt.Errorf("%w: permit_id", ErrInvalidClaims)
	}
	if !isSHA256Thumbprint(claims.ActionDigest) {
		return fmt.Errorf("%w: action_digest", ErrInvalidClaims)
	}
	if claims.HTTPMethod != "POST" || claims.HTTPPath != "/mcp" {
		return fmt.Errorf("%w: HTTP boundary", ErrInvalidClaims)
	}
	if claims.IssuedAt <= 0 || claims.Nonce == "" || len(claims.Nonce) > MaxNonceBytes {
		return fmt.Errorf("%w: issued_at or nonce", ErrInvalidClaims)
	}
	for _, char := range claims.Nonce {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("._~-", char)) {
			return fmt.Errorf("%w: nonce", ErrInvalidClaims)
		}
	}
	return nil
}

// Sign creates the compact proof placed in X-Aegis-Execution-Proof.
func Sign(privateKey ed25519.PrivateKey, keyID string, claims Claims) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", keyprovider.ErrInvalidKey
	}
	if err := keyprovider.ValidateKeyID(keyID); err != nil {
		return "", err
	}
	if err := claims.Validate(); err != nil {
		return "", err
	}
	headerBytes, err := json.Marshal(header{Algorithm: TokenAlgorithm, Type: TokenType, KeyID: keyID, Version: TokenVersion})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := encodedHeader + "." + encodedClaims
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// TokenKeyID reads only the untrusted key selector. Call Verify before using
// any other proof field.
func TokenKeyID(token string) (string, error) {
	parsed, _, _, err := splitToken(token)
	if err != nil {
		return "", err
	}
	if err := validateHeader(parsed); err != nil {
		return "", err
	}
	return parsed.KeyID, nil
}

// Verify authenticates and strictly decodes a compact proof.
func Verify(publicKey ed25519.PublicKey, token string) (Claims, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Claims{}, keyprovider.ErrInvalidKey
	}
	parsedHeader, payload, signature, err := splitToken(token)
	if err != nil {
		return Claims{}, err
	}
	if err := validateHeader(parsedHeader); err != nil {
		return Claims{}, err
	}
	parts := strings.Split(token, ".")
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, ErrInvalidSignature
	}
	if _, err := canonicalaction.CanonicalizeJSON(payload); err != nil {
		return Claims{}, ErrMalformedToken
	}
	var claims Claims
	if err := strictJSON(payload, &claims); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if err := claims.Validate(); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func splitToken(token string) (header, []byte, []byte, error) {
	if token == "" || len(token) > MaxTokenBytes || strings.TrimSpace(token) != token {
		return header{}, nil, nil, ErrMalformedToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return header{}, nil, nil, ErrMalformedToken
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return header{}, nil, nil, ErrMalformedToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return header{}, nil, nil, ErrMalformedToken
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return header{}, nil, nil, ErrMalformedToken
	}
	if _, err := canonicalaction.CanonicalizeJSON(headerBytes); err != nil {
		return header{}, nil, nil, ErrMalformedToken
	}
	var parsed header
	if err := strictJSON(headerBytes, &parsed); err != nil {
		return header{}, nil, nil, ErrMalformedToken
	}
	return parsed, payload, signature, nil
}

func validateHeader(value header) error {
	if value.Algorithm != TokenAlgorithm || value.Type != TokenType || value.Version != TokenVersion || keyprovider.ValidateKeyID(value.KeyID) != nil {
		return ErrMalformedToken
	}
	return nil
}

func strictJSON(input []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON")
		}
		return err
	}
	return nil
}

// Thumbprint is the algorithm-qualified SHA-256 digest of the raw Ed25519
// public key bytes.
func Thumbprint(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", keyprovider.ErrInvalidKey
	}
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidThumbprint(value string) bool { return isSHA256Thumbprint(value) }

func isSHA256Thumbprint(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}
