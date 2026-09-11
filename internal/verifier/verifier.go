// Package verifier is the pre-execution reference monitor. Executors must call
// VerifyExecutionAndConsume immediately before a real side effect and proceed
// only when the returned outcome is VERIFIED.
package verifier

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
	"github.com/szey/Aegis_Router/internal/executionproof"
	"github.com/szey/Aegis_Router/internal/keyprovider"
	"github.com/szey/Aegis_Router/internal/permit"
)

type Outcome string

const (
	OutcomeVerified         Outcome = "VERIFIED"
	OutcomeExpired          Outcome = "EXPIRED"
	OutcomeInvalidSignature Outcome = "INVALID_SIGNATURE"
	OutcomeActionMismatch   Outcome = "ACTION_MISMATCH"
	OutcomeWrongPrincipal   Outcome = "WRONG_PRINCIPAL"
	OutcomeWrongAgent       Outcome = "WRONG_AGENT"
	OutcomeWrongWorkload    Outcome = "WRONG_WORKLOAD"
	OutcomeWrongDelegation  Outcome = "WRONG_DELEGATION"
	OutcomeWrongTool        Outcome = "WRONG_TOOL"
	OutcomeWrongCapability  Outcome = "WRONG_CAPABILITY"
	OutcomeWrongResource    Outcome = "WRONG_RESOURCE"
	OutcomeWrongOperation   Outcome = "WRONG_OPERATION"
	OutcomeWrongProfile     Outcome = "WRONG_PROFILE"
	OutcomeWrongAudience    Outcome = "WRONG_AUDIENCE"
	OutcomeReplayed         Outcome = "REPLAYED"
	OutcomeRevoked          Outcome = "REVOKED"
	OutcomeInvalidIssuer    Outcome = "INVALID_ISSUER"
	OutcomeUnknownPermit    Outcome = "UNKNOWN_PERMIT"
	OutcomeInvalidPermit    Outcome = "INVALID_PERMIT"
	OutcomeInvalidAction    Outcome = "INVALID_ACTION"
	OutcomeNotYetValid      Outcome = "NOT_YET_VALID"
	OutcomeWrongPermitClass Outcome = "WRONG_PERMIT_CLASS"
	OutcomeWrongExecutor    Outcome = "WRONG_EXECUTOR"
	OutcomeValidNotConsumed Outcome = "VALID_NOT_CONSUMED"
)

const (
	DefaultExecutionProofMaxAge = 30 * time.Second
	DefaultExecutionProofSkew   = 5 * time.Second
)

var ErrInvalidConfiguration = errors.New("invalid verifier configuration")

// Result is safe to audit or serialize. It contains signed metadata but never
// the permit token or raw arguments.
type Result struct {
	Outcome    Outcome        `json:"outcome"`
	Verified   bool           `json:"verified"`
	PermitID   string         `json:"permit_id,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	State      permit.State   `json:"state,omitempty"`
	Claims     *permit.Claims `json:"claims,omitempty"`
	VerifiedAt time.Time      `json:"verified_at"`
}

func (r Result) Allowed() bool { return r.Outcome == OutcomeVerified && r.Verified }

type Option func(*Verifier)

func WithClock(clock func() time.Time) Option {
	return func(verifier *Verifier) {
		if clock != nil {
			verifier.clock = clock
		}
	}
}

type Verifier struct {
	keyProvider    keyprovider.VerificationProvider
	expectedIssuer string
	store          permit.Store
	clock          func() time.Time
	workloadKeys   *executionproof.Registry
	proofNonces    *executionproof.NonceStore
	proofMaxAge    time.Duration
	proofClockSkew time.Duration
}

func New(provider keyprovider.VerificationProvider, expectedIssuer string, store permit.Store, options ...Option) (*Verifier, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: key provider is required", ErrInvalidConfiguration)
	}
	if expectedIssuer == "" {
		return nil, fmt.Errorf("%w: expected issuer is required", ErrInvalidConfiguration)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: permit store is required", ErrInvalidConfiguration)
	}
	result := &Verifier{
		keyProvider:    provider,
		expectedIssuer: expectedIssuer,
		store:          store,
		clock:          time.Now,
		workloadKeys:   executionproof.NewRegistry(),
		proofNonces:    executionproof.NewNonceStore(),
		proofMaxAge:    DefaultExecutionProofMaxAge,
		proofClockSkew: DefaultExecutionProofSkew,
	}
	for _, option := range options {
		option(result)
	}
	return result, nil
}

// RegisterWorkloadPublicKey adds a server-owned Ed25519 verification key.
// Embedders should complete registration before accepting MCP traffic.
func (v *Verifier) RegisterWorkloadPublicKey(keyID string, publicKey ed25519.PublicKey) error {
	return v.workloadKeys.Register(keyID, publicKey)
}

// VerifyExecutionAndConsume is the sole execution-Permit consumption entry.
// It validates the Permit, workload proof, action binding, freshness and proof
// nonce before atomically consuming the Permit. No public proof-free execution
// consumption method is provided.
func (v *Verifier) VerifyExecutionAndConsume(permitToken, proofToken string, action canonicalaction.Action, httpMethod, httpPath string) Result {
	result := v.verifyExecutionProof(permitToken, proofToken, action, httpMethod, httpPath)
	if result.Outcome != OutcomeVerified {
		return result
	}
	return v.consumeInspected(result)
}

func (v *Verifier) verifyExecutionProof(permitToken, proofToken string, action canonicalaction.Action, httpMethod, httpPath string) Result {
	result := v.inspectPermit(permitToken, permit.ClassExecution)
	if result.Outcome != OutcomeVerified {
		return result
	}
	claims := result.Claims
	if claims == nil || claims.ExecutorKeyThumbprint == "" {
		result.Outcome = OutcomeInvalidPermit
		return result
	}
	keyID, err := executionproof.TokenKeyID(proofToken)
	if err != nil {
		result.Outcome = OutcomeWrongExecutor
		return result
	}
	publicKey, err := v.workloadKeys.VerificationKey(keyID)
	if err != nil {
		result.Outcome = OutcomeWrongExecutor
		return result
	}
	proofClaims, err := executionproof.Verify(publicKey, proofToken)
	if err != nil {
		result.Outcome = OutcomeWrongExecutor
		return result
	}
	thumbprint, err := executionproof.Thumbprint(publicKey)
	if err != nil || keyID != claims.ExecutorKeyID || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(claims.ExecutorKeyThumbprint)) != 1 {
		result.Outcome = OutcomeWrongExecutor
		return result
	}
	if proofClaims.PermitID != claims.PermitID ||
		subtle.ConstantTimeCompare([]byte(proofClaims.ActionDigest), []byte(claims.ActionDigest)) != 1 ||
		proofClaims.HTTPMethod != httpMethod || proofClaims.HTTPPath != httpPath {
		result.Outcome = OutcomeWrongExecutor
		return result
	}
	now := result.VerifiedAt
	issuedAt := time.Unix(proofClaims.IssuedAt, 0).UTC()
	if issuedAt.After(now.Add(v.proofClockSkew)) || now.Sub(issuedAt) > v.proofMaxAge {
		result.Outcome = OutcomeWrongExecutor
		return result
	}
	if outcome := actionBindingOutcome(action, *claims); outcome != OutcomeVerified {
		result.Outcome = outcome
		return result
	}
	expiresAt := issuedAt.Add(v.proofMaxAge + v.proofClockSkew).Unix()
	if !v.proofNonces.Use(keyID, proofClaims.Nonce, now.Unix(), expiresAt) {
		result.Outcome = OutcomeWrongExecutor
		return result
	}
	result.Verified = true
	return result
}

// CheckExecution validates an execution Permit and its action binding without
// validating workload possession or consuming the Permit. A successful check
// deliberately returns VALID_NOT_CONSUMED with Allowed() == false so it cannot
// be mistaken for execution authorization.
func (v *Verifier) CheckExecution(permitToken string, action canonicalaction.Action) Result {
	result := v.inspectPermit(permitToken, permit.ClassExecution)
	if result.Outcome != OutcomeVerified {
		return result
	}
	if outcome := actionBindingOutcome(action, *result.Claims); outcome != OutcomeVerified {
		result.Outcome = outcome
		return result
	}
	result.Outcome = OutcomeValidNotConsumed
	result.Verified = false
	return result
}

func actionBindingOutcome(action canonicalaction.Action, claims permit.Claims) Outcome {
	if err := action.Validate(); err != nil {
		return OutcomeInvalidAction
	}
	if action.PrincipalID != claims.PrincipalID {
		return OutcomeWrongPrincipal
	}
	if action.AgentID != claims.AgentID {
		return OutcomeWrongAgent
	}
	if action.WorkloadID != claims.WorkloadID {
		return OutcomeWrongWorkload
	}
	if action.DelegatedAuthorityFingerprint != claims.DelegatedAuthorityFingerprint {
		return OutcomeWrongDelegation
	}
	if action.Tool != claims.Tool {
		return OutcomeWrongTool
	}
	if action.Capability != claims.Capability {
		return OutcomeWrongCapability
	}
	if action.Resource != claims.Resource {
		return OutcomeWrongResource
	}
	if action.Operation != claims.Operation {
		return OutcomeWrongOperation
	}
	if action.ProfileID != claims.ProfileID {
		return OutcomeWrongProfile
	}
	if action.Audience != claims.Audience {
		return OutcomeWrongAudience
	}
	digest, err := action.Digest()
	if err != nil {
		return OutcomeInvalidAction
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(claims.ActionDigest)) != 1 {
		return OutcomeActionMismatch
	}
	return OutcomeVerified
}

// VerifySimulationAndConsume is the isolated verification path for
// server-owned demos. Its result must never authorize a real upstream call.
func (v *Verifier) VerifySimulationAndConsume(permitToken string, action canonicalaction.Action) Result {
	result := v.inspectPermit(permitToken, permit.ClassSimulation)
	if result.Outcome != OutcomeVerified {
		return result
	}
	claims := *result.Claims
	if outcome := actionBindingOutcome(action, claims); outcome != OutcomeVerified {
		result.Outcome = outcome
		return result
	}
	return v.consumeInspected(result)
}

func (v *Verifier) consumeInspected(result Result) Result {
	now := result.VerifiedAt
	claims := *result.Claims
	result.Verified = false
	// Re-read the clock at the actual consume boundary: canonicalization and
	// signature checks must not let a permit slip past its expiry.
	consumeTime := v.clock().UTC()
	if consumeTime.Before(now) {
		consumeTime = now
	}
	result.VerifiedAt = consumeTime
	consumed := v.store.Consume(claims.PermitID, consumeTime)
	result.State = consumed.Record.State
	switch consumed.Outcome {
	case permit.ConsumeSucceeded:
		result.Outcome = OutcomeVerified
		result.Verified = true
	case permit.ConsumeExpired:
		result.Outcome = OutcomeExpired
	case permit.ConsumeReplayed:
		result.Outcome = OutcomeReplayed
	case permit.ConsumeRevoked:
		result.Outcome = OutcomeRevoked
	default:
		result.Outcome = OutcomeUnknownPermit
	}
	return result
}

func (v *Verifier) inspectPermit(permitToken string, expectedClass permit.Class) Result {
	now := v.clock().UTC()
	result := Result{Outcome: OutcomeInvalidSignature, VerifiedAt: now}
	keyID, err := permit.TokenKeyID(permitToken)
	if err != nil {
		return result
	}
	publicKey, err := v.keyProvider.VerificationKey(keyID)
	if err != nil {
		return result
	}
	claims, err := permit.VerifyToken(publicKey, permitToken)
	if err != nil {
		if errors.Is(err, permit.ErrInvalidClaims) || errors.Is(err, permit.ErrMalformedToken) || errors.Is(err, permit.ErrUnsupportedToken) {
			result.Outcome = OutcomeInvalidPermit
		}
		return result
	}
	result.PermitID = claims.PermitID
	result.RequestID = claims.RequestID
	result.Claims = copyClaims(claims)
	if claims.PermitClass != expectedClass {
		result.Outcome = OutcomeWrongPermitClass
		return result
	}

	if claims.Issuer != v.expectedIssuer {
		result.Outcome = OutcomeInvalidIssuer
		return result
	}
	record, exists := v.store.Get(claims.PermitID, now)
	if !exists {
		result.Outcome = OutcomeUnknownPermit
		return result
	}
	result.State = record.State
	if record.Claims != claims {
		result.Outcome = OutcomeInvalidPermit
		return result
	}
	if now.Before(claims.IssuedTime()) {
		result.Outcome = OutcomeNotYetValid
		return result
	}
	switch record.State {
	case permit.StateExpired:
		result.Outcome = OutcomeExpired
		return result
	case permit.StateConsumed:
		result.Outcome = OutcomeReplayed
		return result
	case permit.StateRevoked:
		result.Outcome = OutcomeRevoked
		return result
	case permit.StateIssued:
		// Continue to the action binding checks.
	default:
		result.Outcome = OutcomeInvalidPermit
		return result
	}
	result.Outcome = OutcomeVerified
	return result
}

func copyClaims(claims permit.Claims) *permit.Claims {
	copy := claims
	return &copy
}
