package semanticaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
)

// PreparedExecution is the immutable server-owned result used by issuance and
// dispatch. Accessors never share mutable argument buffers with callers.
// The current transport identity is deliberately anonymous: credentials and
// session cookies cannot be smuggled through an unbound request context.
type PreparedExecution struct {
	action      canonicalaction.Action
	arguments   json.RawMessage
	upstreamURL string
	policyFacts PolicyFacts
}

func (p PreparedExecution) Action() canonicalaction.Action {
	action := p.action
	action.Arguments = bytes.Clone(p.action.Arguments)
	return action
}

func (p PreparedExecution) Arguments() json.RawMessage { return bytes.Clone(p.arguments) }
func (p PreparedExecution) UpstreamURL() string        { return p.upstreamURL }
func (p PreparedExecution) CredentialMode() string     { return "anonymous" }
func (p PreparedExecution) PolicyFacts() PolicyFacts   { return p.policyFacts }

func (r *Registry) Prepare(input Input) (PreparedExecution, error) {
	resolved, err := r.Resolve(input)
	if err != nil {
		return PreparedExecution{}, err
	}
	profile := r.byTool[input.Tool]
	if resolved.PolicyFacts.SideEffect == "" || resolved.PolicyFacts.Bytes < 0 {
		return PreparedExecution{}, fmt.Errorf("semantic profile omitted execution policy facts")
	}
	if resolved.Action.PrincipalID != input.PrincipalID || resolved.Action.AgentID != input.AgentID ||
		resolved.Action.WorkloadID != input.WorkloadID || resolved.Action.DelegatedAuthorityFingerprint != input.DelegatedAuthorityFingerprint ||
		resolved.Action.Capability != input.Capability || resolved.Action.Resource != input.Resource || resolved.Action.Operation != input.Operation {
		return PreparedExecution{}, fmt.Errorf("semantic profile changed the authorized identity or action scope")
	}
	if resolved.Action.Tool != profile.Tool() || resolved.Action.ProfileID != profile.ProfileID() ||
		resolved.UpstreamURL != profile.UpstreamURL() || profile.BindingDigest() == "" {
		return PreparedExecution{}, fmt.Errorf("semantic profile returned inconsistent execution bindings")
	}
	arguments, err := canonicalaction.CanonicalizeJSON(resolved.NormalizedArguments)
	if err != nil {
		return PreparedExecution{}, err
	}
	actionArguments, err := canonicalaction.CanonicalizeJSON(resolved.Action.Arguments)
	if err != nil || !bytes.Equal(arguments, actionArguments) {
		return PreparedExecution{}, fmt.Errorf("semantic profile action differs from its dispatch arguments")
	}
	action := resolved.Action
	// Keep the profile's typed wire encoding (for example integer 100, not
	// canonical digest notation 1e2). Canonical bytes above compare meaning;
	// only the digest serializer should choose its numeric representation.
	action.Arguments = bytes.Clone(resolved.NormalizedArguments)
	action.ExecutionBinding = profile.BindingDigest()
	if err := action.Validate(); err != nil {
		return PreparedExecution{}, err
	}
	return PreparedExecution{action: action, arguments: bytes.Clone(resolved.NormalizedArguments), upstreamURL: resolved.UpstreamURL, policyFacts: resolved.PolicyFacts}, nil
}

// executionBinding snapshots configuration once at profile construction. It
// includes the exact route and transport identity, not just an audience label.
// The digest carries no claim that a URL proves endpoint ownership or TLS identity.
func executionBinding(config any, upstreamURL string) (string, error) {
	raw, err := json.Marshal(map[string]any{
		"schema": "aegis.prepared-execution/v2", "profile_config": config,
		"upstream_url": upstreamURL, "credential_mode": "anonymous",
	})
	if err != nil {
		return "", err
	}
	canonical, err := canonicalaction.CanonicalizeJSON(raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
