// Package semanticaction defines the narrow, server-owned business-semantic
// boundary used to produce canonical actions. It is deliberately not a
// runtime plugin system or a generic policy framework.
package semanticaction

import (
	"encoding/json"
	"errors"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
)

type RejectionCode string

const (
	RejectSemanticToolUnmapped     RejectionCode = "SEMANTIC_TOOL_UNMAPPED"
	RejectSemanticArgumentsInvalid RejectionCode = "SEMANTIC_ARGUMENTS_INVALID"
)

type Rejection struct {
	Code   RejectionCode
	Detail string
}

func (e *Rejection) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}

func Code(err error) RejectionCode {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Code
	}
	return RejectSemanticArgumentsInvalid
}

// Input is the complete caller proposal after trusted identity intake. A
// Profile must replace all server-owned bindings in its Resolved action and
// reject conflicting caller assertions.
type Input struct {
	PrincipalID                   string
	AgentID                       string
	WorkloadID                    string
	DelegatedAuthorityFingerprint string
	Tool                          string
	Capability                    string
	Resource                      string
	Operation                     string
	ProfileID                     string
	Audience                      string
	Arguments                     json.RawMessage
}

// Resolved contains the one canonical action shared by authorization and the
// MCP execution boundary. NormalizedArguments are forwarded only after permit
// verification; UpstreamURL remains server-owned routing configuration.
type Resolved struct {
	Action              canonicalaction.Action
	NormalizedArguments json.RawMessage
	UpstreamURL         string
}

// Profile is the entire semantic extension contract. Implementations are
// compiled into the server and may only resolve one fixed tool/profile pair.
type Profile interface {
	ProfileID() string
	Tool() string
	UpstreamURL() string
	Resolve(Input) (Resolved, error)
}
