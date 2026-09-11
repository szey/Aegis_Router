package models

import (
	"encoding/json"
	"strings"
	"time"
)

type Route string

type AuthorizationStatus string

const (
	RouteAllow    Route = "allow"
	RouteRestrict Route = "restrict"
	RouteSandbox  Route = "sandbox"
	RouteDeny     Route = "deny"
	RouteEscalate Route = "escalate"

	AuthorizationStatusAuthorized       AuthorizationStatus = "AUTHORIZED"
	AuthorizationStatusDenied           AuthorizationStatus = "DENIED"
	AuthorizationStatusRequiresApproval AuthorizationStatus = "REQUIRES_APPROVAL"
)

// PrincipalContext identifies the human or service on whose behalf an action
// is attempted. Tenant and environment are labels, never raw request content.
type PrincipalContext struct {
	PrincipalID   string            `json:"principal_id"`
	PrincipalType string            `json:"principal_type"`
	Tenant        string            `json:"tenant,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// AgentIdentity identifies the governed workload separately from its owner.
type AgentIdentity struct {
	AgentID     string `json:"agent_id"`
	WorkloadID  string `json:"workload_id"`
	Owner       string `json:"owner,omitempty"`
	Environment string `json:"environment,omitempty"`
	Framework   string `json:"framework,omitempty"`
	Version     string `json:"version,omitempty"`
}

// DelegatedAuthority deliberately has no bearer-token field. Only a
// non-reversible credential fingerprint and authorization metadata may enter
// the routing or audit model.
type DelegatedAuthority struct {
	CredentialFingerprint string     `json:"credential_fingerprint"`
	Issuer                string     `json:"issuer,omitempty"`
	Scopes                []string   `json:"scopes"`
	Subject               string     `json:"subject,omitempty"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
}

type ToolContext struct {
	ToolID               string `json:"tool_id,omitempty"`
	Name                 string `json:"name"`
	Provider             string `json:"provider,omitempty"`
	SchemaSHA256         string `json:"schema_sha256,omitempty"`
	ExpectedSchemaSHA256 string `json:"expected_schema_sha256,omitempty"`
}

type ActionRequest struct {
	Capability     string `json:"capability"`
	Operation      string `json:"operation"`
	TargetResource string `json:"target_resource"`
	ProfileID      string `json:"profile_id,omitempty"`
	Audience       string `json:"audience,omitempty"`
	// Arguments contains the complete tool argument object used to derive the
	// canonical action digest. It is evaluated in memory and removed before the
	// request is written to the normal audit log.
	Arguments   json.RawMessage `json:"arguments,omitempty"`
	SideEffect  string          `json:"side_effect,omitempty"`
	Destination *Destination    `json:"destination,omitempty"`
	Bytes       int64           `json:"bytes,omitempty"`
}

type ResourceGrant struct {
	AllowedOperations []string                 `json:"allowed_operations"`
	RequiredScopes    []string                 `json:"required_scopes,omitempty"`
	Constraints       AuthorizationConstraints `json:"constraints"`
}

type CapabilityGrant struct {
	AllowedTools   []string                 `json:"allowed_tools"`
	Resources      map[string]ResourceGrant `json:"resources"`
	RequiredScopes []string                 `json:"required_scopes,omitempty"`
	Constraints    AuthorizationConstraints `json:"constraints"`
	Route          Route                    `json:"route,omitempty"`
}

type AgentPolicy struct {
	WorkloadIDs  []string                   `json:"workload_ids,omitempty"`
	Capabilities map[string]CapabilityGrant `json:"capabilities,omitempty"`

	// Deprecated compatibility fields for pre-envelope policy files.
	AllowedCapabilities []string `json:"allowed_capabilities,omitempty"`
	DeniedResources     []string `json:"denied_resources,omitempty"`
}

type ResourcePolicy struct {
	Sensitivity string   `json:"sensitivity"`
	Scopes      []string `json:"required_scopes,omitempty"`
}

type CompatibilityPolicy struct {
	AllowLegacyFlatRequests bool `json:"allow_legacy_flat_requests"`
	AllowMissingTool        bool `json:"allow_missing_tool"`
	AllowMissingOperation   bool `json:"allow_missing_operation"`
}

type PermitPolicy struct {
	TTLSeconds int    `json:"ttl_seconds"`
	Issuer     string `json:"issuer,omitempty"`
}

// PaymentSendV1Config is one of two compiled-in business-semantic profiles.
// Amount limits are integer minor currency units.
type PaymentSendV1Config struct {
	ProfileID                string           `json:"profile_id"`
	MCPTool                  string           `json:"mcp_tool"`
	Capability               string           `json:"capability"`
	Resource                 string           `json:"resource"`
	Operation                string           `json:"operation"`
	Audience                 string           `json:"audience"`
	UpstreamURL              string           `json:"upstream_url"`
	AllowedCurrencies        []string         `json:"allowed_currencies"`
	MaxAmountMinorByCurrency map[string]int64 `json:"max_amount_minor_by_currency"`
	AllowedRecipients        []string         `json:"allowed_recipients"`
}

// WorkspaceWriteV1Config binds a logical write action to a server-owned MCP
// target. Paths are logical identifiers and never host filesystem paths.
type WorkspaceWriteV1Config struct {
	ProfileID       string `json:"profile_id"`
	MCPTool         string `json:"mcp_tool"`
	Capability      string `json:"capability"`
	Resource        string `json:"resource"`
	Operation       string `json:"operation"`
	Audience        string `json:"audience"`
	UpstreamURL     string `json:"upstream_url"`
	MaxPathBytes    int    `json:"max_path_bytes"`
	MaxContentBytes int    `json:"max_content_bytes"`
}

type SemanticActionsConfig struct {
	PaymentSendV1    PaymentSendV1Config    `json:"payment_send_v1"`
	WorkspaceWriteV1 WorkspaceWriteV1Config `json:"workspace_write_v1"`
}

type PolicyConfig struct {
	Version           string                    `json:"version"`
	Agents            map[string]AgentPolicy    `json:"agents"`
	Resources         map[string]ResourcePolicy `json:"resources"`
	SensitiveActions  []string                  `json:"sensitive_actions"`
	RestrictedActions []string                  `json:"restricted_actions"`
	ProhibitedActions []string                  `json:"prohibited_actions"`
	SuspiciousActions []string                  `json:"suspicious_runtime_actions"`
	SessionControls   SessionControls           `json:"session_controls"`
	Compatibility     CompatibilityPolicy       `json:"compatibility,omitempty"`
	Permits           PermitPolicy              `json:"permits,omitempty"`
	SemanticActions   SemanticActionsConfig     `json:"semantic_actions,omitempty"`
}

type SessionControls struct {
	PrivacyReadBudget      int      `json:"privacy_read_budget"`
	CumulativeRiskLimit    int      `json:"cumulative_risk_limit"`
	EgressCapabilities     []string `json:"egress_capabilities"`
	SideEffectCapabilities []string `json:"side_effect_capabilities"`
	InjectionRiskSignals   []string `json:"injection_risk_signals"`
}

type InputSource struct {
	EventID       string   `json:"event_id,omitempty"`
	Kind          string   `json:"kind"`
	Trust         string   `json:"trust"`
	URIClass      string   `json:"uri_class,omitempty"`
	ContentSHA256 string   `json:"content_sha256,omitempty"`
	RiskSignals   []string `json:"risk_signals,omitempty"`
}

// ToolIdentity is kept as an input compatibility alias for older /api/route
// clients. New clients should send Tool.
type ToolIdentity = ToolContext

type DataAccess struct {
	Operation   string `json:"operation"`
	PathClass   string `json:"path_class,omitempty"`
	Protected   bool   `json:"protected"`
	Sensitivity string `json:"sensitivity,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
}

type Destination struct {
	Kind          string `json:"kind"`
	TrustBoundary string `json:"trust_boundary,omitempty"`
	External      bool   `json:"external"`
}

// Request is one attempted action. The structured fields are authoritative.
// Flat fields remain temporarily for the legacy /api/route shape and are
// normalized before evaluation. claimed_intent and planned_actions are
// contextual only and never authorize an action.
type Request struct {
	RequestID      string             `json:"request_id,omitempty"`
	SessionID      string             `json:"session_id,omitempty"`
	ParentEventID  string             `json:"parent_event_id,omitempty"`
	Principal      PrincipalContext   `json:"principal,omitempty"`
	Agent          AgentIdentity      `json:"agent,omitempty"`
	Authority      DelegatedAuthority `json:"delegated_authority,omitempty"`
	Tool           ToolContext        `json:"tool,omitempty"`
	Action         ActionRequest      `json:"action,omitempty"`
	ClaimedIntent  string             `json:"claimed_intent,omitempty"`
	PlannedActions []string           `json:"planned_actions,omitempty"`
	InputSources   []InputSource      `json:"input_sources,omitempty"`
	DataAccess     *DataAccess        `json:"data_access,omitempty"`

	// Deprecated flat compatibility fields. Raw tokens are intentionally not
	// represented; token_scopes contains scope labels only.
	UserID              string        `json:"user_id,omitempty"`
	AgentID             string        `json:"agent_id,omitempty"`
	TokenScopes         []string      `json:"token_scopes,omitempty"`
	RequestedAction     string        `json:"requested_action,omitempty"`
	RequestedCapability string        `json:"requested_capability,omitempty"`
	TargetResource      string        `json:"target_resource,omitempty"`
	ToolIdentity        *ToolIdentity `json:"tool_identity,omitempty"`
	Destination         *Destination  `json:"destination,omitempty"`
}

func (r Request) UsesStructuredContext() bool {
	return r.Principal.PrincipalID != "" || r.Agent.AgentID != "" ||
		r.Authority.CredentialFingerprint != "" || len(r.Authority.Scopes) > 0 ||
		r.Tool.Name != "" || r.Tool.ToolID != "" || r.Action.Capability != "" ||
		r.Action.Operation != "" || r.Action.TargetResource != ""
}

func (r Request) EffectivePrincipal() PrincipalContext {
	if r.Principal.PrincipalID != "" {
		return r.Principal
	}
	return PrincipalContext{PrincipalID: r.UserID, PrincipalType: "human"}
}

func (r Request) EffectiveAgent() AgentIdentity {
	if r.Agent.AgentID != "" {
		return r.Agent
	}
	return AgentIdentity{AgentID: r.AgentID, WorkloadID: r.AgentID}
}

func (r Request) EffectiveAuthority() DelegatedAuthority {
	if r.Authority.CredentialFingerprint != "" || len(r.Authority.Scopes) > 0 || r.Authority.Issuer != "" || r.Authority.Subject != "" || r.Authority.ExpiresAt != nil {
		return r.Authority
	}
	return DelegatedAuthority{Scopes: nonNil(r.TokenScopes), Subject: r.UserID}
}

func (r Request) EffectiveTool() ToolContext {
	if r.Tool.Name != "" || r.Tool.ToolID != "" {
		return r.Tool
	}
	if r.ToolIdentity != nil {
		return *r.ToolIdentity
	}
	return ToolContext{}
}

func (r Request) EffectiveAction() ActionRequest {
	action := r.Action
	if action.Capability == "" {
		action.Capability = r.RequestedCapability
	}
	if action.TargetResource == "" {
		action.TargetResource = r.TargetResource
	}
	if action.Operation == "" && r.DataAccess != nil {
		action.Operation = r.DataAccess.Operation
	}
	if action.Destination == nil {
		action.Destination = r.Destination
	}
	if action.Bytes == 0 && r.DataAccess != nil {
		action.Bytes = r.DataAccess.Bytes
	}
	return action
}

type AuthorizationConstraints struct {
	NetworkEgress      string   `json:"network_egress"`
	SecretAccess       string   `json:"secret_access"`
	WriteAccess        string   `json:"write_access"`
	AllowedSideEffects []string `json:"allowed_side_effects"`
	MaxBytes           int64    `json:"max_bytes,omitempty"`
	MaxDurationMS      int64    `json:"max_duration_ms,omitempty"`
	ExecutorProfile    string   `json:"executor_profile,omitempty"`
}

type MatchedAuthorizationGrant struct {
	AgentID           string                   `json:"agent_id"`
	WorkloadID        string                   `json:"workload_id"`
	Capability        string                   `json:"capability"`
	Tool              string                   `json:"tool"`
	Resource          string                   `json:"resource"`
	AllowedOperations []string                 `json:"allowed_operations"`
	RequiredScopes    []string                 `json:"required_scopes"`
	Constraints       AuthorizationConstraints `json:"constraints"`
}

type PolicyDecision struct {
	Authorized bool                       `json:"authorized"`
	Status     AuthorizationStatus        `json:"status"`
	Route      Route                      `json:"route"`
	Reasons    []string                   `json:"reasons"`
	Rules      []string                   `json:"matched_rules"`
	Grant      *MatchedAuthorizationGrant `json:"matched_grant,omitempty"`
}

// ExecutionObligations are requirements for an executor. Aegis verifies that
// the exact authorized action is presented; it does not itself provide an
// isolation or network sandbox backend.
type ExecutionObligations struct {
	IsolationRequired     bool `json:"isolation_required"`
	NetworkEgressDenied   bool `json:"network_egress_denied"`
	ReadOnly              bool `json:"read_only"`
	HumanApprovalRequired bool `json:"human_approval_required"`
	EnhancedAuditRequired bool `json:"enhanced_audit_required"`
}

type RiskAssessment struct {
	Score        int      `json:"score"`
	Level        string   `json:"level"`
	Signals      []string `json:"signals"`
	AdvisoryOnly bool     `json:"advisory_only"`
}

type DispatchDecision struct {
	Route                   Route    `json:"route"`
	Reasons                 []string `json:"reasons"`
	Rules                   []string `json:"matched_rules"`
	ExecutorProfile         string   `json:"executor_profile"`
	IsolationBackend        string   `json:"isolation_backend"`
	ExecutorInvoked         bool     `json:"executor_invoked"`
	LegacyCompatibilityOnly bool     `json:"legacy_compatibility_only"`
}

type AuthorizationEnvelope struct {
	PermitID                       string                   `json:"permit_id"`
	SigningKeyID                   string                   `json:"signing_key_id"`
	PermitClass                    string                   `json:"permit_class"`
	ProfileID                      string                   `json:"profile_id,omitempty"`
	Audience                       string                   `json:"audience,omitempty"`
	RequestID                      string                   `json:"request_id"`
	SessionID                      string                   `json:"session_id,omitempty"`
	PrincipalID                    string                   `json:"principal_id"`
	AgentID                        string                   `json:"agent_id"`
	WorkloadID                     string                   `json:"workload_id"`
	ExecutorKeyID                  string                   `json:"executor_key_id,omitempty"`
	ExecutorKeyThumbprint          string                   `json:"executor_key_thumbprint,omitempty"`
	DelegatedCredentialFingerprint string                   `json:"delegated_credential_fingerprint,omitempty"`
	AllowedCapability              string                   `json:"allowed_capability"`
	AllowedTool                    string                   `json:"allowed_tool"`
	AllowedResource                string                   `json:"allowed_resource"`
	AllowedOperation               string                   `json:"allowed_operation"`
	AllowedOperations              []string                 `json:"allowed_operations"`
	ActionDigest                   string                   `json:"action_digest"`
	PolicyVersion                  string                   `json:"policy_version"`
	Issuer                         string                   `json:"issuer"`
	SingleUse                      bool                     `json:"single_use"`
	State                          string                   `json:"state"`
	Obligations                    ExecutionObligations     `json:"obligations"`
	Constraints                    AuthorizationConstraints `json:"constraints"`
	IssuedAt                       time.Time                `json:"issued_at"`
	ExpiresAt                      time.Time                `json:"expires_at"`
	Route                          Route                    `json:"route"`
}

// PermitCredential is returned only to the caller that requested a new
// authorization. PermitToken is never embedded in AuditRecord or PermitView.
type PermitCredential struct {
	PermitID     string    `json:"permit_id"`
	SigningKeyID string    `json:"signing_key_id"`
	PermitClass  string    `json:"permit_class"`
	ProfileID    string    `json:"profile_id,omitempty"`
	Audience     string    `json:"audience,omitempty"`
	PermitToken  string    `json:"permit_token"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	SingleUse    bool      `json:"single_use"`
}

type ActionAuthorizationResponse struct {
	Decision AuditRecord       `json:"decision"`
	Permit   *PermitCredential `json:"permit,omitempty"`
}

type PermitVerification struct {
	PermitID       string               `json:"permit_id,omitempty"`
	RequestID      string               `json:"request_id,omitempty"`
	PermitClass    string               `json:"permit_class,omitempty"`
	ProfileID      string               `json:"profile_id,omitempty"`
	Audience       string               `json:"audience,omitempty"`
	Outcome        string               `json:"verification_result"`
	Verified       bool                 `json:"verified"`
	State          string               `json:"permit_state,omitempty"`
	Obligations    ExecutionObligations `json:"obligations"`
	VerifiedAt     time.Time            `json:"verified_at"`
	EvidenceSource string               `json:"evidence_source"`
}

type ExecutionReceipt struct {
	RequestID             string              `json:"request_id"`
	DecisionID            string              `json:"decision_id"`
	PermitID              string              `json:"permit_id,omitempty"`
	PermitClass           string              `json:"permit_class,omitempty"`
	ProfileID             string              `json:"profile_id,omitempty"`
	Audience              string              `json:"audience,omitempty"`
	PrincipalID           string              `json:"principal_id"`
	AgentID               string              `json:"agent_id"`
	WorkloadID            string              `json:"workload_id"`
	Tool                  string              `json:"tool"`
	Capability            string              `json:"capability"`
	Resource              string              `json:"resource"`
	Operation             string              `json:"operation"`
	ActionDigest          string              `json:"action_digest,omitempty"`
	PolicyVersion         string              `json:"policy_version"`
	AuthorizationDecision AuthorizationStatus `json:"authorization_decision"`
	PermitState           string              `json:"permit_state,omitempty"`
	VerificationOutcome   string              `json:"verification_outcome,omitempty"`
	UpstreamAttempted     bool                `json:"upstream_attempted"`
	ExecutionOutcome      string              `json:"execution_outcome,omitempty"`
	Timestamp             time.Time           `json:"timestamp"`
	EvidenceSource        RuntimeEventSource  `json:"evidence_source"`
}

type RuntimeEventSource string
type RuntimeTrustLevel string

const (
	RuntimeSourceGatewayEnforced     RuntimeEventSource = "gateway_enforced"
	RuntimeSourceInstrumentedAdapter RuntimeEventSource = "instrumented_adapter"
	RuntimeSourceAgentSelfReported   RuntimeEventSource = "agent_self_reported"
	RuntimeSourceOSSensor            RuntimeEventSource = "os_sensor"
	RuntimeSourceNetworkSensor       RuntimeEventSource = "network_sensor"
	RuntimeSourceSimulatedDemo       RuntimeEventSource = "simulated_demo"

	RuntimeTrustEnforced          RuntimeTrustLevel = "enforced"
	RuntimeTrustAdapterReported   RuntimeTrustLevel = "adapter_reported"
	RuntimeTrustSelfReported      RuntimeTrustLevel = "self_reported"
	RuntimeTrustIndependentSensor RuntimeTrustLevel = "independent_sensor"
	RuntimeTrustSimulated         RuntimeTrustLevel = "simulated"
)

type RuntimeEvent struct {
	EventID          string             `json:"event_id"`
	PermitID         string             `json:"permit_id"`
	RequestID        string             `json:"request_id"`
	SessionID        string             `json:"session_id,omitempty"`
	AgentID          string             `json:"agent_id"`
	WorkloadID       string             `json:"workload_id,omitempty"`
	Source           RuntimeEventSource `json:"source"`
	TrustLevel       RuntimeTrustLevel  `json:"trust_level"`
	Capability       string             `json:"capability"`
	Tool             string             `json:"tool"`
	Operation        string             `json:"operation"`
	Resource         string             `json:"resource"`
	ResourceClass    string             `json:"resource_class,omitempty"`
	DestinationClass string             `json:"destination_class,omitempty"`
	External         bool               `json:"external"`
	SecretAccess     bool               `json:"secret_access"`
	SideEffect       string             `json:"side_effect,omitempty"`
	Bytes            int64              `json:"bytes,omitempty"`
	Timestamp        time.Time          `json:"timestamp"`
}

type AuthorizationViolation struct {
	Rule     string `json:"rule"`
	Summary  string `json:"summary"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

type RuntimeEventEvaluation struct {
	EventID        string                   `json:"event_id"`
	PermitID       string                   `json:"permit_id"`
	Accepted       bool                     `json:"accepted"`
	WithinEnvelope bool                     `json:"within_authorization_envelope"`
	Terminated     bool                     `json:"execution_terminated"`
	Verdict        string                   `json:"verdict"`
	Violations     []AuthorizationViolation `json:"violations"`
}

type RuntimeCoverage struct {
	GatewayRequests  string `json:"gateway_requests"`
	ToolEvents       string `json:"tool_events"`
	Filesystem       string `json:"filesystem"`
	Network          string `json:"network"`
	OSSyscalls       string `json:"os_syscalls"`
	IsolationBackend string `json:"isolation_backend"`
}

type RuntimeObservation struct {
	Events                  []RuntimeEvent           `json:"events"`
	EventEvaluations        []RuntimeEventEvaluation `json:"event_evaluations"`
	AuthorizationViolations []AuthorizationViolation `json:"authorization_violations"`
	Coverage                RuntimeCoverage          `json:"coverage"`

	// Deprecated descriptive fields. They are never populated from a request
	// and are not the authorization boundary.
	PlannedActions    []string `json:"planned_actions,omitempty"`
	ActualActions     []string `json:"actual_actions,omitempty"`
	UnexpectedActions []string `json:"unexpected_actions,omitempty"`
	SuspiciousActions []string `json:"suspicious_actions,omitempty"`
	DriftDetected     bool     `json:"drift_detected"`
}

type SecurityFinding struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Rule     string   `json:"rule"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence"`
}

type CausalContext struct {
	SessionID              string   `json:"session_id"`
	EventID                string   `json:"event_id"`
	ParentEventID          string   `json:"parent_event_id,omitempty"`
	Ancestors              []string `json:"ancestors"`
	CumulativeRisk         int      `json:"cumulative_risk"`
	PrivacyBudgetRemaining int      `json:"privacy_budget_remaining"`
}

// AdvisorySignals contains non-authoritative risk and request/session
// detection output. These values may enrich an audit record, but they never
// decide policy authorization, Permit issuance, obligations, or execution.
type AdvisorySignals struct {
	RiskAssessment    RiskAssessment    `json:"risk_assessment"`
	DetectionFindings []SecurityFinding `json:"detection_findings"`
	CausalContext     CausalContext     `json:"causal_context"`
}

type ExecutionCompletion struct {
	RequestID         string    `json:"request_id"`
	PermitID          string    `json:"permit_id"`
	Status            string    `json:"status"`
	BoundaryOutcome   string    `json:"boundary_outcome,omitempty"`
	UpstreamAttempted bool      `json:"upstream_attempted"`
	CompletedAt       time.Time `json:"completed_at,omitempty"`
}

// AuthorizationContextProvenance records how identity was established before
// policy evaluation. It contains no credential or raw identity assertion.
type AuthorizationContextProvenance struct {
	Source        string    `json:"source"`
	ProviderID    string    `json:"provider_id"`
	Assurance     string    `json:"assurance"`
	EstablishedAt time.Time `json:"established_at"`
}

type AuditRecord struct {
	RequestID             string                          `json:"request_id"`
	DecisionID            string                          `json:"decision_id"`
	AuthorizationStatus   AuthorizationStatus             `json:"authorization_status"`
	CreatedAt             time.Time                       `json:"created_at"`
	CompletedAt           *time.Time                      `json:"completed_at,omitempty"`
	AuthorizationContext  *AuthorizationContextProvenance `json:"authorization_context_provenance,omitempty"`
	Request               Request                         `json:"request"`
	PolicyDecision        PolicyDecision                  `json:"policy_decision"`
	Obligations           ExecutionObligations            `json:"obligations"`
	AuthorizationEnvelope *AuthorizationEnvelope          `json:"authorization_envelope,omitempty"`
	ExecutionReceipt      *ExecutionReceipt               `json:"execution_receipt,omitempty"`
	RuntimeObservation    RuntimeObservation              `json:"runtime_observation"`
	SecurityFindings      []SecurityFinding               `json:"security_findings"`
	AdvisorySignals       AdvisorySignals                 `json:"advisory_signals"`

	// Deprecated compatibility projections. Permit issuance and MCP
	// enforcement do not depend on these fields.
	RiskAssessment   RiskAssessment   `json:"risk_assessment"`
	DispatchDecision DispatchDecision `json:"dispatch_decision"`
	SelectedExecutor string           `json:"selected_executor"`
	CausalContext    CausalContext    `json:"causal_context"`
	FinalVerdict     string           `json:"final_verdict"`
	DurationMS       int64            `json:"duration_ms"`
}

type Scenario struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Description   string         `json:"description"`
	Expected      Route          `json:"expected_route"`
	Request       Request        `json:"request"`
	SimulatedDemo []RuntimeEvent `json:"simulated_demo,omitempty"`
}

func IsWriteOperation(operation string) bool {
	switch strings.ToLower(operation) {
	case "write", "create", "update", "delete", "append", "execute", "invoke", "admin":
		return true
	default:
		return false
	}
}

func nonNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}
