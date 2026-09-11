package router

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"agent-governance-gateway/internal/audit"
	"agent-governance-gateway/internal/canonicalaction"
	"agent-governance-gateway/internal/detection"
	"agent-governance-gateway/internal/intake"
	"agent-governance-gateway/internal/keyprovider"
	"agent-governance-gateway/internal/models"
	"agent-governance-gateway/internal/observer"
	"agent-governance-gateway/internal/permit"
	"agent-governance-gateway/internal/policy"
	"agent-governance-gateway/internal/risk"
	"agent-governance-gateway/internal/semanticaction"
	"agent-governance-gateway/internal/verifier"
)

// ErrStructuredExecutionContextRequired prevents legacy identity projection
// from becoming eligible for a real execution Permit.
var ErrStructuredExecutionContextRequired = errors.New("execution permit requires structured security context")

type Router struct {
	policy           *policy.Engine
	risk             *risk.Scorer
	observer         *observer.Observer
	audit            *audit.Store
	detection        *detection.Engine
	clock            func() time.Time
	permitTTL        time.Duration
	policyVersion    string
	permitIssuer     *permit.Issuer
	permitStore      *permit.MemoryStore
	permitVerifier   *verifier.Verifier
	semanticRegistry *semanticaction.Registry

	mu      sync.RWMutex
	permits map[string]models.AuthorizationEnvelope
}

func New(cfg models.PolicyConfig, store *audit.Store) *Router {
	return NewWithClock(cfg, store, time.Now)
}

func NewWithClock(cfg models.PolicyConfig, store *audit.Store, clock func() time.Time) *Router {
	provider, err := keyprovider.NewEphemeral()
	if err != nil {
		panic(fmt.Sprintf("initialize execution-permit signing key: %v", err))
	}
	return NewWithClockAndKeyProvider(cfg, store, clock, provider)
}

// NewWithKeyProvider lets an embedding process supply a persistent local key
// provider without coupling Aegis permit logic to a key-file or KMS format.
func NewWithKeyProvider(cfg models.PolicyConfig, store *audit.Store, provider keyprovider.Provider) *Router {
	return NewWithClockAndKeyProvider(cfg, store, time.Now, provider)
}

func NewWithClockAndKeyProvider(cfg models.PolicyConfig, store *audit.Store, clock func() time.Time, provider keyprovider.Provider) *Router {
	if clock == nil {
		clock = time.Now
	}
	if provider == nil {
		panic("initialize execution-permit signing key: key provider is required")
	}
	ttl := time.Duration(cfg.Permits.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = permit.DefaultTTL
	}
	if ttl > permit.MaxTTL {
		ttl = permit.MaxTTL
	}
	issuerName := strings.TrimSpace(cfg.Permits.Issuer)
	if issuerName == "" {
		issuerName = "aegis-router"
	}
	policyVersion := strings.TrimSpace(cfg.Version)
	if policyVersion == "" {
		policyVersion = "policy-v1"
	}
	permitStore := permit.NewMemoryStore()
	issuer, err := permit.NewIssuer(issuerName, provider, permitStore, permit.WithIssuerClock(clock))
	if err != nil {
		panic(fmt.Sprintf("initialize execution-permit issuer: %v", err))
	}
	permitVerifier, err := verifier.New(provider, issuerName, permitStore, verifier.WithClock(clock))
	if err != nil {
		panic(fmt.Sprintf("initialize execution-permit verifier: %v", err))
	}
	semanticRegistry, err := semanticaction.NewRegistryFromConfig(cfg.SemanticActions)
	if err != nil {
		panic(fmt.Sprintf("initialize semantic action registry: %v", err))
	}
	return &Router{
		policy: policy.New(cfg), risk: risk.New(cfg), observer: observer.New(cfg), audit: store,
		detection: detection.New(cfg.SessionControls), clock: clock, permitTTL: ttl,
		policyVersion: policyVersion, permitIssuer: issuer, permitStore: permitStore, permitVerifier: permitVerifier,
		semanticRegistry: semanticRegistry,
		permits:          make(map[string]models.AuthorizationEnvelope),
	}
}

// AuthorizeTrustedAction is the only normal execution-permit issuance entry
// point. The sealed intake value proves that a configured trust boundary
// resolved the security identity instead of the Router trusting a naked
// models.Request. In-process integrations must explicitly construct this
// value through intake.NewTrustedAuthorization or an intake implementation.
// Even a sealed value is Permit-eligible only when it retains the full
// structured security context; deprecated flat projections fail here.
func (r *Router) AuthorizeTrustedAction(authorization intake.Authorization) (models.ActionAuthorizationResponse, error) {
	if !authorization.Valid() {
		return models.ActionAuthorizationResponse{}, intake.ErrTrustedContextRequired
	}
	request := authorization.Request()
	if !request.UsesStructuredContext() {
		return models.ActionAuthorizationResponse{}, ErrStructuredExecutionContextRequired
	}
	return r.authorizeResolvedAction(request, authorization.Provenance(), authorization.WorkloadBinding(), permit.ClassExecution, 0)
}

// AuthorizeSyntheticDemoAction is restricted to server-owned fixtures. It
// permits a shorter TTL so expiration can be demonstrated without changing
// the production policy or accepting a client-controlled lifetime.
func (r *Router) AuthorizeSyntheticDemoAction(req models.Request, ttl time.Duration) (models.ActionAuthorizationResponse, error) {
	return r.authorizeResolvedAction(req, models.AuthorizationContextProvenance{
		Source: "server_owned_fixture", ProviderID: "aegis-demo-lab",
		Assurance: "simulated_demo",
	}, intake.WorkloadBinding{}, permit.ClassSimulation, ttl)
}

func (r *Router) authorizeResolvedAction(req models.Request, provenance models.AuthorizationContextProvenance, workloadBinding intake.WorkloadBinding, permitClass permit.Class, ttlOverride time.Duration) (models.ActionAuthorizationResponse, error) {
	if err := Validate(req); err != nil {
		return models.ActionAuthorizationResponse{}, err
	}
	started := r.clock().UTC()
	if provenance.EstablishedAt.IsZero() {
		provenance.EstablishedAt = started
	}
	if req.RequestID == "" {
		req.RequestID = newIdentifier("req")
	}

	// Only deterministic policy output controls status, obligations, and Permit
	// issuance. Risk and request/session detection run later solely to enrich
	// advisory audit metadata.
	policyDecision := r.policy.Evaluate(req)
	status := policyDecision.Status
	obligations := policyObligations(policyDecision)
	decisionID := newIdentifier("decision")

	var resolvedAction canonicalaction.Action
	var resolved bool
	if status == models.AuthorizationStatusAuthorized && policyDecision.Authorized && policyDecision.Grant != nil {
		candidate, resolveErr := r.resolveAuthorizedAction(req, *policyDecision.Grant, permitClass)
		if resolveErr != nil {
			code := string(semanticaction.Code(resolveErr))
			policyDecision.Authorized = false
			policyDecision.Status = models.AuthorizationStatusDenied
			policyDecision.Route = models.RouteDeny
			policyDecision.Reasons = append(policyDecision.Reasons, code)
			policyDecision.Rules = append(policyDecision.Rules, "semantic_action."+strings.ToLower(code))
			policyDecision.Grant = nil
			status = models.AuthorizationStatusDenied
			obligations = models.ExecutionObligations{}
		} else {
			resolvedAction = candidate
			resolved = true
		}
	}
	dispatch := compatibilityDispatchFor(policyDecision)

	observation := models.RuntimeObservation{
		Events: []models.RuntimeEvent{}, EventEvaluations: []models.RuntimeEventEvaluation{},
		AuthorizationViolations: []models.AuthorizationViolation{},
		PlannedActions:          nonNil(req.PlannedActions), ActualActions: []string{},
		UnexpectedActions: []string{}, SuspiciousActions: []string{},
		Coverage: r.RuntimeCoverage(),
	}

	var envelope *models.AuthorizationEnvelope
	var credential *models.PermitCredential
	var actionDigest string
	if policyDecision.Grant != nil {
		action := canonicalAction(req, *policyDecision.Grant)
		if resolved {
			action = resolvedAction
		}
		var err error
		actionDigest, err = action.Digest()
		if err != nil {
			return models.ActionAuthorizationResponse{}, fmt.Errorf("canonicalize authorized action: %w", err)
		}
	}
	if status == models.AuthorizationStatusAuthorized && policyDecision.Authorized && policyDecision.Grant != nil {
		issued, issueErr := r.issuePermit(req, *policyDecision.Grant, obligations, resolvedActionOrDefault(resolvedAction, resolved, req, *policyDecision.Grant), actionDigest, started, workloadBinding, permitClass, ttlOverride)
		if issueErr != nil {
			return models.ActionAuthorizationResponse{}, issueErr
		}
		envelope = envelopeFor(issued, req.SessionID, policyDecision.Grant.Constraints, dispatch.Route)
		credential = &models.PermitCredential{
			PermitID: issued.PermitID, SigningKeyID: issued.Claims.SigningKeyID, PermitClass: string(issued.Claims.PermitClass),
			ProfileID: issued.Claims.ProfileID, Audience: issued.Claims.Audience, PermitToken: issued.Token(), IssuedAt: issued.Claims.IssuedTime(),
			ExpiresAt: issued.Claims.ExpiresTime(), SingleUse: issued.Claims.SingleUse,
		}
		r.mu.Lock()
		r.permits[envelope.PermitID] = *envelope
		r.mu.Unlock()
	}

	// Advisory evaluation deliberately occurs only after the deterministic
	// Permit decision has been completed. Its scores, findings, and recommended
	// routes cannot change status, obligations, or whether a Permit exists.
	advisory := r.evaluateAdvisorySignals(req)
	assessment := advisory.RiskAssessment
	detectedContext := advisory.CausalContext

	auditRequest := privacySafeRequest(req)
	receipt := authorizationReceipt(decisionID, req, status, envelope, actionDigest, r.policyVersion, started)
	record := models.AuditRecord{
		RequestID: req.RequestID, DecisionID: decisionID, AuthorizationStatus: status,
		CreatedAt: started, Request: auditRequest, AuthorizationContext: &provenance,
		PolicyDecision: policyDecision, Obligations: obligations,
		AuthorizationEnvelope: envelope, ExecutionReceipt: receipt, SelectedExecutor: dispatch.ExecutorProfile,
		RuntimeObservation: observation, SecurityFindings: []models.SecurityFinding{}, AdvisorySignals: advisory,
		RiskAssessment: assessment, DispatchDecision: dispatch, CausalContext: detectedContext,
		FinalVerdict: authorizationVerdict(status),
		DurationMS:   elapsedMilliseconds(started, r.clock().UTC()),
	}
	if err := r.audit.Append(record); err != nil {
		if envelope != nil {
			_, _ = r.permitStore.Revoke(envelope.PermitID, r.clock().UTC())
			r.mu.Lock()
			delete(r.permits, envelope.PermitID)
			r.mu.Unlock()
		}
		return models.ActionAuthorizationResponse{}, err
	}
	return models.ActionAuthorizationResponse{Decision: record, Permit: credential}, nil
}

func (r *Router) evaluateAdvisorySignals(req models.Request) models.AdvisorySignals {
	assessment := models.RiskAssessment{
		Level: "not_evaluated", Signals: []string{"advisory risk analysis is disabled"}, AdvisoryOnly: true,
	}
	if r.risk == nil {
		return models.AdvisorySignals{RiskAssessment: assessment, DetectionFindings: []models.SecurityFinding{}}
	}
	assessment = r.risk.Assess(req)
	assessment.AdvisoryOnly = true
	if r.detection == nil {
		return models.AdvisorySignals{RiskAssessment: assessment, DetectionFindings: []models.SecurityFinding{}}
	}
	detected := r.detection.Evaluate(req, assessment.Score)
	assessment = mergeAdvisoryRisk(assessment, detected)
	return models.AdvisorySignals{
		RiskAssessment: assessment, DetectionFindings: nonNilFindings(detected.Findings),
		CausalContext: detected.Context,
	}
}

// VerifyAndConsume is the only authorization method an executor should trust.
// A permit identifier alone is never accepted as an execution credential.
func (r *Router) VerifyAndConsume(permitToken string, action canonicalaction.Action) (models.PermitVerification, error) {
	return r.verifyAndConsume(permitToken, action, permit.ClassExecution, models.RuntimeSourceGatewayEnforced)
}

// RegisterWorkloadPublicKey configures an Ed25519 executor key used for MCP
// proof-of-possession checks. Registration is local and exposes no HTTP API.
func (r *Router) RegisterWorkloadPublicKey(keyID string, publicKey ed25519.PublicKey) error {
	return r.permitVerifier.RegisterWorkloadPublicKey(keyID, publicKey)
}

// VerifyExecutionProof authenticates the workload proof without consuming the
// execution Permit. Failed proof checks are audited at the gateway boundary.
func (r *Router) VerifyExecutionProof(permitToken, proofToken string, action canonicalaction.Action, httpMethod, httpPath string) (models.PermitVerification, error) {
	result := r.permitVerifier.VerifyExecutionProof(permitToken, proofToken, action, httpMethod, httpPath)
	verification := permitVerification(result, models.RuntimeSourceGatewayEnforced)
	if result.Allowed() {
		return verification, nil
	}
	return r.auditPermitVerification(result, models.RuntimeSourceGatewayEnforced, verification)
}

func (r *Router) VerifySyntheticDemo(permitToken string, action canonicalaction.Action) (models.PermitVerification, error) {
	return r.verifyAndConsume(permitToken, action, permit.ClassSimulation, models.RuntimeSourceSimulatedDemo)
}

func (r *Router) verifyAndConsume(permitToken string, action canonicalaction.Action, expectedClass permit.Class, source models.RuntimeEventSource) (models.PermitVerification, error) {
	var result verifier.Result
	if expectedClass == permit.ClassSimulation {
		result = r.permitVerifier.VerifySimulationAndConsume(permitToken, action)
	} else {
		result = r.permitVerifier.VerifyAndConsume(permitToken, action)
	}
	verification := permitVerification(result, source)
	return r.auditPermitVerification(result, source, verification)
}

func permitVerification(result verifier.Result, source models.RuntimeEventSource) models.PermitVerification {
	verification := models.PermitVerification{
		PermitID: result.PermitID, RequestID: result.RequestID, Outcome: string(result.Outcome),
		Verified: result.Allowed(), State: string(result.State), VerifiedAt: result.VerifiedAt,
		EvidenceSource: string(source),
	}
	if result.Claims != nil {
		verification.PermitClass = string(result.Claims.PermitClass)
		verification.ProfileID = result.Claims.ProfileID
		verification.Audience = result.Claims.Audience
		verification.Obligations = models.ExecutionObligations{
			IsolationRequired:     result.Claims.Obligations.IsolationRequired,
			NetworkEgressDenied:   result.Claims.Obligations.NetworkEgressDenied,
			ReadOnly:              result.Claims.Obligations.ReadOnly,
			HumanApprovalRequired: result.Claims.Obligations.HumanApprovalRequired,
			EnhancedAuditRequired: result.Claims.Obligations.EnhancedAuditRequired,
		}
	}
	return verification
}

func (r *Router) auditPermitVerification(result verifier.Result, source models.RuntimeEventSource, verification models.PermitVerification) (models.PermitVerification, error) {
	if result.RequestID == "" {
		attemptID, auditErr := r.auditUnboundVerificationFailure(result, source)
		verification.RequestID = attemptID
		return verification, auditErr
	}
	_, err := r.audit.Mutate(result.RequestID, func(record *models.AuditRecord) error {
		if record.AuthorizationEnvelope != nil && record.AuthorizationEnvelope.PermitID == result.PermitID {
			record.AuthorizationEnvelope.State = string(result.State)
		}
		existingOutcome := ""
		if record.ExecutionReceipt != nil {
			existingOutcome = record.ExecutionReceipt.VerificationOutcome
			record.ExecutionReceipt.PermitState = string(result.State)
			if verificationOutcomePriority(string(result.Outcome)) >= verificationOutcomePriority(existingOutcome) {
				record.ExecutionReceipt.VerificationOutcome = string(result.Outcome)
				record.ExecutionReceipt.Timestamp = result.VerifiedAt
				record.ExecutionReceipt.EvidenceSource = source
			}
		}
		if verificationOutcomePriority(string(result.Outcome)) >= verificationOutcomePriority(existingOutcome) {
			record.FinalVerdict = permitVerdict(result.Outcome)
		}
		record.DurationMS = elapsedMilliseconds(record.CreatedAt, result.VerifiedAt)
		return nil
	})
	if err != nil {
		return verification, err
	}
	return verification, nil
}

func (r *Router) auditUnboundVerificationFailure(result verifier.Result, source models.RuntimeEventSource) (string, error) {
	attemptID := newIdentifier("verify")
	decisionID := newIdentifier("decision")
	verdict := permitVerdict(result.Outcome)
	record := models.AuditRecord{
		RequestID: attemptID, DecisionID: decisionID, AuthorizationStatus: models.AuthorizationStatusDenied,
		CreatedAt: result.VerifiedAt,
		PolicyDecision: models.PolicyDecision{
			Authorized: false, Status: models.AuthorizationStatusDenied, Route: models.RouteDeny,
			Reasons: []string{"the execution credential could not be authenticated; token claims were not trusted"},
			Rules:   []string{"permit.untrusted_credential"},
		},
		RiskAssessment:   models.RiskAssessment{Level: "not_evaluated", Signals: []string{"verification failed before trusted claims were available"}, AdvisoryOnly: true},
		DispatchDecision: dispatch(models.RouteDeny, "none", "not_applicable", []string{"execution blocked at the permit boundary"}, []string{"permit.untrusted_credential"}),
		ExecutionReceipt: &models.ExecutionReceipt{
			RequestID: attemptID, DecisionID: decisionID, AuthorizationDecision: models.AuthorizationStatusDenied,
			VerificationOutcome: string(result.Outcome), Timestamp: result.VerifiedAt, EvidenceSource: source,
		},
		RuntimeObservation: models.RuntimeObservation{
			Events: []models.RuntimeEvent{}, EventEvaluations: []models.RuntimeEventEvaluation{},
			AuthorizationViolations: []models.AuthorizationViolation{}, PlannedActions: []string{}, ActualActions: []string{},
			UnexpectedActions: []string{}, SuspiciousActions: []string{}, Coverage: r.RuntimeCoverage(),
		},
		SecurityFindings: []models.SecurityFinding{}, AdvisorySignals: models.AdvisorySignals{
			RiskAssessment:    models.RiskAssessment{Level: "not_evaluated", Signals: []string{"verification failed before trusted claims were available"}, AdvisoryOnly: true},
			DetectionFindings: []models.SecurityFinding{},
		}, FinalVerdict: verdict,
	}
	if err := r.audit.Append(record); err != nil {
		return attemptID, err
	}
	return attemptID, nil
}

func verificationOutcomePriority(outcome string) int {
	if outcome == "" {
		return 0
	}
	if outcome == string(verifier.OutcomeVerified) {
		return 1
	}
	return 2
}

func (r *Router) VerifyRequestAndConsume(permitToken string, req models.Request) (models.PermitVerification, error) {
	if strings.TrimSpace(permitToken) == "" {
		return models.PermitVerification{}, fmt.Errorf("permit_token is required")
	}
	if err := Validate(req); err != nil {
		return models.PermitVerification{}, err
	}
	action, err := r.resolveExecutionAction(req)
	if err != nil {
		return models.PermitVerification{}, err
	}
	return r.VerifyAndConsume(permitToken, action)
}

func (r *Router) VerifySyntheticDemoRequest(permitToken string, req models.Request) (models.PermitVerification, error) {
	if strings.TrimSpace(permitToken) == "" {
		return models.PermitVerification{}, fmt.Errorf("permit_token is required")
	}
	if err := Validate(req); err != nil {
		return models.PermitVerification{}, err
	}
	return r.VerifySyntheticDemo(permitToken, executionAction(req))
}

func (r *Router) ListPermits() []permit.Record {
	return r.permitStore.List(r.clock().UTC())
}

func (r *Router) GetPermit(permitID string) (permit.Record, bool) {
	return r.permitStore.Get(permitID, r.clock().UTC())
}

func (r *Router) RevokePermit(permitID string) (permit.Record, error) {
	now := r.clock().UTC()
	record, err := r.permitStore.Revoke(permitID, now)
	if err != nil {
		return record, err
	}
	r.mu.Lock()
	delete(r.permits, permitID)
	r.mu.Unlock()
	if _, ok := r.audit.Get(record.Claims.RequestID); ok {
		_, updateErr := r.audit.Mutate(record.Claims.RequestID, func(auditRecord *models.AuditRecord) error {
			if auditRecord.AuthorizationEnvelope != nil {
				auditRecord.AuthorizationEnvelope.State = string(record.State)
			}
			if auditRecord.ExecutionReceipt != nil {
				auditRecord.ExecutionReceipt.PermitState = string(record.State)
				auditRecord.ExecutionReceipt.VerificationOutcome = string(verifier.OutcomeRevoked)
				auditRecord.ExecutionReceipt.Timestamp = now
			}
			auditRecord.FinalVerdict = "PERMIT_REVOKED"
			auditRecord.DurationMS = elapsedMilliseconds(auditRecord.CreatedAt, now)
			return nil
		})
		if updateErr != nil {
			return record, updateErr
		}
	}
	return record, nil
}

func authorizationReceipt(decisionID string, req models.Request, status models.AuthorizationStatus, envelope *models.AuthorizationEnvelope, digest, policyVersion string, at time.Time) *models.ExecutionReceipt {
	principal := req.EffectivePrincipal()
	agent := req.EffectiveAgent()
	tool := req.EffectiveTool().Name
	action := req.EffectiveAction()
	permitID, permitState, permitClass, profileID, audience := "", "", "", "", ""
	if envelope != nil {
		permitID, permitState = envelope.PermitID, envelope.State
		permitClass = envelope.PermitClass
		profileID, audience = envelope.ProfileID, envelope.Audience
		tool = envelope.AllowedTool
		action.Capability = envelope.AllowedCapability
		action.TargetResource = envelope.AllowedResource
		action.Operation = envelope.AllowedOperation
	}
	return &models.ExecutionReceipt{
		RequestID: req.RequestID, DecisionID: decisionID, PermitID: permitID, PermitClass: permitClass,
		ProfileID: profileID, Audience: audience,
		PrincipalID: principal.PrincipalID, AgentID: agent.AgentID, WorkloadID: agent.WorkloadID,
		Tool: tool, Capability: action.Capability, Resource: action.TargetResource, Operation: action.Operation,
		ActionDigest: digest, PolicyVersion: policyVersion, AuthorizationDecision: status,
		PermitState: permitState, Timestamp: at, EvidenceSource: models.RuntimeSourceGatewayEnforced,
	}
}

func permitVerdict(outcome verifier.Outcome) string {
	switch outcome {
	case verifier.OutcomeVerified:
		return "PERMIT_VERIFIED"
	case verifier.OutcomeActionMismatch, verifier.OutcomeWrongPrincipal, verifier.OutcomeWrongAgent,
		verifier.OutcomeWrongWorkload, verifier.OutcomeWrongDelegation, verifier.OutcomeWrongTool,
		verifier.OutcomeWrongCapability, verifier.OutcomeWrongResource, verifier.OutcomeWrongOperation,
		verifier.OutcomeWrongProfile, verifier.OutcomeWrongAudience:
		return "PERMIT_ACTION_MISMATCH"
	case verifier.OutcomeExpired:
		return "PERMIT_EXPIRED"
	case verifier.OutcomeReplayed:
		return "PERMIT_REPLAY"
	case verifier.OutcomeRevoked:
		return "PERMIT_REVOKED"
	case verifier.OutcomeInvalidSignature:
		return "PERMIT_INVALID_SIGNATURE"
	case verifier.OutcomeWrongPermitClass:
		return "PERMIT_CLASS_MISMATCH"
	case verifier.OutcomeWrongExecutor:
		return "PERMIT_WRONG_EXECUTOR"
	default:
		return "PERMIT_REJECTED"
	}
}

// IngestRuntimeEvent accepts privacy-preserving metadata from a named evidence
// source and evaluates it against the permit. Source/trust mismatches, expired
// permits, and identity/request mismatches are explicitly rejected.
func (r *Router) IngestRuntimeEvent(event models.RuntimeEvent) (models.RuntimeEventEvaluation, error) {
	now := r.clock().UTC()
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	if violation := validateRuntimeMetadata(event); violation != nil {
		evaluation := rejectedEvaluation(event, *violation)
		if err := r.auditRejectedEvent(event, evaluation, false, now); err != nil {
			return evaluation, err
		}
		return evaluation, nil
	}

	r.mu.Lock()
	permit, ok := r.permits[event.PermitID]
	if !ok {
		r.mu.Unlock()
		evaluation := rejectedEvaluation(event, models.AuthorizationViolation{
			Rule: "runtime.permit_unknown", Summary: "runtime event references an unknown execution permit",
			Expected: "active permit", Actual: event.PermitID,
		})
		if err := r.auditRejectedEvent(event, evaluation, true, now); err != nil {
			return evaluation, err
		}
		return evaluation, nil
	}

	evaluation := r.observer.Evaluate(permit, event, now)
	if evaluation.Terminated {
		delete(r.permits, permit.PermitID)
	}
	r.mu.Unlock()
	if evaluation.Terminated {
		_, _ = r.permitStore.Revoke(permit.PermitID, now)
	}
	_, err := r.audit.Mutate(permit.RequestID, func(record *models.AuditRecord) error {
		record.RuntimeObservation.Events = append(record.RuntimeObservation.Events, event)
		record.RuntimeObservation.EventEvaluations = append(record.RuntimeObservation.EventEvaluations, evaluation)
		record.RuntimeObservation.AuthorizationViolations = append(record.RuntimeObservation.AuthorizationViolations, evaluation.Violations...)
		record.RuntimeObservation.ActualActions = append(record.RuntimeObservation.ActualActions, event.Operation)
		record.RuntimeObservation.Coverage.ToolEvents = coverageFor(event)
		if len(evaluation.Violations) > 0 {
			for _, item := range evaluation.Violations {
				record.SecurityFindings = append(record.SecurityFindings, models.SecurityFinding{
					ID: event.EventID + ":" + item.Rule, Category: "authorization_boundary", Severity: "critical",
					Rule: item.Rule, Summary: item.Summary,
					Evidence: []string{"event_id=" + safeEvidence(event.EventID), "source=" + string(event.Source), "trust_level=" + string(event.TrustLevel)},
				})
			}
		}
		if !evaluation.Accepted {
			record.FinalVerdict = "RUNTIME_EVENT_REJECTED"
		}
		if evaluation.Accepted && !evaluation.WithinEnvelope {
			record.FinalVerdict = "AUTHORIZATION_BOUNDARY_VIOLATION"
		}
		if evaluation.Terminated {
			completed := now
			record.CompletedAt = &completed
		}
		record.DurationMS = elapsedMilliseconds(record.CreatedAt, now)
		return nil
	})
	if err != nil {
		return evaluation, err
	}
	return evaluation, nil
}

// CompleteExecution is retained for compatibility evidence. It cannot prove
// that a permit was verified at the execution boundary.
func (r *Router) CompleteExecution(completion models.ExecutionCompletion) (models.AuditRecord, error) {
	return r.completeExecution(completion, models.RuntimeSourceAgentSelfReported)
}

// CompleteVerifiedExecution is called only by an in-process enforcement
// adapter after VerifyAndConsume and an upstream execution attempt.
func (r *Router) CompleteVerifiedExecution(completion models.ExecutionCompletion) (models.AuditRecord, error) {
	return r.completeExecution(completion, models.RuntimeSourceGatewayEnforced)
}

func (r *Router) CompleteSyntheticDemoExecution(completion models.ExecutionCompletion) (models.AuditRecord, error) {
	return r.completeExecution(completion, models.RuntimeSourceSimulatedDemo)
}

func (r *Router) completeExecution(completion models.ExecutionCompletion, source models.RuntimeEventSource) (models.AuditRecord, error) {
	if !safeMetadataLabel(completion.RequestID) || !safeMetadataLabel(completion.PermitID) {
		return models.AuditRecord{}, fmt.Errorf("request_id and permit_id must be short metadata identifiers")
	}
	if completion.Status != "completed" && completion.Status != "failed" && completion.Status != "terminated" {
		return models.AuditRecord{}, fmt.Errorf("status must be completed, failed, or terminated")
	}
	if completion.BoundaryOutcome != "" {
		if source != models.RuntimeSourceGatewayEnforced && source != models.RuntimeSourceSimulatedDemo {
			return models.AuditRecord{}, fmt.Errorf("boundary_outcome is reserved for a trusted execution adapter")
		}
		if completion.BoundaryOutcome != "UNSATISFIED_OBLIGATION" {
			return models.AuditRecord{}, fmt.Errorf("unsupported boundary_outcome")
		}
	}
	if completion.UpstreamAttempted && source != models.RuntimeSourceGatewayEnforced && source != models.RuntimeSourceSimulatedDemo {
		return models.AuditRecord{}, fmt.Errorf("upstream_attempted is reserved for a trusted execution adapter")
	}
	receivedAt := r.clock().UTC()
	if source == models.RuntimeSourceGatewayEnforced || source == models.RuntimeSourceSimulatedDemo {
		permitRecord, exists := r.permitStore.Get(completion.PermitID, receivedAt)
		if !exists || permitRecord.State != permit.StateConsumed {
			return models.AuditRecord{}, fmt.Errorf("trusted execution completion requires a consumed permit")
		}
	}
	r.mu.Lock()
	permit, ok := r.permits[completion.PermitID]
	if !ok || permit.RequestID != completion.RequestID {
		r.mu.Unlock()
		return models.AuditRecord{}, fmt.Errorf("execution permit is unknown or bound to another request")
	}
	delete(r.permits, completion.PermitID)
	r.mu.Unlock()
	permitRecord, _ := r.permitStore.Get(completion.PermitID, receivedAt)
	expired := !permit.ExpiresAt.After(receivedAt) || (!completion.CompletedAt.IsZero() && !permit.ExpiresAt.After(completion.CompletedAt.UTC()))
	return r.audit.Mutate(completion.RequestID, func(record *models.AuditRecord) error {
		if expired {
			violation := models.AuthorizationViolation{
				Rule: "execution.permit_expired", Summary: "execution completion was reported after the authorization permit expired",
				Expected: "completion before " + permit.ExpiresAt.UTC().Format(time.RFC3339Nano), Actual: receivedAt.Format(time.RFC3339Nano),
			}
			record.RuntimeObservation.AuthorizationViolations = append(record.RuntimeObservation.AuthorizationViolations, violation)
			record.SecurityFindings = append(record.SecurityFindings, models.SecurityFinding{
				ID: safeEvidence(completion.RequestID) + ":execution.permit_expired", Category: "execution_completion", Severity: "high",
				Rule: violation.Rule, Summary: violation.Summary,
				Evidence: []string{"request_id=" + safeEvidence(completion.RequestID), "permit_id=" + safeEvidence(completion.PermitID)},
			})
			record.CompletedAt = &receivedAt
			if record.AuthorizationEnvelope != nil {
				record.AuthorizationEnvelope.State = string(permitRecord.State)
			}
			if record.ExecutionReceipt != nil {
				record.ExecutionReceipt.PermitState = string(permitRecord.State)
				record.ExecutionReceipt.VerificationOutcome = string(verifier.OutcomeExpired)
				record.ExecutionReceipt.Timestamp = receivedAt
				record.ExecutionReceipt.EvidenceSource = source
			}
			record.FinalVerdict = "PERMIT_EXPIRED"
			record.DurationMS = elapsedMilliseconds(record.CreatedAt, receivedAt)
			return nil
		}

		completed := receivedAt
		record.CompletedAt = &completed
		if record.AuthorizationEnvelope != nil {
			record.AuthorizationEnvelope.State = string(permitRecord.State)
		}
		if record.ExecutionReceipt != nil {
			record.ExecutionReceipt.PermitState = string(permitRecord.State)
			record.ExecutionReceipt.Timestamp = receivedAt
			record.ExecutionReceipt.EvidenceSource = source
			record.ExecutionReceipt.UpstreamAttempted = completion.UpstreamAttempted
			record.ExecutionReceipt.ExecutionOutcome = completion.Status
			if completion.BoundaryOutcome != "" {
				record.ExecutionReceipt.ExecutionOutcome = completion.BoundaryOutcome
			}
		}
		if completion.BoundaryOutcome == "UNSATISFIED_OBLIGATION" {
			record.FinalVerdict = "EXECUTION_OBLIGATION_UNSATISFIED"
		} else if record.FinalVerdict != "AUTHORIZATION_BOUNDARY_VIOLATION" && record.FinalVerdict != "RUNTIME_EVENT_REJECTED" &&
			!(strings.HasPrefix(record.FinalVerdict, "PERMIT_") && record.FinalVerdict != "PERMIT_VERIFIED") {
			switch completion.Status {
			case "completed":
				if record.ExecutionReceipt != nil && record.ExecutionReceipt.VerificationOutcome == string(verifier.OutcomeVerified) && source == models.RuntimeSourceGatewayEnforced {
					record.FinalVerdict = "EXECUTED_WITH_VALID_PERMIT"
				} else if record.ExecutionReceipt != nil && record.ExecutionReceipt.VerificationOutcome == string(verifier.OutcomeVerified) && source == models.RuntimeSourceSimulatedDemo {
					record.FinalVerdict = "SIMULATED_EXECUTION_WITH_VALID_PERMIT"
				} else {
					record.FinalVerdict = "COMPLETED_WITHOUT_BOUNDARY_VERIFICATION"
				}
			case "failed":
				record.FinalVerdict = "EXECUTION_FAILED"
			case "terminated":
				record.FinalVerdict = "EXECUTION_TERMINATED"
			}
		}
		record.DurationMS = elapsedMilliseconds(record.CreatedAt, completed)
		return nil
	})
}

func (r *Router) auditRejectedEvent(event models.RuntimeEvent, evaluation models.RuntimeEventEvaluation, includeEvent bool, now time.Time) error {
	if !safeMetadataLabel(event.RequestID) {
		return nil
	}
	_, ok := r.audit.Get(event.RequestID)
	if !ok {
		return nil
	}
	_, err := r.audit.Mutate(event.RequestID, func(record *models.AuditRecord) error {
		if includeEvent {
			record.RuntimeObservation.Events = append(record.RuntimeObservation.Events, event)
		}
		record.RuntimeObservation.EventEvaluations = append(record.RuntimeObservation.EventEvaluations, evaluation)
		record.RuntimeObservation.AuthorizationViolations = append(record.RuntimeObservation.AuthorizationViolations, evaluation.Violations...)
		for _, item := range evaluation.Violations {
			record.SecurityFindings = append(record.SecurityFindings, models.SecurityFinding{
				ID: safeEvidence(event.EventID) + ":" + item.Rule, Category: "runtime_event_rejection", Severity: "high",
				Rule: item.Rule, Summary: item.Summary,
				Evidence: []string{"event_id=" + safeEvidence(event.EventID), "source=" + string(event.Source), "trust_level=" + string(event.TrustLevel)},
			})
		}
		if record.FinalVerdict != "AUTHORIZATION_BOUNDARY_VIOLATION" {
			record.FinalVerdict = "RUNTIME_EVENT_REJECTED"
		}
		record.DurationMS = elapsedMilliseconds(record.CreatedAt, now)
		return nil
	})
	return err
}

func (r *Router) RuntimeCoverage() models.RuntimeCoverage {
	return models.RuntimeCoverage{
		GatewayRequests: "instrumented", ToolEvents: "not_reported",
		Filesystem: "not_instrumented", Network: "not_instrumented", OSSyscalls: "not_instrumented",
		IsolationBackend: "not_connected",
	}
}

func Validate(req models.Request) error {
	if req.UsesStructuredContext() {
		principal := req.EffectivePrincipal()
		agent := req.EffectiveAgent()
		authority := req.EffectiveAuthority()
		tool := req.EffectiveTool()
		action := req.EffectiveAction()
		for name, value := range map[string]string{
			"principal.principal_id": principal.PrincipalID, "principal.principal_type": principal.PrincipalType,
			"agent.agent_id": agent.AgentID, "agent.workload_id": agent.WorkloadID,
			"tool.name": tool.Name, "action.capability": action.Capability,
			"action.operation": action.Operation, "action.target_resource": action.TargetResource,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required", name)
			}
		}
		if principal.PrincipalType != "human" && principal.PrincipalType != "service" {
			return fmt.Errorf("principal.principal_type must be human or service")
		}
		if !sha256Pattern.MatchString(authority.CredentialFingerprint) {
			return fmt.Errorf("delegated_authority.credential_fingerprint must be a 64-character hex digest")
		}
		if err := validateStructuredLabels(principal, agent, authority, tool, action); err != nil {
			return err
		}
	} else {
		for name, value := range map[string]string{
			"user_id": req.UserID, "agent_id": req.AgentID,
			"requested_capability": req.RequestedCapability, "target_resource": req.TargetResource,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required", name)
			}
			if !safeMetadataLabel(value) {
				return fmt.Errorf("%s must be a short metadata label", name)
			}
		}
		for index, scope := range req.TokenScopes {
			if !safeMetadataLabel(scope) {
				return fmt.Errorf("token_scopes[%d] must be a short metadata label", index)
			}
		}
	}
	if req.ClaimedIntent != "" && !safeMetadataLabel(req.ClaimedIntent) {
		return fmt.Errorf("claimed_intent must be a short metadata label, not prompt content")
	}
	for _, action := range req.PlannedActions {
		if !safeMetadataLabel(action) {
			return fmt.Errorf("planned_actions must contain metadata labels")
		}
	}
	for name, value := range map[string]string{"request_id": req.RequestID, "session_id": req.SessionID, "parent_event_id": req.ParentEventID} {
		if value != "" && !safeMetadataLabel(value) {
			return fmt.Errorf("%s must be a short metadata identifier", name)
		}
	}
	for index, source := range req.InputSources {
		if !safeMetadataLabel(source.Kind) || !safeMetadataLabel(source.Trust) {
			return fmt.Errorf("input_sources[%d] kind and trust must be metadata labels", index)
		}
		if source.URIClass != "" && !safeMetadataLabel(source.URIClass) {
			return fmt.Errorf("input_sources[%d].uri_class must be a class label, not a URL or path", index)
		}
		if source.ContentSHA256 != "" && !sha256Pattern.MatchString(source.ContentSHA256) {
			return fmt.Errorf("input_sources[%d].content_sha256 must be a 64-character hex digest", index)
		}
	}
	if req.DataAccess != nil {
		if !safeMetadataLabel(req.DataAccess.Operation) || (req.DataAccess.PathClass != "" && !safeMetadataLabel(req.DataAccess.PathClass)) {
			return fmt.Errorf("data_access operation and path_class must be metadata labels, not raw paths")
		}
		if req.DataAccess.Bytes < 0 {
			return fmt.Errorf("data_access.bytes cannot be negative")
		}
	}
	if arguments := req.EffectiveAction().Arguments; len(arguments) > 0 {
		if _, err := canonicalaction.CanonicalizeJSON(arguments); err != nil {
			return fmt.Errorf("action.arguments must be valid deterministic JSON: %w", err)
		}
	}
	return nil
}

func validateStructuredLabels(principal models.PrincipalContext, agent models.AgentIdentity, authority models.DelegatedAuthority, tool models.ToolContext, action models.ActionRequest) error {
	labels := map[string]string{
		"principal.principal_id": principal.PrincipalID, "principal.principal_type": principal.PrincipalType,
		"principal.tenant": principal.Tenant, "principal.environment": principal.Environment,
		"agent.agent_id": agent.AgentID, "agent.workload_id": agent.WorkloadID, "agent.owner": agent.Owner,
		"agent.environment": agent.Environment, "agent.framework": agent.Framework, "agent.version": agent.Version,
		"delegated_authority.issuer": authority.Issuer, "delegated_authority.subject": authority.Subject,
		"tool.tool_id": tool.ToolID, "tool.name": tool.Name, "tool.provider": tool.Provider,
		"action.capability": action.Capability, "action.operation": action.Operation,
		"action.target_resource": action.TargetResource, "action.side_effect": action.SideEffect,
	}
	for name, value := range labels {
		if value != "" && !safeMetadataLabel(value) {
			return fmt.Errorf("%s must be a short metadata label", name)
		}
	}
	for index, scope := range authority.Scopes {
		if !safeMetadataLabel(scope) {
			return fmt.Errorf("delegated_authority.scopes[%d] must be a short metadata label", index)
		}
	}
	for key, value := range principal.Metadata {
		if !safeMetadataLabel(key) || !safeMetadataLabel(value) {
			return fmt.Errorf("principal.metadata must contain metadata labels only")
		}
	}
	for name, digest := range map[string]string{"schema_sha256": tool.SchemaSHA256, "expected_schema_sha256": tool.ExpectedSchemaSHA256} {
		if digest != "" && !sha256Pattern.MatchString(digest) {
			return fmt.Errorf("tool.%s must be a 64-character hex digest", name)
		}
	}
	if action.Bytes < 0 {
		return fmt.Errorf("action.bytes cannot be negative")
	}
	if action.Destination != nil {
		if !safeMetadataLabel(action.Destination.Kind) || (action.Destination.TrustBoundary != "" && !safeMetadataLabel(action.Destination.TrustBoundary)) {
			return fmt.Errorf("action.destination must use class labels, not a raw address")
		}
	}
	return nil
}

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func safeMetadataLabel(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}

func validateRuntimeMetadata(event models.RuntimeEvent) *models.AuthorizationViolation {
	labels := []string{event.EventID, event.PermitID, event.RequestID, event.AgentID, event.WorkloadID, event.Capability, event.Tool, event.Operation, event.Resource, event.ResourceClass, event.DestinationClass, event.SideEffect}
	for _, label := range labels {
		if label != "" && !safeMetadataLabel(label) {
			return &models.AuthorizationViolation{Rule: "runtime.metadata_invalid", Summary: "runtime event contains a raw or invalid metadata value", Expected: "short class labels", Actual: "invalid_or_sensitive_value"}
		}
	}
	if event.Bytes < 0 {
		return &models.AuthorizationViolation{Rule: "runtime.bytes_invalid", Summary: "runtime event byte count cannot be negative", Expected: ">=0", Actual: fmt.Sprintf("%d", event.Bytes)}
	}
	return nil
}

func mergeAdvisoryRisk(assessment models.RiskAssessment, detected detection.Result) models.RiskAssessment {
	assessment.AdvisoryOnly = true
	if detected.RiskDelta > 0 {
		if len(assessment.Signals) == 1 && assessment.Signals[0] == "no elevated risk signals" {
			assessment.Signals = []string{}
		}
		assessment.Score += detected.RiskDelta
		if assessment.Score > 100 {
			assessment.Score = 100
		}
		assessment.Level = riskLevel(assessment.Score)
	}
	for _, finding := range detected.Findings {
		assessment.Signals = append(assessment.Signals, finding.Summary)
	}
	return assessment
}

// compatibilityDispatchFor projects deterministic policy into the deprecated
// routing shape consumed by older API clients. It is not consulted by Permit
// issuance, verification, or MCP enforcement.
func compatibilityDispatchFor(policyDecision models.PolicyDecision) models.DispatchDecision {
	if !policyDecision.Authorized || policyDecision.Route == models.RouteDeny {
		return dispatch(models.RouteDeny, "none", "not_applicable", policyDecision.Reasons, policyDecision.Rules)
	}
	route := policyDecision.Route
	if route == "" {
		route = models.RouteAllow
	}
	profile, isolation := routeProfile(route)
	reasons := append([]string(nil), policyDecision.Reasons...)
	reasons = append(reasons, "legacy dispatch projection only; deterministic policy status controls Permit issuance")
	return dispatch(route, profile, isolation, reasons, policyDecision.Rules)
}

// policyObligations derives signed execution requirements solely from the
// matched deterministic grant. Advisory risk/detection output is not an input.
func policyObligations(policyDecision models.PolicyDecision) models.ExecutionObligations {
	constraints := models.AuthorizationConstraints{}
	if policyDecision.Grant != nil {
		constraints = policyDecision.Grant.Constraints
	}
	return models.ExecutionObligations{
		IsolationRequired:     policyDecision.Route == models.RouteSandbox,
		NetworkEgressDenied:   constraints.NetworkEgress != "allow",
		ReadOnly:              constraints.WriteAccess != "allow",
		HumanApprovalRequired: policyDecision.Status == models.AuthorizationStatusRequiresApproval,
		EnhancedAuditRequired: policyDecision.Route == models.RouteRestrict || policyDecision.Route == models.RouteSandbox,
	}
}

func dispatch(route models.Route, profile, isolation string, reasons, rules []string) models.DispatchDecision {
	return models.DispatchDecision{
		Route: route, Reasons: nonNil(reasons), Rules: nonNil(rules), ExecutorProfile: profile,
		IsolationBackend: isolation, ExecutorInvoked: false, LegacyCompatibilityOnly: true,
	}
}

func routeProfile(route models.Route) (string, string) {
	switch route {
	case models.RouteAllow:
		return "standard-route", "not_applicable"
	case models.RouteRestrict:
		return "restricted-route", "policy_constraints_only"
	case models.RouteSandbox:
		return "isolation-required", "obligation_only_not_provided"
	case models.RouteEscalate:
		return "approval-queue", "not_applicable"
	default:
		return "none", "not_applicable"
	}
}

func canonicalAction(req models.Request, grant models.MatchedAuthorizationGrant) canonicalaction.Action {
	result := executionAction(req)
	action := req.EffectiveAction()
	operation := action.Operation
	if operation == "" && len(grant.AllowedOperations) > 0 {
		operation = grant.AllowedOperations[0]
	}
	if result.Tool == "" {
		result.Tool = grant.Tool
	}
	result.Capability = grant.Capability
	result.Resource = grant.Resource
	result.Operation = operation
	return result
}

func resolvedActionOrDefault(resolvedAction canonicalaction.Action, resolved bool, req models.Request, grant models.MatchedAuthorizationGrant) canonicalaction.Action {
	if resolved {
		return resolvedAction
	}
	return canonicalAction(req, grant)
}

func (r *Router) resolveAuthorizedAction(req models.Request, grant models.MatchedAuthorizationGrant, permitClass permit.Class) (canonicalaction.Action, error) {
	if permitClass != permit.ClassExecution {
		return canonicalAction(req, grant), nil
	}
	return r.resolveSemanticAction(req)
}

func (r *Router) resolveExecutionAction(req models.Request) (canonicalaction.Action, error) {
	return r.resolveSemanticAction(req)
}

func (r *Router) resolveSemanticAction(req models.Request) (canonicalaction.Action, error) {
	base := executionAction(req)
	resolved, err := r.semanticRegistry.Resolve(semanticaction.Input{
		PrincipalID: base.PrincipalID, AgentID: base.AgentID, WorkloadID: base.WorkloadID,
		DelegatedAuthorityFingerprint: base.DelegatedAuthorityFingerprint,
		Tool:                          base.Tool, Capability: base.Capability, Resource: base.Resource, Operation: base.Operation,
		ProfileID: base.ProfileID, Audience: base.Audience, Arguments: base.Arguments,
	})
	if err != nil {
		return canonicalaction.Action{}, err
	}
	return resolved.Action, nil
}

// SemanticRegistry exposes the immutable, server-owned dispatcher to the MCP
// enforcement boundary so authorization and execution use the same profile
// implementations and configuration.
func (r *Router) SemanticRegistry() *semanticaction.Registry {
	return r.semanticRegistry
}

func executionAction(req models.Request) canonicalaction.Action {
	principal := req.EffectivePrincipal()
	agent := req.EffectiveAgent()
	authority := req.EffectiveAuthority()
	tool := req.EffectiveTool()
	action := req.EffectiveAction()
	toolName := tool.Name
	if toolName == "" {
		toolName = tool.ToolID
	}
	delegationBinding := authority.CredentialFingerprint
	if bound, err := canonicalaction.BindDelegatedAuthorityFingerprint(authority.CredentialFingerprint); err == nil {
		delegationBinding = bound
	}
	return canonicalaction.Action{
		PrincipalID: principal.PrincipalID, AgentID: agent.AgentID, WorkloadID: agent.WorkloadID,
		DelegatedAuthorityFingerprint: delegationBinding,
		Tool:                          toolName, Capability: action.Capability, Resource: action.TargetResource,
		Operation: action.Operation, ProfileID: action.ProfileID, Audience: action.Audience, Arguments: action.Arguments,
	}
}

func (r *Router) issuePermit(req models.Request, grant models.MatchedAuthorizationGrant, obligations models.ExecutionObligations, action canonicalaction.Action, actionDigest string, issuedAt time.Time, workloadBinding intake.WorkloadBinding, permitClass permit.Class, ttlOverride time.Duration) (permit.IssuedPermit, error) {
	ttl := r.permitTTL
	if ttlOverride > 0 && ttlOverride < ttl {
		ttl = ttlOverride
	}
	if grant.Constraints.MaxDurationMS > 0 {
		maximum := time.Duration(grant.Constraints.MaxDurationMS) * time.Millisecond
		if maximum < ttl {
			ttl = maximum
		}
	}
	if expires := req.EffectiveAuthority().ExpiresAt; expires != nil {
		remaining := expires.UTC().Sub(issuedAt)
		if remaining < ttl {
			ttl = remaining
		}
	}
	ttl = ttl.Truncate(time.Second)
	if ttl < time.Second {
		return permit.IssuedPermit{}, fmt.Errorf("execution permit lifetime is shorter than one second")
	}
	issued, err := r.permitIssuer.Issue(permit.IssueRequest{
		RequestID: req.RequestID, PermitClass: permitClass, PrincipalID: action.PrincipalID, AgentID: action.AgentID,
		WorkloadID: action.WorkloadID, DelegatedAuthorityFingerprint: action.DelegatedAuthorityFingerprint,
		ExecutorKeyID: workloadBinding.KeyID, ExecutorKeyThumbprint: workloadBinding.PublicKeyThumbprint,
		Tool: action.Tool, Capability: action.Capability, Resource: action.Resource, Operation: action.Operation,
		ProfileID: action.ProfileID, Audience: action.Audience,
		ActionDigest: actionDigest, PolicyVersion: r.policyVersion, TTL: ttl,
		Obligations: permit.Obligations{
			IsolationRequired: obligations.IsolationRequired, NetworkEgressDenied: obligations.NetworkEgressDenied,
			ReadOnly: obligations.ReadOnly, HumanApprovalRequired: obligations.HumanApprovalRequired,
			EnhancedAuditRequired: obligations.EnhancedAuditRequired,
		},
	})
	if err != nil {
		return permit.IssuedPermit{}, fmt.Errorf("issue signed execution permit: %w", err)
	}
	return issued, nil
}

func envelopeFor(issued permit.IssuedPermit, sessionID string, constraints models.AuthorizationConstraints, route models.Route) *models.AuthorizationEnvelope {
	claims := issued.Claims
	return &models.AuthorizationEnvelope{
		PermitID: claims.PermitID, SigningKeyID: claims.SigningKeyID, PermitClass: string(claims.PermitClass), RequestID: claims.RequestID, SessionID: sessionID,
		PrincipalID: claims.PrincipalID, AgentID: claims.AgentID, WorkloadID: claims.WorkloadID,
		ExecutorKeyID:                  claims.ExecutorKeyID,
		ExecutorKeyThumbprint:          claims.ExecutorKeyThumbprint,
		DelegatedCredentialFingerprint: claims.DelegatedAuthorityFingerprint,
		AllowedCapability:              claims.Capability, AllowedTool: claims.Tool, AllowedResource: claims.Resource,
		AllowedOperation: claims.Operation, AllowedOperations: []string{claims.Operation}, ProfileID: claims.ProfileID, Audience: claims.Audience,
		ActionDigest: claims.ActionDigest, PolicyVersion: claims.PolicyVersion, Issuer: claims.Issuer,
		SingleUse: claims.SingleUse, State: string(permit.StateIssued), Constraints: constraints, Route: route,
		Obligations: models.ExecutionObligations{
			IsolationRequired: claims.Obligations.IsolationRequired, NetworkEgressDenied: claims.Obligations.NetworkEgressDenied,
			ReadOnly: claims.Obligations.ReadOnly, HumanApprovalRequired: claims.Obligations.HumanApprovalRequired,
			EnhancedAuditRequired: claims.Obligations.EnhancedAuditRequired,
		},
		IssuedAt: claims.IssuedTime(), ExpiresAt: claims.ExpiresTime(),
	}
}

func privacySafeRequest(req models.Request) models.Request {
	// requested_action can contain prompt text in legacy clients. It is not an
	// authorization input and is deliberately omitted from the audit record.
	req.RequestedAction = ""
	req.Action.Arguments = nil
	// Profile and audience assertions are caller input. The authoritative values
	// are recorded from signed claims/receipts; rejected assertions are reduced
	// to stable semantic rejection codes instead of persisted verbatim.
	req.Action.ProfileID = ""
	req.Action.Audience = ""
	if bound, err := canonicalaction.BindDelegatedAuthorityFingerprint(req.Authority.CredentialFingerprint); err == nil {
		req.Authority.CredentialFingerprint = bound
	} else {
		req.Authority.CredentialFingerprint = ""
	}
	return req
}

func authorizationVerdict(status models.AuthorizationStatus) string {
	switch status {
	case models.AuthorizationStatusDenied:
		return "BLOCKED_BEFORE_EXECUTION"
	case models.AuthorizationStatusRequiresApproval:
		return "APPROVAL_REQUIRED"
	default:
		return "AUTHORIZED"
	}
}

func rejectedEvaluation(event models.RuntimeEvent, item models.AuthorizationViolation) models.RuntimeEventEvaluation {
	return models.RuntimeEventEvaluation{
		EventID: event.EventID, PermitID: event.PermitID, Accepted: false, WithinEnvelope: false,
		Terminated: true, Verdict: "RUNTIME_EVENT_REJECTED", Violations: []models.AuthorizationViolation{item},
	}
}

func coverageFor(event models.RuntimeEvent) string {
	switch event.Source {
	case models.RuntimeSourceGatewayEnforced:
		return "gateway_enforced"
	case models.RuntimeSourceInstrumentedAdapter:
		return "adapter_reported"
	case models.RuntimeSourceAgentSelfReported:
		return "self_reported"
	case models.RuntimeSourceOSSensor:
		return "os_sensor"
	case models.RuntimeSourceNetworkSensor:
		return "network_sensor"
	case models.RuntimeSourceSimulatedDemo:
		return "simulated_demo"
	default:
		return "unknown"
	}
}

func riskLevel(score int) string {
	if score >= 70 {
		return "high"
	}
	if score >= 35 {
		return "medium"
	}
	return "low"
}

func newIdentifier(prefix string) string {
	data := make([]byte, 12)
	if _, err := rand.Read(data); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(data)
}

func nonNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

func nonNilFindings(items []models.SecurityFinding) []models.SecurityFinding {
	if items == nil {
		return []models.SecurityFinding{}
	}
	return items
}

func elapsedMilliseconds(start, end time.Time) int64 {
	if end.Before(start) {
		return 0
	}
	return end.Sub(start).Milliseconds()
}

func safeEvidence(value string) string {
	if safeMetadataLabel(value) {
		return value
	}
	return "invalid_or_redacted"
}
