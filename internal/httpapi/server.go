package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"agent-governance-gateway/internal/audit"
	"agent-governance-gateway/internal/discovery"
	"agent-governance-gateway/internal/intake"
	"agent-governance-gateway/internal/models"
	"agent-governance-gateway/internal/permit"
	"agent-governance-gateway/internal/router"
	"agent-governance-gateway/internal/sessionaudit"
)

type Server struct {
	router                *router.Router
	audits                *audit.Store
	policy                models.PolicyConfig
	scenarios             []models.Scenario
	discovery             *discovery.Manager
	sessionAuditPath      string
	static                fs.FS
	logger                *slog.Logger
	experimentalInventory bool
	mcpHandler            http.Handler
	authorizationIntake   intake.TrustedAuthorizationIntake
}

type Options struct {
	ExperimentalInventory bool
	MCPHandler            http.Handler
	AuthorizationIntake   intake.TrustedAuthorizationIntake
}

func New(r *router.Router, audits *audit.Store, policyConfig models.PolicyConfig, scenarios []models.Scenario, manager *discovery.Manager, sessionAuditPath string, static fs.FS, logger *slog.Logger) *Server {
	return NewWithOptions(r, audits, policyConfig, scenarios, manager, sessionAuditPath, static, logger, Options{})
}

func NewWithOptions(r *router.Router, audits *audit.Store, policyConfig models.PolicyConfig, scenarios []models.Scenario, manager *discovery.Manager, sessionAuditPath string, static fs.FS, logger *slog.Logger, options Options) *Server {
	authorizationIntake := options.AuthorizationIntake
	if authorizationIntake == nil {
		authorizationIntake = intake.RejectAll{}
	}
	return &Server{
		router: r, audits: audits, policy: policyConfig, scenarios: scenarios, discovery: manager,
		sessionAuditPath: sessionAuditPath, static: static, logger: logger,
		experimentalInventory: options.ExperimentalInventory && manager != nil, mcpHandler: options.MCPHandler,
		authorizationIntake: authorizationIntake,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/decisions", s.listDecisions)
	mux.HandleFunc("POST /api/actions/authorize", s.authorizeAction)
	mux.HandleFunc("GET /api/permits", s.listPermits)
	mux.HandleFunc("GET /api/permits/{id}", s.getPermit)
	mux.HandleFunc("POST /api/permits/{id}/revoke", s.revokePermit)
	mux.HandleFunc("POST /api/permits/verify", s.verifyPermit)
	mux.HandleFunc("GET /api/demo-lab", s.listPermitDemos)
	mux.HandleFunc("GET /api/runtime-coverage", s.runtimeCoverage)
	mux.HandleFunc("GET /api/policies", s.listPolicies)
	mux.HandleFunc("GET /api/scenarios", s.listScenarios)
	if s.experimentalInventory {
		mux.HandleFunc("GET /api/agents", s.listAgents)
		mux.HandleFunc("GET /api/discoveries", s.listDiscoveries)
		mux.HandleFunc("POST /api/discoveries/rescan", s.rescanDiscoveries)
		mux.HandleFunc("GET /api/approved-agents", s.listApprovedAgents)
		mux.HandleFunc("POST /api/approved-agents", s.saveApprovedAgent)
		mux.HandleFunc("DELETE /api/approved-agents/{id}", s.deleteApprovedAgent)
	}
	mux.HandleFunc("GET /api/session-events", s.listSessionEvents)
	mux.HandleFunc("POST /api/route", s.route)
	mux.HandleFunc("POST /api/authorize", s.authorize)
	mux.HandleFunc("POST /api/runtime-events", s.ingestRuntimeEvent)
	mux.HandleFunc("POST /api/executions/{id}/complete", s.completeExecution)
	mux.HandleFunc("POST /api/demo-lab/{id}/run", s.runDemoScenario)
	mux.HandleFunc("GET /api/audits", s.listAudits)
	if s.mcpHandler != nil {
		mux.Handle("POST /mcp", s.mcpHandler)
	}
	mux.Handle("/", http.FileServerFS(s.static))
	return s.middleware(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "service": "aegis-router", "repository": "agent-governance-gateway",
		"product": "execution-permits-for-ai-agent-actions",
		"description": "Framework-agnostic execution permits for AI agent tool calls. " +
			"Authorize once; execute exactly what was authorized.",
		"features": map[string]bool{"mcp_enforcement": s.mcpHandler != nil, "experimental_inventory": s.experimentalInventory},
	})
}

func (s *Server) overview(w http.ResponseWriter, _ *http.Request) {
	records := s.audits.Recent(100)
	counts := map[string]int{"AUTHORIZED": 0, "DENIED": 0, "PERMIT_VIOLATIONS": 0, "REPLAY_BLOCKS": 0}
	for _, record := range records {
		switch record.AuthorizationStatus {
		case models.AuthorizationStatusAuthorized:
			counts["AUTHORIZED"]++
		case models.AuthorizationStatusDenied, models.AuthorizationStatusRequiresApproval:
			counts["DENIED"]++
		}
		if (strings.HasPrefix(record.FinalVerdict, "PERMIT_") && record.FinalVerdict != "PERMIT_VERIFIED") || record.FinalVerdict == "EXECUTION_OBLIGATION_UNSATISFIED" {
			counts["PERMIT_VIOLATIONS"]++
		}
		if record.FinalVerdict == "PERMIT_REPLAY" {
			counts["REPLAY_BLOCKS"]++
		}
	}
	recent := records
	if len(recent) > 8 {
		recent = recent[:8]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"execution_permit_counts": counts,
		"recent_activity":         recent,
		"principle":               "Authorize once. Execute exactly what was authorized.",
		"experimental_inventory":  s.experimentalInventory,
	})
}

func (s *Server) listDecisions(w http.ResponseWriter, req *http.Request) {
	limit, ok := parseLimit(w, req, 30)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.audits.Recent(limit))
}

func (s *Server) authorizeAction(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var input models.Request
	if err := decodeJSON(req, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_action", err.Error())
		return
	}
	authorization, err := s.authorizationIntake.Resolve(req, input)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "trusted_authorization_context_required", err.Error())
		return
	}
	result, err := s.router.AuthorizeTrustedAction(authorization)
	if err != nil {
		writeError(w, http.StatusBadRequest, "authorization_failed", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

type permitView struct {
	PermitID              string             `json:"permit_id"`
	SigningKeyID          string             `json:"signing_key_id"`
	PermitClass           permit.Class       `json:"permit_class"`
	ProfileID             string             `json:"profile_id,omitempty"`
	Audience              string             `json:"audience,omitempty"`
	State                 permit.State       `json:"state"`
	RequestID             string             `json:"request_id"`
	PrincipalID           string             `json:"principal_id"`
	AgentID               string             `json:"agent_id"`
	WorkloadID            string             `json:"workload_id"`
	ExecutorKeyID         string             `json:"executor_key_id,omitempty"`
	ExecutorKeyThumbprint string             `json:"executor_key_thumbprint,omitempty"`
	Tool                  string             `json:"tool"`
	Capability            string             `json:"capability"`
	Resource              string             `json:"resource"`
	Operation             string             `json:"operation"`
	ActionDigest          string             `json:"action_digest"`
	PolicyVersion         string             `json:"policy_version"`
	Issuer                string             `json:"issuer"`
	SingleUse             bool               `json:"single_use"`
	Obligations           permit.Obligations `json:"obligations"`
	IssuedAt              time.Time          `json:"issued_at"`
	ExpiresAt             time.Time          `json:"expires_at"`
	ConsumedAt            *time.Time         `json:"consumed_at,omitempty"`
	ExpiredAt             *time.Time         `json:"expired_at,omitempty"`
	RevokedAt             *time.Time         `json:"revoked_at,omitempty"`
	VerificationResult    string             `json:"verification_result,omitempty"`
}

func viewPermit(record permit.Record) permitView {
	claims := record.Claims
	return permitView{
		PermitID: claims.PermitID, SigningKeyID: claims.SigningKeyID, PermitClass: claims.PermitClass,
		ProfileID: claims.ProfileID, Audience: claims.Audience, State: record.State, RequestID: claims.RequestID,
		PrincipalID: claims.PrincipalID, AgentID: claims.AgentID, WorkloadID: claims.WorkloadID,
		ExecutorKeyID: claims.ExecutorKeyID, ExecutorKeyThumbprint: claims.ExecutorKeyThumbprint,
		Tool: claims.Tool, Capability: claims.Capability, Resource: claims.Resource, Operation: claims.Operation,
		ActionDigest: claims.ActionDigest, PolicyVersion: claims.PolicyVersion, Issuer: claims.Issuer,
		SingleUse: claims.SingleUse, Obligations: claims.Obligations,
		IssuedAt: claims.IssuedTime(), ExpiresAt: claims.ExpiresTime(), ConsumedAt: record.ConsumedAt,
		ExpiredAt: record.ExpiredAt, RevokedAt: record.RevokedAt,
	}
}

func (s *Server) listPermits(w http.ResponseWriter, req *http.Request) {
	limit, ok := parseLimit(w, req, 50)
	if !ok {
		return
	}
	records := s.router.ListPermits()
	if len(records) > limit {
		records = records[:limit]
	}
	items := make([]permitView, 0, len(records))
	for _, record := range records {
		view := viewPermit(record)
		if auditRecord, exists := s.audits.Get(record.Claims.RequestID); exists && auditRecord.ExecutionReceipt != nil {
			view.VerificationResult = auditRecord.ExecutionReceipt.VerificationOutcome
		}
		items = append(items, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"permits": items})
}

func (s *Server) getPermit(w http.ResponseWriter, req *http.Request) {
	record, ok := s.router.GetPermit(req.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "permit_not_found", "execution permit was not found")
		return
	}
	view := viewPermit(record)
	if auditRecord, exists := s.audits.Get(record.Claims.RequestID); exists && auditRecord.ExecutionReceipt != nil {
		view.VerificationResult = auditRecord.ExecutionReceipt.VerificationOutcome
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) revokePermit(w http.ResponseWriter, req *http.Request) {
	if !requireLocalAdmin(w, req) {
		return
	}
	record, err := s.router.RevokePermit(req.PathValue("id"))
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, permit.ErrPermitNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, "permit_not_revoked", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, viewPermit(record))
}

type permitVerificationRequest struct {
	PermitToken string         `json:"permit_token"`
	Action      models.Request `json:"action"`
}

func (s *Server) verifyPermit(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var input permitVerificationRequest
	if err := decodeJSON(req, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_verification_request", err.Error())
		return
	}
	result, err := s.router.VerifyRequestAndConsume(input.PermitToken, input.Action)
	if err != nil {
		writeError(w, http.StatusBadRequest, "permit_verification_failed", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) runtimeCoverage(w http.ResponseWriter, _ *http.Request) {
	coverage := s.router.RuntimeCoverage()
	writeJSON(w, http.StatusOK, map[string]any{
		"coverage":  coverage,
		"principle": "Unknown and disconnected sensors remain explicit; zero events never implies zero coverage gaps.",
	})
}

func (s *Server) listPolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":    s.policy,
		"principle": "Authorization is explicit; risk may tighten dispatch but never overrides an authorization denial.",
	})
}

func (s *Server) listAgents(w http.ResponseWriter, _ *http.Request) {
	agentIDs := make([]string, 0, len(s.policy.Agents))
	for agentID := range s.policy.Agents {
		agentIDs = append(agentIDs, agentID)
	}
	sort.Strings(agentIDs)
	identities := make([]map[string]any, 0, len(agentIDs))
	for _, agentID := range agentIDs {
		item := s.policy.Agents[agentID]
		identities = append(identities, map[string]any{
			"agent_id": agentID, "workload_ids": item.WorkloadIDs,
			"policy_profiles": len(item.Capabilities),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"governed_identities": identities,
		"asset_registry":      s.discovery.Registry(),
		"agent_types":         s.discovery.AgentTypes(),
		"discovery":           privacySafeDiscovery(s.discovery.Report()),
		"principle":           "Asset registration permits a workload to participate; behavioral permissions live in policy.",
	})
}

func (s *Server) listScenarios(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.scenarios)
}

func (s *Server) listPermitDemos(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"evidence_source": "simulated_demo",
		"scenarios": []map[string]string{
			{"id": "valid-permit", "title": "Valid permit", "description": "The exact authorized action verifies once and the simulated executor may proceed."},
			{"id": "action-mutation", "title": "Action mutation / TOCTOU", "description": "A changed security-relevant argument produces ACTION_MISMATCH before execution."},
			{"id": "permit-replay", "title": "Permit replay", "description": "A second use of the same single-use permit is blocked as REPLAYED."},
			{"id": "expired-permit", "title": "Expired permit", "description": "A short-lived permit is rejected after its signed expiration time."},
		},
		"advanced_regression_fixtures": s.scenarios,
	})
}

func (s *Server) listDiscoveries(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, privacySafeDiscovery(s.discovery.Report()))
}

func (s *Server) rescanDiscoveries(w http.ResponseWriter, req *http.Request) {
	if !requireLocalAdmin(w, req) {
		return
	}
	report, err := s.discovery.Rescan()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "discovery_rescan_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, privacySafeDiscovery(report))
}

func (s *Server) listApprovedAgents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"approved_agents": s.discovery.Registry(),
		"agent_types":     s.discovery.AgentTypes(),
		"principle":       "Approval permits the Agent to exist; it never bypasses per-action policy or audit.",
	})
}

func (s *Server) saveApprovedAgent(w http.ResponseWriter, req *http.Request) {
	if !requireLocalAdmin(w, req) {
		return
	}
	defer req.Body.Close()
	var entry discovery.RegistryEntry
	if err := decodeJSON(req, &entry); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_approval", err.Error())
		return
	}
	saved, report, err := s.discovery.SaveApproval(entry)
	if err != nil {
		writeError(w, http.StatusBadRequest, "approval_not_saved", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approved_agent": saved, "discovery": privacySafeDiscovery(report)})
}

func (s *Server) deleteApprovedAgent(w http.ResponseWriter, req *http.Request) {
	if !requireLocalAdmin(w, req) {
		return
	}
	report, err := s.discovery.DeleteApproval(req.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "approval_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "discovery": privacySafeDiscovery(report)})
}

func (s *Server) listSessionEvents(w http.ResponseWriter, req *http.Request) {
	limit, ok := parseLimit(w, req, 30)
	if !ok {
		return
	}
	events, err := sessionaudit.Recent(s.sessionAuditPath, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_audit_unavailable", err.Error())
		return
	}
	observer, selfReported := 0, 0
	for _, event := range events {
		switch event.Trust {
		case sessionaudit.TrustObserver:
			observer++
		case sessionaudit.TrustSelfReported:
			selfReported++
		}
	}
	coverage := "no_session_data"
	if observer > 0 || selfReported > 0 {
		coverage = "wrapper_and_self_reported_only"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"summary": map[string]any{
			"total": len(events), "observer_recorded": observer, "self_reported": selfReported,
			"coverage": coverage,
		},
		"limitation": "Agent behavior is not independently corroborated until OS and network sensors are connected.",
	})
}

func (s *Server) route(w http.ResponseWriter, req *http.Request) {
	markCompatibilityEndpoint(w, "/api/actions/authorize")
	s.authorize(w, req)
}

func (s *Server) authorize(w http.ResponseWriter, req *http.Request) {
	markCompatibilityEndpoint(w, "/api/actions/authorize")
	defer req.Body.Close()
	var input models.Request
	if err := decodeJSON(req, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	authorization, err := s.authorizationIntake.Resolve(req, input)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "trusted_authorization_context_required", err.Error())
		return
	}
	result, err := s.router.AuthorizeTrustedAction(authorization)
	if err != nil {
		writeError(w, http.StatusBadRequest, "authorization_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result.Decision)
}

func (s *Server) ingestRuntimeEvent(w http.ResponseWriter, req *http.Request) {
	markCompatibilityEndpoint(w, "pre-execution MCP permit verification")
	defer req.Body.Close()
	var event models.RuntimeEvent
	if err := decodeJSON(req, &event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_runtime_event", err.Error())
		return
	}
	switch event.Source {
	case models.RuntimeSourceInstrumentedAdapter, models.RuntimeSourceAgentSelfReported:
		// These sources state exactly what the endpoint can substantiate. Stronger
		// gateway/demo/OS/network labels are reserved for internal integrations.
	default:
		writeError(w, http.StatusBadRequest, "reserved_runtime_source", "this endpoint accepts instrumented_adapter or agent_self_reported evidence only")
		return
	}
	evaluation, err := s.router.IngestRuntimeEvent(event)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "runtime_event_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, evaluation)
}

func (s *Server) completeExecution(w http.ResponseWriter, req *http.Request) {
	markCompatibilityEndpoint(w, "MCP enforcement adapter completion")
	defer req.Body.Close()
	var completion models.ExecutionCompletion
	if err := decodeJSON(req, &completion); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_execution_completion", err.Error())
		return
	}
	requestID := req.PathValue("id")
	if completion.RequestID == "" {
		completion.RequestID = requestID
	} else if completion.RequestID != requestID {
		writeError(w, http.StatusBadRequest, "execution_binding_mismatch", "path id must match request_id")
		return
	}
	record, err := s.router.CompleteExecution(completion)
	if err != nil {
		writeError(w, http.StatusBadRequest, "execution_completion_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func markCompatibilityEndpoint(w http.ResponseWriter, successor string) {
	w.Header().Set("Deprecation", "true")
	w.Header().Set("X-Aegis-Compatibility-Endpoint", "true")
	w.Header().Set("Warning", fmt.Sprintf(`299 - "Compatibility endpoint; use %s"`, successor))
}

func (s *Server) runDemoScenario(w http.ResponseWriter, req *http.Request) {
	if isPermitDemo(req.PathValue("id")) {
		result, err := s.runPermitDemo(req.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "permit_demo_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	var scenario *models.Scenario
	for index := range s.scenarios {
		if s.scenarios[index].ID == req.PathValue("id") {
			scenario = &s.scenarios[index]
			break
		}
	}
	if scenario == nil {
		writeError(w, http.StatusNotFound, "demo_scenario_not_found", "demo scenario was not found")
		return
	}
	authorized, err := s.router.AuthorizeSyntheticDemoAction(scenario.Request, 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "demo_authorization_failed", err.Error())
		return
	}
	record := authorized.Decision
	if record.AuthorizationEnvelope == nil {
		writeJSON(w, http.StatusOK, record)
		return
	}
	permit := record.AuthorizationEnvelope
	terminated := false
	for index, fixture := range scenario.SimulatedDemo {
		fixture.EventID = firstNonEmpty(fixture.EventID, fmt.Sprintf("demo-%s-%d", scenario.ID, index+1))
		fixture.PermitID = permit.PermitID
		fixture.RequestID = record.RequestID
		fixture.SessionID = permit.SessionID
		fixture.AgentID = permit.AgentID
		fixture.WorkloadID = permit.WorkloadID
		fixture.Source = models.RuntimeSourceSimulatedDemo
		fixture.TrustLevel = models.RuntimeTrustSimulated
		evaluation, ingestErr := s.router.IngestRuntimeEvent(fixture)
		if ingestErr != nil {
			writeError(w, http.StatusInternalServerError, "demo_runtime_event_failed", ingestErr.Error())
			return
		}
		if evaluation.Terminated {
			terminated = true
			break
		}
	}
	if !terminated {
		record, err = s.router.CompleteExecution(models.ExecutionCompletion{
			RequestID: record.RequestID, PermitID: permit.PermitID, Status: "completed",
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "demo_completion_failed", err.Error())
			return
		}
	} else if latest, ok := s.audits.Get(record.RequestID); ok {
		record = latest
	}
	writeJSON(w, http.StatusOK, record)
}

func isPermitDemo(id string) bool {
	switch id {
	case "valid-permit", "action-mutation", "permit-replay", "expired-permit":
		return true
	default:
		return false
	}
}

func (s *Server) runPermitDemo(id string) (map[string]any, error) {
	action := permitDemoRequest(id)
	var (
		authorized models.ActionAuthorizationResponse
		err        error
	)
	if id == "expired-permit" {
		authorized, err = s.router.AuthorizeSyntheticDemoAction(action, time.Second)
	} else {
		authorized, err = s.router.AuthorizeSyntheticDemoAction(action, 30*time.Second)
	}
	if err != nil {
		return nil, err
	}
	if authorized.Permit == nil {
		return map[string]any{
			"scenario_id": id, "evidence_source": models.RuntimeSourceSimulatedDemo,
			"verification_result": "DENIED", "upstream_invoked": false, "decision": authorized.Decision,
		}, nil
	}

	actual := action
	attempts := []models.PermitVerification{}
	upstreamInvoked := false
	verify := func() (models.PermitVerification, error) {
		result, verifyErr := s.router.VerifySyntheticDemoRequest(authorized.Permit.PermitToken, actual)
		attempts = append(attempts, result)
		return result, verifyErr
	}

	switch id {
	case "action-mutation":
		actual.Action.Arguments = json.RawMessage(`{"amount":10000,"currency":"USD","recipient":"merchant-456"}`)
		if _, err = verify(); err != nil {
			return nil, err
		}
	case "permit-replay":
		var first models.PermitVerification
		first, err = verify()
		if err != nil {
			return nil, err
		}
		if first.Verified {
			upstreamInvoked = true
			_, _ = s.router.CompleteSyntheticDemoExecution(models.ExecutionCompletion{
				RequestID: first.RequestID, PermitID: first.PermitID, Status: "completed", UpstreamAttempted: true,
			})
		}
		if _, err = verify(); err != nil {
			return nil, err
		}
	case "expired-permit":
		wait := time.Until(authorized.Permit.ExpiresAt) + 25*time.Millisecond
		if wait > 0 {
			time.Sleep(wait)
		}
		if _, err = verify(); err != nil {
			return nil, err
		}
	default:
		var result models.PermitVerification
		result, err = verify()
		if err != nil {
			return nil, err
		}
		if result.Verified {
			upstreamInvoked = true
			_, _ = s.router.CompleteSyntheticDemoExecution(models.ExecutionCompletion{
				RequestID: result.RequestID, PermitID: result.PermitID, Status: "completed", UpstreamAttempted: true,
			})
		}
	}

	latest := attempts[len(attempts)-1]
	permitRecord, _ := s.router.GetPermit(authorized.Permit.PermitID)
	return map[string]any{
		"scenario_id": id, "simulated": true, "evidence_source": models.RuntimeSourceSimulatedDemo,
		"verification_result": latest.Outcome, "permit_state": permitRecord.State,
		"permit": viewPermit(permitRecord), "attempts": attempts, "upstream_invoked": upstreamInvoked,
		"decision": authorized.Decision,
	}, nil
}

func permitDemoRequest(id string) models.Request {
	request := models.Request{
		Principal: models.PrincipalContext{PrincipalID: "demo-user", PrincipalType: "human", Environment: "synthetic"},
		Agent:     models.AgentIdentity{AgentID: "coder-agent", WorkloadID: "coder-workload-v1", Environment: "synthetic"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("d", 64), Scopes: []string{"code.read"}, Subject: "demo-user",
		},
		Tool: models.ToolContext{Name: "coder", Provider: "simulated-demo"},
		Action: models.ActionRequest{
			Capability: "generate_code", Operation: "generate", TargetResource: "public_workspace",
			Arguments: json.RawMessage(`{"language":"go","task":"permit-demo"}`), SideEffect: "none",
		},
	}
	if id == "action-mutation" {
		request.Agent = models.AgentIdentity{AgentID: "finance-agent", WorkloadID: "finance-workload-v1", Environment: "synthetic"}
		request.Authority.Scopes = []string{"payment.transfer"}
		request.Tool = models.ToolContext{Name: "payment.send", Provider: "simulated-demo"}
		request.Action = models.ActionRequest{
			Capability: "payment_transfer", Operation: "transfer", TargetResource: "account-123",
			Arguments:  json.RawMessage(`{"amount":100,"currency":"USD","recipient":"merchant-456"}`),
			SideEffect: "financial_transaction",
		}
	}
	return request
}

func (s *Server) listAudits(w http.ResponseWriter, req *http.Request) {
	limit, ok := parseLimit(w, req, 20)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.audits.Recent(limit))
}

func parseLimit(w http.ResponseWriter, req *http.Request, defaultLimit int) (int, bool) {
	limit := defaultLimit
	if value := req.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 100")
			return 0, false
		}
		limit = parsed
	}
	return limit, true
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		started := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, req)
		s.logger.Info("request", "method", req.Method, "path", req.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": strings.TrimSpace(message)})
}

func decodeJSON(req *http.Request, value any) error {
	decoder := json.NewDecoder(io.LimitReader(req.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON object")
	}
	return nil
}

func requireLocalAdmin(w http.ResponseWriter, req *http.Request) bool {
	if req.Header.Get("X-Agent-Governance-Admin") != "local-ui" {
		writeError(w, http.StatusForbidden, "local_admin_header_required", "local registry changes require the Aegis Router admin header")
		return false
	}
	return true
}

func effectiveRoute(record models.AuditRecord) models.Route {
	if record.DispatchDecision.Route != "" {
		return record.DispatchDecision.Route
	}
	return record.PolicyDecision.Route
}

func privacySafeDiscovery(report discovery.Report) discovery.Report {
	result := report
	result.Roots = make([]string, len(report.Roots))
	for index, root := range report.Roots {
		result.Roots[index] = classifyLocalPath(root)
	}
	result.Gaps = append([]discovery.CoverageGap(nil), report.Gaps...)
	for index := range result.Gaps {
		if filepath.IsAbs(result.Gaps[index].Source) {
			result.Gaps[index].Source = classifyLocalPath(result.Gaps[index].Source)
		}
	}
	result.Agents = make([]discovery.DiscoveredAgent, len(report.Agents))
	for index, agent := range report.Agents {
		result.Agents[index] = agent
		switch agent.Status {
		case discovery.StatusShadow:
			result.Agents[index].Name = "Unregistered " + agent.AgentType + " workload candidate"
		case discovery.StatusUnassessed:
			result.Agents[index].Name = "Available " + agent.AgentType + " integration evidence"
		}
		result.Agents[index].Evidence = append([]discovery.Evidence(nil), agent.Evidence...)
		for evidenceIndex := range result.Agents[index].Evidence {
			result.Agents[index].Evidence[evidenceIndex].Source = privacySafeEvidenceSource(result.Agents[index].Evidence[evidenceIndex].Source)
		}
	}
	return result
}

func privacySafeEvidenceSource(source string) string {
	if filepath.IsAbs(source) {
		return classifyLocalPath(source)
	}
	normalized := filepath.ToSlash(filepath.Clean(source))
	parts := strings.Split(normalized, "/")
	for index, part := range parts {
		switch strings.ToLower(part) {
		case ".workbuddy", "workbuddy", ".codex", ".claude":
			return strings.Join(parts[index:], "/")
		case "users":
			if index+2 < len(parts) {
				return strings.Join(parts[index+2:], "/")
			}
		}
	}
	return normalized
}

func classifyLocalPath(path string) string {
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	switch {
	case strings.Contains(normalized, "/examples/shadow-agent-sample"):
		return "DEMO_FIXTURE"
	case strings.Contains(normalized, "/.workbuddy") || strings.Contains(normalized, "/workbuddy"):
		return "USER_PROFILE / AGENT_CONFIG"
	case strings.Contains(normalized, "/users/"):
		return "USER_PROFILE"
	case filepath.IsAbs(path):
		return "LOCAL_SCAN_ROOT"
	default:
		return filepath.ToSlash(path)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
