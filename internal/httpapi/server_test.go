package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/szey/Aegis_Router/internal/adapters/mcp"
	"github.com/szey/Aegis_Router/internal/audit"
	"github.com/szey/Aegis_Router/internal/config"
	"github.com/szey/Aegis_Router/internal/discovery"
	"github.com/szey/Aegis_Router/internal/executionproof"
	"github.com/szey/Aegis_Router/internal/httpapi"
	"github.com/szey/Aegis_Router/internal/intake"
	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/router"
	"github.com/szey/Aegis_Router/internal/scenario"
	"github.com/szey/Aegis_Router/internal/sessionaudit"
)

const httpTestWorkloadKeyID = "http-test-workload-key"

func TestLegacyRouteCannotReachExecutionPermitBoundary(t *testing.T) {
	handler := testHandler(t)
	input := models.Request{
		UserID: "user-01", AgentID: "coder-agent", TokenScopes: []string{"code.read"},
		RequestedAction: "Generate code", ClaimedIntent: "code_generation",
		RequestedCapability: "generate_code", TargetResource: "public_workspace",
		PlannedActions: []string{"read_safe_files", "generate_code"},
	}
	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/api/route", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "execution permit requires structured security context") || strings.Contains(recorder.Body.String(), "permit_token") {
		t.Fatalf("legacy route did not fail safely: %s", recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("content security policy header is missing")
	}
}

func TestAuthorizationHTTPFailsClosedWithoutTrustedIntake(t *testing.T) {
	handler := testHandlerWithServerOptions(t, filepath.Join(t.TempDir(), "session-audit.jsonl"), nil, nil, httpapi.Options{
		AuthorizationIntake: intake.RejectAll{},
	})
	body, _ := json.Marshal(structuredSafeRequest())
	request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "trusted_authorization_context_required") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestTrustedIntakeOverridesForgedHTTPIdentityAndIsAudited(t *testing.T) {
	identity := intake.IdentityContext{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human", Environment: "test"},
		Agent:     models.AgentIdentity{AgentID: "finance-agent", WorkloadID: "finance-workload-v1", Environment: "test"},
		DelegatedAuthority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("b", 64), Scopes: []string{"payment.transfer"}, Subject: "user-01",
		},
		WorkloadBinding: httpTestWorkloadBinding(t),
	}
	trustedIntake, err := intake.NewStatic(identity, "authenticated-test-middleware")
	if err != nil {
		t.Fatal(err)
	}
	handler := testHandlerWithServerOptions(t, filepath.Join(t.TempDir(), "session-audit.jsonl"), nil, nil, httpapi.Options{
		AuthorizationIntake: trustedIntake,
	})
	proposal := structuredSafeRequest()
	proposal.Principal.PrincipalID = "forged-user"
	proposal.Agent.AgentID = "forged-agent"
	proposal.Agent.WorkloadID = "forged-workload"
	proposal.Authority.CredentialFingerprint = strings.Repeat("b", 64)
	body, _ := json.Marshal(proposal)
	request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result models.ActionAuthorizationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Permit == nil || result.Decision.Request.Principal.PrincipalID != "user-01" || result.Decision.Request.Agent.AgentID != "finance-agent" {
		t.Fatalf("trusted identity did not replace caller metadata: %#v", result.Decision.Request)
	}
	provenance := result.Decision.AuthorizationContext
	if provenance == nil || provenance.ProviderID != "authenticated-test-middleware" || provenance.Assurance != intake.AssuranceAuthenticated {
		t.Fatalf("authorization provenance = %#v", provenance)
	}
}

func TestTrustedProxyAuthorizationExecutesOneNormalizedPaymentThroughMCP(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamCalls.Add(1)
		var rpc struct {
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(req.Body).Decode(&rpc); err != nil {
			t.Errorf("decode upstream request: %v", err)
		} else if string(rpc.Params.Arguments) != `{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}` {
			t.Errorf("upstream arguments = %s", rpc.Params.Arguments)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
	}))
	defer upstream.Close()

	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SemanticActions.PaymentSendV1.UpstreamURL = upstream.URL
	cfg = mockExecutionPolicy(cfg, "finance-agent", "payment_transfer", "account-123")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(cfg, store)
	if err := r.RegisterWorkloadPublicKey(httpTestWorkloadKeyID, httpTestWorkloadPrivateKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	mcpProxy, err := mcp.New(r, r.SemanticRegistry(), upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	trustedProxy, err := intake.NewTrustedProxy([]string{"127.0.0.1/32"}, "local-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	static, err := fs.Sub(fstest.MapFS{"static/index.html": {Data: []byte("ok")}}, "static")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	api := httpapi.NewWithOptions(r, store, cfg, nil, nil, filepath.Join(t.TempDir(), "session-audit.jsonl"), static, logger, httpapi.Options{
		MCPHandler: mcpProxy, AuthorizationIntake: trustedProxy,
	})
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	proposal := structuredSafeRequest()
	proposal.Principal = models.PrincipalContext{PrincipalID: "forged-admin", PrincipalType: "service"}
	proposal.Agent = models.AgentIdentity{AgentID: "attacker-agent", WorkloadID: "attacker-workload"}
	proposal.Authority = models.DelegatedAuthority{CredentialFingerprint: strings.Repeat("a", 64), Scopes: []string{"payment.unlimited"}, Subject: "forged-admin"}
	proposal.Action.Arguments = json.RawMessage(`{"recipient":"merchant-456","amount_minor":100,"currency":"USD"}`)
	proposalBody, _ := json.Marshal(proposal)
	authorizeRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/actions/authorize", bytes.NewReader(proposalBody))
	if err != nil {
		t.Fatal(err)
	}
	authorizeRequest.Header.Set("Content-Type", "application/json")
	setTrustedProxyAuthorizationHeaders(authorizeRequest.Header)
	authorizeResponse, err := server.Client().Do(authorizeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer authorizeResponse.Body.Close()
	if authorizeResponse.StatusCode != http.StatusOK {
		t.Fatalf("authorization status = %d", authorizeResponse.StatusCode)
	}
	var authorized models.ActionAuthorizationResponse
	if err := json.NewDecoder(authorizeResponse.Body).Decode(&authorized); err != nil {
		t.Fatal(err)
	}
	if authorized.Permit == nil || authorized.Decision.Request.Principal.PrincipalID != "user-01" || authorized.Decision.Request.Agent.AgentID != "finance-agent" || authorized.Decision.Request.Agent.WorkloadID != "finance-workload-v1" {
		t.Fatalf("trusted proxy identity was not authoritative: %#v", authorized.Decision.Request)
	}
	envelope := authorized.Decision.AuthorizationEnvelope
	if envelope == nil || envelope.PrincipalID != "user-01" || envelope.AgentID != "finance-agent" || envelope.WorkloadID != "finance-workload-v1" {
		t.Fatalf("signed Permit binding did not use trusted identity: %#v", envelope)
	}
	provenance := authorized.Decision.AuthorizationContext
	if provenance == nil || provenance.Source != intake.SourceTrustedIntegration || provenance.ProviderID != "local-auth-gateway" || provenance.Assurance != intake.AssuranceAuthenticated || provenance.EstablishedAt.IsZero() {
		t.Fatalf("trusted proxy provenance = %#v", provenance)
	}

	checkBody, _ := json.Marshal(map[string]any{
		"permit_token": authorized.Permit.PermitToken,
		"action":       structuredSafeRequest(),
	})
	checkRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/permits/verify", bytes.NewReader(checkBody))
	if err != nil {
		t.Fatal(err)
	}
	checkRequest.Header.Set("Content-Type", "application/json")
	checkResponse, err := server.Client().Do(checkRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer checkResponse.Body.Close()
	var checked models.PermitVerification
	if err := json.NewDecoder(checkResponse.Body).Decode(&checked); err != nil {
		t.Fatal(err)
	}
	if checkResponse.StatusCode != http.StatusOK || checked.Verified || checked.Outcome != "VALID_NOT_CONSUMED" || checked.State != "ISSUED" {
		t.Fatalf("diagnostic check status=%d result=%#v", checkResponse.StatusCode, checked)
	}
	permitRecord, ok := r.GetPermit(authorized.Permit.PermitID)
	if !ok || permitRecord.State != "ISSUED" {
		t.Fatalf("diagnostic HTTP route consumed Permit: %#v exists=%v", permitRecord, ok)
	}

	mcpBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payment.send","arguments":{"currency":"USD","recipient":"merchant-456","amount_minor":100},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	executeRequest, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(mcpBody))
	if err != nil {
		t.Fatal(err)
	}
	executeRequest.Header.Set("Authorization", "AegisPermit "+authorized.Permit.PermitToken)
	executeRequest.Header.Set(mcp.HeaderExecutionProof, httpExecutionProof(t, authorized, "payment-proof-01"))
	executeRequest.Header.Set(mcp.HeaderProtocolVersion, mcp.ProtocolVersion20260728)
	executeRequest.Header.Set(mcp.HeaderMethod, "tools/call")
	executeRequest.Header.Set(mcp.HeaderName, "payment.send")
	executeRequest.Header.Set(mcp.HeaderPrincipalID, "user-01")
	executeRequest.Header.Set(mcp.HeaderAgentID, "finance-agent")
	executeRequest.Header.Set(mcp.HeaderWorkloadID, "finance-workload-v1")
	executeRequest.Header.Set(mcp.HeaderDelegationFingerprint, strings.Repeat("b", 64))
	executeRequest.Header.Set(mcp.HeaderCapability, "payment_transfer")
	executeRequest.Header.Set(mcp.HeaderResource, "account-123")
	executeRequest.Header.Set(mcp.HeaderOperation, "transfer")
	executeResponse, err := server.Client().Do(executeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer executeResponse.Body.Close()
	if executeResponse.StatusCode != http.StatusOK || upstreamCalls.Load() != 1 {
		t.Fatalf("execution status=%d upstream calls=%d", executeResponse.StatusCode, upstreamCalls.Load())
	}

	record, ok := store.Get(authorized.Decision.RequestID)
	if !ok || record.AuthorizationContext == nil || record.AuthorizationContext.ProviderID != "local-auth-gateway" || record.ExecutionReceipt == nil ||
		record.ExecutionReceipt.PrincipalID != "user-01" || record.ExecutionReceipt.AgentID != "finance-agent" || record.ExecutionReceipt.WorkloadID != "finance-workload-v1" ||
		record.ExecutionReceipt.Tool != "payment.send" || record.ExecutionReceipt.Capability != "payment_transfer" || record.ExecutionReceipt.Resource != "account-123" || record.ExecutionReceipt.Operation != "transfer" ||
		record.ExecutionReceipt.ProfileID != "payment.send/v1" || record.ExecutionReceipt.Audience != "mcp://local-payment-sandbox" || record.ExecutionReceipt.ActionDigest == "" ||
		record.ExecutionReceipt.VerificationOutcome != "VERIFIED" || record.ExecutionReceipt.PermitID == "" {
		t.Fatalf("trusted execution audit record = %#v", record)
	}
	persisted, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{authorized.Permit.PermitToken, "forged-admin", "attacker-agent", "attacker-workload", "merchant-456"} {
		if bytes.Contains(persisted, []byte(forbidden)) {
			t.Fatalf("audit leaked caller-controlled or secret value %q", forbidden)
		}
	}
}

func TestTrustedProxyAuthorizationExecutesWorkspaceWriteThroughSharedMCPBoundary(t *testing.T) {
	const rawContentMarker = "TRUSTED_WORKSPACE_CONTENT_MUST_STAY_PRIVATE_9c42"
	var workspaceCalls atomic.Int32
	workspaceUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		workspaceCalls.Add(1)
		var rpc struct {
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(req.Body).Decode(&rpc); err != nil {
			t.Errorf("decode workspace upstream request: %v", err)
		} else if rpc.Params.Name != "workspace.write" || string(rpc.Params.Arguments) != `{"path":"reports/result.txt","content":"`+rawContentMarker+`"}` {
			t.Errorf("workspace upstream action=%#v", rpc.Params)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
	}))
	defer workspaceUpstream.Close()
	paymentUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer paymentUpstream.Close()

	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SemanticActions.PaymentSendV1.UpstreamURL = paymentUpstream.URL
	cfg.SemanticActions.WorkspaceWriteV1.UpstreamURL = workspaceUpstream.URL
	cfg = mockExecutionPolicy(cfg, "workspace-agent", "workspace_write", "demo-workspace")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(cfg, store)
	if err := r.RegisterWorkloadPublicKey(httpTestWorkloadKeyID, httpTestWorkloadPrivateKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	mcpProxy, err := mcp.New(r, r.SemanticRegistry(), paymentUpstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	trustedProxy, err := intake.NewTrustedProxy([]string{"127.0.0.1/32"}, "local-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	static, err := fs.Sub(fstest.MapFS{"static/index.html": {Data: []byte("ok")}}, "static")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	api := httpapi.NewWithOptions(r, store, cfg, nil, nil, filepath.Join(t.TempDir(), "session-audit.jsonl"), static, logger, httpapi.Options{
		MCPHandler: mcpProxy, AuthorizationIntake: trustedProxy,
	})
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	proposal := models.Request{
		Principal: models.PrincipalContext{PrincipalID: "forged-admin", PrincipalType: "service"},
		Agent:     models.AgentIdentity{AgentID: "attacker-agent", WorkloadID: "attacker-workload"},
		Authority: models.DelegatedAuthority{CredentialFingerprint: strings.Repeat("a", 64), Scopes: []string{"workspace.admin"}},
		Tool:      models.ToolContext{Name: "workspace.write", Provider: "mcp"},
		Action: models.ActionRequest{
			Capability: "workspace_write", TargetResource: "demo-workspace", Operation: "write",
			Arguments: json.RawMessage(`{"content":"` + rawContentMarker + `","path":"reports/result.txt"}`),
		},
	}
	proposalBody, _ := json.Marshal(proposal)
	authorizeRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/actions/authorize", bytes.NewReader(proposalBody))
	authorizeRequest.Header.Set("Content-Type", "application/json")
	setTrustedProxyWorkspaceAuthorizationHeaders(authorizeRequest.Header)
	authorizeResponse, err := server.Client().Do(authorizeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer authorizeResponse.Body.Close()
	var authorized models.ActionAuthorizationResponse
	if err := json.NewDecoder(authorizeResponse.Body).Decode(&authorized); err != nil {
		t.Fatal(err)
	}
	if authorizeResponse.StatusCode != http.StatusOK || authorized.Permit == nil || authorized.Permit.ProfileID != "workspace.write/v1" ||
		authorized.Decision.Request.Agent.AgentID != "workspace-agent" || authorized.Decision.Request.Agent.WorkloadID != "workspace-workload-v1" {
		t.Fatalf("workspace authorization status=%d result=%#v", authorizeResponse.StatusCode, authorized)
	}

	mcpBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace.write","arguments":{"path":"reports/result.txt","content":"` + rawContentMarker + `"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	executeRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(mcpBody))
	executeRequest.Header.Set("Authorization", "AegisPermit "+authorized.Permit.PermitToken)
	executeRequest.Header.Set(mcp.HeaderExecutionProof, httpExecutionProof(t, authorized, "workspace-proof-01"))
	executeRequest.Header.Set(mcp.HeaderProtocolVersion, mcp.ProtocolVersion20260728)
	executeRequest.Header.Set(mcp.HeaderMethod, "tools/call")
	executeRequest.Header.Set(mcp.HeaderName, "workspace.write")
	executeRequest.Header.Set(mcp.HeaderPrincipalID, "user-01")
	executeRequest.Header.Set(mcp.HeaderAgentID, "workspace-agent")
	executeRequest.Header.Set(mcp.HeaderWorkloadID, "workspace-workload-v1")
	executeRequest.Header.Set(mcp.HeaderDelegationFingerprint, strings.Repeat("e", 64))
	executeRequest.Header.Set(mcp.HeaderCapability, "workspace_write")
	executeRequest.Header.Set(mcp.HeaderResource, "demo-workspace")
	executeRequest.Header.Set(mcp.HeaderOperation, "write")
	executeResponse, err := server.Client().Do(executeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer executeResponse.Body.Close()
	if executeResponse.StatusCode != http.StatusOK || workspaceCalls.Load() != 1 {
		t.Fatalf("workspace execution status=%d calls=%d", executeResponse.StatusCode, workspaceCalls.Load())
	}
	record, ok := store.Get(authorized.Decision.RequestID)
	if !ok || record.AuthorizationContext == nil || record.AuthorizationContext.ProviderID != "local-auth-gateway" ||
		record.ExecutionReceipt == nil || record.ExecutionReceipt.ProfileID != "workspace.write/v1" || record.ExecutionReceipt.VerificationOutcome != "VERIFIED" {
		t.Fatalf("workspace trusted execution audit=%#v", record)
	}
	persisted, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{rawContentMarker, authorized.Permit.PermitToken, "forged-admin", "attacker-agent", "attacker-workload"} {
		if bytes.Contains(persisted, []byte(forbidden)) {
			t.Fatalf("workspace audit leaked %q", forbidden)
		}
	}
}

func TestTrustedProxyHTTPFailuresIssueNoPermit(t *testing.T) {
	provider, err := intake.NewTrustedProxy([]string{"127.0.0.1/32"}, "local-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		remoteAddr string
		mutate     func(http.Header)
	}{
		{"untrusted direct peer", "192.0.2.10:43210", func(http.Header) {}},
		{"missing workload header", "127.0.0.1:43210", func(header http.Header) { header.Del(intake.HeaderWorkloadID) }},
		{"invalid delegation fingerprint", "127.0.0.1:43210", func(header http.Header) { header.Set(intake.HeaderDelegationFingerprint, "not-a-fingerprint") }},
		{"malformed scopes", "127.0.0.1:43210", func(header http.Header) { header.Set(intake.HeaderDelegatedScopes, "payment.transfer,,finance.read") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, store := trustedProxyTestHandler(t, provider)
			body, _ := json.Marshal(structuredSafeRequest())
			request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", bytes.NewReader(body))
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("Content-Type", "application/json")
			setTrustedProxyAuthorizationHeaders(request.Header)
			test.mutate(request.Header)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "permit_token") || len(store.Recent(10)) != 0 {
				t.Fatalf("status=%d body=%s audit records=%d", response.Code, response.Body.String(), len(store.Recent(10)))
			}
		})
	}
}

func TestTrustedProxyLegacyFlatAuthorizationCannotIssueExecutionPermit(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	provider, err := intake.NewTrustedProxy([]string{"127.0.0.1/32"}, "local-auth-gateway")
	if err != nil {
		t.Fatal(err)
	}
	handler, store := trustedProxyMCPTestHandler(t, provider, upstream.URL)
	legacy := models.Request{
		UserID: "forged-user", AgentID: "finance-agent", TokenScopes: []string{"payment.transfer"},
		RequestedCapability: "payment_transfer", TargetResource: "account-123",
	}
	body, _ := json.Marshal(legacy)
	for _, test := range []struct {
		name              string
		trustedWorkloadID string
	}{
		{"legacy flat identity", "finance-workload-v1"},
		{"agent-derived workload fallback", "attacker-workload"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", bytes.NewReader(body))
			request.RemoteAddr = "127.0.0.1:43210"
			request.Header.Set("Content-Type", "application/json")
			setTrustedProxyAuthorizationHeaders(request.Header)
			request.Header.Set(intake.HeaderWorkloadID, test.trustedWorkloadID)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "execution permit requires structured security context") ||
				strings.Contains(response.Body.String(), "permit_token") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if upstreamCalls.Load() != 0 || len(store.Recent(10)) != 0 {
		t.Fatalf("legacy request produced execution evidence: upstream=%d audits=%d", upstreamCalls.Load(), len(store.Recent(10)))
	}
}

func TestRouteEndpointRejectsUnknownFields(t *testing.T) {
	handler := testHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/route", bytes.NewBufferString(`{"surprise":true}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestAuthorizeIssuesPermitWithoutInventingRuntimeEvents(t *testing.T) {
	handler := testHandler(t)
	input := structuredSafeRequest()
	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/api/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var record models.AuditRecord
	if err := json.NewDecoder(response.Body).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if !record.PolicyDecision.Authorized || record.AuthorizationEnvelope == nil {
		t.Fatalf("authorization result = %#v", record)
	}
	if len(record.RuntimeObservation.Events) != 0 || len(record.RuntimeObservation.EventEvaluations) != 0 {
		t.Fatalf("authorize invented runtime evidence: %#v", record.RuntimeObservation)
	}
	if record.DispatchDecision.ExecutorInvoked {
		t.Fatal("routing must not claim that an unconnected executor ran")
	}
}

func TestActionPermitAPINeverListsCredentialAndVerifyRouteOnlyChecks(t *testing.T) {
	handler := testHandler(t)
	input := structuredSafeRequest()
	input.Action.Arguments = json.RawMessage(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
	body, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var authorized models.ActionAuthorizationResponse
	if err := json.NewDecoder(response.Body).Decode(&authorized); err != nil {
		t.Fatal(err)
	}
	if authorized.Permit == nil || authorized.Permit.PermitToken == "" || authorized.Permit.PermitID == "" {
		t.Fatalf("authorization response = %#v", authorized)
	}
	if authorized.Decision.ExecutionReceipt == nil || authorized.Decision.ExecutionReceipt.ActionDigest == "" {
		t.Fatalf("authorization receipt = %#v", authorized.Decision.ExecutionReceipt)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/permits?limit=10", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("permit list status = %d", response.Code)
	}
	listed := response.Body.String()
	if strings.Contains(listed, authorized.Permit.PermitToken) || strings.Contains(listed, "merchant-456") || strings.Contains(listed, "permit_token") {
		t.Fatalf("permit list leaked credential or raw arguments: %s", listed)
	}

	verificationBody, _ := json.Marshal(map[string]any{"permit_token": authorized.Permit.PermitToken, "action": input})
	request = httptest.NewRequest(http.MethodPost, "/api/permits/verify", bytes.NewReader(verificationBody))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var first models.PermitVerification
	if err := json.NewDecoder(response.Body).Decode(&first); err != nil {
		t.Fatal(err)
	}
	if first.Verified || first.Outcome != "VALID_NOT_CONSUMED" || first.State != "ISSUED" {
		t.Fatalf("first verification = %#v", first)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/permits/verify", bytes.NewReader(verificationBody))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var second models.PermitVerification
	if err := json.NewDecoder(response.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	if second.Verified || second.Outcome != "VALID_NOT_CONSUMED" || second.State != "ISSUED" {
		t.Fatalf("second verification = %#v", second)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/permits/"+authorized.Permit.PermitID, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"ISSUED"`) {
		t.Fatalf("HTTP check consumed Permit: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPrimaryPermitDemosExerciseFocusedOutcomes(t *testing.T) {
	handler := testHandler(t)
	cases := []struct {
		id              string
		outcome         string
		upstreamInvoked bool
		attempts        int
	}{
		{"valid-permit", "VERIFIED", true, 1},
		{"action-mutation", "ACTION_MISMATCH", false, 1},
		{"permit-replay", "REPLAYED", true, 2},
		{"expired-permit", "EXPIRED", false, 1},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/demo-lab/"+test.id+"/run", bytes.NewBufferString(`{}`))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			var result struct {
				VerificationResult string                      `json:"verification_result"`
				EvidenceSource     models.RuntimeEventSource   `json:"evidence_source"`
				UpstreamInvoked    bool                        `json:"upstream_invoked"`
				Attempts           []models.PermitVerification `json:"attempts"`
				Decision           models.AuditRecord          `json:"decision"`
			}
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if result.VerificationResult != test.outcome || result.UpstreamInvoked != test.upstreamInvoked || len(result.Attempts) != test.attempts {
				t.Fatalf("demo result = %#v", result)
			}
			if result.EvidenceSource != models.RuntimeSourceSimulatedDemo {
				t.Fatalf("demo evidence source = %q", result.EvidenceSource)
			}
			auditRequest := httptest.NewRequest(http.MethodGet, "/api/audits?limit=100", nil)
			auditResponse := httptest.NewRecorder()
			handler.ServeHTTP(auditResponse, auditRequest)
			var records []models.AuditRecord
			if err := json.NewDecoder(auditResponse.Body).Decode(&records); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, record := range records {
				if record.RequestID == result.Decision.RequestID {
					found = record.ExecutionReceipt != nil && record.ExecutionReceipt.EvidenceSource == models.RuntimeSourceSimulatedDemo
					break
				}
			}
			if !found {
				t.Fatalf("persisted demo audit did not retain simulated_demo provenance for %s", result.Decision.RequestID)
			}
		})
	}
}

func TestPublicRequestRejectsLegacySimulatedActionsField(t *testing.T) {
	handler := testHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/authorize", bytes.NewBufferString(`{
		"user_id":"user-01","agent_id":"coder-agent","token_scopes":["code.read"],
		"requested_capability":"generate_code","target_resource":"public_workspace",
		"simulated_actions":["read_secret"]
	}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestRuntimeEventEndpointEvaluatesPermitAndReservesDemoSource(t *testing.T) {
	handler := testHandler(t)
	authorizeBody, _ := json.Marshal(structuredSafeRequest())
	authorizeRequest := httptest.NewRequest(http.MethodPost, "/api/authorize", bytes.NewReader(authorizeBody))
	authorizeResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizeResponse, authorizeRequest)
	var record models.AuditRecord
	if err := json.NewDecoder(authorizeResponse.Body).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record.AuthorizationEnvelope == nil {
		t.Fatalf("authorize body = %s", authorizeResponse.Body.String())
	}
	permit := record.AuthorizationEnvelope
	event := models.RuntimeEvent{
		EventID: "event-1", PermitID: permit.PermitID, RequestID: record.RequestID,
		AgentID: permit.AgentID, WorkloadID: permit.WorkloadID,
		Source: models.RuntimeSourceInstrumentedAdapter, TrustLevel: models.RuntimeTrustAdapterReported,
		Capability: permit.AllowedCapability, Tool: permit.AllowedTool,
		Operation: permit.AllowedOperations[0], Resource: permit.AllowedResource,
	}
	eventBody, _ := json.Marshal(event)
	eventRequest := httptest.NewRequest(http.MethodPost, "/api/runtime-events", bytes.NewReader(eventBody))
	eventResponse := httptest.NewRecorder()
	handler.ServeHTTP(eventResponse, eventRequest)
	if eventResponse.Code != http.StatusOK {
		t.Fatalf("event status = %d, body = %s", eventResponse.Code, eventResponse.Body.String())
	}
	var evaluation models.RuntimeEventEvaluation
	if err := json.NewDecoder(eventResponse.Body).Decode(&evaluation); err != nil {
		t.Fatal(err)
	}
	if !evaluation.Accepted || !evaluation.WithinEnvelope {
		t.Fatalf("evaluation = %#v", evaluation)
	}

	event.EventID = "event-demo-forgery"
	event.Source = models.RuntimeSourceSimulatedDemo
	event.TrustLevel = models.RuntimeTrustSimulated
	eventBody, _ = json.Marshal(event)
	eventRequest = httptest.NewRequest(http.MethodPost, "/api/runtime-events", bytes.NewReader(eventBody))
	eventResponse = httptest.NewRecorder()
	handler.ServeHTTP(eventResponse, eventRequest)
	if eventResponse.Code != http.StatusBadRequest {
		t.Fatalf("reserved demo source status = %d, body = %s", eventResponse.Code, eventResponse.Body.String())
	}
}

func TestDemoLabRunsServerOwnedTelemetryAndShowsBoundaryViolation(t *testing.T) {
	handler := testHandlerWithDemoScenarios(t)
	req := httptest.NewRequest(http.MethodPost, "/api/demo-lab/authorization-boundary-violation/run", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var record models.AuditRecord
	if err := json.NewDecoder(response.Body).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record.FinalVerdict != "AUTHORIZATION_BOUNDARY_VIOLATION" {
		t.Fatalf("final verdict = %q", record.FinalVerdict)
	}
	if len(record.RuntimeObservation.Events) != 2 || len(record.RuntimeObservation.EventEvaluations) != 2 {
		t.Fatalf("runtime observation = %#v", record.RuntimeObservation)
	}
	for _, event := range record.RuntimeObservation.Events {
		if event.Source != models.RuntimeSourceSimulatedDemo || event.TrustLevel != models.RuntimeTrustSimulated {
			t.Fatalf("demo event provenance = %q/%q", event.Source, event.TrustLevel)
		}
	}
	if len(record.RuntimeObservation.AuthorizationViolations) == 0 {
		t.Fatal("boundary violation must be explicit in the audit record")
	}
}

func TestAdvancedDemoFixtureRemainsEvidenceOnlyCompatibility(t *testing.T) {
	handler := testHandlerWithDemoScenarios(t)
	req := httptest.NewRequest(http.MethodPost, "/api/demo-lab/safe-code/run", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var record models.AuditRecord
	if err := json.NewDecoder(response.Body).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record.FinalVerdict != "COMPLETED_WITHOUT_BOUNDARY_VERIFICATION" {
		t.Fatalf("final verdict = %q", record.FinalVerdict)
	}
	if len(record.RuntimeObservation.Events) != 1 || record.RuntimeObservation.Events[0].Source != models.RuntimeSourceSimulatedDemo {
		t.Fatalf("runtime observation = %#v", record.RuntimeObservation)
	}
}

func TestRuntimeCoverageNeverPresentsMissingSensorsAsZeroEvents(t *testing.T) {
	handler := testHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/runtime-coverage", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Coverage  models.RuntimeCoverage `json:"coverage"`
		Principle string                 `json:"principle"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Coverage.Filesystem != "not_instrumented" || body.Coverage.Network != "not_instrumented" || body.Coverage.IsolationBackend != "not_connected" {
		t.Fatalf("coverage = %#v", body.Coverage)
	}
	if !strings.Contains(body.Principle, "zero events never implies") {
		t.Fatalf("principle = %q", body.Principle)
	}
}

func TestExperimentalInventoryIsDisabledByDefault(t *testing.T) {
	handler := testHandlerWithServerOptions(t, filepath.Join(t.TempDir(), "session-audit.jsonl"), nil, nil, httpapi.Options{})
	request := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("inventory status = %d, want 404 while disabled", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/health", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var body struct {
		Features map[string]bool `json:"features"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Features["experimental_inventory"] {
		t.Fatal("health advertised experimental inventory as enabled by default")
	}
}

func TestDiscoveryAPIClassifiesLocalRootsAndKeepsEvidenceRelative(t *testing.T) {
	root := t.TempDir()
	privateSegment := "private-user-segment"
	configDir := filepath.Join(root, privateSegment, ".workbuddy")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "mcp.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := testHandlerWithOptions(t, filepath.Join(t.TempDir(), "session-audit.jsonl"), nil, []string{root})
	req := httptest.NewRequest(http.MethodGet, "/api/discoveries", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var report discovery.Report
	if err := json.NewDecoder(response.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	responseText := strings.ToLower(response.Body.String())
	if len(report.Roots) != 1 || filepath.IsAbs(report.Roots[0]) || strings.Contains(responseText, strings.ToLower(filepath.ToSlash(root))) || strings.Contains(responseText, privateSegment) {
		t.Fatalf("discovery API exposed a local root: %s", response.Body.String())
	}
	if len(report.Agents) != 1 || len(report.Agents[0].Evidence) == 0 || report.Agents[0].Evidence[0].Source != ".workbuddy/mcp.json" {
		t.Fatalf("evidence is not a relative inventory reference: %#v", report)
	}
}

func TestAgentsAPIDistinguishesGovernedIdentitiesFromAssetRegistry(t *testing.T) {
	handler := testHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body struct {
		GovernedIdentities []map[string]any          `json:"governed_identities"`
		AssetRegistry      []discovery.RegistryEntry `json:"asset_registry"`
		Principle          string                    `json:"principle"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.GovernedIdentities) != 5 || len(body.AssetRegistry) != 0 {
		t.Fatalf("agents response conflated policy identities and registration: %#v", body)
	}
	if !strings.Contains(strings.ToLower(body.Principle), "behavioral permissions live in policy") {
		t.Fatalf("principle = %q", body.Principle)
	}
}

func TestApprovedAgentRegistryRequiresAdminHeader(t *testing.T) {
	handler := testHandler(t)
	body := bytes.NewBufferString(`{"name":"WorkBuddy","agent_type":"mcp","path_contains":".mcp.json","owner":"security"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/approved-agents", body)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestApprovedAgentRegistryCanBeManagedFromLocalUI(t *testing.T) {
	handler := testHandler(t)
	body := bytes.NewBufferString(`{"name":"WorkBuddy","agent_type":"mcp","path_contains":".mcp.json","owner":"security"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/approved-agents", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Admin", "local-ui")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var result struct {
		Approved discovery.RegistryEntry `json:"approved_agent"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Approved.ID == "" || result.Approved.Name != "WorkBuddy" {
		t.Fatalf("approved entry = %#v", result.Approved)
	}
}

func TestAllowAndDenyDecisionsAreBothAudited(t *testing.T) {
	handler := testHandler(t)
	allowed := structuredSafeRequest()
	denied := structuredSafeRequest()
	denied.Action.Arguments = json.RawMessage(`{"amount_minor":10001,"currency":"USD","recipient":"merchant-456"}`)
	requests := []models.Request{allowed, denied}
	for _, input := range requests {
		body, _ := json.Marshal(input)
		req := httptest.NewRequest(http.MethodPost, "/api/actions/authorize", bytes.NewReader(body))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("route status = %d, body = %s", response.Code, response.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audits?limit=10", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	var records []models.AuditRecord
	if err := json.NewDecoder(response.Body).Decode(&records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].PolicyDecision.Route != models.RouteDeny || records[1].PolicyDecision.Route != models.RouteAllow {
		t.Fatalf("audits = %#v, want deny and allow", records)
	}
}

func TestSessionEventsEndpointDistinguishesEvidenceTrust(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-audit.jsonl")
	recorder, err := sessionaudit.New(path, "codex-pilot-001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.RecordLifecycle("process.started", "running", []string{"pid=42"}); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.RecordJSONLine([]byte(`{"type":"item.completed","item":{"id":"item-1","type":"command_execution","status":"completed","exit_code":0}}`)); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}

	handler := testHandlerWithSessionAudit(t, path)
	req := httptest.NewRequest(http.MethodGet, "/api/session-events?limit=10", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Events  []sessionaudit.Event `json:"events"`
		Summary struct {
			Observer     int    `json:"observer_recorded"`
			SelfReported int    `json:"self_reported"`
			Coverage     string `json:"coverage"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Events) != 2 || body.Summary.Observer != 1 || body.Summary.SelfReported != 1 {
		t.Fatalf("unexpected session report: %#v", body)
	}
	if body.Summary.Coverage != "wrapper_and_self_reported_only" {
		t.Fatalf("coverage = %q", body.Summary.Coverage)
	}
}

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	return testHandlerWithOptions(t, filepath.Join(t.TempDir(), "session-audit.jsonl"), nil, nil)
}

func testHandlerWithSessionAudit(t *testing.T, sessionAuditPath string) http.Handler {
	t.Helper()
	return testHandlerWithOptions(t, sessionAuditPath, nil, nil)
}

func testHandlerWithDemoScenarios(t *testing.T) http.Handler {
	t.Helper()
	scenarios, err := scenario.LoadDirectory(filepath.Join("..", "..", "examples"))
	if err != nil {
		t.Fatal(err)
	}
	return testHandlerWithOptions(t, filepath.Join(t.TempDir(), "session-audit.jsonl"), scenarios, nil)
}

func testHandlerWithOptions(t *testing.T, sessionAuditPath string, scenarios []models.Scenario, discoveryRoots []string) http.Handler {
	return testHandlerWithServerOptions(t, sessionAuditPath, scenarios, discoveryRoots, httpapi.Options{ExperimentalInventory: true})
}

func testHandlerWithServerOptions(t *testing.T, sessionAuditPath string, scenarios []models.Scenario, discoveryRoots []string, options httpapi.Options) http.Handler {
	t.Helper()
	if options.AuthorizationIntake == nil {
		developmentIntake, err := intake.NewLoopbackDevelopment("httpapi-test", httpTestWorkloadBinding(t))
		if err != nil {
			t.Fatal(err)
		}
		options.AuthorizationIntake = developmentIntake
	}
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	static, err := fs.Sub(fstest.MapFS{"static/index.html": {Data: []byte("ok")}}, "static")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	discoveryConfig := filepath.Join(t.TempDir(), "discovery.json")
	if err := os.WriteFile(discoveryConfig, []byte(`{
		"signatures":[{"agent_type":"mcp","display_name":"MCP","file_names":["mcp.json"]}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := discovery.NewManager(discoveryConfig, filepath.Join(t.TempDir(), "approved-agents.json"), discoveryRoots)
	if err != nil {
		t.Fatal(err)
	}
	handler := httpapi.NewWithOptions(router.New(cfg, store), store, cfg, scenarios, manager, sessionAuditPath, static, logger, options).Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.RemoteAddr = "127.0.0.1:54321"
		handler.ServeHTTP(w, req)
	})
}

func structuredSafeRequest() models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human", Environment: "test"},
		Agent:     models.AgentIdentity{AgentID: "finance-agent", WorkloadID: "finance-workload-v1", Environment: "test"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("b", 64), Scopes: []string{"payment.transfer"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "payment.send", Provider: "mcp"},
		Action: models.ActionRequest{
			Capability: "payment_transfer", Operation: "transfer", TargetResource: "account-123",
			Arguments:  json.RawMessage(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`),
			SideEffect: "financial_transaction",
		},
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func trustedProxyTestHandler(t *testing.T, provider *intake.TrustedProxy) (http.Handler, *audit.Store) {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	static, err := fs.Sub(fstest.MapFS{"static/index.html": {Data: []byte("ok")}}, "static")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	server := httpapi.NewWithOptions(router.New(cfg, store), store, cfg, nil, nil, filepath.Join(t.TempDir(), "session-audit.jsonl"), static, logger, httpapi.Options{
		AuthorizationIntake: provider,
	})
	return server.Handler(), store
}

func trustedProxyMCPTestHandler(t *testing.T, provider *intake.TrustedProxy, upstreamURL string) (http.Handler, *audit.Store) {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SemanticActions.PaymentSendV1.UpstreamURL = upstreamURL
	store, err := audit.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(cfg, store)
	if err := r.RegisterWorkloadPublicKey(httpTestWorkloadKeyID, httpTestWorkloadPrivateKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	proxy, err := mcp.New(r, r.SemanticRegistry(), upstreamURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	static, err := fs.Sub(fstest.MapFS{"static/index.html": {Data: []byte("ok")}}, "static")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	server := httpapi.NewWithOptions(r, store, cfg, nil, nil, filepath.Join(t.TempDir(), "session-audit.jsonl"), static, logger, httpapi.Options{
		MCPHandler: proxy, AuthorizationIntake: provider,
	})
	return server.Handler(), store
}

func setTrustedProxyAuthorizationHeaders(header http.Header) {
	header.Set(intake.HeaderAuthenticatedPrincipal, "user-01")
	header.Set(intake.HeaderAgentID, "finance-agent")
	header.Set(intake.HeaderWorkloadID, "finance-workload-v1")
	header.Set(intake.HeaderDelegatedScopes, "payment.transfer")
	header.Set(intake.HeaderDelegationFingerprint, strings.Repeat("b", 64))
	header.Set(intake.HeaderWorkloadKeyID, httpTestWorkloadKeyID)
	header.Set(intake.HeaderWorkloadKeyThumbprint, httpTestWorkloadBindingValue().PublicKeyThumbprint)
}

func setTrustedProxyWorkspaceAuthorizationHeaders(header http.Header) {
	header.Set(intake.HeaderAuthenticatedPrincipal, "user-01")
	header.Set(intake.HeaderAgentID, "workspace-agent")
	header.Set(intake.HeaderWorkloadID, "workspace-workload-v1")
	header.Set(intake.HeaderDelegatedScopes, "workspace.write")
	header.Set(intake.HeaderDelegationFingerprint, strings.Repeat("e", 64))
	header.Set(intake.HeaderWorkloadKeyID, httpTestWorkloadKeyID)
	header.Set(intake.HeaderWorkloadKeyThumbprint, httpTestWorkloadBindingValue().PublicKeyThumbprint)
}

func httpTestWorkloadPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(100 + index)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func httpTestWorkloadBindingValue() intake.WorkloadBinding {
	thumbprint, _ := executionproof.Thumbprint(httpTestWorkloadPrivateKey().Public().(ed25519.PublicKey))
	return intake.WorkloadBinding{KeyID: httpTestWorkloadKeyID, PublicKeyThumbprint: thumbprint}
}

func httpTestWorkloadBinding(t *testing.T) intake.WorkloadBinding {
	t.Helper()
	binding := httpTestWorkloadBindingValue()
	if binding.PublicKeyThumbprint == "" {
		t.Fatal("derive test workload thumbprint")
	}
	return binding
}

func httpExecutionProof(t *testing.T, authorized models.ActionAuthorizationResponse, nonce string) string {
	t.Helper()
	proof, err := executionproof.Sign(httpTestWorkloadPrivateKey(), httpTestWorkloadKeyID, executionproof.Claims{
		PermitID: authorized.Permit.PermitID, ActionDigest: authorized.Decision.AuthorizationEnvelope.ActionDigest,
		HTTPMethod: http.MethodPost, HTTPPath: "/mcp", IssuedAt: authorized.Permit.IssuedAt.Unix(), Nonce: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
