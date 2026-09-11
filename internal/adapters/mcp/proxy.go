// Package mcp implements the focused MVP enforcement boundary for MCP
// tools/call requests. Protocol setup and tool discovery may pass through, but
// an upstream tool call is never made until an Aegis permit verifies and is
// atomically consumed.
package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"agent-governance-gateway/internal/canonicalaction"
	"agent-governance-gateway/internal/models"
	"agent-governance-gateway/internal/semanticaction"
)

const (
	HeaderPrincipalID           = "X-Aegis-Principal-Id"
	HeaderAgentID               = "X-Aegis-Agent-Id"
	HeaderWorkloadID            = "X-Aegis-Workload-Id"
	HeaderDelegationFingerprint = "X-Aegis-Delegation-Fingerprint"
	HeaderCapability            = "X-Aegis-Capability"
	HeaderResource              = "X-Aegis-Resource"
	HeaderOperation             = "X-Aegis-Operation"
	HeaderProfileID             = "X-Aegis-Profile-Id"
	HeaderAudience              = "X-Aegis-Audience"
	HeaderExecutionProof        = "X-Aegis-Execution-Proof"
	HeaderProtocolVersion       = "MCP-Protocol-Version"
	HeaderMethod                = "Mcp-Method"
	HeaderName                  = "Mcp-Name"
	ProtocolVersion20260728     = "2026-07-28"
	permitScheme                = "AegisPermit"
	maxRequestBytes             = canonicalaction.MaxArgumentsBytes + 64*1024
	headerMismatchCode          = -32020
	unsupportedVersionCode      = -32022
)

type Gate interface {
	VerifyExecutionProof(permitToken, proofToken string, action canonicalaction.Action, httpMethod, httpPath string) (models.PermitVerification, error)
	VerifyAndConsume(permitToken string, action canonicalaction.Action) (models.PermitVerification, error)
	IngestRuntimeEvent(event models.RuntimeEvent) (models.RuntimeEventEvaluation, error)
	CompleteVerifiedExecution(completion models.ExecutionCompletion) (models.AuditRecord, error)
}

type Proxy struct {
	gate            Gate
	registry        *semanticaction.Registry
	controlUpstream *url.URL
	client          *http.Client
}

func New(gate Gate, registry *semanticaction.Registry, controlUpstreamURL string, client *http.Client) (*Proxy, error) {
	if gate == nil {
		return nil, fmt.Errorf("MCP proxy requires an execution-permit gate")
	}
	if registry == nil || registry.Len() == 0 {
		return nil, fmt.Errorf("MCP proxy requires at least one server-owned semantic profile")
	}
	target, err := url.Parse(strings.TrimSpace(controlUpstreamURL))
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("MCP control upstream must be an absolute HTTP(S) URL")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("MCP control upstream scheme must be http or https")
	}
	if !registry.OwnsUpstreamURL(target.String()) {
		return nil, fmt.Errorf("MCP control upstream must match a server-owned semantic profile upstream")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Proxy{gate: gate, registry: registry, controlUpstream: target, client: client}, nil
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type toolCallParams struct {
	Name      string                     `json:"name"`
	Arguments json.RawMessage            `json:"arguments"`
	Meta      map[string]json.RawMessage `json:"_meta,omitempty"`
}

type routingMetadata struct {
	ProtocolVersion string
	Method          string
	Name            string
	Modern          bool
}

type routingValidationError struct {
	code    int
	message string
}

func (e routingValidationError) Error() string { return e.message }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, nil, -32600, "POST required", nil)
		return
	}
	defer req.Body.Close()
	body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		writeRPCError(w, http.StatusRequestEntityTooLarge, nil, -32600, "MCP request is too large", nil)
		return
	}
	// A parser differential at this boundary could authorize one value while
	// the upstream executes another. Reject duplicate keys and lossy JSON
	// encodings before decoding the request used for either decision.
	if _, err := canonicalaction.CanonicalizeJSON(body); err != nil {
		writeRPCError(w, http.StatusBadRequest, nil, -32700, "Invalid or ambiguous JSON-RPC request", nil)
		return
	}
	var rpc rpcRequest
	if err := json.Unmarshal(body, &rpc); err != nil || rpc.JSONRPC != "2.0" || strings.TrimSpace(rpc.Method) == "" {
		writeRPCError(w, http.StatusBadRequest, rpc.ID, -32700, "Invalid JSON-RPC request", nil)
		return
	}
	routing, err := validateRoutingMetadata(req.Header, rpc)
	if err != nil {
		code := headerMismatchCode
		data := any(nil)
		if typed, ok := err.(routingValidationError); ok {
			code = typed.code
			if code == unsupportedVersionCode {
				data = map[string]any{"supported": []string{ProtocolVersion20260728}, "requested": req.Header.Get(HeaderProtocolVersion)}
			}
		}
		writeRPCError(w, http.StatusBadRequest, rpc.ID, code, err.Error(), data)
		return
	}

	if rpc.Method != "tools/call" {
		if !safeProtocolMethod(rpc.Method, routing.Modern) {
			writeRPCError(w, http.StatusForbidden, rpc.ID, -32601, "Only MCP protocol setup, tools/list, and permit-gated tools/call are supported", nil)
			return
		}
		p.forward(w, req, body, routing, models.PermitVerification{}, nil, p.controlUpstream)
		return
	}

	params, err := parseToolCallParams(rpc.Params)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, rpc.ID, -32602, err.Error(), nil)
		return
	}
	if err := validateBoundToolMeta(params.Meta, routing.ProtocolVersion); err != nil {
		writeRPCError(w, http.StatusBadRequest, rpc.ID, -32602, err.Error(), nil)
		return
	}

	token, ok := permitToken(req.Header.Get("Authorization"))
	if !ok {
		writeRPCError(w, http.StatusUnauthorized, rpc.ID, -32001, "A signed Aegis execution permit is required", map[string]string{"verification_result": "MISSING_PERMIT"})
		return
	}
	arguments := params.Arguments
	if len(bytes.TrimSpace(arguments)) == 0 {
		arguments = json.RawMessage(`{}`)
	}
	delegationBinding := req.Header.Get(HeaderDelegationFingerprint)
	if bound, bindErr := canonicalaction.BindDelegatedAuthorityFingerprint(delegationBinding); bindErr == nil {
		delegationBinding = bound
	}
	resolved, resolveErr := p.registry.Resolve(semanticaction.Input{
		PrincipalID: req.Header.Get(HeaderPrincipalID), AgentID: req.Header.Get(HeaderAgentID),
		WorkloadID: req.Header.Get(HeaderWorkloadID), DelegatedAuthorityFingerprint: delegationBinding,
		Tool: params.Name, Capability: req.Header.Get(HeaderCapability), Resource: req.Header.Get(HeaderResource),
		Operation: req.Header.Get(HeaderOperation), ProfileID: req.Header.Get(HeaderProfileID),
		Audience: req.Header.Get(HeaderAudience), Arguments: arguments,
	})
	if resolveErr != nil {
		writeRPCError(w, http.StatusForbidden, rpc.ID, -32005, "MCP action rejected by the server-owned semantic profile", map[string]string{
			"semantic_result": string(semanticaction.Code(resolveErr)),
		})
		return
	}
	upstream, upstreamErr := url.Parse(resolved.UpstreamURL)
	if upstreamErr != nil || upstream.Scheme == "" || upstream.Host == "" ||
		(upstream.Scheme != "http" && upstream.Scheme != "https") || !p.registry.OwnsUpstreamURL(upstream.String()) {
		writeRPCError(w, http.StatusInternalServerError, rpc.ID, -32603, "Aegis semantic profile has an invalid upstream binding", nil)
		return
	}
	action := resolved.Action
	normalizedBody, err := normalizedToolCallBody(rpc, params, resolved.NormalizedArguments)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, rpc.ID, -32603, "Aegis could not construct the normalized upstream request", nil)
		return
	}
	proofToken := ""
	if proofValues := req.Header.Values(HeaderExecutionProof); len(proofValues) == 1 {
		proofToken = proofValues[0]
	}
	proofVerification, err := p.gate.VerifyExecutionProof(token, proofToken, action, req.Method, req.URL.Path)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, rpc.ID, -32603, "Aegis could not record execution proof verification", nil)
		return
	}
	if !proofVerification.Verified || proofVerification.Outcome != "VERIFIED" {
		writeRPCError(w, http.StatusForbidden, rpc.ID, -32006, "Aegis workload execution proof rejected", map[string]string{
			"verification_result": proofVerification.Outcome, "permit_id": proofVerification.PermitID,
		})
		return
	}
	// Consumption is the commit point and happens before the upstream side
	// effect. Upstream failure or timeout never restores this permit; a retry
	// must obtain a newly authorized permit.
	verification, err := p.gate.VerifyAndConsume(token, action)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, rpc.ID, -32603, "Aegis could not record permit verification", nil)
		return
	}
	if !verification.Verified || verification.Outcome != "VERIFIED" {
		writeRPCError(w, http.StatusForbidden, rpc.ID, -32003, "Aegis execution permit rejected", map[string]string{
			"verification_result": verification.Outcome, "permit_id": verification.PermitID,
		})
		return
	}
	if verification.Obligations.IsolationRequired || verification.Obligations.HumanApprovalRequired {
		_, completionErr := p.gate.CompleteVerifiedExecution(models.ExecutionCompletion{
			RequestID: verification.RequestID, PermitID: verification.PermitID, Status: "terminated",
			BoundaryOutcome: "UNSATISFIED_OBLIGATION",
		})
		if completionErr != nil {
			writeRPCError(w, http.StatusInternalServerError, rpc.ID, -32603, "Aegis could not record the unsatisfied execution obligation", nil)
			return
		}
		writeRPCError(w, http.StatusForbidden, rpc.ID, -32004, "The focused MCP proxy cannot satisfy this signed execution obligation", map[string]any{
			"verification_result": "UNSATISFIED_OBLIGATION",
			"permit_id":           verification.PermitID,
			"obligations":         verification.Obligations,
		})
		return
	}
	p.forward(w, req, normalizedBody, routing, verification, &action, upstream)
}

func normalizedToolCallBody(rpc rpcRequest, params toolCallParams, normalizedArguments json.RawMessage) ([]byte, error) {
	params.Arguments = normalizedArguments
	normalizedParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	rpc.Params = normalizedParams
	return json.Marshal(rpc)
}

func (p *Proxy) forward(w http.ResponseWriter, inbound *http.Request, body []byte, routing routingMetadata, verification models.PermitVerification, action *canonicalaction.Action, upstream *url.URL) {
	outbound, err := http.NewRequestWithContext(inbound.Context(), http.MethodPost, upstream.String(), bytes.NewReader(body))
	if err != nil {
		if verification.Verified {
			_, _ = p.gate.CompleteVerifiedExecution(models.ExecutionCompletion{
				RequestID: verification.RequestID, PermitID: verification.PermitID, Status: "failed",
				UpstreamAttempted: false,
			})
		}
		writeRPCError(w, http.StatusBadGateway, nil, -32603, "MCP upstream request could not be created", nil)
		return
	}
	copySafeHeaders(outbound.Header, inbound.Header)
	if routing.ProtocolVersion != "" {
		outbound.Header.Set(HeaderProtocolVersion, routing.ProtocolVersion)
	}
	if routing.Modern {
		outbound.Header.Set(HeaderMethod, routing.Method)
		if routing.Name != "" {
			outbound.Header.Set(HeaderName, routing.Name)
		}
	}
	response, err := p.client.Do(outbound)
	if err != nil {
		if verification.Verified {
			_, _ = p.gate.CompleteVerifiedExecution(models.ExecutionCompletion{
				RequestID: verification.RequestID, PermitID: verification.PermitID, Status: "failed", UpstreamAttempted: true,
			})
		}
		writeRPCError(w, http.StatusBadGateway, nil, -32002, "MCP upstream is unavailable", nil)
		return
	}
	defer response.Body.Close()

	if verification.Verified {
		now := time.Now().UTC()
		event := models.RuntimeEvent{
			EventID: "mcp-" + strings.TrimPrefix(verification.PermitID, "p_"), PermitID: verification.PermitID,
			RequestID: verification.RequestID, Source: models.RuntimeSourceGatewayEnforced,
			TrustLevel: models.RuntimeTrustEnforced, Timestamp: now,
		}
		// Only the already verified binding metadata is copied; raw arguments
		// never enter runtime evidence.
		if action != nil {
			event.AgentID, event.WorkloadID = action.AgentID, action.WorkloadID
			event.Tool, event.Capability = action.Tool, action.Capability
			event.Resource, event.Operation = action.Resource, action.Operation
			_, _ = p.gate.IngestRuntimeEvent(event)
		}
		status := "completed"
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			status = "failed"
		}
		if _, err := p.gate.CompleteVerifiedExecution(models.ExecutionCompletion{
			RequestID: verification.RequestID, PermitID: verification.PermitID, Status: status,
			UpstreamAttempted: true, CompletedAt: now,
		}); err != nil {
			w.Header().Set("X-Aegis-Audit-Status", "completion-record-failed")
		}
	}

	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func permitToken(value string) (string, bool) {
	parts := strings.Fields(value)
	returnValue := ""
	if len(parts) == 2 && strings.EqualFold(parts[0], permitScheme) {
		returnValue = parts[1]
	}
	return returnValue, returnValue != ""
}

func safeProtocolMethod(method string, modern bool) bool {
	if modern {
		return method == "server/discover" || method == "tools/list"
	}
	switch method {
	case "initialize", "notifications/initialized", "ping", "tools/list":
		return true
	default:
		return false
	}
}

func copySafeHeaders(destination, source http.Header) {
	// Arbitrary inbound headers are not part of CanonicalAction and therefore
	// must not reach the upstream tool. Rebuild only inert transport negotiation
	// here; MCP routing headers are rebuilt separately from validated JSON.
	destination.Set("Content-Type", "application/json")
	if accept := strings.TrimSpace(source.Get("Accept")); accept != "" {
		destination.Set("Accept", accept)
	}
}

func validateRoutingMetadata(headers http.Header, rpc rpcRequest) (routingMetadata, error) {
	version, err := singleHeader(headers, HeaderProtocolVersion)
	if err != nil {
		return routingMetadata{}, err
	}
	modern := version == ProtocolVersion20260728
	if version != "" && !modern {
		// Older protocol versions remain a compatibility path. Unknown future
		// revisions fail closed because their action-carrying fields may differ.
		if version > ProtocolVersion20260728 {
			return routingMetadata{}, routingValidationError{
				code:    unsupportedVersionCode,
				message: fmt.Sprintf("unsupported MCP protocol version %q; supported modern version is %s", version, ProtocolVersion20260728),
			}
		}
	}

	methodHeader, err := singleHeader(headers, HeaderMethod)
	if err != nil {
		return routingMetadata{}, err
	}
	nameHeader, err := singleHeader(headers, HeaderName)
	if err != nil {
		return routingMetadata{}, err
	}
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "mcp-param-") {
			return routingMetadata{}, fmt.Errorf("%s is unsupported because this focused proxy has no schema-aware Mcp-Param validation", key)
		}
	}

	var params map[string]json.RawMessage
	if len(bytes.TrimSpace(rpc.Params)) > 0 {
		if err := json.Unmarshal(rpc.Params, &params); err != nil {
			return routingMetadata{}, fmt.Errorf("params must be a JSON object")
		}
	}
	name := ""
	if rawName, ok := params["name"]; ok {
		if err := json.Unmarshal(rawName, &name); err != nil {
			return routingMetadata{}, fmt.Errorf("params.name must be a string")
		}
	}
	if modern {
		if methodHeader == "" || methodHeader != rpc.Method {
			return routingMetadata{}, fmt.Errorf("Mcp-Method must exactly match JSON-RPC method")
		}
		if rpc.Method == "tools/call" && (nameHeader == "" || nameHeader != name) {
			return routingMetadata{}, fmt.Errorf("Mcp-Name must exactly match tools/call params.name")
		}
		if rpc.Method != "tools/call" && nameHeader != "" && nameHeader != name {
			return routingMetadata{}, fmt.Errorf("Mcp-Name does not match the JSON-RPC body")
		}
		metaVersion, metaErr := requestMetaProtocolVersion(params)
		if metaErr != nil || metaVersion != version {
			return routingMetadata{}, fmt.Errorf("MCP-Protocol-Version must match params._meta protocolVersion")
		}
	} else {
		if methodHeader != "" && methodHeader != rpc.Method {
			return routingMetadata{}, fmt.Errorf("Mcp-Method does not match the JSON-RPC body")
		}
		if nameHeader != "" && nameHeader != name {
			return routingMetadata{}, fmt.Errorf("Mcp-Name does not match the JSON-RPC body")
		}
	}
	return routingMetadata{ProtocolVersion: version, Method: rpc.Method, Name: name, Modern: modern}, nil
}

func parseToolCallParams(raw json.RawMessage) (toolCallParams, error) {
	var fields map[string]json.RawMessage
	if len(bytes.TrimSpace(raw)) == 0 || json.Unmarshal(raw, &fields) != nil {
		return toolCallParams{}, fmt.Errorf("tools/call params must be a JSON object")
	}
	for key := range fields {
		switch key {
		case "name", "arguments", "_meta":
		default:
			return toolCallParams{}, fmt.Errorf("tools/call params.%s is not supported by the focused action binding", key)
		}
	}
	var params toolCallParams
	if err := json.Unmarshal(raw, &params); err != nil || strings.TrimSpace(params.Name) == "" {
		return toolCallParams{}, fmt.Errorf("tools/call params.name is required")
	}
	arguments := bytes.TrimSpace(params.Arguments)
	if len(arguments) > 0 && arguments[0] != '{' {
		return toolCallParams{}, fmt.Errorf("tools/call params.arguments must be a JSON object")
	}
	return params, nil
}

func validateBoundToolMeta(meta map[string]json.RawMessage, protocolVersion string) error {
	for key, raw := range meta {
		if key != "io.modelcontextprotocol/protocolVersion" {
			return fmt.Errorf("tools/call params._meta.%s is not part of the focused action binding", key)
		}
		var version string
		if err := json.Unmarshal(raw, &version); err != nil || version == "" || version != protocolVersion {
			return fmt.Errorf("tools/call protocolVersion metadata is not bound to the validated transport version")
		}
	}
	return nil
}

func requestMetaProtocolVersion(params map[string]json.RawMessage) (string, error) {
	rawMeta, ok := params["_meta"]
	if !ok {
		return "", fmt.Errorf("params._meta is required")
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		return "", err
	}
	rawVersion, ok := meta["io.modelcontextprotocol/protocolVersion"]
	if !ok {
		return "", fmt.Errorf("protocolVersion metadata is required")
	}
	var version string
	if err := json.Unmarshal(rawVersion, &version); err != nil || version == "" {
		return "", fmt.Errorf("protocolVersion metadata must be a string")
	}
	return version, nil
}

func singleHeader(headers http.Header, name string) (string, error) {
	values := headers.Values(name)
	if len(values) > 1 {
		return "", fmt.Errorf("%s must appear at most once", name)
	}
	if len(values) == 0 {
		return "", nil
	}
	return strings.TrimSpace(values[0]), nil
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": message, "data": data},
	})
}
