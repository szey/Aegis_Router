package mcp_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/adapters/mcp"
	"github.com/szey/Aegis_Router/internal/audit"
	"github.com/szey/Aegis_Router/internal/config"
	"github.com/szey/Aegis_Router/internal/executionproof"
	"github.com/szey/Aegis_Router/internal/intake"
	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/router"
	"github.com/szey/Aegis_Router/internal/semanticaction"
)

const testWorkloadKeyID = "mcp-test-workload-key"

var proofNonce atomic.Uint64

func TestValidPermitInvokesMCPUpstreamExactlyOnceAndAuditsReceipt(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.Header.Get("Authorization") != "" || req.Header.Get(mcp.HeaderExecutionProof) != "" || req.Header.Get(mcp.HeaderAgentID) != "" || req.Header.Get("Cookie") != "" || req.Header.Get("X-Upstream-Action") != "" || req.Header.Get("Content-Encoding") != "" {
			t.Error("credential, binding, or unbound transport headers leaked to upstream")
		}
		if req.Header.Get(mcp.HeaderProtocolVersion) != mcp.ProtocolVersion20260728 || req.Header.Get(mcp.HeaderMethod) != "tools/call" || req.Header.Get(mcp.HeaderName) != "payment.send" {
			t.Errorf("normalized MCP routing headers were not forwarded: %#v", req.Header)
		}
		var forwarded struct {
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(req.Body).Decode(&forwarded); err != nil {
			t.Errorf("decode normalized upstream body: %v", err)
		} else if string(forwarded.Params.Arguments) != `{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}` {
			t.Errorf("upstream arguments were not the authorized normalized value: %s", forwarded.Params.Arguments)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	}))
	defer upstream.Close()

	r, store, auditPath := testRouter(t)
	action := paymentRequest(`{"currency":"USD","recipient":"merchant-456","amount_minor":100}`)
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, nil)

	reordered := json.RawMessage(`{"recipient":"merchant-456","amount_minor":100,"currency":"USD"}`)
	proof := signExecutionProof(t, authorized, testWorkloadPrivateKey(), "valid-proof-no-audit-leak")
	response := invokeWithProof(t, proxy, authorized.Permit.PermitToken, proof, action, action.Tool.Name, reordered)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
	record, ok := store.Get(authorized.Decision.RequestID)
	if !ok || record.FinalVerdict != "EXECUTED_WITH_VALID_PERMIT" {
		t.Fatalf("audit record = %#v", record)
	}
	if record.ExecutionReceipt == nil || record.ExecutionReceipt.VerificationOutcome != "VERIFIED" || !record.ExecutionReceipt.UpstreamAttempted {
		t.Fatalf("execution receipt = %#v", record.ExecutionReceipt)
	}
	if len(record.RuntimeObservation.Events) != 1 || record.RuntimeObservation.Events[0].Source != models.RuntimeSourceGatewayEnforced {
		t.Fatalf("runtime evidence = %#v", record.RuntimeObservation)
	}
	persisted, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted, []byte(authorized.Permit.PermitToken)) {
		t.Fatal("permit token leaked into audit")
	}
	if bytes.Contains(persisted, []byte(proof)) {
		t.Fatal("execution proof leaked into audit")
	}
	if bytes.Contains(persisted, []byte("merchant-456")) {
		t.Fatal("raw action arguments leaked into audit")
	}
}

func TestWorkloadExecutionProofFailuresNeverConsumePermitOrReachUpstream(t *testing.T) {
	type fixture struct {
		r          *router.Router
		store      *audit.Store
		calls      *atomic.Int32
		authorized models.ActionAuthorizationResponse
		action     models.Request
		proxy      *mcp.Proxy
	}
	setup := func(t *testing.T) fixture {
		t.Helper()
		calls := &atomic.Int32{}
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}))
		t.Cleanup(upstream.Close)
		r, store, _ := testRouter(t)
		action := validPaymentRequest()
		authorized, err := authorizeAction(t, r, action)
		if err != nil {
			t.Fatal(err)
		}
		return fixture{r: r, store: store, calls: calls, authorized: authorized, action: action, proxy: newProxy(t, r, upstream.URL, nil)}
	}
	assertIssued := func(t *testing.T, item fixture) {
		t.Helper()
		record, ok := item.r.GetPermit(item.authorized.Permit.PermitID)
		if !ok || record.State != "ISSUED" || item.calls.Load() != 0 {
			t.Fatalf("failed proof changed execution state: permit=%#v exists=%v upstream=%d", record, ok, item.calls.Load())
		}
	}

	t.Run("missing proof", func(t *testing.T) {
		item := setup(t)
		response := invokeWithProof(t, item.proxy, item.authorized.Permit.PermitToken, "", item.action, item.action.Tool.Name, item.action.Action.Arguments)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "WRONG_EXECUTOR") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		auditRecord, ok := item.store.Get(item.authorized.Decision.RequestID)
		if !ok || auditRecord.FinalVerdict != "PERMIT_WRONG_EXECUTOR" || auditRecord.ExecutionReceipt == nil || auditRecord.ExecutionReceipt.VerificationOutcome != "WRONG_EXECUTOR" {
			t.Fatalf("wrong executor audit=%#v exists=%v", auditRecord, ok)
		}
		assertIssued(t, item)
		proof := signExecutionProof(t, item.authorized, testWorkloadPrivateKey(), fmt.Sprintf("nonce-%d", proofNonce.Add(1)))
		accepted := invokeWithProof(t, item.proxy, item.authorized.Permit.PermitToken, proof, item.action, item.action.Tool.Name, item.action.Action.Arguments)
		if accepted.Code != http.StatusOK || item.calls.Load() != 1 {
			t.Fatalf("valid request after missing proof status=%d calls=%d body=%s", accepted.Code, item.calls.Load(), accepted.Body.String())
		}
	})

	t.Run("another workload key", func(t *testing.T) {
		item := setup(t)
		seed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
		otherPrivate := ed25519.NewKeyFromSeed(seed)
		if err := item.r.RegisterWorkloadPublicKey("other-workload-key", otherPrivate.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
		proof := signExecutionProofWithKey(t, item.authorized, "other-workload-key", otherPrivate, "other-workload-proof")
		response := invokeWithProof(t, item.proxy, item.authorized.Permit.PermitToken, proof, item.action, item.action.Tool.Name, item.action.Action.Arguments)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "WRONG_EXECUTOR") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		assertIssued(t, item)
	})

	t.Run("stale proof", func(t *testing.T) {
		item := setup(t)
		stale := item.authorized
		stalePermit := *item.authorized.Permit
		stalePermit.IssuedAt = stalePermit.IssuedAt.Add(-time.Minute)
		stale.Permit = &stalePermit
		proof := signExecutionProof(t, stale, testWorkloadPrivateKey(), "stale-proof")
		response := invokeWithProof(t, item.proxy, item.authorized.Permit.PermitToken, proof, item.action, item.action.Tool.Name, item.action.Action.Arguments)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "WRONG_EXECUTOR") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		assertIssued(t, item)
	})

	t.Run("proof copied to another permit", func(t *testing.T) {
		item := setup(t)
		other, err := authorizeAction(t, item.r, item.action)
		if err != nil {
			t.Fatal(err)
		}
		proof := signExecutionProof(t, item.authorized, testWorkloadPrivateKey(), "copied-permit-proof")
		response := invokeWithProof(t, item.proxy, other.Permit.PermitToken, proof, item.action, item.action.Tool.Name, item.action.Action.Arguments)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "WRONG_EXECUTOR") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		record, ok := item.r.GetPermit(other.Permit.PermitID)
		if !ok || record.State != "ISSUED" || item.calls.Load() != 0 {
			t.Fatalf("copied proof consumed target Permit: %#v exists=%v calls=%d", record, ok, item.calls.Load())
		}
	})

	t.Run("proof copied to another normalized action", func(t *testing.T) {
		item := setup(t)
		proof := signExecutionProof(t, item.authorized, testWorkloadPrivateKey(), "copied-action-proof")
		mutated := json.RawMessage(`{"amount_minor":101,"currency":"USD","recipient":"merchant-456"}`)
		response := invokeWithProof(t, item.proxy, item.authorized.Permit.PermitToken, proof, item.action, item.action.Tool.Name, mutated)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "ACTION_MISMATCH") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		assertIssued(t, item)
	})

	t.Run("reused nonce across permits", func(t *testing.T) {
		item := setup(t)
		firstProof := signExecutionProof(t, item.authorized, testWorkloadPrivateKey(), "shared-proof-nonce")
		first := invokeWithProof(t, item.proxy, item.authorized.Permit.PermitToken, firstProof, item.action, item.action.Tool.Name, item.action.Action.Arguments)
		if first.Code != http.StatusOK || item.calls.Load() != 1 {
			t.Fatalf("first status=%d calls=%d body=%s", first.Code, item.calls.Load(), first.Body.String())
		}
		secondAuthorization, err := authorizeAction(t, item.r, item.action)
		if err != nil {
			t.Fatal(err)
		}
		secondProof := signExecutionProof(t, secondAuthorization, testWorkloadPrivateKey(), "shared-proof-nonce")
		second := invokeWithProof(t, item.proxy, secondAuthorization.Permit.PermitToken, secondProof, item.action, item.action.Tool.Name, item.action.Action.Arguments)
		if second.Code != http.StatusForbidden || !strings.Contains(second.Body.String(), "WRONG_EXECUTOR") || item.calls.Load() != 1 {
			t.Fatalf("second status=%d calls=%d body=%s", second.Code, item.calls.Load(), second.Body.String())
		}
		record, ok := item.r.GetPermit(secondAuthorization.Permit.PermitID)
		if !ok || record.State != "ISSUED" {
			t.Fatalf("nonce replay consumed second Permit: %#v exists=%v", record, ok)
		}
	})
}

func TestWorkspaceWriteV1TrustedPermitInvokesOnlyItsConfiguredUpstream(t *testing.T) {
	const rawContentMarker = "WORKSPACE_RAW_CONTENT_MUST_NOT_ENTER_AUDIT_7f13"
	var paymentCalls atomic.Int32
	paymentUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		paymentCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer paymentUpstream.Close()
	var workspaceCalls atomic.Int32
	workspaceUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		workspaceCalls.Add(1)
		var forwarded struct {
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(req.Body).Decode(&forwarded); err != nil {
			t.Errorf("decode workspace upstream request: %v", err)
		} else if forwarded.Params.Name != "workspace.write" || string(forwarded.Params.Arguments) != `{"path":"reports/result.txt","content":"`+rawContentMarker+`"}` {
			t.Errorf("workspace upstream received non-normalized action: %#v", forwarded.Params)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	}))
	defer workspaceUpstream.Close()

	r, store, auditPath, proxy := twoProfileProxy(t, paymentUpstream.URL, workspaceUpstream.URL)
	action := workspaceRequest(`{"content":"` + rawContentMarker + `","path":"reports/result.txt"}`)
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Permit == nil || authorized.Permit.ProfileID != "workspace.write/v1" || authorized.Permit.Audience != "mcp://local-workspace-sandbox" {
		t.Fatalf("workspace Permit missing server-owned bindings: %#v", authorized.Permit)
	}
	response := invoke(t, proxy, authorized, action, "workspace.write", json.RawMessage(`{"path":"reports/result.txt","content":"`+rawContentMarker+`"}`))
	if response.Code != http.StatusOK || workspaceCalls.Load() != 1 || paymentCalls.Load() != 0 {
		t.Fatalf("status=%d workspace=%d payment=%d body=%s", response.Code, workspaceCalls.Load(), paymentCalls.Load(), response.Body.String())
	}
	permitRecord, ok := r.GetPermit(authorized.Permit.PermitID)
	if !ok || permitRecord.State != "CONSUMED" {
		t.Fatalf("workspace Permit state=%#v exists=%v", permitRecord, ok)
	}
	record, ok := store.Get(authorized.Decision.RequestID)
	if !ok || record.ExecutionReceipt == nil || record.ExecutionReceipt.VerificationOutcome != "VERIFIED" ||
		record.ExecutionReceipt.ProfileID != "workspace.write/v1" || record.ExecutionReceipt.Audience != "mcp://local-workspace-sandbox" ||
		record.ExecutionReceipt.Tool != "workspace.write" || record.ExecutionReceipt.Resource != "demo-workspace" {
		t.Fatalf("workspace audit receipt=%#v", record)
	}
	persisted, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{rawContentMarker, authorized.Permit.PermitToken, strings.Repeat("e", 64)} {
		if bytes.Contains(persisted, []byte(forbidden)) {
			t.Fatalf("workspace audit leaked forbidden value %q", forbidden)
		}
	}
}

func TestWorkspaceWriteV1MutationAndReplayFailBeforeUpstream(t *testing.T) {
	mutations := []struct {
		name string
		raw  json.RawMessage
	}{
		{"path", json.RawMessage(`{"path":"reports/other.txt","content":"hello"}`)},
		{"content", json.RawMessage(`{"path":"reports/result.txt","content":"goodbye"}`)},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			var workspaceCalls atomic.Int32
			workspaceUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				workspaceCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer workspaceUpstream.Close()
			paymentUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			defer paymentUpstream.Close()
			r, _, _, proxy := twoProfileProxy(t, paymentUpstream.URL, workspaceUpstream.URL)
			action := workspaceRequest(`{"path":"reports/result.txt","content":"hello"}`)
			authorized, err := authorizeAction(t, r, action)
			if err != nil {
				t.Fatal(err)
			}
			response := invoke(t, proxy, authorized, action, "workspace.write", mutation.raw)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "ACTION_MISMATCH") || workspaceCalls.Load() != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, workspaceCalls.Load(), response.Body.String())
			}
			permitRecord, ok := r.GetPermit(authorized.Permit.PermitID)
			if !ok || permitRecord.State != "ISSUED" {
				t.Fatalf("workspace mismatch consumed Permit: %#v exists=%v", permitRecord, ok)
			}
		})
	}

	t.Run("replay", func(t *testing.T) {
		var workspaceCalls atomic.Int32
		workspaceUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			workspaceCalls.Add(1)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}))
		defer workspaceUpstream.Close()
		paymentUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		defer paymentUpstream.Close()
		r, _, _, proxy := twoProfileProxy(t, paymentUpstream.URL, workspaceUpstream.URL)
		action := workspaceRequest(`{"path":"reports/result.txt","content":"hello"}`)
		authorized, err := authorizeAction(t, r, action)
		if err != nil {
			t.Fatal(err)
		}
		first := invoke(t, proxy, authorized, action, "workspace.write", action.Action.Arguments)
		second := invoke(t, proxy, authorized, action, "workspace.write", action.Action.Arguments)
		if first.Code != http.StatusOK || second.Code != http.StatusForbidden || !strings.Contains(second.Body.String(), "REPLAYED") || workspaceCalls.Load() != 1 {
			t.Fatalf("first=%d second=%d calls=%d second body=%s", first.Code, second.Code, workspaceCalls.Load(), second.Body.String())
		}
	})
}

func TestCrossProfilePermitsNeverReachEitherUpstream(t *testing.T) {
	var paymentCalls, workspaceCalls atomic.Int32
	paymentUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		paymentCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer paymentUpstream.Close()
	workspaceUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		workspaceCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer workspaceUpstream.Close()

	r, _, _, proxy := twoProfileProxy(t, paymentUpstream.URL, workspaceUpstream.URL)
	payment := validPaymentRequest()
	paymentAuthorized, err := authorizeAction(t, r, payment)
	if err != nil {
		t.Fatal(err)
	}
	workspace := workspaceRequest(`{"path":"reports/result.txt","content":"hello"}`)
	workspaceAuthorized, err := authorizeAction(t, r, workspace)
	if err != nil {
		t.Fatal(err)
	}

	paymentIdentityWorkspaceAction := workspace
	paymentIdentityWorkspaceAction.Principal = payment.Principal
	paymentIdentityWorkspaceAction.Agent = payment.Agent
	paymentIdentityWorkspaceAction.Authority = payment.Authority
	first := invoke(t, proxy, paymentAuthorized, paymentIdentityWorkspaceAction, "workspace.write", workspace.Action.Arguments)

	workspaceIdentityPaymentAction := payment
	workspaceIdentityPaymentAction.Principal = workspace.Principal
	workspaceIdentityPaymentAction.Agent = workspace.Agent
	workspaceIdentityPaymentAction.Authority = workspace.Authority
	second := invoke(t, proxy, workspaceAuthorized, workspaceIdentityPaymentAction, "payment.send", payment.Action.Arguments)
	if first.Code != http.StatusForbidden || second.Code != http.StatusForbidden ||
		!strings.Contains(first.Body.String(), "WRONG_TOOL") || !strings.Contains(second.Body.String(), "WRONG_TOOL") ||
		paymentCalls.Load() != 0 || workspaceCalls.Load() != 0 {
		t.Fatalf("payment->workspace=%d %s; workspace->payment=%d %s; calls=%d/%d", first.Code, first.Body.String(), second.Code, second.Body.String(), paymentCalls.Load(), workspaceCalls.Load())
	}
	for _, permitID := range []string{paymentAuthorized.Permit.PermitID, workspaceAuthorized.Permit.PermitID} {
		permitRecord, ok := r.GetPermit(permitID)
		if !ok || permitRecord.State != "ISSUED" {
			t.Fatalf("cross-profile mismatch consumed Permit %s: %#v exists=%v", permitID, permitRecord, ok)
		}
	}
}

func TestActionMutationNeverInvokesMCPUpstream(t *testing.T) {
	mutations := []struct {
		name string
		raw  json.RawMessage
	}{
		{"amount", json.RawMessage(`{"amount_minor":10000,"currency":"USD","recipient":"merchant-456"}`)},
		{"currency", json.RawMessage(`{"amount_minor":100,"currency":"CNY","recipient":"merchant-456"}`)},
		{"recipient", json.RawMessage(`{"amount_minor":100,"currency":"USD","recipient":"merchant-demo"}`)},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			r, store, _ := testRouter(t)
			action := paymentRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
			authorized, err := authorizeAction(t, r, action)
			if err != nil {
				t.Fatal(err)
			}
			proxy := newProxy(t, r, upstream.URL, nil)
			response := invoke(t, proxy, authorized, action, action.Tool.Name, mutation.raw)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "ACTION_MISMATCH") || calls.Load() != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
			}
			record, _ := store.Get(authorized.Decision.RequestID)
			if record.FinalVerdict != "PERMIT_ACTION_MISMATCH" || record.ExecutionReceipt == nil || record.ExecutionReceipt.UpstreamAttempted {
				t.Fatalf("failed verification audit = %#v", record)
			}
		})
	}
}

func TestInvalidSignatureNeverInvokesMCPUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	r, store, auditPath := testRouter(t)
	action := validPaymentRequest()
	authorized, _ := authorizeAction(t, r, action)
	token := authorized.Permit.PermitToken
	last := "A"
	if strings.HasSuffix(token, last) {
		last = "B"
	}
	token = token[:len(token)-1] + last
	proxy := newProxy(t, r, upstream.URL, nil)
	tampered := authorized
	tamperedPermit := *authorized.Permit
	tamperedPermit.PermitToken = token
	tampered.Permit = &tamperedPermit
	response := invoke(t, proxy, tampered, action, action.Tool.Name, action.Action.Arguments)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "INVALID_SIGNATURE") {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid signature invoked upstream %d times", calls.Load())
	}
	records := store.Recent(10)
	if len(records) != 2 || records[0].FinalVerdict != "PERMIT_INVALID_SIGNATURE" || !strings.HasPrefix(records[0].RequestID, "verify-") {
		t.Fatalf("invalid-signature attempt was not independently audited: %#v", records)
	}
	persisted, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted, []byte(token)) {
		t.Fatal("invalid permit credential leaked into the audit")
	}
}

func TestSimulationPermitNeverInvokesMCPUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	r, store, _ := testRouter(t)
	if err := r.RegisterWorkloadPublicKey(testWorkloadKeyID, testWorkloadPrivateKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	action := validPaymentRequest()
	authorized, err := r.AuthorizeSyntheticDemoAction(action, 0)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, nil)
	proof := signExecutionProof(t, authorized, testWorkloadPrivateKey(), fmt.Sprintf("nonce-%d", proofNonce.Add(1)))
	response := invokeWithProof(t, proxy, authorized.Permit.PermitToken, proof, action, action.Tool.Name, action.Action.Arguments)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "WRONG_PERMIT_CLASS") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("simulation permit invoked upstream %d times", calls.Load())
	}
	record, _ := store.Get(authorized.Decision.RequestID)
	if record.ExecutionReceipt == nil || record.ExecutionReceipt.PermitClass != "simulation" || record.ExecutionReceipt.VerificationOutcome != "WRONG_PERMIT_CLASS" || record.FinalVerdict != "PERMIT_CLASS_MISMATCH" {
		t.Fatalf("purpose rejection was not safely audited: %#v", record)
	}
	permitRecord, _ := r.GetPermit(authorized.Permit.PermitID)
	if permitRecord.State != "ISSUED" {
		t.Fatalf("wrong-purpose MCP attempt consumed permit: %#v", permitRecord)
	}
}

func TestAllBoundPermitFailuresNeverInvokeMCPUpstream(t *testing.T) {
	tests := []struct {
		name    string
		outcome string
		mutate  func(*models.Request, *string)
	}{
		{"wrong principal", "WRONG_PRINCIPAL", func(action *models.Request, _ *string) { action.Principal.PrincipalID = "user-02" }},
		{"wrong agent", "WRONG_AGENT", func(action *models.Request, _ *string) { action.Agent.AgentID = "other-agent" }},
		{"wrong workload", "WRONG_WORKLOAD", func(action *models.Request, _ *string) { action.Agent.WorkloadID = "other-workload" }},
		{"wrong delegation", "WRONG_DELEGATION", func(action *models.Request, _ *string) {
			action.Authority.CredentialFingerprint = strings.Repeat("c", 64)
		}},
		{"wrong tool", "SEMANTIC_TOOL_UNMAPPED", func(_ *models.Request, tool *string) { *tool = "admin-tool" }},
		{"wrong capability", "PAYMENT_BINDING_CONFLICT", func(action *models.Request, _ *string) { action.Action.Capability = "admin" }},
		{"wrong resource", "PAYMENT_BINDING_CONFLICT", func(action *models.Request, _ *string) { action.Action.TargetResource = "account-999" }},
		{"wrong operation", "PAYMENT_BINDING_CONFLICT", func(action *models.Request, _ *string) { action.Action.Operation = "delete" }},
		{"wrong profile", "PAYMENT_PROFILE_MISMATCH", func(action *models.Request, _ *string) { action.Action.ProfileID = "payment.send/v2" }},
		{"wrong audience", "PAYMENT_AUDIENCE_MISMATCH", func(action *models.Request, _ *string) { action.Action.Audience = "mcp://attacker" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			r, _, _ := testRouter(t)
			authorizedAction := paymentRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
			authorized, err := authorizeAction(t, r, authorizedAction)
			if err != nil {
				t.Fatal(err)
			}
			actual := authorizedAction
			tool := actual.Tool.Name
			test.mutate(&actual, &tool)
			proxy := newProxy(t, r, upstream.URL, nil)
			response := invoke(t, proxy, authorized, actual, tool, actual.Action.Arguments)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), test.outcome) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatalf("%s invoked upstream %d times", test.outcome, calls.Load())
			}
		})
	}
}

func TestReplayExpiredAndRevokedPermitsNeverAddAnUpstreamCall(t *testing.T) {
	t.Run("replay", func(t *testing.T) {
		var calls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}))
		defer upstream.Close()
		r, store, _ := testRouter(t)
		action := validPaymentRequest()
		authorized, _ := authorizeAction(t, r, action)
		proxy := newProxy(t, r, upstream.URL, nil)
		if first := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments); first.Code != http.StatusOK {
			t.Fatalf("first status = %d, body = %s", first.Code, first.Body.String())
		}
		second := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
		if second.Code != http.StatusForbidden || !strings.Contains(second.Body.String(), "REPLAYED") {
			t.Fatalf("second status = %d, body = %s", second.Code, second.Body.String())
		}
		if calls.Load() != 1 {
			t.Fatalf("upstream calls = %d, want exactly 1", calls.Load())
		}
		record, _ := store.Get(authorized.Decision.RequestID)
		if record.FinalVerdict != "PERMIT_REPLAY" {
			t.Fatalf("final verdict = %q", record.FinalVerdict)
		}
	})

	t.Run("expired", func(t *testing.T) {
		var calls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()
		cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
		if err != nil {
			t.Fatal(err)
		}
		current := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
		store, _ := audit.NewStore("")
		r := router.NewWithClock(cfg, store, func() time.Time { return current })
		action := validPaymentRequest()
		authorized, _ := authorizeAction(t, r, action)
		current = authorized.Permit.ExpiresAt
		proxy := newProxy(t, r, upstream.URL, nil)
		response := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "EXPIRED") || calls.Load() != 0 {
			t.Fatalf("status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
		}
	})

	t.Run("revoked", func(t *testing.T) {
		var calls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()
		r, _, _ := testRouter(t)
		action := validPaymentRequest()
		authorized, _ := authorizeAction(t, r, action)
		if _, err := r.RevokePermit(authorized.Permit.PermitID); err != nil {
			t.Fatal(err)
		}
		proxy := newProxy(t, r, upstream.URL, nil)
		response := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "REVOKED") || calls.Load() != 0 {
			t.Fatalf("status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
		}
	})
}

func TestFailedUpstreamDoesNotRestorePermitAndRetryRequiresNewAuthorization(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()

	r, store, _ := testRouter(t)
	action := validPaymentRequest()
	firstAuthorization, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, nil)
	failed := invoke(t, proxy, firstAuthorization, action, action.Tool.Name, action.Action.Arguments)
	if failed.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("failed attempt status=%d calls=%d body=%s", failed.Code, calls.Load(), failed.Body.String())
	}
	permitRecord, ok := r.GetPermit(firstAuthorization.Permit.PermitID)
	if !ok || permitRecord.State != "CONSUMED" {
		t.Fatalf("permit after upstream failure = %#v, exists=%v", permitRecord, ok)
	}
	auditRecord, _ := store.Get(firstAuthorization.Decision.RequestID)
	if auditRecord.FinalVerdict != "EXECUTION_FAILED" || auditRecord.ExecutionReceipt.ExecutionOutcome != "failed" || !auditRecord.ExecutionReceipt.UpstreamAttempted {
		t.Fatalf("failed execution receipt = %#v", auditRecord)
	}

	replayed := invoke(t, proxy, firstAuthorization, action, action.Tool.Name, action.Action.Arguments)
	if replayed.Code != http.StatusForbidden || !strings.Contains(replayed.Body.String(), "REPLAYED") || calls.Load() != 1 {
		t.Fatalf("reused failed-attempt permit status=%d calls=%d body=%s", replayed.Code, calls.Load(), replayed.Body.String())
	}

	secondAuthorization, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	if secondAuthorization.Permit.PermitID == firstAuthorization.Permit.PermitID {
		t.Fatal("retry authorization reused the prior permit id")
	}
	succeeded := invoke(t, proxy, secondAuthorization, action, action.Tool.Name, action.Action.Arguments)
	if succeeded.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("newly authorized retry status=%d calls=%d body=%s", succeeded.Code, calls.Load(), succeeded.Body.String())
	}
}

func TestTimedOutUpstreamDoesNotRestoreConsumedPermit(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		select {
		case <-req.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer upstream.Close()

	r, store, _ := testRouter(t)
	action := validPaymentRequest()
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, &http.Client{Timeout: 20 * time.Millisecond})
	failed := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
	if failed.Code != http.StatusBadGateway || calls.Load() != 1 {
		t.Fatalf("timeout status=%d calls=%d body=%s", failed.Code, calls.Load(), failed.Body.String())
	}
	permitRecord, ok := r.GetPermit(authorized.Permit.PermitID)
	if !ok || permitRecord.State != "CONSUMED" {
		t.Fatalf("permit after timeout = %#v, exists=%v", permitRecord, ok)
	}
	auditRecord, _ := store.Get(authorized.Decision.RequestID)
	if auditRecord.ExecutionReceipt == nil || !auditRecord.ExecutionReceipt.UpstreamAttempted || auditRecord.ExecutionReceipt.ExecutionOutcome != "failed" {
		t.Fatalf("timeout execution receipt = %#v", auditRecord.ExecutionReceipt)
	}
	replayed := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
	if replayed.Code != http.StatusForbidden || !strings.Contains(replayed.Body.String(), "REPLAYED") || calls.Load() != 1 {
		t.Fatalf("timeout replay status=%d calls=%d body=%s", replayed.Code, calls.Load(), replayed.Body.String())
	}
}

func TestConcurrentMCPReplayInvokesUpstreamExactlyOnce(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()
	r, store, _ := testRouter(t)
	action := validPaymentRequest()
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, nil)

	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			responses <- invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
		}()
	}
	ready.Wait()
	close(start)

	var succeeded, replayed int
	for range 2 {
		response := <-responses
		switch {
		case response.Code == http.StatusOK:
			succeeded++
		case response.Code == http.StatusForbidden && strings.Contains(response.Body.String(), "REPLAYED"):
			replayed++
		default:
			t.Fatalf("unexpected concurrent response: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if succeeded != 1 || replayed != 1 || calls.Load() != 1 {
		t.Fatalf("succeeded=%d replayed=%d upstream=%d, want 1/1/1", succeeded, replayed, calls.Load())
	}
	record, _ := store.Get(authorized.Decision.RequestID)
	if record.FinalVerdict != "PERMIT_REPLAY" || record.ExecutionReceipt.VerificationOutcome != "REPLAYED" {
		t.Fatalf("concurrent replay audit lost the violation: %#v", record)
	}
}

func TestUnmappedMCPToolFailsClosedBeforePermitConsumption(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	r, _, _ := testRouter(t)
	authorizedAction := paymentRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
	authorized, err := authorizeAction(t, r, authorizedAction)
	if err != nil {
		t.Fatal(err)
	}
	action := configReadRequest()
	proxy := newProxy(t, r, upstream.URL, nil)
	response := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "SEMANTIC_TOOL_UNMAPPED") || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}
	permitRecord, _ := r.GetPermit(authorized.Permit.PermitID)
	if permitRecord.State != "ISSUED" {
		t.Fatalf("unmapped tool consumed the permit: %#v", permitRecord)
	}
}

func TestModernMCPHeaderOrBodyAmbiguityNeverInvokesUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	r, _, _ := testRouter(t)
	action := validPaymentRequest()
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, nil)

	validBody := modernToolCallBody(t, "coder", action.Action.Arguments)
	tests := []struct {
		name   string
		body   []byte
		mutate func(http.Header)
		code   int
	}{
		{"method header mismatch", validBody, func(header http.Header) { header.Set(mcp.HeaderMethod, "tools/list") }, -32020},
		{"name header mismatch", validBody, func(header http.Header) { header.Set(mcp.HeaderName, "admin-tool") }, -32020},
		{"protocol metadata mismatch", bytes.Replace(validBody, []byte(mcp.ProtocolVersion20260728), []byte("2025-11-25"), 1), nil, -32020},
		{"unknown future protocol", bytes.Replace(validBody, []byte(mcp.ProtocolVersion20260728), []byte("2099-01-01"), 1), func(header http.Header) { header.Set(mcp.HeaderProtocolVersion, "2099-01-01") }, -32022},
		{"custom mirrored header without schema", validBody, func(header http.Header) { header.Set("Mcp-Param-Region", "us-east-1") }, -32020},
		{"duplicate tool name", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coder","name":"admin-tool","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`), nil, -32700},
		{"unbound MRTR params", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coder","arguments":{},"requestState":"opaque","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`), nil, -32602},
		{"unbound tool metadata", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coder","arguments":{"task":"preview"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","vendor.example/actionMode":"admin"}}}`), nil, -32602},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(test.body))
			setModernHeaders(request.Header, "tools/call", "coder")
			request.Header.Set("Authorization", "AegisPermit "+authorized.Permit.PermitToken)
			if test.mutate != nil {
				test.mutate(request.Header)
			}
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), fmt.Sprintf(`"code":%d`, test.code)) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("ambiguous modern MCP request invoked upstream %d times", calls.Load())
	}
}

func TestModernServerDiscoverPassesThroughWithoutPermit(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.Header.Get(mcp.HeaderMethod) != "server/discover" || req.Header.Get(mcp.HeaderProtocolVersion) != mcp.ProtocolVersion20260728 {
			t.Errorf("discover routing headers = %#v", req.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}`)
	}))
	defer upstream.Close()
	r, _, _ := testRouter(t)
	proxy := newProxy(t, r, upstream.URL, nil)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	setModernHeaders(request.Header, "server/discover", "")
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("status = %d, calls = %d, body = %s", response.Code, calls.Load(), response.Body.String())
	}
}

func invoke(t *testing.T, handler http.Handler, authorized models.ActionAuthorizationResponse, action models.Request, tool string, arguments json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	proof := signExecutionProof(t, authorized, testWorkloadPrivateKey(), fmt.Sprintf("nonce-%d", proofNonce.Add(1)))
	return invokeWithProof(t, handler, authorized.Permit.PermitToken, proof, action, tool, arguments)
}

func invokeWithProof(t *testing.T, handler http.Handler, token, proof string, action models.Request, tool string, arguments json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body := modernToolCallBody(t, tool, arguments)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "upstream-session=must-not-pass")
	req.Header.Set("X-Upstream-Action", "must-not-pass")
	req.Header.Set("Content-Encoding", "gzip")
	setModernHeaders(req.Header, "tools/call", tool)
	req.Header.Set("Authorization", "AegisPermit "+token)
	if proof != "" {
		req.Header.Set(mcp.HeaderExecutionProof, proof)
	}
	req.Header.Set(mcp.HeaderPrincipalID, action.Principal.PrincipalID)
	req.Header.Set(mcp.HeaderAgentID, action.Agent.AgentID)
	req.Header.Set(mcp.HeaderWorkloadID, action.Agent.WorkloadID)
	req.Header.Set(mcp.HeaderDelegationFingerprint, action.Authority.CredentialFingerprint)
	req.Header.Set(mcp.HeaderCapability, action.Action.Capability)
	req.Header.Set(mcp.HeaderResource, action.Action.TargetResource)
	req.Header.Set(mcp.HeaderOperation, action.Action.Operation)
	if action.Action.ProfileID != "" {
		req.Header.Set(mcp.HeaderProfileID, action.Action.ProfileID)
	}
	if action.Action.Audience != "" {
		req.Header.Set(mcp.HeaderAudience, action.Action.Audience)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func signExecutionProof(t *testing.T, authorized models.ActionAuthorizationResponse, privateKey ed25519.PrivateKey, nonce string) string {
	return signExecutionProofWithKey(t, authorized, testWorkloadKeyID, privateKey, nonce)
}

func signExecutionProofWithKey(t *testing.T, authorized models.ActionAuthorizationResponse, keyID string, privateKey ed25519.PrivateKey, nonce string) string {
	t.Helper()
	if authorized.Permit == nil || authorized.Decision.AuthorizationEnvelope == nil {
		t.Fatal("execution proof requires an issued Permit")
	}
	proof, err := executionproof.Sign(privateKey, keyID, executionproof.Claims{
		PermitID: authorized.Permit.PermitID, ActionDigest: authorized.Decision.AuthorizationEnvelope.ActionDigest,
		HTTPMethod: http.MethodPost, HTTPPath: "/mcp", IssuedAt: authorized.Permit.IssuedAt.Unix(), Nonce: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func testWorkloadPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testWorkloadBinding(t *testing.T) intake.WorkloadBinding {
	t.Helper()
	privateKey := testWorkloadPrivateKey()
	thumbprint, err := executionproof.Thumbprint(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return intake.WorkloadBinding{KeyID: testWorkloadKeyID, PublicKeyThumbprint: thumbprint}
}

func modernToolCallBody(t *testing.T, tool string, arguments json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name": tool, "arguments": json.RawMessage(arguments),
			"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": mcp.ProtocolVersion20260728},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func setModernHeaders(header http.Header, method, name string) {
	header.Set(mcp.HeaderProtocolVersion, mcp.ProtocolVersion20260728)
	header.Set(mcp.HeaderMethod, method)
	if name != "" {
		header.Set(mcp.HeaderName, name)
	}
}

func authorizeAction(t *testing.T, r *router.Router, request models.Request) (models.ActionAuthorizationResponse, error) {
	t.Helper()
	privateKey := testWorkloadPrivateKey()
	if err := r.RegisterWorkloadPublicKey(testWorkloadKeyID, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	authorization, err := intake.NewTrustedAuthorization(request, intake.IdentityContext{
		Principal: request.EffectivePrincipal(), Agent: request.EffectiveAgent(),
		DelegatedAuthority: request.EffectiveAuthority(),
		WorkloadBinding:    testWorkloadBinding(t),
	}, "mcp-test-trusted-integration", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return r.AuthorizeTrustedAction(authorization)
}

func testRouter(t *testing.T) (*router.Router, *audit.Store, string) {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return router.New(unconstrainedMockPolicy(cfg), store), store, path
}

func newProxy(t *testing.T, r *router.Router, upstreamURL string, client *http.Client) *mcp.Proxy {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	profileConfig := cfg.SemanticActions.PaymentSendV1
	profileConfig.UpstreamURL = upstreamURL
	profile, err := semanticaction.NewPaymentSendV1(profileConfig)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := semanticaction.NewRegistry(profile)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := mcp.New(r, registry, upstreamURL, client)
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}

func twoProfileProxy(t *testing.T, paymentUpstreamURL, workspaceUpstreamURL string) (*router.Router, *audit.Store, string, *mcp.Proxy) {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SemanticActions.PaymentSendV1.UpstreamURL = paymentUpstreamURL
	cfg.SemanticActions.WorkspaceWriteV1.UpstreamURL = workspaceUpstreamURL
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(unconstrainedMockPolicy(cfg), store)
	proxy, err := mcp.New(r, r.SemanticRegistry(), paymentUpstreamURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, store, auditPath, proxy
}

func validPaymentRequest() models.Request {
	return paymentRequest(`{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}`)
}

func paymentRequest(arguments string) models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "finance-agent", WorkloadID: "finance-workload-v1"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("b", 64), Scopes: []string{"payment.transfer"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "payment.send"},
		Action: models.ActionRequest{
			Capability: "payment_transfer", Operation: "transfer", TargetResource: "account-123",
			Arguments: json.RawMessage(arguments), SideEffect: "financial_transaction",
		},
	}
}

func workspaceRequest(arguments string) models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "workspace-agent", WorkloadID: "workspace-workload-v1"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("e", 64), Scopes: []string{"workspace.write"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "workspace.write"},
		Action: models.ActionRequest{
			Capability: "workspace_write", Operation: "write", TargetResource: "demo-workspace",
			Arguments: json.RawMessage(arguments), SideEffect: "logical_workspace_write",
		},
	}
}

func configReadRequest() models.Request {
	return models.Request{
		Principal: models.PrincipalContext{PrincipalID: "user-01", PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: "coder-agent", WorkloadID: "coder-workload-v1"},
		Authority: models.DelegatedAuthority{
			CredentialFingerprint: strings.Repeat("d", 64), Scopes: []string{"config.read"}, Subject: "user-01",
		},
		Tool: models.ToolContext{Name: "config_reader"},
		Action: models.ActionRequest{
			Capability: "read_config", Operation: "read", TargetResource: "protected_config",
			Arguments: json.RawMessage(`{"path_class":"approved-config"}`), SideEffect: "read_only",
		},
	}
}
