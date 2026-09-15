package mcp_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/szey/Aegis_Router/internal/adapters/mcp"
	"github.com/szey/Aegis_Router/internal/audit"
	"github.com/szey/Aegis_Router/internal/config"
	"github.com/szey/Aegis_Router/internal/permit"
	"github.com/szey/Aegis_Router/internal/router"
)

// The upstream reads exact JSON member names, as required by JSON-RPC. This
// deliberately differs from encoding/json's case-insensitive struct matching.
// No Permit, proof, trusted identity, or permissive policy is supplied.
func TestEnvelopeCaseAliasesCannotTurnToolCallIntoProtocolBypass(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, alias := range []string{"METHOD", "MeThOd", `\u004dETHOD`} {
			t.Run(fmt.Sprintf("modern=%v/alias=%s", modern, alias), func(t *testing.T) {
				var requests, toolCalls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					requests.Add(1)
					var fields map[string]json.RawMessage
					if err := json.NewDecoder(req.Body).Decode(&fields); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					var method string
					if err := json.Unmarshal(fields["method"], &method); err == nil && method == "tools/call" {
						toolCalls.Add(1)
					}
					w.WriteHeader(http.StatusOK)
				}))
				defer upstream.Close()
				proxy := sharedConfigProxy(t, upstream.URL)
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","%s":"tools/list","params":{"name":"payment.send","arguments":{"amount_minor":100,"currency":"USD","recipient":"merchant-456"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, alias)
				request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
				if modern {
					setModernHeaders(request.Header, "tools/list", "")
				}
				response := httptest.NewRecorder()
				proxy.ServeHTTP(response, request)
				if response.Code != http.StatusBadRequest || requests.Load() != 0 || toolCalls.Load() != 0 {
					t.Fatalf("status=%d upstream_requests=%d upstream_tool_calls=%d; want 400, 0, 0", response.Code, requests.Load(), toolCalls.Load())
				}
			})
		}
	}
}

func TestEnvelopeUnknownMembersFailClosed(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := sharedConfigProxy(t, upstream.URL)
	for _, body := range []string{
		`{"jsonrpc":"2.0","METHOD":"tools/call","method":"ping"}`,
		`{"jsonrpc":"2.0","METHOD":"ping"}`,
		`{"jsonrpc":"2.0","JSONRPC":"2.0","method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"ID":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"ping","params":{},"PARAMS":{}}`,
		`{"jsonrpc":"2.0","method":"ping","requestState":"unbound"}`,
		`{"jsonrpc":"2.0","method":"ping","vendorExtension":{}}`,
	} {
		response := httptest.NewRecorder()
		proxy.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":-32600`) {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("unsupported envelope invoked upstream %d times", calls.Load())
	}
}

func TestExactProtocolEnvelopeStillReachesUpstream(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(fmt.Sprintf("modern=%v", modern), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				var fields map[string]json.RawMessage
				if err := json.NewDecoder(req.Body).Decode(&fields); err != nil || string(fields["method"]) != `"tools/list"` || string(fields["id"]) != `"check-1"` {
					t.Errorf("upstream received a different envelope: %s, err=%v", fields, err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			proxy := sharedConfigProxy(t, upstream.URL)
			// Escapes for the exact lowercase key remain valid JSON. Rejecting
			// case aliases must not reject equivalent encodings of valid keys.
			body := `{"jsonrpc":"2.0","id":"check-1","\u006dethod":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			if modern {
				setModernHeaders(request.Header, "tools/list", "")
			}
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != http.StatusOK || calls.Load() != 1 {
				t.Fatalf("status=%d calls=%d; want 200, 1", response.Code, calls.Load())
			}
		})
	}
}

func TestInvalidEnvelopePreservesPermitAndProofForValidCall(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	r, _, _ := testRouter(t, upstream.URL) // Explicitly unconstrained, synthetic success policy.
	action := validPaymentRequest()
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, nil)
	proof := signExecutionProof(t, authorized, testWorkloadPrivateKey(), "envelope-case-retry")
	body := strings.Replace(string(modernToolCallBody(t, action.Tool.Name, action.Action.Arguments)), `"method":"tools/call"`, `"method":"tools/call","METHOD":"tools/list"`, 1)
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	setModernHeaders(request.Header, "tools/list", "")
	request.Header.Set("Authorization", "AegisPermit "+authorized.Permit.PermitToken)
	request.Header.Set(mcp.HeaderExecutionProof, proof)
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	state, _ := r.GetPermit(authorized.Permit.PermitID)
	if response.Code != http.StatusBadRequest || calls.Load() != 0 || state.State != permit.StateIssued {
		t.Fatalf("status=%d calls=%d state=%s; want 400, 0, ISSUED", response.Code, calls.Load(), state.State)
	}
	response = invokeWithProof(t, proxy, authorized.Permit.PermitToken, proof, action, action.Tool.Name, action.Action.Arguments)
	state, _ = r.GetPermit(authorized.Permit.PermitID)
	if response.Code != http.StatusOK || calls.Load() != 1 || state.State != permit.StateConsumed {
		t.Fatalf("valid retry: status=%d calls=%d state=%s; want 200, 1, CONSUMED", response.Code, calls.Load(), state.State)
	}
}

// Mirror cmd/server wiring: the authorizer and proxy share the same immutable
// registry, and the shipped policy (including deny-egress) remains intact.
func sharedConfigProxy(t *testing.T, upstreamURL string) *mcp.Proxy {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SemanticActions.PaymentSendV1.UpstreamURL = upstreamURL
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(cfg, store)
	proxy, err := mcp.New(r, r.SemanticRegistry(), upstreamURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}
