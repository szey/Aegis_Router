package mcp_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/szey/Aegis_Router/internal/adapters/mcp"
	"github.com/szey/Aegis_Router/internal/audit"
	"github.com/szey/Aegis_Router/internal/config"
	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/permit"
	"github.com/szey/Aegis_Router/internal/router"
	"github.com/szey/Aegis_Router/internal/semanticaction"
)

func TestPolicyChecksPreparedEffectsAndBytes(t *testing.T) {
	for _, dimension := range []string{"workspace-bytes", "workspace-effect", "payment-effect"} {
		t.Run(dimension, func(t *testing.T) {
			cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
			if err != nil {
				t.Fatal(err)
			}
			cfg = unconstrainedMockPolicy(cfg)
			action := workspaceRequest(`{"path":"notes/a.txt","content":"你好"}`)
			wantRule := "constraint.side_effect_not_granted"
			if dimension == "payment-effect" {
				action = validPaymentRequest()
			}
			agent := cfg.Agents[action.Agent.AgentID]
			capability := agent.Capabilities[action.Action.Capability]
			resource := capability.Resources[action.Action.TargetResource]
			if dimension == "workspace-bytes" {
				resource.Constraints.MaxBytes = 5 // Two characters, six UTF-8 bytes.
				wantRule = "constraint.max_bytes_exceeded"
			} else {
				resource.Constraints.AllowedSideEffects = []string{}
			}
			capability.Resources[action.Action.TargetResource] = resource
			agent.Capabilities[action.Action.Capability] = capability
			cfg.Agents[action.Agent.AgentID] = agent
			action.Action.Bytes, action.Action.SideEffect = 0, "none"
			store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			r := router.New(cfg, store)
			result, err := authorizeAction(t, r, action)
			if err != nil {
				t.Fatal(err)
			}
			if result.Permit != nil || result.Decision.AuthorizationStatus != models.AuthorizationStatusDenied {
				t.Fatalf("underdeclared %s issued a permit: status=%s", dimension, result.Decision.AuthorizationStatus)
			}
			if !strings.Contains(strings.Join(result.Decision.PolicyDecision.Rules, ","), wantRule) {
				t.Fatalf("missing derived policy denial %s", wantRule)
			}
		})
	}
}

func TestChangedExecutionConfigurationNeverConsumesOrDispatches(t *testing.T) {
	for _, change := range []string{"upstream", "profile-limit"} {
		t.Run(change, func(t *testing.T) {
			var calls atomic.Int32
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer receiver.Close()
			cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.SemanticActions.PaymentSendV1.UpstreamURL = receiver.URL + "/approved"
			store, _ := audit.NewStore(filepath.Join(t.TempDir(), "audit.jsonl"))
			r := router.New(unconstrainedMockPolicy(cfg), store)
			action := validPaymentRequest()
			authorized, err := authorizeAction(t, r, action)
			if err != nil {
				t.Fatal(err)
			}
			changed := cfg.SemanticActions.PaymentSendV1
			if change == "upstream" {
				changed.UpstreamURL = receiver.URL + "/different"
			} else {
				changed.MaxAmountMinorByCurrency["USD"]++
			}
			profile, err := semanticaction.NewPaymentSendV1(changed)
			if err != nil {
				t.Fatal(err)
			}
			registry, _ := semanticaction.NewRegistry(profile)
			proxy, err := mcp.New(r, registry, changed.UpstreamURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
			state, _ := r.GetPermit(authorized.Permit.PermitID)
			if response.Code != http.StatusForbidden || calls.Load() != 0 || state.State != permit.StateIssued {
				t.Fatalf("status=%d calls=%d state=%s; want 403, 0, ISSUED", response.Code, calls.Load(), state.State)
			}
			if !strings.Contains(response.Body.String(), "WRONG_EXECUTION_BINDING") {
				t.Fatal(response.Body.String())
			}
		})
	}
}

func TestAuthorityRevocationCannotBeUndoneByReenable(t *testing.T) {
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	defer receiver.Close()
	r, _, _ := testRouter(t, receiver.URL)
	proxy := newProxy(t, r, receiver.URL, nil)
	action := validPaymentRequest()
	old, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	key := permit.AuthorityKey{PrincipalID: action.Principal.PrincipalID, AgentID: action.Agent.AgentID, WorkloadID: action.Agent.WorkloadID}
	if _, err := r.SetAuthorityEnabled(key, false); err != nil {
		t.Fatal(err)
	}
	response := invoke(t, proxy, old, action, action.Tool.Name, action.Action.Arguments)
	if response.Code != http.StatusForbidden || calls.Load() != 0 || !strings.Contains(response.Body.String(), "REVOKED") {
		t.Fatalf("revoked execution: %d %s", response.Code, response.Body.String())
	}
	denied, err := authorizeAction(t, r, action)
	if err != nil || denied.Permit != nil || string(denied.Decision.AuthorizationStatus) != "DENIED" {
		t.Fatalf("disabled authority issued: err=%v", err)
	}
	if _, err := r.SetAuthorityEnabled(key, true); err != nil {
		t.Fatal(err)
	}
	response = invoke(t, proxy, old, action, action.Tool.Name, action.Action.Arguments)
	if response.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatal("old permit revived")
	}
	fresh, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Permit.AuthorityEpoch != 3 {
		t.Fatal("fresh authorization lacks current epoch")
	}
	response = invoke(t, proxy, fresh, action, action.Tool.Name, action.Action.Arguments)
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("fresh permit: %d %s", response.Code, response.Body.String())
	}
}

func TestAnonymousBindingRejectsImplicitTransportCredentials(t *testing.T) {
	r, _, _ := testRouter(t, "http://127.0.0.1:3001/mcp")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*http.Client{{Jar: jar}, {Transport: http.DefaultTransport}} {
		if _, err := mcp.New(r, r.SemanticRegistry(), "http://127.0.0.1:3001/mcp", client); err == nil {
			t.Fatal("accepted an unbound transport identity")
		}
	}
}

func TestAuditFailureCannotRollBackAuthorityRevocation(t *testing.T) {
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	defer receiver.Close()
	r, _, auditPath := testRouter(t, receiver.URL)
	action := validPaymentRequest()
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	// Replace only this test's temporary audit file with a directory, making
	// audit persistence fail after the authoritative Store transition commits.
	if err := os.Remove(auditPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(auditPath, 0700); err != nil {
		t.Fatal(err)
	}
	key := permit.AuthorityKey{PrincipalID: action.Principal.PrincipalID, AgentID: action.Agent.AgentID, WorkloadID: action.Agent.WorkloadID}
	state, err := r.SetAuthorityEnabled(key, false)
	if err == nil || state.Enabled || state.Epoch != 2 {
		t.Fatal("audit fault did not preserve committed authority transition")
	}
	record, ok := r.GetPermit(authorized.Permit.PermitID)
	if !ok || record.State != permit.StateRevoked {
		t.Fatal("audit failure revived a permit")
	}
	response := invoke(t, newProxy(t, r, receiver.URL, nil), authorized, action, action.Tool.Name, action.Action.Arguments)
	if response.Code < 400 || calls.Load() != 0 {
		t.Fatal("execution passed after failed revocation audit")
	}
}
