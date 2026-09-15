package mcp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/szey/Aegis_Router/internal/audit"
	"github.com/szey/Aegis_Router/internal/config"
	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/permit"
	"github.com/szey/Aegis_Router/internal/router"
)

// Only the synthetic successful-forwarding fixtures omit the upstream-network
// obligation. The shipped policy remains deny-egress and must fail closed.
func unconstrainedMockPolicy(cfg models.PolicyConfig) models.PolicyConfig {
	for _, agent := range []string{"finance-agent", "workspace-agent"} {
		policy := cfg.Agents[agent]
		for name, capability := range policy.Capabilities {
			capability.Constraints.NetworkEgress = "allow"
			for resource, grant := range capability.Resources {
				grant.Constraints.NetworkEgress = "allow"
				capability.Resources[resource] = grant
			}
			policy.Capabilities[name] = capability
		}
		cfg.Agents[agent] = policy
	}
	return cfg
}

func TestShippedNetworkObligationNeverConsumesOrInvokesUpstream(t *testing.T) {
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
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SemanticActions.PaymentSendV1.UpstreamURL = upstream.URL
	r := router.New(cfg, store)
	action := validPaymentRequest()
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxy(t, r, upstream.URL, nil)
	response := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
	state, _ := r.GetPermit(authorized.Permit.PermitID)
	if response.Code != http.StatusForbidden || calls.Load() != 0 || state.State != permit.StateIssued {
		t.Fatalf("status=%d calls=%d state=%s; want 403, zero calls, ISSUED", response.Code, calls.Load(), state.State)
	}
	if !strings.Contains(response.Body.String(), "UNSATISFIED_OBLIGATION") {
		t.Fatal(response.Body.String())
	}
	record, _ := store.Get(authorized.Decision.RequestID)
	if record.FinalVerdict != "EXECUTION_OBLIGATION_UNSATISFIED" || record.ExecutionReceipt.UpstreamAttempted {
		t.Fatalf("unexpected receipt: %#v", record.ExecutionReceipt)
	}
	checks := record.ExecutionReceipt.ConstraintChecks
	if len(checks) != 1 || checks[0].Requirement != "network_egress_denied" || checks[0].Status != "UNSUPPORTED" {
		t.Fatalf("missing admission evidence: %#v", checks)
	}
}

func TestConstraintAuditFailureStillCannotConsumeOrDispatch(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SemanticActions.PaymentSendV1.UpstreamURL = upstream.URL
	r := router.New(cfg, store)
	action := validPaymentRequest()
	authorized, err := authorizeAction(t, r, action)
	if err != nil {
		t.Fatal(err)
	}
	// Replace only this test's synthetic log with a directory to force a
	// deterministic write failure without changing permissions or real data.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	response := invoke(t, newProxy(t, r, upstream.URL, nil), authorized, action, action.Tool.Name, action.Action.Arguments)
	state, _ := r.GetPermit(authorized.Permit.PermitID)
	if response.Code != http.StatusInternalServerError || calls.Load() != 0 || state.State != permit.StateIssued {
		t.Fatalf("status=%d calls=%d state=%s", response.Code, calls.Load(), state.State)
	}
}

func TestRedirectNeverDispatchesToSecondReceiver(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, suppliedClient := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/custom-client-%v", status, suppliedClient), func(t *testing.T) {
				var first, second atomic.Int32
				receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					second.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				defer receiver.Close()
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					first.Add(1)
					http.Redirect(w, req, receiver.URL+"/unapproved", status)
				}))
				defer upstream.Close()
				cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", "policy.json"))
				if err != nil {
					t.Fatal(err)
				}
				store, err := audit.NewStore("")
				if err != nil {
					t.Fatal(err)
				}
				cfg.SemanticActions.PaymentSendV1.UpstreamURL = upstream.URL
				r := router.New(unconstrainedMockPolicy(cfg), store)
				var client *http.Client
				if suppliedClient {
					client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
				}
				proxy := newProxy(t, r, upstream.URL, client)
				action := validPaymentRequest()
				authorized, err := authorizeAction(t, r, action)
				if err != nil {
					t.Fatal(err)
				}
				response := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
				if response.Code != http.StatusBadGateway || first.Load() != 1 || second.Load() != 0 {
					t.Fatalf("status=%d first=%d second=%d; want 502, 1, 0", response.Code, first.Load(), second.Load())
				}
				if response.Header().Get("Location") != "" {
					t.Fatal("redirect target leaked to caller")
				}
				state, _ := r.GetPermit(authorized.Permit.PermitID)
				if state.State != permit.StateConsumed {
					t.Fatalf("permit restored: %s", state.State)
				}
				record, _ := store.Get(authorized.Decision.RequestID)
				if record.ExecutionReceipt.ExecutionOutcome != "UPSTREAM_REDIRECT_BLOCKED" || !record.ExecutionReceipt.UpstreamAttempted {
					t.Fatalf("unexpected receipt: %#v", record.ExecutionReceipt)
				}
				retry := invoke(t, proxy, authorized, action, action.Tool.Name, action.Action.Arguments)
				if retry.Code != http.StatusForbidden || first.Load() != 1 || second.Load() != 0 {
					t.Fatal("redirect retried a consumed permit")
				}
			})
		}
	}
}
