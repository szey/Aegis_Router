package semanticaction_test

import (
	"testing"

	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/semanticaction"
)

type stubProfile struct {
	id   string
	tool string
}

func (p stubProfile) ProfileID() string { return p.id }
func (p stubProfile) Tool() string      { return p.tool }
func (p stubProfile) UpstreamURL() string {
	return "http://127.0.0.1/mcp"
}
func (p stubProfile) Resolve(semanticaction.Input) (semanticaction.Resolved, error) {
	return semanticaction.Resolved{}, nil
}

func TestRegistryRejectsDuplicateOrAmbiguousProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles []semanticaction.Profile
	}{
		{"duplicate profile id", []semanticaction.Profile{stubProfile{id: "one/v1", tool: "one"}, stubProfile{id: "one/v1", tool: "two"}}},
		{"ambiguous tool", []semanticaction.Profile{stubProfile{id: "one/v1", tool: "shared"}, stubProfile{id: "two/v1", tool: "shared"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := semanticaction.NewRegistry(test.profiles...); err == nil {
				t.Fatal("ambiguous registry configuration was accepted")
			}
		})
	}
}

func TestRegistryFailsClosedForUnknownTool(t *testing.T) {
	registry, err := semanticaction.NewRegistry(stubProfile{id: "one/v1", tool: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(semanticaction.Input{Tool: "unknown"}); err == nil || semanticaction.Code(err) != semanticaction.RejectSemanticToolUnmapped {
		t.Fatalf("unknown tool error=%v code=%s", err, semanticaction.Code(err))
	}
}

func TestCompiledRegistryRejectsPartialOrConflictingConfiguration(t *testing.T) {
	config := models.SemanticActionsConfig{
		PaymentSendV1: models.PaymentSendV1Config{
			ProfileID: semanticaction.PaymentSendV1ID,
		},
	}
	if _, err := semanticaction.NewRegistryFromConfig(config); err == nil {
		t.Fatal("partially configured compiled profile was silently ignored")
	}

	config = models.SemanticActionsConfig{
		WorkspaceWriteV1: models.WorkspaceWriteV1Config{
			ProfileID: semanticaction.WorkspaceWriteV1ID, MCPTool: "payment.send",
			Capability: "workspace_write", Resource: "demo-workspace", Operation: "write",
			Audience: "mcp://workspace", UpstreamURL: "http://127.0.0.1:3002/mcp",
		},
	}
	if _, err := semanticaction.NewRegistryFromConfig(config); err == nil {
		t.Fatal("conflicting compiled tool ownership was accepted")
	}
}
