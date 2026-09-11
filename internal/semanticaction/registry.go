package semanticaction

import (
	"fmt"
	"strings"

	"github.com/szey/Aegis_Router/internal/models"
)

// Registry is a fixed dispatcher for profiles compiled into the server. It
// has no runtime registration, discovery, reflection, or external schemas.
type Registry struct {
	byTool      map[string]Profile
	byProfileID map[string]Profile
}

func NewRegistry(profiles ...Profile) (*Registry, error) {
	registry := &Registry{byTool: make(map[string]Profile), byProfileID: make(map[string]Profile)}
	for _, profile := range profiles {
		if profile == nil {
			return nil, fmt.Errorf("semantic profile is required")
		}
		profileID := strings.TrimSpace(profile.ProfileID())
		tool := strings.TrimSpace(profile.Tool())
		if profileID == "" || tool == "" {
			return nil, fmt.Errorf("semantic profile id and tool are required")
		}
		if _, exists := registry.byProfileID[profileID]; exists {
			return nil, fmt.Errorf("duplicate semantic profile id %q", profileID)
		}
		if existing, exists := registry.byTool[tool]; exists {
			return nil, fmt.Errorf("ambiguous semantic tool %q claimed by %q and %q", tool, existing.ProfileID(), profileID)
		}
		registry.byProfileID[profileID] = profile
		registry.byTool[tool] = profile
	}
	return registry, nil
}

// NewRegistryFromConfig constructs exactly the two compiled-in profiles when
// configured. A partially populated profile fails startup through its own
// constructor rather than being silently ignored.
func NewRegistryFromConfig(config models.SemanticActionsConfig) (*Registry, error) {
	profiles := make([]Profile, 0, 2)
	if paymentConfigPresent(config.PaymentSendV1) {
		profile, err := NewPaymentSendV1(config.PaymentSendV1)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	if workspaceConfigPresent(config.WorkspaceWriteV1) {
		profile, err := NewWorkspaceWriteV1(config.WorkspaceWriteV1)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return NewRegistry(profiles...)
}

func (r *Registry) Resolve(input Input) (Resolved, error) {
	if r == nil {
		return Resolved{}, &Rejection{Code: RejectSemanticToolUnmapped, Detail: "semantic registry is unavailable"}
	}
	profile, ok := r.byTool[input.Tool]
	if !ok {
		code := RejectSemanticToolUnmapped
		switch input.Tool {
		case "payment.send":
			code = RejectToolUnmapped
		case "workspace.write":
			code = RejectWorkspaceToolUnmapped
		}
		return Resolved{}, &Rejection{Code: code, Detail: "MCP tool has no server-owned semantic mapping"}
	}
	return profile.Resolve(input)
}

func (r *Registry) OwnsUpstreamURL(upstreamURL string) bool {
	if r == nil {
		return false
	}
	for _, profile := range r.byProfileID {
		if profile.UpstreamURL() == upstreamURL {
			return true
		}
	}
	return false
}

func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byProfileID)
}

func paymentConfigPresent(config models.PaymentSendV1Config) bool {
	return config.ProfileID != "" || config.MCPTool != "" || config.Capability != "" || config.Resource != "" ||
		config.Operation != "" || config.Audience != "" || config.UpstreamURL != "" || len(config.AllowedCurrencies) > 0 ||
		len(config.MaxAmountMinorByCurrency) > 0 || len(config.AllowedRecipients) > 0
}

func workspaceConfigPresent(config models.WorkspaceWriteV1Config) bool {
	return config.ProfileID != "" || config.MCPTool != "" || config.Capability != "" || config.Resource != "" ||
		config.Operation != "" || config.Audience != "" || config.UpstreamURL != "" || config.MaxPathBytes != 0 || config.MaxContentBytes != 0
}
