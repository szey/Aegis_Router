package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/permit"
)

func Load(path string) (models.PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return models.PolicyConfig{}, fmt.Errorf("read policy config: %w", err)
	}

	var cfg models.PolicyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return models.PolicyConfig{}, fmt.Errorf("parse policy config: %w", err)
	}
	if len(cfg.Agents) == 0 || len(cfg.Resources) == 0 {
		return models.PolicyConfig{}, fmt.Errorf("policy config must define agents and resources")
	}
	if cfg.Permits.TTLSeconds <= 0 {
		cfg.Permits.TTLSeconds = int(permit.DefaultTTL / time.Second)
	}
	if strings.TrimSpace(cfg.Version) == "" {
		cfg.Version = "policy-v1"
	}
	if strings.TrimSpace(cfg.Permits.Issuer) == "" {
		cfg.Permits.Issuer = "aegis-router"
	}
	for agentID, agent := range cfg.Agents {
		if strings.TrimSpace(agentID) == "" {
			return models.PolicyConfig{}, fmt.Errorf("policy config contains an empty agent id")
		}
		for capability, grant := range agent.Capabilities {
			if len(grant.AllowedTools) == 0 {
				return models.PolicyConfig{}, fmt.Errorf("agent %q capability %q must define allowed_tools", agentID, capability)
			}
			if len(grant.Resources) == 0 {
				return models.PolicyConfig{}, fmt.Errorf("agent %q capability %q must define resources", agentID, capability)
			}
			if grant.Route != "" && grant.Route != models.RouteAllow && grant.Route != models.RouteRestrict && grant.Route != models.RouteSandbox {
				return models.PolicyConfig{}, fmt.Errorf("agent %q capability %q has invalid authorized route %q", agentID, capability, grant.Route)
			}
			for resourceID, resourceGrant := range grant.Resources {
				if _, ok := cfg.Resources[resourceID]; !ok {
					return models.PolicyConfig{}, fmt.Errorf("agent %q capability %q references unknown resource %q", agentID, capability, resourceID)
				}
				if len(resourceGrant.AllowedOperations) == 0 {
					return models.PolicyConfig{}, fmt.Errorf("agent %q capability %q resource %q must define allowed_operations", agentID, capability, resourceID)
				}
			}
		}
	}
	return cfg, nil
}
