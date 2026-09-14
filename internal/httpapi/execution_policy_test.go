package httpapi_test

import "github.com/szey/Aegis_Router/internal/models"

// Successful HTTP fixtures use a synthetic grant with no upstream egress
// obligation: the mock tool has no independent network enforcer. Shipped
// constraints are tested unchanged at the MCP boundary and are never relaxed
// by production code to make an execution eligible.
func mockExecutionPolicy(cfg models.PolicyConfig, agent, capability, resource string) models.PolicyConfig {
	policy := cfg.Agents[agent]
	grant := policy.Capabilities[capability]
	grant.Constraints.NetworkEgress = "allow"
	resourceGrant := grant.Resources[resource]
	resourceGrant.Constraints.NetworkEgress = "allow"
	grant.Resources[resource] = resourceGrant
	policy.Capabilities[capability] = grant
	cfg.Agents[agent] = policy
	return cfg
}
