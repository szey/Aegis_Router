// Package executionconstraints evaluates signed requirements at the final
// execution boundary. It accepts no request-body or Agent-reported evidence.
package executionconstraints

import (
	"time"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
	"github.com/szey/Aegis_Router/internal/permit"
)

type Status string

const (
	Satisfied   Status = "SATISFIED"
	Unsupported Status = "UNSUPPORTED"
	Unknown     Status = "UNKNOWN"
)

// Check contains only safe requirement metadata. CheckedAt is the evaluation
// time, not evidence that an external control was installed or attested.
type Check struct {
	Requirement string    `json:"requirement"`
	Status      Status    `json:"status"`
	Scope       string    `json:"scope"`
	Reason      string    `json:"reason"`
	CheckedAt   time.Time `json:"checked_at"`
}

// Evaluation's zero value denies execution. An explicitly evaluated Permit
// with no required obligations is eligible; an empty caller-supplied evidence
// list is never used to satisfy a required obligation.
type Evaluation struct {
	Allowed bool
	Checks  []Check
}

// Evaluate is deliberately fail-closed for every external obligation in M1.
// The focused Router has no runtime controller, approval-completion service or
// transactional dispatch journal. Signing these requirements, binding an
// operation, or appending local JSONL cannot establish their enforcement.
// Adding a satisfier requires a trusted integration and scope/freshness tests;
// a configuration boolean or Agent-provided status is not such an integration.
func Evaluate(required permit.Obligations, action canonicalaction.Action, at time.Time) Evaluation {
	result := Evaluation{Allowed: required == (permit.Obligations{}), Checks: []Check{}}
	add := func(required bool, name, scope, reason string) {
		if required {
			result.Checks = append(result.Checks, Check{
				Requirement: name, Status: Unsupported, Scope: scope, Reason: reason, CheckedAt: at.UTC(),
			})
		}
	}
	add(required.IsolationRequired, "isolation_required", "upstream_runtime", "runtime_controller_not_connected")
	add(required.NetworkEgressDenied, "network_egress_denied", "upstream_runtime", "network_enforcer_not_connected")
	readOnlyReason := "resource_enforcer_not_connected"
	switch action.Operation {
	case "write", "append", "delete", "transfer":
		readOnlyReason = "action_mutates_target_resource"
	}
	add(required.ReadOnly, "read_only", "target_resource", readOnlyReason)
	add(required.HumanApprovalRequired, "human_approval_required", "canonical_action", "approval_completion_not_implemented")
	add(required.EnhancedAuditRequired, "enhanced_audit_required", "dispatch_intent", "durable_dispatch_journal_not_implemented")
	// A future field added to Obligations cannot silently turn into an allow
	// even if its diagnostic mapping has not been added here yet.
	if !result.Allowed && len(result.Checks) == 0 {
		result.Checks = append(result.Checks, Check{
			Requirement: "unrecognized_obligation", Status: Unknown, Scope: "unknown",
			Reason: "obligation_evaluator_not_available", CheckedAt: at.UTC(),
		})
	}
	return result
}
