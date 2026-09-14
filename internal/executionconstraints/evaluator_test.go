package executionconstraints_test

import (
	"testing"
	"time"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
	"github.com/szey/Aegis_Router/internal/executionconstraints"
	"github.com/szey/Aegis_Router/internal/permit"
)

func TestMissingEnforcersNeverSatisfyAnyRequiredCombination(t *testing.T) {
	if (executionconstraints.Evaluation{}).Allowed {
		t.Fatal("unevaluated result must deny")
	}
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	for mask := 0; mask < 32; mask++ {
		obligations := permit.Obligations{
			ReadOnly: mask&1 != 0, NetworkEgressDenied: mask&2 != 0,
			IsolationRequired: mask&4 != 0, HumanApprovalRequired: mask&8 != 0,
			EnhancedAuditRequired: mask&16 != 0,
		}
		result := executionconstraints.Evaluate(obligations, canonicalaction.Action{Operation: "write"}, now)
		if result.Allowed != (mask == 0) {
			t.Fatalf("mask %d: allowed=%v", mask, result.Allowed)
		}
		if mask != 0 && len(result.Checks) == 0 {
			t.Fatalf("mask %d: missing rejection reason", mask)
		}
		for _, check := range result.Checks {
			if check.Status != executionconstraints.Unsupported || check.Scope == "" || check.Reason == "" || !check.CheckedAt.Equal(now) {
				t.Fatalf("invalid constraint diagnostic: %#v", check)
			}
		}
	}
}

func TestReadOnlyDoesNotMistakeAnOperationNameForEnforcement(t *testing.T) {
	for _, operation := range []string{"read", "write", "transfer"} {
		result := executionconstraints.Evaluate(permit.Obligations{ReadOnly: true}, canonicalaction.Action{Operation: operation}, time.Now())
		if result.Allowed || len(result.Checks) != 1 || result.Checks[0].Scope != "target_resource" {
			t.Fatalf("operation %s: %#v", operation, result)
		}
		if operation != "read" && result.Checks[0].Reason != "action_mutates_target_resource" {
			t.Fatal("write conflict not explained")
		}
	}
}
