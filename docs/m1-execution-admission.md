# M1: pre-consumption constraints and fixed MCP routing

English | [简体中文](m1-execution-admission.zh-CN.md)

Implemented on 2026-09-14 against research/code baseline `11451c58d583041e4009d8799bfd07b17199b481`, using the updated `$research-to-product` skill to deliver M1 of the [redesign proposal](manus-redesign.md). Disposition: `implement`; delivery: `completed`. This records the implemented local boundary; M2 durable transactions, M3 external sandbox integration and M4 lifecycle remain pending.

## From research to code

The proposal's R1/R3 distinguish environment configuration, Agent reports and trusted execution facts; M1/M3/M4 motivate independent environment and lifecycle controls. Those external sources remain `V1`; their incidents and sandbox escapes were not reproduced here. The concrete change is supported by local E02/E07 comparisons for `REDESIGN-2026-09-13-06`, promoted to `S1/V2` for this code-level finding only.

| Hypothesis and experiment | Before | After |
|---|---|---|
| E02: requirements without a trusted enforcer must reject before consumption | The core returned `VERIFIED` and consumed for each of the five requirements; a deny-egress MCP fixture still called upstream once | All five requirements reject; Permit remains `ISSUED`; reusing the identical proof still rejects on constraints, showing the nonce was not consumed; zero upstream calls |
| E07: a server-owned URL must not expand through redirects | Default and custom clients followed 301/302/303/307/308 to a second receiver | 502; original receiver once, second receiver zero times; no Location or redirect body forwarded; Permit remains `CONSUMED`, retry sends nothing |
| Regression: valid actions, forged identity, parameter mutation and replay | Existing positive/negative fixtures | Both profiles still execute synthetic actions with no additional obligations; concurrent replay succeeds at most once; unknown signed requirements, audit failure and existing binding failures cannot create unauthorized calls |

All experiments use temporary directories, synthetic identities and local mock HTTP servers. Logs are retained locally in ignored `tmp/m1-validation/`; the repository retains reproducible fixtures and these sanitized conclusions, not temporary tokens or raw logs.

## Execution sequence

```text
signature, issuer, class, time and Permit state
  → workload proof and exact action binding
  → executionconstraints: explain and reject unsupported requirements
  → proof nonce + atomic Permit consumption
  → Router records verification
  → MCP sends to the fixed target without redirects
  → record boundary result; failure never restores a Permit
```

The core verifier invokes `internal/executionconstraints` before nonce and Permit consumption. MCP no longer implements a separate partial post-consumption check. The strict Token parser continues to reject unknown signed fields rather than dropping them. HTTP `POST /api/permits/verify` remains a non-consuming diagnostic: `VALID_NOT_CONSUMED` neither checks environmental requirements nor authorizes execution.

`constraint_checks` adds safe metadata to responses and Audit Receipts: `requirement`, `status`, `scope`, `reason` and `checked_at`. The timestamp records Aegis's evaluation, not installation of an external control. With no trusted enforcer connected, no `enforcer_id` or `config_digest` is invented, and no API accepts an Agent-reported `SATISFIED` result.

| Requirement | Scope | M1 result |
|---|---|---|
| `network_egress_denied` | Direct egress from the upstream tool runtime | `UNSUPPORTED`: no network enforcer; a fixed broker URL is not upstream-tool network isolation |
| `read_only` | Target resource | `UNSUPPORTED`: no resource enforcer; write/append/delete/transfer also receive a target-mutation conflict reason |
| `isolation_required` | Upstream runtime | `UNSUPPORTED`: no runtime controller |
| `human_approval_required` | Same canonical action | `UNSUPPORTED`: no approval-completion chain |
| `enhanced_audit_required` | Dispatch intent | `UNSUPPORTED`: local JSONL does not establish a durable consume/dispatch transaction |

The current real-execution path permits only actions with no required signed obligations, after all other Permit checks pass. An unevaluated zero value denies; a future requirement cannot allow execution merely because its diagnostic mapping is missing. `SATISFIED / UNSUPPORTED / UNKNOWN` is the result vocabulary, but M1 has no external control integration capable of establishing `SATISFIED`. A future enforcer must validate scope, provenance, configuration version and freshness; an `enabled: true` flag is insufficient.

Constraint denial returns `UNSATISFIED_OBLIGATION` with final verdict `EXECUTION_OBLIGATION_UNSATISFIED`; the Permit is not consumed. Redirect denial records execution outcome `UPSTREAM_REDIRECT_BLOCKED` and final verdict `EXECUTION_REDIRECT_BLOCKED`; the original target was attempted, so the Permit stays consumed. A redirect response cannot establish whether that target committed a business side effect.

## Compatibility and migration

This corrects enforcement of existing signed obligations without adding or changing Token fields. The v1 format and two semantic profiles remain. Future run/lease/epoch bindings still require a new contract version.

**Behavior change: the shipped payment and workspace policies require denied egress, so real MCP execution now rejects.** The original configuration and project safety fields are unchanged. Requirements must not be automatically removed or given fictional fulfillment settings to restore old behavior. Deployments need a trusted control integration, or a separately considered policy change reflecting actual tool permissions. Successful synthetic tests explicitly omit the upstream-egress obligation for mock tools; they do not demonstrate isolation.

Server-owned simulation remains a class-isolated demonstration without real MCP forwarding. Fixed URLs and redirect blocking cover this HTTP dispatch only, not host firewalls, DNS/IP pinning, proxy isolation, sandbox integrity, durable replay protection or business exactly-once execution.

## Validation record

- New baseline fixtures failed as expected; corrected core, MCP and HTTP integration tests passed.
- `go test ./...` and `go vet ./...` passed; frontend type checking and build passed with unchanged generated assets.
- Windows `go test -race ./...` could not run without the cgo toolchain; `docker build .` could not finish because the Docker Linux daemon was not running. The workflow for this commit is the authority for final Linux CI results.
- The local npm launcher pointed at a missing file; the existing npm CLI ran the same package scripts. esbuild needed current-user permissions for path resolution. Global environment, dependency versions and project scripts were unchanged.
- Lifecycle, real network isolation, crash recovery and end-to-end performance are not validated capabilities of this iteration. E03/E05/E06/E08–E11 and full E12 performance measurements remain for later stages.
