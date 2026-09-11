# Aegis_Router MCP Execution-Permit Pilot

English | [简体中文](enterprise-agent-pilot.zh-CN.md)

Status: **the prior Discovery exploration is complete; the new controlled MCP execution-permit pilot has not started.**

The old company-endpoint trial showed only that a bounded scan could produce configuration evidence, and exposed permission errors, cache noise, and UI refresh problems. It did not validate signed Permits, pre-execution MCP blocking, or replay defense. It is neither the success baseline for this pilot nor `V3 pilot_verified`.

## This pilot proves only one thing

> The authorized MCP action must be exactly the action forwarded upstream.

```text
Controlled MCP client proposes tools/call
  → Aegis derives CanonicalAction
  → Policy authorizes exact action
  → issue short-lived Ed25519 Permit
  → MCP boundary verifies + consumes before side effect
  → forward to controlled upstream only after VERIFIED
  → write redacted Audit Receipt
```

This pilot does not evaluate generic Agent management, Shadow discovery, sandboxing, EDR, IAM, or full-endpoint visibility. If the company Agent has no approved MCP/tool-proxy entry point, directory scanning or Agent self-reporting cannot substitute for a real execution boundary; stop the pilot.

## Questions that must be answered

1. Do principal, Agent, workload, delegation fingerprint, tool, capability, resource, operation, and security-relevant arguments enter the same canonical action?
2. Do equivalent JSON key orders produce the same digest, while amount/resource/tool/operation changes produce a different digest?
3. Does the Permit validate signature, issuer, TTL, and every binding?
4. Are `permit_id` and `permit_token` always separate, with the ID never authorizing by itself?
5. Does a valid Permit call upstream exactly once and become `CONSUMED`?
6. Do invalid signature, expiry, revocation, wrong binding, action mismatch, and replay all leave the upstream-call count at zero?
7. Does exactly one of two concurrent replay attempts succeed?
8. Do UI, audit, errors, and upstream metadata all exclude `permit_token`, raw delegated tokens, and raw sensitive arguments?
9. Does Demo remain `simulated_demo`, with RuntimeEvent clearly secondary evidence?
10. Are CPU, memory, latency, and audit growth within the pre-approved envelope?
11. Does every side-effecting upstream provide independent business idempotency, with no pilot claim that a single-use Permit means exactly-once business execution?

## Single-use Permit and business idempotency

This pilot can prove only that one Execution Permit is successfully consumed at most once; it cannot prove that an arbitrary upstream business side effect occurs exactly once. If the upstream completes an action but its response is lost, Aegis still leaves the original Permit `CONSUMED`, and every retry needs a new authorization and new Permit. Side-effecting tools for payments, orders, account changes, message sending, and similar operations must use the upstream system's own business idempotency key or deduplication mechanism. The pilot neither implements nor simulates an Aegis business idempotency engine.

## Authorization and prohibited scope

Before starting, obtain written approval from the device owner, IT/security, and data owner. Name the device, operator, MCP client/Agent, Proxy, upstream, test tool, argument classes, time window, network target, retention, rollback, and accountable owner.

Use only synthetic arguments, test credentials, harmless local tools, and approved loopback/internal test targets. Never:

- use production tokens, real secrets, customer/employee data, or real payment/deletion/publication actions;
- capture coworker sessions, scan unapproved directories, or monitor company-wide traffic;
- bypass EDR, DLP, antivirus, proxy, certificate, or application-allowlist controls;
- upload company logs, paths, device identifiers, or Permit tokens to personal GitHub/cloud storage/external AI services;
- interpret `isolation_required` or a legacy `SANDBOX` field as isolation supplied by Aegis;
- use Aegis as the sole production blocking control.

The project contract still has `allow_deploy=false` and requires explicit company-device authorization. This protocol does not itself grant deployment authority.

## Gate 0: local P0 regression

Before any company-device work, the development environment must pass:

- valid Permit;
- invalid signature;
- expired and revoked Permit;
- wrong principal/agent/workload/tool/resource/operation;
- argument digest mismatch;
- sequential and concurrent replay;
- audit/token privacy;
- zero MCP upstream calls after failed verification;
- MCP `2026-07-28` header/body/version mismatch, duplicate JSON keys, arbitrary headers/session context, unbound tool `_meta`, MRTR, or `Mcp-Param-*` inputs fail closed or are stripped before upstream;
- a Permit carrying unsatisfied isolation or human-approval obligations produces `EXECUTION_OBLIGATION_UNSATISFIED`, with zero upstream calls;
- Demo telemetry remains `simulated_demo`;
- `go test ./...`, `go test -race ./...`, `go vet ./...`, and frontend check/build.

If the race toolchain is unavailable, report it as an open gate rather than a pass.

## Gate 1: minimal company-endpoint baseline

- reconfirm the written scope;
- transfer source/binary through the approved company method and verify SHA-256;
- listen only on approved interfaces, preferring `127.0.0.1` by default;
- use a temporary test signing key, never a production or personal long-lived key;
- use a harmless local upstream MCP fixture;
- record idle CPU, memory, ports, and audit directory;
- do not enable `--enable-experimental-inventory` without a separate written need.

Discovery is not an acceptance item for this Gate.

## Gate 2: four focused Demos

| Scenario | Action | Expected result |
|---|---|---|
| Valid Permit | Authorize and execute the same `config.read` | `VERIFIED`; one upstream call; Permit is `CONSUMED` |
| Action Mutation / TOCTOU | Authorize `amount=100`, execute `10000` | `PERMIT_ACTION_MISMATCH`; zero upstream calls |
| Permit Replay | Use the same token twice | First is `VERIFIED`; second is `PERMIT_REPLAY` |
| Expired Permit | Execute after TTL | `PERMIT_EXPIRED`; zero upstream calls |

These Server fixtures are `simulated_demo` and prove only the local deterministic path.

## Gate 3: controlled real MCP boundary

Proceed only if the company Agent/tool system supports an approved MCP client or Proxy configuration. The current executable subset supports only `payment.send/v1`; use synthetic amounts and a local mock upstream, never a real payment provider or credential:

1. Set `semantic_actions.payment_send_v1.upstream_url` to one harmless local MCP mock with a call counter, and start Aegis with an exactly matching `--mcp-upstream` value.
2. Have approved authenticated middleware establish principal, Agent/workload, and delegated authority through Trusted Intake; do not use the `development_only` body intake as company identity assurance.
3. Derive a canonical action for one `tools/call`, call the authorization API, and retain redacted `authorization_context_provenance` and `signing_key_id`.
4. Put `permit_token` only in the controlled client-to-Proxy execution channel, never command history or screenshots.
5. The Proxy reuses the core verifier and atomically consumes before forwarding.
6. On `2026-07-28`, also verify that `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` match the body, and forward only after `VERIFIED`.
7. Retain a redacted receipt and upstream call counter.
8. Repeat each negative outcome and confirm the counter remains zero.
9. Make one verified call fail or time out upstream, confirm its Permit remains `CONSUMED`, and allow retry only after a fresh authorization produces a new Permit.
10. For any side-effecting test tool, use the upstream's own idempotency key. Simulate “side effect succeeded but response was lost,” confirm the record distinguishes single-use Permit consumption from business exactly-once semantics, and never reuse the original Permit.

If WorkBuddy or another Agent cannot configure an approved MCP boundary, this Gate does not pass. Do not modify the company Agent, bypass policy, or collect whole-machine behavior to “complete” the test.

## Gate 4: evidence review and exit

Audit must explain trust context, action, deterministic policy, obligations, Permit, verification, and execution in that order. It must answer request/decision/permit ID, `signing_key_id`, `permit_class`, profile ID, audience, principal, Agent/workload, authorization-context provenance, tool, resource, operation, action digest, policy version, authorization decision, Permit state, verification outcome, upstream attempted, execution outcome, timestamp, evidence source, and upstream call count. Risk/detection may appear only under advisory signals. It contains no token or raw sensitive arguments.

At exit, stop Aegis, the Proxy, and test upstream; revoke every unconsumed Permit; remove temporary private keys and synthetic payloads; and let the company owner decide local audit retention/deletion. Only redacted conclusions and a synthetic minimal reproduction may return to the public repository.

## Evidence trust

| Source | What it proves | What it cannot prove |
|---|---|---|
| `gateway_enforced` / MCP Proxy receipt | A specific call crossed the verification boundary and its outcome | Every action by the company Agent crossed Aegis |
| upstream call counter | Whether the controlled test server was invoked | A real business system or arbitrary MCP Server is safe |
| `instrumented_adapter` | Test metadata reported by the adapter | Independent OS observation or full-endpoint coverage |
| `simulated_demo` | A Demo fixture traversed the code path | A real Agent, executor, or production telemetry |
| `agent_self_reported` | The Agent claims an action occurred | A complete, unforgeable fact |

Uninstrumented capability remains `UNKNOWN / not instrumented`. `UNKNOWN != SAFE` and does not mean zero events.

## Performance and acceptance gate

These are pilot goals to approve before the run, not current promises:

| Metric | Initial target |
|---|---:|
| Average idle Aegis CPU | < 2% |
| Aegis process memory | < 100 MB |
| Median Permit verify+consume increment | < 10 ms |
| Median Proxy end-to-end latency increment | < 10% |
| Audit file for one pilot | < 50 MB |

Mark the pilot `V3 pilot_verified` only when the written scope matches execution; P0/race regression passes; a real MCP boundary is demonstrably before the side effect; every negative result leaves upstream uncalled; exactly one concurrent replay succeeds; no token/sensitive argument leaks; performance/privacy evidence stays inside the approved boundary; and cleanup completes.
