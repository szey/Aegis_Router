# Aegis_Router Project Brief

English | [简体中文](project-brief.zh-CN.md)

> **Execution Permits for AI Agent Actions**

The 2026-09-13 [redesign proposal](manus-redesign.md) has an implemented first stage: [M1 execution admission and fixed routes](m1-execution-admission.md). Unsupported obligations reject before consumption; redirects cannot expand the target. Durable state, environment leases and lifecycle remain subsequent stages. The project contract is unchanged.

The real MCP path uses [PreparedExecution and Permit v2](prepared-execution.md) to bind the exact route, profile configuration, and anonymous upstream identity, with Policy rechecking bytes/effects derived from actual arguments. Authority epochs are checked under the registration/consumption lock; disable, re-enable, and refresh invalidate old Permits. Epoch/disabled state is not durable and must be reestablished by trusted code after restart. Resource/lease evidence is synthetic only; no real broker is integrated.

## One-line position

Aegis_Router is a framework-agnostic execution-permit layer with server-owned semantic action profiles. It first evaluates deterministic Policy eligibility, then resolves a granted request into an exact normalized action, issues a short-lived, signed, action-bound, single-use permit, and requires the MCP execution boundary to verify and consume it before the real side effect.

> **The action that was authorized must be exactly the action that executes.**

## Product boundary

Aegis focuses on one reference-monitor primitive, not a broad AI Agent security platform.

Its only core modules, listed in current authorization order, are:

1. Structured request validation;
2. Deterministic Policy eligibility;
3. Server-owned semantic action normalization;
4. Execution Permit issuance;
5. Permit verification;
6. Permit consumption and replay prevention;
7. Audit receipt;
8. One real execution boundary: MCP.

Aegis does not provide generic permission management, endpoint sandboxing, workspace isolation, enterprise Agent Inventory, Shadow Agent governance, full IAM, EDR-style observation, or broad risk dashboards. It also does not implement HTTP, A2A, database, shell, or cloud adapters.

The implementation contains exactly two compiled-in semantic profiles—`payment.send/v1` and logical `workspace.write/v1`—plus one immutable server-owned registry and one MCP adapter. It has no third profile, dynamic loading, plugin SDK, arbitrary schemas, or user-selected upstreams.

## Security property and execution order

```text
Authenticated identity + Agent proposes action
    ↓
Validate structured request
    ↓
Deterministic Policy eligibility
    ↓
Resolve server-owned semantic profile
    ↓
CanonicalAction
    ↓
Issue signed Execution Permit
    ↓
Executor/MCP boundary verifies and atomically consumes Permit
    ↓
Execute exactly the authorized action
    ↓
Write redacted Audit Receipt
```

Deterministic Policy first establishes whether the structured request is eligible for the requested capability, resource, operation, and tool. If Policy grants it, the server-owned semantic profile resolves the exact executable meaning into a `CanonicalAction`. Any semantic mismatch or normalization failure converts the result to `DENIED` before Permit issuance. Policy authorization alone is not sufficient to produce an Execution Permit, and semantic profile resolution never overrides a Policy denial.

`Authenticated identity + exact semantic intent + signed single-use Permit = cryptographically bound execution.`

Authorization and verification reuse the same canonicalizer. Receiving a RuntimeEvent after execution cannot replace this pre-execution check. If permit verification fails, the upstream tool-call count must remain zero.

## Trusted Authorization Intake

Principal, Agent, workload, and delegated authority from an HTTP body/header cannot become authorization facts directly. `TrustedAuthorizationIntake` first resolves and overwrites those fields from a configured trust boundary, then records source, provider, assurance, and establishment time in `authorization_context_provenance`. HTTP authorization fails closed when no intake is configured.

The standalone Server selects exactly one of three modes: secure-default `RejectAll`; explicit `LoopbackDevelopment`; or `TrustedProxy`, which accepts a strict seven-header identity-and-workload-key contract only from a direct TCP peer inside configured IPv4/IPv6 CIDRs. `WorkloadBinding{KeyID, PublicKeyThumbprint}` comes from that authenticated infrastructure context, never the authorization JSON body. Development mode likewise requires one separately configured public key. TrustedProxy derives trust only from `request.RemoteAddr`, never forwarded-address headers, and overwrites every body identity field. Development and proxy modes cannot coexist.

TrustedProxy provenance records `source=trusted_integration`, configured provider ID, `assurance=authenticated_context`, and server establishment time. Aegis authenticates neither users nor OAuth tokens itself; it consumes identity established by a separately trusted authentication boundary. This is not IAM, SSO, OAuth, RBAC, or bearer-token verification. A signed `workload_id` is a binding to that intake claim, not live attestation of remote workload state or undeclared downstream components.

`Router.AuthorizeTrustedAction(intake.Authorization)` is the only normal Permit-issuance entry point. `Router` no longer exposes `AuthorizeAction/Authorize/Process` methods that accept a naked `models.Request`; in-process integrations must also call `intake.NewTrustedAuthorization(...)` or cross an intake implementation to create a sealed context. Process locality is not identity provenance. Server-owned fixtures may use only the synthetic entry point whose name and provenance explicitly say `simulated_demo`.

Sealing alone does not make a deprecated flat request eligible. The execution boundary additionally requires a structured principal, Agent/workload, delegated authority, tool, and action context. A legacy flat projection is rejected before execution-Permit issuance, including for in-process callers. `allow_legacy_flat_requests` preserves compatibility-only Policy interpretation and never permits an executable Permit with an Agent-derived workload or missing delegation fingerprint.

## CanonicalAction

The canonical action binds principal ID, Agent ID, workload ID, delegated-authority fingerprint, tool, capability, resource, operation, profile ID/version, audience, and security-relevant arguments.

Arguments use deterministic canonical JSON: empty arguments become `{}`; object keys sort recursively by Unicode lexical order; duplicate keys, malformed UTF-8, and unpaired surrogates are rejected; arrays preserve order; strings use JSON escaping; and numbers normalize exactly without float conversion. The full canonical action produces a SHA-256 `sha256:<64 lowercase hex>` digest.

Equivalent JSON objects therefore ignore key order, while a changed amount, recipient, resource, tool, operation, identity, or another bound field produces a different digest. Audit retains the digest rather than raw sensitive arguments.

## AuthorizationEnvelope and signed Permit

The structured `AuthorizationEnvelope` is retained. It continues to represent request, principal, Agent/workload, delegation, tool, resource, operation, policy, and obligations; the issuer also generates a verifiable `permit_token`.

Permit claims include at least:

- `jti/permit_id`, `signing_key_id`, and `request_id`;
- `issuer`, `principal_id`, `agent_id`, and `workload_id`;
- mandatory `executor_key_id` and `executor_key_thumbprint` for `execution` only;
- delegated-authority digest/fingerprint;
- `tool`, `capability`, `resource`, and `operation`;
- `action_digest` and `policy_version`;
- `issued_at`, `expires_at`, and `single_use=true`.

The MVP token is a project-specific Ed25519-signed compact format: `base64url(header).base64url(payload).base64url(signature)`, with `alg=EdDSA`, `typ=AEGIS-PERMIT`, `v=2`, and `kid` in its header. The unverified `kid` only selects a KeyProvider public key; after signature verification it must match the signed `signing_key_id` claim. The format borrows the JWS shape but does not claim general JWT/JWS interoperability.

TTL uses whole seconds, defaults to 30 seconds, and is currently capped at 15 minutes.

`permit_id` is an audit correlation ID; `permit_token` is the secret execution credential. Lists, details, logs, and UI show only the former.

`KeyProvider` separates key storage/lifecycle from Permit logic: the issuer requests the current signing key and the verifier resolves a public key by `kid`. The default Server still uses a process-local ephemeral development key; the static provider accepts a persistent local Ed25519 key securely loaded by an embedding process. Key-file format, automatic rotation, and KMS/HSM are outside this milestone.

## Verifier and PermitStore

The verifier checks signature, issuer, time, Permit ID, principal, Agent/workload, tool, resource, operation, and action digest before the side effect. It accepts only `VERIFIED`.

A concurrency-safe PermitStore maintains `ISSUED / CONSUMED / EXPIRED / REVOKED`. Successful verification and consumption are atomic. If two requests concurrently reuse the same Permit, exactly one succeeds and the other receives an explicit replay outcome. An in-process-only state store cannot provide restart- or replica-wide replay guarantees.

Consumption occurs before the upstream side effect and is an irreversible commit point. An upstream failure or timeout leaves the Permit `CONSUMED`; retry requires a new authorization and new Permit. There is no `unconsume`.

This guarantees only that one Permit is successfully consumed at most once; it does not make upstream payments, orders, account changes, message sends, or other business side effects exactly once. If a side effect succeeds but its response is lost, retry still needs a new Permit and must rely on the upstream's own business idempotency key or deduplication mechanism. Aegis does not implement a business idempotency engine.

## MCP adapter

MCP is the focused MVP's only production-shaped adapter. Before consuming an execution Permit, `tools/call` verifies a fresh Ed25519 `X-Aegis-Execution-Proof` against a server-registered workload public key. The proof binds Permit ID, action digest, `POST /mcp`, issuance time, and a nonce; its key ID and public-key thumbprint must match the signed Permit. Missing/invalid proofs, wrong workloads, stale proofs, and reused nonces fail before Permit consumption and before upstream. The proof is never forwarded or audited. The adapter then performs the existing action verification and atomic Permit consumption and forwards only normalized arguments.

`WRONG_EXECUTOR` distinguishes a valid Permit presented without possession of its bound workload key from an invalid Permit signature. Both workload keys and proof-nonce replay state are currently process-local. Private-key theft/sharing, restart-wide replay, multi-replica coordination, hardware attestation, and software-integrity measurement remain outside the implementation.

`payment.send/v1` accepts only positive integer minor-unit amount, allowlisted currency, and allowlisted recipient, with a per-currency limit. `workspace.write/v1` accepts only JSON-string `path` and `content`; the path is a logical relative `/`-separated identifier with no backslash, drive prefix, empty/`.`/`..`/`~` segment, edge slash, control character, or normalization. Sample limits are 1,024 bytes for path and 4 KiB for content. It forwards to a mock/logical upstream and never writes the host filesystem. Raw content participates in the digest but never enters normal audit.

The adapter cannot “call first and alert later” after a failed verification, and cannot forward on `permit_id` alone. A server-owned upstream URL/resource/audience means only that Aegis bound that configuration; it does not prove the expected organization owns the endpoint or cloud resource. Resource ownership, upstream MCP TLS/authentication, tool side effects, and deployment bypass remain separate deployment responsibilities.

For MCP `2026-07-28`, the current adapter validates `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` against the JSON-RPC body; rejects duplicate JSON keys, UTF-8-BOM-prefixed payloads, and unbound tool `_meta`; and strips arbitrary headers/session context before rebuilding minimal transport/routing headers. It implements only the focused subset for `server/discover`, `tools/list`, and permit-gated `tools/call` on the exact HTTP `POST /mcp` route; `/sse` suffix paths never enter the Proxy, and Final SEP-2640 Skills-extension `skills/list`/`skills/get` also fail closed. Base64-wrapped `Mcp-Name`, MRTR fields, and schema-driven `Mcp-Param-*` fail closed for now, and full protocol conformance is not claimed. Discovery/list responses are relayed from upstream, so their descriptions, instructions, and other metadata remain untrusted Host inputs rather than Aegis-sanitized content.

## Policy, Risk, and obligations

Policy first evaluates the structured request for deterministic eligibility. Only a Policy grant reaches one of the two compiled-in semantic profiles; both the grant and successful semantic resolution are required before an Execution Permit can exist. The executable outcomes are `AUTHORIZED / DENIED`. `REQUIRES_APPROVAL` remains representable but has no supported approval-completion workflow and is not an implemented execution capability.

Risk/detection remain optional advisory metadata under `advisory_signals`; they cannot change authorization status, create a grant, issue a Permit, or select an executor. Obligations such as `human_approval_required`, `isolation_required`, or `enhanced_audit_required` require an explicit deterministic Policy/configuration mapping.

All five signed obligations require an independent, trusted implementation. M1 has none connected, so the core rejects required isolation, denied egress, read-only behavior, human approval or enhanced audit before consumption. This deliberately blocks the shipped deny-egress payment/workspace grants from real forwarding. The response and receipt explain scope and rejection in `constraint_checks`; they do not assert enforcement. MCP also refuses redirects and retains consumption after the original dispatch.

## Audit Receipt and Runtime Evidence

Each action produces an explainable receipt in `TRUST CONTEXT → POLICY ELIGIBILITY/OBLIGATIONS → SEMANTIC ACTION → PERMIT → VERIFICATION → EXECUTION` order, including upstream attempted and execution outcome. Risk/detection appear only under `ADVISORY SIGNALS`.

The supported executable authorization status uses `AUTHORIZED / DENIED`. Current execution final verdicts include `EXECUTED_WITH_VALID_PERMIT`, `PERMIT_ACTION_MISMATCH`, `PERMIT_EXPIRED`, `PERMIT_REPLAY`, `PERMIT_INVALID_SIGNATURE`, `PERMIT_REVOKED`, and `EXECUTION_OBLIGATION_UNSATISFIED`, while the receipt also retains the verifier's precise outcome and execution outcome.

RuntimeEvent and its source/trust model remain, but only as during- or post-execution evidence. `agent_self_reported`, `instrumented_adapter`, and `simulated_demo` cannot masquerade as independent sensors; uninstrumented coverage stays `UNKNOWN`.

## API and UI

Primary APIs are `POST /api/actions/authorize`, diagnostic-only `POST /api/permits/verify`, Permit revoke/list/detail, `GET /api/decisions`, and `GET /api/audits`. The MCP adapter uses the verifier's single proof-bearing `VerifyExecutionAndConsume` execution boundary. The diagnostic HTTP check never consumes a Permit, reports a valid check as `VALID_NOT_CONSUMED` with `verified=false`, and cannot authorize execution. Every HTTP authorization endpoint crosses Trusted Intake; it fails closed when unconfigured, and the loopback body intake is explicit development mode only. Legacy `/api/authorize`, `/api/route`, and `/api/runtime-events` remain temporarily and are labeled clearly.

The UI has only `Decisions / Permits / Audit / Demo` as primary navigation. Permit detail shows `permit_id`, `signing_key_id`, state, principal, Agent/workload, tool, capability, resource, operation, action digest, policy version, issued/expires/consumed time, and the latest verification result—never the token, signing key, raw delegated credential, or raw sensitive arguments.

Four primary demos cover valid, action mutation/TOCTOU, replay, and expired Permits. Historical scenarios move to advanced regression fixtures and remain labeled `simulated_demo`.

## Experimental Discovery

Existing Discovery/Registry code remains buildable but is frozen, disabled by default, and hidden from normal UI. `--enable-experimental-inventory` is required to expose related Server capability; `cmd/discover` remains a standalone experimental utility.

No process, OAuth, CI/CD, cloud, or central enterprise Inventory expansion is planned. Discovery traces cannot prove an Agent is running and do not affect an execution permit.

## Completion definition and limitations

The focused MVP is complete only when it repeatedly proves that an exact action is authorized and receives a signed Permit; the MCP boundary verifies and consumes it before the upstream call; any bound-field change blocks execution; a consumed Permit cannot replay; and the full audit chain leaks neither the token nor sensitive payload.

Even when every local test passes, this remains a reference implementation. An in-process Store, default ephemeral development key, local audit, a deployment boundary not yet connected to real authenticated middleware, and incomplete independent review are not production guarantees.

Migration: real execution Permits must be reissued as v2. v1 remains for core compatibility/simulation; the current MCP path rejects old v1 execution Permits.
