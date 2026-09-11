# Security Policy

English | [简体中文](SECURITY.zh-CN.md)

This document applies to **Aegis_Router — Execution Permits for AI Agent Actions** in [`szey/Aegis_Router`](https://github.com/szey/Aegis_Router).

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. If GitHub Private Vulnerability Reporting is enabled, use it and include the affected version/commit, a minimal safe reproduction, expected and actual verification results, whether the upstream tool was called, potential impact, and a feasible mitigation.

Before the first formal tag, only the latest commit on the default branch is supported.

## Trust boundary

Aegis is a reference implementation, not an independently reviewed production security boundary. It protects only tool calls that actually cross its verifier/MCP adapter. Installing Aegis does not automatically discover or block behavior that bypasses that boundary.

The core control first validates a trusted structured request and evaluates deterministic Policy eligibility for its capability, resource, operation, and tool. Only after a Policy grant does the server-owned semantic profile resolve the exact executable meaning into a `CanonicalAction`. Successful Policy eligibility and semantic resolution are both required before Aegis issues a signed, short-lived, action-bound, single-use `permit_token`. Any semantic mismatch or normalization failure converts the result to `DENIED` before Permit issuance. Policy authorization alone is not sufficient to produce an Execution Permit, and semantic profile resolution never overrides a Policy denial.

The Permit is verified and atomically consumed before the real tool side effect. `permit_id` is correlation only and cannot authorize by itself. The upstream tool must remain uncalled after verification failure.

`AuthorizationEnvelope` continues to carry structured principal, Agent/workload, delegation, tool, capability, resource, operation, and policy context, but an execution credential must also carry a verifiable signature and the same action digest.

HTTP authorization requests must also cross `TrustedAuthorizationIntake`. The three standalone-server modes are: fail-closed `RejectAll` by default; explicit `LoopbackDevelopment`, which trusts body identity only for a loopback direct peer and labels it `development_only`; and `TrustedProxy`, which consumes strict identity headers from a separately authenticated proxy whose direct TCP peer belongs to a configured IPv4/IPv6 CIDR. TrustedProxy and development mode cannot coexist, and partial trusted-proxy configuration prevents startup.

TrustedProxy establishes sender trust exclusively from `request.RemoteAddr`. It never uses `X-Forwarded-For`, `Forwarded`, or `X-Real-IP`. Required identity headers must be singular, bounded, control-free, and syntactically valid. The proxy must also assert `X-Aegis-Workload-Key-Id` and `X-Aegis-Workload-Key-Thumbprint`; this `WorkloadBinding` comes from authenticated infrastructure context and has no authorization-body representation. Delegated scopes use one comma-separated representation, reject empty/duplicate entries, and are sorted. The delegation fingerprint is exactly 64 hexadecimal SHA-256 characters; bearer/OAuth tokens, API keys, passwords, cookies, and other raw credentials are not accepted.

Successful proxy intake records `source=trusted_integration`, configured `provider_id`, `assurance=authenticated_context`, and server `established_at` in `authorization_context_provenance`; rejected proxy input never falls back to body identity. `Router` still has no normal Permit-issuance entry point accepting a naked `models.Request`; it consumes sealed `intake.Authorization`. Aegis authenticates neither users nor OAuth tokens itself—it consumes identity established by the separately trusted authentication boundary. This is not a complete IAM, SSO, OAuth, or RBAC system. Sharing a process or network is not authentication, and authenticated proxy operation, transport security, and topology enforcement remain deployment responsibilities.

Every execution Permit signs the executor key ID and the SHA-256 thumbprint of its Ed25519 public key. MCP `tools/call` additionally requires `X-Aegis-Execution-Proof`: a fresh compact Ed25519 signature over the Permit ID, action digest, `POST /mcp`, issuance time, and nonce. Aegis resolves the proof `kid` only from its local registered-key set, verifies that key's thumbprint against the Permit, rejects stale proofs and reused nonces, and performs these checks before Permit consumption or upstream invocation. Permit and proof checks plus atomic consumption are exposed together only through `VerifyExecutionAndConsume`; there is no public proof-free execution-consumption method. The proof header is never forwarded or audited. A valid Permit presented by the wrong workload returns `WRONG_EXECUTOR`; malformed Permit credentials retain their separate invalid-Permit/signature outcomes. The legacy-named `POST /api/permits/verify` route is a diagnostic check only: it does not consume and returns `VALID_NOT_CONSUMED` with `verified=false` for a valid Permit/action pair.

This proof demonstrates control of a registered private key for one fresh request. It is not hardware attestation or software-integrity measurement. Theft, copying, or intentional sharing of the workload private key defeats the binding. The nonce store and registered-key set are process-local, so restart and multi-replica replay protection require external coordination that this milestone does not implement. Old execution Permits without executor-key claims are rejected and must be reissued; simulation Permits remain unbound to workload keys and cannot reach MCP execution.

A sealed intake value is necessary but not sufficient for execution issuance: `Router.AuthorizeTrustedAction` also requires a structured security context that preserves principal, Agent/workload, delegated authority, tool, and action fields. Deprecated flat requests fail before Policy execution-Permit authorization, audit creation, or Permit issuance. `allow_legacy_flat_requests` keeps compatibility-only Policy interpretation available; it does not make a flat request execution-Permit eligible and cannot justify an empty delegation fingerprint or an Agent-ID-derived workload in signed claims.

## Tokens, keys, and replay

The focused MVP uses a project-specific Ed25519-signed compact format shaped as `base64url(header).base64url(payload).base64url(signature)`. It does not claim general JWT/JWS interoperability. The header carries `kid` only as a KeyProvider public-key selector; after signature verification it must match the signed `signing_key_id` claim.

Permit TTL uses whole seconds, defaults to 30 seconds, and is currently capped at 15 minutes.

- the private key stays inside the permit issuer's approved boundary and never enters UI, audit, errors, or the repository;
- `KeyProvider` supplies the current signing key and resolves verification keys by `kid`; the default remains process-local and ephemeral, while an embedding process may inject a securely loaded persistent local key;
- key-file format, automatic rotation, HSM/KMS, cross-instance trust, and disaster recovery are outside this MVP;
- permits are single-use by default and use a concurrency-safe Store for atomic consumption;
- expired, revoked, consumed, or unknown permits fail closed;
- an in-process-only Store has restart and multi-replica replay-state gaps; do not claim cluster-wide replay defense before shared persistence and key-lifecycle design exist.

The Permit is consumed before the upstream side effect. Upstream failure or timeout never restores it; a retry requires a fresh authorization and a new Permit. The Store exposes no `unconsume` operation because such semantics would reopen replay and duplicate-side-effect windows.

### Exactly-once boundary

Aegis guarantees that one Execution Permit can be successfully consumed at most once. It prevents authorization-credential replay; it does not guarantee that an arbitrary business side effect executes exactly once. If a payment, order, account change, or message send completes upstream but its response is lost, the original Permit remains `CONSUMED`. A retry requires a new authorization and new Permit and must rely on the upstream system's own business idempotency key or deduplication mechanism. Aegis does not implement a business idempotency engine.

## Action binding and canonicalization

Authorizer and executor must reuse the same canonicalizer. Empty arguments become `{}`; object keys sort recursively by Unicode lexical order; duplicate keys, malformed UTF-8, and unpaired surrogates are rejected; arrays preserve order; strings use JSON escaping; and numbers normalize exactly without float conversion before a SHA-256 `sha256:<64 lowercase hex>` digest is produced.

Any change to principal, Agent/workload, delegation fingerprint, tool, capability, resource, operation, profile ID/version, audience, or security-relevant arguments must fail the binding check. Do not use `claimed_intent`, a natural-language plan, or a client-provided digest as a substitute for server-side normalization.

## MCP execution boundary

MCP is the only production-shaped adapter in the current milestone. The adapter accepts only signed `permit_class=execution` permits and verifies and consumes one before forwarding an upstream `tools/call`. Server-owned Demo issuance creates only `permit_class=simulation`, which is accepted only by a separate non-forwarding simulation verifier. Missing, unknown, mismatched, or tampered classes fail before consumption and must never call the upstream. Invalid signature, expiry, revocation, replay, wrong agent/workload/tool/resource/operation, or action mismatch likewise never calls the upstream.

Tokens issued before `permit_class` existed are intentionally invalid and require fresh authorization and issuance. Never infer `execution` from a missing claim.

For MCP `2026-07-28`, `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` must agree with the JSON-RPC body. The Proxy rejects duplicate JSON keys and unbound tool `_meta`, strips arbitrary inbound headers/session context, and rebuilds only minimal transport and standard routing headers. Base64-wrapped `Mcp-Name` is not decoded and fails closed. The focused subset does not cache tool schemas, so it cannot safely validate `Mcp-Param-*`, and it has not bound MRTR `inputResponses`/`requestState` into the action digest; those inputs fail closed before upstream. Do not describe this subset as full MCP conformance.

The Proxy relays `server/discover` and `tools/list` responses from the configured upstream. Descriptions, instructions, and other returned metadata are untrusted content and are not sanitized by Aegis. Hosts must not place them into a trusted prompt without their own isolation and review. This limitation does not bypass the independent Permit gate on a later real `tools/call`.

Protection covers only calls routed through this adapter. Trusted Intake makes identity provenance explicit, rejectable, and auditable; it does not implement IAM/SSO/RBAC, and a real integration must still supply context from authenticated middleware. Binding headers on an MCP execution request matter only when they exactly match a signed Permit; they are not identity credentials. Upstream TLS/authentication, transport framing, tool-side effects, deployment bypass, and confused-deputy risks still need a separate threat model.

Exactly two server-owned semantic mappings are compiled in and dispatched through one immutable registry: `payment.send/v1` and logical `workspace.write/v1`. Duplicate profile IDs, ambiguous tool mappings, unknown tools, missing mappings, and conflicting caller assertions fail closed; no caller can load code, choose a profile, or select an upstream URL. Both authorization and MCP execution use the same registry and profile parsers, and each resolved profile supplies its own fixed upstream target.

`payment.send/v1` fixes tool, capability, resource, operation, profile version, audience, and target. Its strict three-field parser accepts a positive `int64` `amount_minor`, exact allowlisted currency, and exact allowlisted recipient. Per-currency limits are independent minor-unit ceilings with no implicit exchange-rate conversion.

`workspace.write/v1` fixes the same binding categories for a logical `workspace.write`. Its strict parser accepts only JSON-string `path` and `content`. The path is not an OS path: only relative `/`-separated segments are accepted, without backslashes, drive prefixes, empty/`.`/`..`/`~` segments, edge slashes, control characters, or repair/normalization. The configured sample limits path to 1,024 bytes and content to 4 KiB. Content and path are included in action semantics but excluded from Permit claims and normal audit. The profile forwards only to its configured logical/mock upstream; it performs no filesystem write or isolation.

## Policy, Risk, and isolation

Policy and the two supported semantic profiles remain deterministic. Policy evaluates request eligibility first; only a grant reaches server-owned semantic resolution. Both the Policy grant and successful semantic resolution are required for Permit issuance and signed obligations. The executable flow currently supports `AUTHORIZED / DENIED`. The model can represent `REQUIRES_APPROVAL`, but no supported approval-completion flow exists and it cannot produce an executable Permit. Risk scores and detection findings enter only `advisory_signals`; they cannot override denial, create a grant, issue a Permit, or select an executor. Obligations such as `human_approval_required`, `isolation_required`, or `enhanced_audit_required` require an explicit deterministic Policy/configuration mapping.

Aegis does not implement a sandbox. `isolation_required: true` asks an external executor to supply isolation; the focused MCP proxy fails closed with `EXECUTION_OBLIGATION_UNSATISFIED` instead of forwarding when isolation or human approval is still required. `read_only` and `network_egress_denied` remain signed requirements that an independently trusted executor/control must actually enforce. `SANDBOX` in compatibility output is also a profile hint. Do not claim Docker, gVisor, Firecracker, filesystem, or network isolation.

## Audit and sensitive data

Normal audit is explained in trust-context, structured-request validation, deterministic Policy eligibility/obligations, semantic action, Permit, verification, and execution order. It may retain request/decision/permit IDs, `signing_key_id`, `permit_class`, normalized identity fields, `authorization_context_provenance`, tool/resource/operation, `action_digest`, policy version, authorization decision, Permit state, verification result/rejection reason, whether upstream was attempted, execution outcome, timestamp, and evidence source. Risk/detection are labeled separately as `advisory_signals`.

The caller must hash delegated credentials before submission. Aegis additionally rehashes the declared 64-hex fingerprint before any Permit/audit persistence, so a digest-shaped input is not retained verbatim; this defense does not turn the authorization API into a credential authenticator.

Never retain or display:

- `permit_token` or signing private keys;
- raw bearer/delegated tokens, cookies, or secret values;
- raw sensitive action arguments, prompts, retrieved documents, files, or tool-output bodies;
- full personal paths, usernames, or unredacted URLs in normal runtime audit;
- unredacted employee, customer, or production data.

A local audit file is not a tamper-resistant central audit store. Error paths also require redaction review so exceptions and request dumps cannot leak tokens.

## Runtime evidence and experimental Discovery

`gateway_enforced`, `instrumented_adapter`, `agent_self_reported`, `os_sensor`, `network_sensor`, and `simulated_demo` retain distinct source/trust meanings. The event API is a secondary evidence path, not pre-execution control. Uninstrumented coverage is `UNKNOWN / not instrumented`, not zero risk.

Discovery is frozen, disabled by default, and exposed by the Server only with `--enable-experimental-inventory`. Configuration/dependency/manifest matches are heuristic evidence and cannot prove runtime behavior. Do not expand process, OAuth, CI/CD, cloud, or central enterprise Inventory.

## Company endpoints and production exclusions

A company pilot requires renewed written authorization from the device owner, IT/security, and data owner, and may use only synthetic arguments, test credentials, and an approved MCP upstream. Never capture coworker behavior, bypass EDR/DLP/proxy/application controls, or upload company logs to a personal GitHub account or external AI service.

Until independent review, a controlled MCP pilot, persistent replay/key design, and formal operations exist, do not use Aegis as the sole blocking control in front of production credentials or customer data. See the [execution-permit pilot](docs/experiments/enterprise-agent-pilot.md).
