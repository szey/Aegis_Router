# Aegis_Router

English | [简体中文](README.zh-CN.md)

**Execution Permits for AI Agent Actions**

Aegis_Router implements a framework-agnostic execution-permit model with a focused MCP enforcement path and server-owned semantic action profiles. Before a privileged tool action executes, Aegis validates the structured request and evaluates deterministic Policy eligibility. After a Policy grant, a server-owned semantic profile resolves the exact executable action; Aegis then issues a signed, short-lived, action-bound, single-use-by-default execution permit. The executor verifies and consumes that permit immediately before the real side effect.

If the Agent changes the tool, operation, resource, or security-relevant arguments after authorization, the permit no longer matches and the tool must not execute.

> **The action that was authorized must be exactly the action that executes.**

Aegis is not a sandbox, EDR, IAM system, Agent management platform, or enterprise Inventory product. The project and GitHub repository now share the **Aegis_Router** name: [`szey/Aegis_Router`](https://github.com/szey/Aegis_Router).

## Core execution path

```text
Authenticated identity + Agent proposes action
  → validate structured request
  → deterministic Policy eligibility
  → resolve server-owned semantic profile into CanonicalAction
  → issue Execution Permit
  → verify Permit/proof/action and check constraints before consumption
  → atomically consume Permit; dispatch to a fixed target without redirects
  → call upstream tool only after VERIFIED
  → write a redacted Audit Receipt
```

Deterministic Policy first establishes whether the structured request is eligible for the requested capability, resource, operation, and tool. If Policy grants it, the server-owned semantic profile resolves the exact executable meaning into a `CanonicalAction`. Any semantic mismatch or normalization failure converts the result to `DENIED` before Permit issuance. Policy authorization alone is not sufficient to produce an Execution Permit, and semantic profile resolution never overrides a Policy denial.

`Authenticated identity + exact semantic intent + signed single-use Permit = cryptographically bound execution.`

The security boundary is **before the real tool side effect**. `POST /api/runtime-events` may still record during- or post-execution evidence, but an after-the-fact event is not the primary blocking mechanism.

## Capability status

- **Implemented:** fail-closed, loopback-development, and trusted reverse-proxy authorization intake modes; signed `execution`/`simulation` class separation; short-lived single-use permits; replay protection; canonical action binding; exactly two compiled-in profiles (`payment.send/v1` and logical `workspace.write/v1`); and one shared focused MCP HTTP `POST` enforcement path.
- **Demo or experimental:** server-owned simulation scenarios and telemetry; frozen Inventory is hidden unless explicitly enabled.
- **Not implemented:** an approval completion workflow, sandbox/EDR/IAM, business exactly-once delivery, a third or dynamically loaded semantic profile, additional execution adapters, real filesystem writes, and full MCP protocol conformance. `REQUIRES_APPROVAL` remains a model/config result only; no supported approval flow can turn it into an executable Permit.

- **M1 implemented:** all five signed execution requirements fail closed before consumption, with receipt diagnostics; fixed MCP routes never follow redirects. Without external enforcers, real execution carrying any of these requirements rejects.
- **2026-09-15 boundary fix:** exact, case-sensitive MCP envelope keys and forwarding of the classified envelope prevent a parser differential from bypassing Permits. See [authorization/execution binding](docs/authorization-execution-binding.md) for research, comparisons, and proposed route/resource-version work.
- The real MCP path uses [PreparedExecution and Permit v2](docs/prepared-execution.md) to bind the exact route, profile configuration, and anonymous upstream identity, with Policy rechecking bytes/effects derived from actual arguments. Authority epochs are checked under the registration/consumption lock; disable, re-enable, and refresh invalidate old Permits. Epoch/disabled state is not durable and must be reestablished by trusted code after restart. Resource/lease evidence is synthetic only; no real broker is integrated.

## Core objects

### CanonicalAction

The authorizer and executor must derive the same normalized action from the same fields:

- principal identity;
- Agent and workload identity;
- delegated-authority fingerprint;
- tool, capability, resource, operation, profile ID/version, and audience;
- security-relevant arguments.

Arguments use deterministic canonical JSON and a SHA-256 digest. Empty arguments normalize to `{}`; object keys sort recursively by Unicode lexical order; duplicate keys, malformed UTF-8, and unpaired surrogates are rejected; arrays preserve order; and numbers normalize exactly without float conversion (`100.0` and `1e2` are equivalent). Object key order does not change the digest; changing an amount, resource, tool, operation, or another bound field does. The digest is `sha256:<64 lowercase hex>`. Normal audit records retain `action_digest`, not raw sensitive arguments.

### Execution Permit

The `AuthorizationEnvelope` concept is retained and strengthened into a signed execution credential. A permit binds at least:

```text
permit_id / jti      signing_key_id / kid
permit_class         execution | simulation
request_id           principal_id
agent_id / workload_id
executor_key_id / executor_key_thumbprint
delegation_digest    tool / capability
resource / operation action_digest
profile_id / audience
policy_version       issued_at / expires_at
single_use=true
```

The focused MVP uses an Ed25519-signed compact token: `base64url(header).base64url(payload).base64url(signature)`. Its header carries `alg=EdDSA`, `typ=AEGIS-PERMIT`, `v=2`, and `kid=<signing_key_id>`. The unverified header `kid` only selects a public key from the KeyProvider; after signature verification it must also match the signed `signing_key_id` claim. This is a project-specific JWS-shaped format and does not claim general JWT/JWS interoperability.

TTL uses whole seconds, defaults to 30 seconds, and is currently capped at 15 minutes.

`permit_id` is a safe correlation identifier; `permit_token` is the execution credential. An ID alone cannot authorize execution. Signing keys, `permit_token`, raw delegated credentials, and secret arguments must never enter the UI or audit log. Callers submit only a 64-hex SHA-256 credential fingerprint; Aegis hashes that declared fingerprint again into an algorithm-qualified binding before it enters CanonicalAction, Permit claims, or audit. This is defense in depth, not permission to submit a bearer token.

Issuance and verification use a `KeyProvider` abstraction to obtain the current signing key and resolve verification keys by `kid`. The Server currently generates one process-local ephemeral development key; an embedding process may supply a securely loaded persistent local Ed25519 private key through the static provider. The project does not yet define a key-file format, automatic rotation, KMS/HSM integration, or cross-instance keyring operations.

### Verification and replay defense

The execution boundary validates signature, issuer, expiry, `permit_class`, principal/Agent/workload, tool, resource, operation, profile version, audience, action digest, and workload proof, then atomically consumes the permit through the single `VerifyExecutionAndConsume` entry point. Every `execution` Permit also carries mandatory signed `executor_key_id` and `executor_key_thumbprint` (`sha256:<64 lowercase hex>`) claims; `simulation` Permits carry neither. There is no public proof-free execution-consumption method. The server-owned Demo verifier remains separate and accepts only `simulation`. Only an execution-boundary result of `VERIFIED` may call upstream. Failure outcomes include invalid signature/class, expiry, revocation, `WRONG_EXECUTOR`, action mismatch, and replay.

`permit_class` is selected by the server entry point and covered by the signature; request callers cannot set or override it. Old execution tokens without executor-key claims are invalid and must be re-authorized and reissued. No compatibility branch treats a missing class or missing workload-key binding as executable.

The lifecycle is `ISSUED → CONSUMED`, or `ISSUED → EXPIRED/REVOKED`.

Consumption is the commit point before the upstream side effect. An upstream failure or timeout leaves the Permit `CONSUMED`; it is never restored to `ISSUED`. Every retry requires a new authorization and a new Permit. There is no `unconsume` operation.

### A single-use Permit is not an exactly-once business side effect

Aegis guarantees that one Execution Permit can be successfully consumed **at most once**. This is execution-authorization replay protection, not a guarantee that an arbitrary upstream business operation executes exactly once. For example, an upstream payment may complete while its network response is lost, leaving the caller with a timeout. The original Permit remains `CONSUMED`; a retry requires a new authorization and new Permit and must rely on the payment, order, account-change, message-sending, or other upstream system's own idempotency key or deduplication mechanism. Aegis does not provide a business idempotency engine.

## The only MVP adapter: MCP

The focused MVP has exactly one production-shaped execution boundary: MCP tool calls.

```text
MCP client
  → Aegis MCP adapter/proxy
  → normalize tools/call
  → authorize exact action
  → issue signed permit
  → verify fresh Ed25519 workload proof
  → verify + consume permit immediately before forwarding
  → upstream MCP server
  → audit result metadata
```

Every verification failure must occur before the upstream `tools/call`. A `simulation` token is rejected before consumption and before any upstream call, even when every action field otherwise matches. This milestone does not implement HTTP, A2A, database, shell, or cloud-policy adapters.

Configure a server-owned control upstream to mount permit-gated `POST /mcp`. `--mcp-upstream` must exactly match one compiled-in profile's configured `upstream_url`; protocol setup/list compatibility methods use that target, while each `tools/call` is sent to the upstream owned by its resolved profile. This configuration binding does not prove endpoint or cloud-resource ownership; deployments must independently verify resource ownership, TLS, and upstream authentication. The `--allow-development-intake` flag below accepts body identity from loopback requests only and labels it `development_only`; it is not a production mode:

```bash
go run ./cmd/server --allow-development-intake \
  --workload-public-key docs-demo=ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ \
  --mcp-upstream http://127.0.0.1:3001/mcp
```

`tools/call` uses `Authorization: AegisPermit <permit_token>` and exactly one `X-Aegis-Execution-Proof` header, plus the existing action-binding headers. The proof is an Ed25519-signed compact token binding `permit_id`, `action_digest`, `POST`, `/mcp`, issuance time, and a nonce. It must be fresh (30-second window with 5-second clock skew), signed by the registered workload key selected by its signed `kid`, and match the executor key signed into the Permit. Missing/invalid proofs, wrong workloads, and reused nonces return `WRONG_EXECUTOR` without consuming the Permit. The Proxy strips both credentials and every `X-Aegis-*` header; the proof is never forwarded upstream.

For MCP `2026-07-28`, the Proxy also requires `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` to agree exactly with `params._meta` and the JSON-RPC body, then rebuilds forwarded routing headers from the validated body. Duplicate JSON keys and UTF-8-BOM-prefixed payloads are rejected before Permit verification. On `tools/call`, the only accepted `_meta` entry is the validated protocol version; unbound extension metadata is rejected. This is an intentionally narrow HTTP `POST` subset: only the exact `POST /mcp` route supports `server/discover`, `tools/list`, and permit-gated `tools/call`; full MCP conformance is not claimed. Final SEP-2640 `skills/list`/`skills/get` are outside this subset and fail closed, while `/sse` and other suffix paths never enter the MCP Proxy. Base64-wrapped `Mcp-Name` values are not decoded in this subset and fail closed, including when the decoded value would equal a supported ASCII tool name. MRTR `inputResponses`/`requestState` and schema-aware `Mcp-Param-*` validation are not yet part of `CanonicalAction`, so they also fail closed. The old `initialize` path remains compatibility-only when a modern version is not declared.

`server/discover` and `tools/list` responses are relayed from the configured upstream. Their descriptions, instructions, and other metadata remain untrusted upstream content: Aegis does not sanitize them or make them safe for insertion into a system prompt. The Host must isolate and review that content; any resulting real `tools/call` still has to pass the independent Policy, semantic profile, and Execution Permit boundary.

### Exactly two compiled-in semantic actions

A small immutable registry dispatches by MCP tool to exactly one compiled-in profile. Duplicate profile IDs, ambiguous tool ownership, unknown tools, and conflicting profile assertions fail closed. Callers cannot register code, load schemas, select a destination, or choose a more permissive profile. This is a fixed dispatcher, not a plugin system.

#### `payment.send/v1`

`configs/policy.json` is the server-owned mapping from MCP tool `payment.send` and its configured upstream URL to capability `payment_transfer`, resource `account-123`, operation `transfer`, profile `payment.send/v1`, and audience `mcp://local-payment-sandbox`. The client cannot select an upstream URL. Unknown MCP tools and conflicting capability/resource/operation/profile/audience assertions fail before Permit consumption and before upstream.

Payment arguments are exactly:

```json
{"amount_minor":100,"currency":"USD","recipient":"merchant-456"}
```

`amount_minor` is a positive JSON integer in the currency's smallest unit—USD cents and CNY fen in the sample configuration. No floating point, string conversion, or exchange-rate conversion occurs. Zero, negatives, `int64` overflow, missing/wrongly typed fields, duplicate keys, and unknown business fields are rejected. The configuration explicitly pairs each allowed currency with its per-transaction minor-unit maximum and separately allowlists recipients. Authorizer and MCP proxy use the same `payment.send/v1` parser; the proxy forwards its normalized three-field object, not the caller's original serialization.

#### `workspace.write/v1`

This profile proves reuse of the same security primitive for a semantically different action. It binds MCP tool `workspace.write` to capability `workspace_write`, logical resource `demo-workspace`, operation `write`, audience `mcp://local-workspace-sandbox`, and its own configured test upstream. Its exact arguments are:

```json
{"path":"reports/result.txt","content":"hello"}
```

`path` is a logical workspace-relative identifier, not an operating-system path. It uses `/` only, has a 1,024-byte sample limit, and rejects absolute paths, drive prefixes, backslashes, empty/`.`/`..`/`~` segments, leading/trailing slashes, and control characters; Aegis never repairs or filesystem-normalizes it. `content` must be a present JSON string and is limited to 4 KiB in the sample configuration. Only `path` and `content` are accepted. Both values enter normalized action semantics so either mutation invalidates the Permit, but raw content is never persisted in normal audit. This profile only forwards to a local/mock logical workspace upstream; Aegis performs no host filesystem write and provides no workspace sandbox.

Run the authorization examples from the repository root. Keep the server in terminal 1, then send both requests from terminal 2:

```bash
# Terminal 1
go run ./cmd/server --allow-development-intake \
  --workload-public-key docs-demo=ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ

# Terminal 2
curl -sS -H "Content-Type: application/json" --data-binary @docs/examples/payment-send-valid.json http://127.0.0.1:8080/api/actions/authorize
curl -sS -H "Content-Type: application/json" --data-binary @docs/examples/payment-send-over-limit.json http://127.0.0.1:8080/api/actions/authorize
curl -sS -H "Content-Type: application/json" --data-binary @docs/examples/workspace-write-valid.json http://127.0.0.1:8080/api/actions/authorize
```

The first response is `AUTHORIZED` and contains an `execution` Permit bound to `payment.send/v1` and the configured audience. The second is `DENIED`, has no Permit, and includes stable reason `PAYMENT_AMOUNT_EXCEEDS_LIMIT`. The third is `AUTHORIZED` with a Permit bound to `workspace.write/v1`; authorization alone does not write a file or call an upstream. These commands exercise local development intake and do not contact a payment provider or host filesystem.

## Policy, Risk, and obligations

Authorization stays deterministic. The currently executable flow has two outcomes:

- `AUTHORIZED`;
- `DENIED`.

The model can represent `REQUIRES_APPROVAL`, but this release has no supported approval-completion workflow and therefore does not claim it as an implemented capability. Deterministic Policy decides eligibility first; only a Policy grant reaches one of the two compiled-in semantic profiles. Both the grant and successful semantic resolution are required for Permit issuance. Risk scores and detection findings are written only under `advisory_signals`; they cannot change a deterministic result, issue a Permit, or select an executor. Isolation, read-only behavior, denied network egress, human approval, and enhanced audit become decision/Permit obligations only through deterministic Policy/configuration mappings, for example:

```json
{
  "isolation_required": true,
  "network_egress_denied": true,
  "read_only": true,
  "human_approval_required": false,
  "enhanced_audit_required": true
}
```

All five signed obligations are checked in the core verifier before proof-nonce or Permit consumption. M1 has no trusted runtime/resource enforcer, approval-completion chain or durable dispatch journal, so any required `isolation_required`, `network_egress_denied`, `read_only`, `human_approval_required` or `enhanced_audit_required` returns `UNSATISFIED_OBLIGATION`, leaves the Permit `ISSUED`, records `EXECUTION_OBLIGATION_UNSATISFIED` with `constraint_checks`, and calls no upstream. The shipped deny-egress payment/workspace grants therefore reject real MCP execution; they have not been weakened. An operation binding is not evidence of upstream enforcement. See the [M1 implementation and migration record](docs/m1-execution-admission.md). Legacy route labels remain obligation/profile hints.

## Trusted authorization intake modes

The standalone server selects exactly one identity-provenance mode:

1. **RejectAll** — secure default. Without an explicit intake configuration, HTTP authorization fails closed.
2. **LoopbackDevelopment** — enabled only by `--allow-development-intake`. It accepts body identity only from a loopback direct peer and records assurance `development_only`; startup requires exactly one separately configured workload public key, never a body field.
3. **TrustedProxy** — accepts identity headers from a separately authenticated reverse proxy only when the direct TCP peer in `request.RemoteAddr` belongs to one of the explicitly configured trusted CIDRs. It records `source=trusted_integration`, the configured provider ID, `assurance=authenticated_context`, and the server establishment time.

TrustedProxy uses only this explicit header contract: `X-Aegis-Authenticated-Principal`, `X-Aegis-Agent-Id`, `X-Aegis-Workload-Id`, `X-Aegis-Delegated-Scopes`, `X-Aegis-Delegation-Fingerprint`, `X-Aegis-Workload-Key-Id`, and `X-Aegis-Workload-Key-Thumbprint`. The last two form `WorkloadBinding` and must come from authenticated infrastructure context, never the authorization JSON body. The thumbprint is exactly `sha256:` plus 64 lowercase hexadecimal characters. Other identity labels remain exact 1–128 byte metadata identifiers; the delegation fingerprint remains an unprefixed 64-hex digest.

Trust is based exclusively on the direct peer. `X-Forwarded-For`, `Forwarded`, and `X-Real-IP` are never used to decide whether the sender is trusted. TrustedProxy then overwrites principal, Agent, workload, and delegated authority from the JSON proposal before Policy, Permit issuance, or audit. It never falls back to body identity after a trust error.

```bash
go run ./cmd/server \
  --trusted-proxy-cidr 127.0.0.1/32 \
  --trusted-proxy-provider-id local-auth-gateway \
  --workload-public-key finance-workload-key=<unpadded-base64url-Ed25519-public-key>
```

Repeat `--trusted-proxy-cidr` to allow additional IPv4 or IPv6 direct peers. CIDR and provider ID must be configured together. TrustedProxy configuration cannot coexist with `--allow-development-intake`; ambiguous or partial configuration stops server startup.

**Aegis authenticates neither users nor OAuth tokens itself.** Proof of possession demonstrates control of the registered private key for one fresh MCP request; it is not hardware attestation, a software-integrity measurement, or proof that undeclared downstream components are absent. A stolen or shared workload key defeats this binding.

Legacy flat request compatibility is **not execution-Permit eligible**. `Router.AuthorizeTrustedAction` requires structured principal, Agent/workload, delegated authority, tool, and action context even when an intake successfully authenticated and sealed the request. `allow_legacy_flat_requests` only preserves deprecated Policy/compatibility interpretation outside execution-Permit issuance; it never authorizes identity degradation into `user_id`, `agent_id`, or `token_scopes`, and it cannot produce an executable Permit.

## API direction

Focused APIs:

- `POST /api/actions/authorize` — authorize a normalized action; success returns a decision and a permit object containing `permit_id`, `permit_token`, and `expires_at`;
- `POST /api/permits/verify` — check Permit and action consistency without workload proof or consumption; a valid check returns `VALID_NOT_CONSUMED` with `verified=false`;
- `POST /api/permits/{id}/revoke` — revoke an unconsumed permit;
- `GET /api/permits` and `GET /api/permits/{id}` — return safe metadata only;
- `GET /api/decisions` and `GET /api/audits` — read authorization decisions and audit receipts.

The MCP adapter calls the verifier's single proof-bearing `VerifyExecutionAndConsume` entry point. Every HTTP authorization endpoint first crosses `TrustedAuthorizationIntake` and the Router still accepts execution authorization only through sealed `intake.Authorization`; it has no normal Permit-issuance method that accepts a naked `models.Request`. Process locality alone is not identity provenance. `POST /api/permits/verify` is diagnostic only: it never consumes a Permit and never returns execution-authoritative `VERIFIED`. Real execution consumption is reachable only through the proof-bearing execution entry used by `/mcp`. `/api/authorize`, `/api/runtime-events`, and `/api/route` remain temporarily as compatibility endpoints; compatibility authorization also crosses the selected intake.

## UI

Primary navigation is limited to `Decisions / Permits / Audit / Demo`:

- the home view shows `AUTHORIZED`, `DENIED`, `PERMIT VIOLATIONS`, and `REPLAY BLOCKS`;
- permit details show `permit_id`, `signing_key_id`, state, principal, Agent/workload, tool, capability, resource, operation, `action_digest`, policy version, issued/expires/consumed time, and verification result;
- the UI never shows `permit_token`, raw delegated credentials, secret values, or raw sensitive arguments;
- Inventory does not appear in normal navigation.

## Demo Lab

Four primary scenarios directly test the execution-permit invariant:

| Scenario | Expected result |
|---|---|
| Valid Permit | Exact action is `VERIFIED`, upstream is called, Permit becomes `CONSUMED` |
| Action Mutation / TOCTOU | A post-authorization argument change returns `PERMIT_ACTION_MISMATCH`; upstream is not called |
| Permit Replay | First use succeeds; second use returns `PERMIT_REPLAY` |
| Expired Permit | Execution after TTL returns `PERMIT_EXPIRED` |

Historical security scenarios may remain under `Advanced regression fixtures`. All Demo telemetry remains `simulated_demo`; it is not real Agent or production observation.

## Experimental Inventory

Discovery remains buildable but is frozen, disabled by default, and outside the primary product story. Related Server API/UI is exposed only after explicit enablement:

```bash
go run ./cmd/server --enable-experimental-inventory
```

The standalone read-only utility remains under `cmd/discover`. Process, OAuth, CI/CD, cloud, and central enterprise Agent Inventory expansion is not planned. Discovery evidence cannot prove runtime behavior.

## Quick start

Go 1.26 is required. Node.js is needed only when changing the TypeScript frontend.

```bash
go run ./cmd/server
```

Open [http://localhost:8080](http://localhost:8080). This runs server-owned Demos, while HTTP authorization fails closed in RejectAll mode. Local execution development additionally needs `--allow-development-intake` and exactly one `--workload-public-key <kid>=<unpadded-base64url-Ed25519-public-key>`; trusted-proxy mode may register multiple keys by repeating the latter flag. For MCP enforcement, also add `--mcp-upstream <absolute-http(s)-url>` and start with a harmless controlled upstream.

## Audit and evidence truth

Each action produces an explainable, redacted receipt read as `TRUST CONTEXT → POLICY ELIGIBILITY/OBLIGATIONS → SEMANTIC ACTION → PERMIT → VERIFICATION → EXECUTION`; execution states whether upstream was attempted and whether it completed, failed, or terminated. Risk/detection appear only under `ADVISORY SIGNALS`, not as authorization reasons. Audit still excludes tokens, raw arguments, and secrets.

Runtime sources remain distinct: `gateway_enforced`, `instrumented_adapter`, `agent_self_reported`, `os_sensor`, `network_sensor`, and `simulated_demo`. Runtime evidence is secondary. Uninstrumented coverage remains `UNKNOWN / not instrumented`: `UNKNOWN != SAFE` and `UNKNOWN != ZERO`.

## Documentation and verification

Chinese is the semantic working source; English changes in the same commit:

| Topic | 简体中文 | English |
|---|---|---|
| Product brief | [中文](docs/project-brief.zh-CN.md) | [English](docs/project-brief.md) |
| Manus and three security studies: redesign (M1 implemented; later stages pending) | [中文](docs/manus-redesign.zh-CN.md) | [English](docs/manus-redesign.md) |
| M1 admission and fixed routes: implementation, experiments and migration | [中文](docs/m1-execution-admission.zh-CN.md) | [English](docs/m1-execution-admission.md) |
| MCP execution-permit pilot | [中文](docs/experiments/enterprise-agent-pilot.zh-CN.md) | [English](docs/experiments/enterprise-agent-pilot.md) |
| Research and product decisions | [中文](docs/research-product-mapping-iteration.zh-CN.md) | [English](docs/research-product-mapping-iteration.md) |
| Contributing | [中文](CONTRIBUTING.zh-CN.md) | [English](CONTRIBUTING.md) |
| Security policy | [中文](SECURITY.zh-CN.md) | [English](SECURITY.md) |

```bash
npm install
npm run check:web
npm run build:web
go test ./...
go test -race ./...
go vet ./...
docker build .
```

The frontend source is `web/src/app.ts`; the generated `web/static/app.js` is committed too. If the environment lacks the race-detector toolchain, report that limitation exactly instead of claiming it passed.

## Security boundaries

- Aegis protects only actions that actually cross its verifier/MCP boundary; bypassed calls are not automatically discovered or blocked;
- an in-process PermitStore, default ephemeral key, and local audit are not production-grade high availability, tamper resistance, persistent key lifecycle, or cross-instance replay defense;
- MCP adapter identity, upstream transport, and deployment topology still need a separate threat model and security review;
- Aegis does not provide real isolation, EDR sensors, full IAM, SSO, RBAC, or multi-tenancy;
- do not use production credentials, customer data, or uncontrolled Internet targets before independent review and a formally authorized pilot.

## License

[MIT](LICENSE)

Migration: real execution Permits must be reissued as v2. v1 remains for core compatibility/simulation; the current MCP path rejects old v1 execution Permits.
