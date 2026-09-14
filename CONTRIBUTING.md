# Contributing

English | [简体中文](CONTRIBUTING.zh-CN.md)

Thank you for improving **Aegis_Router — Execution Permits for AI Agent Actions**. The repository is [`szey/Aegis_Router`](https://github.com/szey/Aegis_Router).

## Preserve one security property

Every core change must strengthen this execution path:

```text
CanonicalAction → deterministic authorization → signed Permit
  → pre-execution verify + atomic consume → MCP upstream → Audit Receipt
```

> The action that was authorized must be exactly the action that executes.

Do not expand Aegis into a generic Agent permission platform, sandbox, EDR, IAM system, Shadow Agent manager, enterprise Inventory, or broad risk dashboard. MCP is the only adapter in this milestone; HTTP, A2A, database, and shell adapters are out of scope.

## Security invariants

Every pull request must preserve:

- principal, Agent, workload, delegation fingerprint, tool, capability, resource, operation, and security-relevant arguments all participate in the canonical-action binding;
- canonical JSON is deterministic: object key order cannot change the digest, duplicate keys are rejected, and array order is preserved;
- the digest uses SHA-256 and normal audit does not retain raw sensitive arguments;
- `permit_id` is correlation only while `permit_token` is the signed execution credential; an ID alone cannot authorize;
- HTTP authorization identity must come from `TrustedAuthorizationIntake`; an unconfigured intake fails closed, while local body intake is explicit and labeled `development_only`;
- the Permit header `kid` must resolve exactly through KeyProvider and match the signed `signing_key_id` claim;
- permits are short-lived, action-bound, and single-use by default; verification and consumption are atomic;
- any failed signature, issuer, time, Agent/workload, tool, resource, operation, or digest check prevents the upstream tool call;
- MCP `2026-07-28` version, `Mcp-Method`, and `Mcp-Name` must match the body; duplicate keys, arbitrary headers/session context, unbound tool `_meta`, MRTR, or `Mcp-Param-*` inputs not bound into the canonical action must fail closed or be stripped before upstream;
- exactly one of two concurrent consumption attempts succeeds and the other receives an explicit replay result;
- revoked and expired permits cannot execute;
- a Permit is consumed before upstream; failure/timeout never restores it, retry requires a fresh authorization, and `unconsume` must not be added;
- `permit_token`, signing private keys, raw bearer/delegated tokens, secret values, and raw sensitive arguments never enter logs, UI, or error messages;
- authorization stays deterministic; risk/detection enter only `advisory_signals` and cannot change status, issue a Permit, or create obligations;
- all five signed execution obligations are checked before nonce/Permit consumption; unsupported requirements leave the Permit `ISSUED` and upstream untouched; no boolean or Agent report may stand in for a trusted enforcer;
- runtime evidence retains source/trust, and `agent_self_reported` or `simulated_demo` never masquerades as independent observation;
- uninstrumented coverage remains `UNKNOWN / not instrumented`.

## Development workflow

1. State a falsifiable security property and whether a failure could call the upstream tool.
2. Add a safe synthetic fixture and negative test first.
3. Implement the smallest deterministic control.
4. Check replay concurrency, expiry/revocation, privacy, latency, and failure modes.
5. Synchronize APIs, capability boundaries, research register, and bilingual docs.
6. Report actual test results; do not turn local regression results into a production claim.

Minimum coverage includes trusted intake overriding forged HTTP identity, fail-closed missing intake, a valid Permit, `kid`, invalid signature, expiry, revocation, wrong agent/workload/tool/resource/operation, argument digest mismatch, sequential replay, concurrent replay, consumption retained after upstream failure/timeout, token-free audit, and zero MCP upstream calls after every verification failure.

## API, MCP, and compatibility

The primary authorization entry point is `POST /api/actions/authorize`. Permit lists and details return safe metadata only. Any response containing `permit_token` must avoid caches, logs, and UI exposure.

The MCP adapter must reuse the core canonicalizer and verifier before forwarding `tools/call`; do not create a second digest or permit implementation inside the adapter. The Runtime Event API is a secondary evidence path, not a substitute for pre-execution verification.

The current adapter claims only a focused HTTP `POST` subset, not full MCP conformance. Before adding MRTR or `Mcp-Param-*`, bind its semantics into the same action and add header/body parser-differential tests.

Legacy `/api/authorize`, `/api/route`, and `/api/runtime-events` may remain temporarily but must be labeled clearly. `SANDBOX/RESTRICT` in compatibility fields are obligation/profile hints and must not imply that Aegis supplies real isolation.

## Experimental Discovery

Discovery is frozen and disabled by default. Related Server API/UI is available only with `--enable-experimental-inventory`; `cmd/discover` remains a buildable experimental utility. Do not add process, OAuth, CI/CD, cloud, or central Inventory features.

## Verification

```bash
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
npm run check:web
npm run build:web
docker build .
```

If the race-detector toolchain is unavailable, report that limitation exactly instead of claiming an unrun check passed.

## Documentation and data

Chinese is the semantic working source and English must change in the same PR. Identifiers, endpoints, statuses, dates, links, and capability boundaries must match. Research-driven changes use `$research-to-product` and the [project contract](.codex/research-to-product.json); do not alter its publish, deploy, production-data, or company-device safety flags.

Never commit credentials, signing keys, Permit tokens, production audit, real company paths, employee activity, customer data, or raw company-device logs. Only redacted conclusions or synthetic fixtures may return from a company pilot to the public repository.
