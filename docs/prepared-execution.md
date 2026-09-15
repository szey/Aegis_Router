# PreparedExecution and authority epochs

English | [简体中文](prepared-execution.zh-CN.md)

Date: 2026-09-15. Baseline: `797b9c5c4e3b0d69a36e5d27619c1aace3d2da01`. Continues `BIND-2026-09-15-02` through `05` from the [binding review](authorization-execution-binding.md), reusing its primary sources and applicability analysis. External papers/specifications do not become local execution evidence.

## 1. Delivered scope

The real MCP path now uses immutable PreparedExecution, Permit v2 route/configuration binding, and process-local authority epochs/bulk revocation. Resource-version and lease contracts passed synthetic experiments at an independent final writer but **are not integrated with Server, Docker, E2B, or a real filesystem**. Full M2 durability and M3 external brokers remain incomplete; this delivery does not complete the entire redesign.

## 2. From preparation to dispatch

Private fields in `internal/semanticaction/prepared.go` retain the action, typed normalized arguments, and upstream address. Accessors copy argument buffers. Mutating input/returned values cannot change the snapshot. Preparation rejects changed trusted identity/scope, an inconsistent route, or differing action and dispatch arguments.

Each compiled profile snapshots `execution_binding` at construction: canonical JSON/SHA-256 over schema `aegis.prepared-execution/v2`, profile configuration, exact upstream URL, and `credential_mode=anonymous`. Later map mutations cannot change the constructed profile's controls or digest. Workspace size defaults are resolved before hashing; reordering other configuration lists can still require reauthorization, a conservative configuration-identity rule.

Authorization and execution independently prepare the request and prove matching bindings through the signed action digest. They do not retain one Go object across HTTP or persist raw arguments. CanonicalAction includes execution binding, and claims bind it explicitly. The proxy takes action, arguments, and route from its PreparedExecution; a different binding rejects before consumption with `WRONG_EXECUTION_BINDING`. Separate registries with identical contents remain interoperable; identical profile IDs/audiences cannot conceal changed configuration.

Digest canonicalization is separate from typed wire encoding: integer `100` may hash as `1e2`, but the upstream still receives typed JSON `100`. This preserves existing integer decoding and upstream contracts.

The current upstream identity is explicitly anonymous: inbound credentials are stripped; URL userinfo/query/fragment, CookieJar, and custom RoundTripper clients reject; a private transport without client certificates is used. Caller timeouts and mandatory redirect rejection remain. URL hashing does not establish endpoint ownership or replace TLS server identity and host/proxy-network trust. Credentialed upstreams need a future explicit credential binding, not a custom-transport escape from the anonymous contract.

Policy no longer relies solely on caller-declared bytes/side_effect. Compiled profiles derive PolicyFacts from normalized arguments: UTF-8 content bytes and logical_workspace_write for workspace; normalized argument bytes and financial_transaction for payments (money is not bytes). Initial eligibility denials remain final. Only eligible prepared actions receive a second deterministic Policy check with these facts, preserving a larger caller byte declaration conservatively. This second check cannot turn an initial denial into an allow.

## 3. Permit v2 migration

Real MCP authorization now emits header `v=2`, requiring nonempty signed `execution_binding` and positive `authority_epoch` together. The v1 codec remains available for legacy low-level verification/simulation, but the current MCP path always recomputes a nonempty binding, so old v1 execution Permits cannot match. Correctly signed tokens with incompatible version/binding fields also reject.

Clients must reauthorize and use the returned action digest for proof generation rather than reconstructing a v1 digest. No client-controlled binding/epoch input fields were added. Safe binding/epoch metadata appears in Permit responses, verification, envelopes, and receipts; raw routes, secrets, and arguments do not thereby enter normal audit. Workload proofs retain their existing Permit ID/action digest/method/path/time/nonce format.

Old Permits are not converted to v2, and no temporary allow path bypasses shipped policy. The two business-profile IDs retain their names: this upgrades execution Permits, not the number of semantic profiles.

## 4. Authority changes and consumption ordering

AuthorityKey identifies a principal/Agent/workload grant domain. The Router reads its epoch before policy evaluation and carries it into issuance. Registration checks under the Store lock that the epoch is unchanged and authority remains enabled. Revocation between policy evaluation and registration prevents the stale decision from registering a Permit.

Trusted Go integrations can call `Router.SetAuthorityEnabled(key, enabled)`. There is no unauthenticated HTTP equivalent. Every transition increments the epoch, including enabled→enabled policy refreshes. Disabling denies fresh authorization with `DENIED/AUTHORITY_REVOKED` and revokes outstanding execution Permits. Re-enabling requires fresh authorization and never restores old Permits. Simulation Permits are outside this authority-revocation scope.

Authority checks and consumption share the Store mutex. Revocation committed first prevents old consumption; consumption committed first remains CONSUMED/in flight, without promising to reverse an upstream effect. Audit updates occur after the control-state transition; audit failure does not roll it back. Nonce validation and this Store remain separate in-process components, not a durable nonce/Permit/dispatch-intent transaction.

**Persistence boundary:** epochs and disabled state live only in memory. Old Permits reject after restart because they are unregistered, but management state disabling an authority does not automatically restore. A trusted identity/policy system must reestablish decisions. Before durable storage exists, this API is not a persistent IAM ban. Signing-key, authority-version, and intent recovery remain M2 work.

## 5. Reproducible evidence

| Experiment | Control/acceptance and result | Scope |
|---|---|---|
| Changed upstream path or currency limit under the same audience/profile | Both baseline cases returned 200, one call, CONSUMED. Fixed: 403, zero calls, ISSUED | Real MCP tests with explicitly unconstrained synthetic grants; shipped deny-egress policy unchanged |
| Understated actual bytes/effects | Before the second Policy check on this branch, six UTF-8 bytes declared as zero and workspace/payment declared as none all yielded AUTHORIZED; fixed: all DENIED without a Permit | Same MCP authorization integration, exact max_bytes_exceeded/side_effect_not_granted rules |
| Snapshot mutation, inconsistent profile, v2 downgrade | Input/getter mutation cannot change snapshot; identity/resource/route/argument inconsistencies reject; correctly re-signed incompatible token versions reject | Core unit/contract tests |
| Authority disable/re-enable | Old tokens and new authorization while disabled reject; re-enabling accepts only a fresh epoch-3 Permit | In-process MCP integration |
| Authority changed after decision/before registration; concurrent consumption/revocation | Stale-epoch registration rejects; 64 races yield a single CONSUMED or REVOKED ordering; no consumption succeeds after completed revocation | Store atomicity, not cross-process proof |
| Audit failure after revocation | Replacing the temporary audit file with a directory makes persistence fail; authority stays disabled, Permit stays REVOKED, upstream calls remain zero | Local fault injection, no real audit data |
| Final resource/lease contract | Eight cases: same-name replacement, object generation, namespace, lease generation, executor, scope, environment policy, expiry. Action-only controls each write once; guarded cases each write zero times. Valid call and 32 competing writes yield one mutation | `experiments/executionbinding/contract_test.go`: independent signed controller grant and memory writer, not the real Permit codec/filesystem/runtime |

Run `go test ./internal/adapters/mcp ./internal/semanticaction ./internal/permit -count=1` and `go test ./experiments/executionbinding -count=1 -v`. These checks were executed and passed. Successful-forwarding fixtures now configure the correct route before issuance, removing split test configurations; production policy was not relaxed to repair tests.

Local full Go tests, vet, and project-contract validation passed. Full frontend, race, Docker, and Linux CI results are recorded in the corresponding PR. Windows cgo/Docker-daemon limitations must not be represented as passes.

## 6. External broker acceptance boundary

| research_id | Current disposition / status | Next work |
|---|---|---|
| `BIND-2026-09-15-02` | `implement` / `completed`, local `S1/V2` | Separately validate distributed and credentialed transport modes |
| `BIND-2026-09-15-04` | `implement` / `completed`, process-local epoch subset only, `S1/V2` | Durable Store, nonce, and dispatch intent remain planned; parent M2/M4 milestones are not complete |
| `BIND-2026-09-15-03` | `experiment` / `completed`, synthetic contract only, `V2` | Integrate server-obtained stable ID/version into the existing workspace profile and atomically validate at the final writer |
| `BIND-2026-09-15-05` | `experiment` / `completed`, synthetic contract only, `V2` | Choose an external runtime and trusted lease controller; actual enforcement remains `V1`, undeployed |

A local Docker reference integration is the initial candidate, not evidence of safety. It needs fixed controller identity, container/lease generation, workspace ownership, final conditional commit, a trusted credential mode, and failure recovery. Guest writes around the broker, a version read only at the Router, or an Agent's self-reported lease do not satisfy acceptance. MCP remains the sole execution adapter; no general IAM, scheduler, or in-house sandbox is introduced.
