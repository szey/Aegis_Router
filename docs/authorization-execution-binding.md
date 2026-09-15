# Authorization and execution must refer to the same thing

English | [简体中文](authorization-execution-binding.zh-CN.md)

Review: 2026-09-15. Baseline: `6e4d77197668afe91ddcd53527c9ce4f97b17641`. This research-to-product review combines primary sources, current code, and synthetic experiments.

## 1. Conclusion and delivered scope

The user's observation that the checked object, scope, or identity can differ from what executes is a useful Aegis design principle. This review establishes neither a frequency/severity ranking nor the quotation's original attribution.

We found an actual gap: Go decoded the top-level JSON-RPC envelope with case-insensitive struct matching, while protocol requests exempt from Permits forwarded the original body. Aegis could classify a request as `tools/list` while an upstream reading exact member names saw `tools/call`. Duplicate-key detection cannot catch `method` and `METHOD`: they are distinct JSON keys.

This delivery fixes that entry point and adds negative integration tests and valid-call controls. Route configuration, object versions, revocation ordering, and environment leases remain explicitly proposed work below. Permit v1 and the shipped deny-egress policy remain unchanged; no sandbox was added.

## 2. Evidence and applicability

All sources were retrieved on 2026-09-15. Full text was accessible; the locator identifies reviewed sections. Provenance and local validation are separate.

| Evidence | Version, date, locator | Transferable mechanism and limit |
|---|---|---|
| JSON-RPC Working Group, `S1/V1` | [JSON-RPC 2.0](https://www.jsonrpc.org/specification), updated 2013-01-04, §§2, 4 | Member matching is case-sensitive. Envelope classification must respect this without rejecting equivalent encodings of valid JSON. |
| Go maintainers, `S1/V1` | [encoding/json.Unmarshal](https://pkg.go.dev/encoding/json#Unmarshal), rolling documentation; locally exercised Go `1.26.0 windows/amd64` | Struct decoding accepts case-insensitive field matches and ignores unknown fields by default. `DisallowUnknownFields` alone does not fix case aliases. Together with the preceding specification, this is one parser-differential evidence family; local reproduction is separately `V2`. |
| MITRE CWE, `S1/V1` | [CWE-367](https://cwe.mitre.org/data/definitions/367.html), page updated 2026-04-30, Description and Example 2 | A name may identify a different object between a check and an open. Future workspace executors need stable handles or atomic conditional writes; hashing a path is insufficient. Aegis currently opens no files, and no filesystem race was reproduced here. |
| IETF, `S1/V1` | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html), September 2019, §§2–3 | An audience may be abstract; the actual endpoint still needs independent correspondence validation. Aegis audience binding does not establish endpoint ownership. This informs binding design, not an OAuth implementation claim. |
| MCP maintainers, `S1/V1` | [Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices#token-passthrough), draft at retrieval, Token Passthrough | Wrong audiences and unchanged credential forwarding can misuse a proxy's trust relationships. Aegis strips inbound authorization/Cookie headers but does not thereby authenticate downstream identity. Draft guidance does not replace the pinned protocol baseline. |
| Google systems paper, `S1/V1` for its own system record | [Zanzibar](https://storage.googleapis.com/gweb-research2023-media/pubtools/5068.pdf), USENIX ATC 2019, §2.2, PDF pages 2–3 | The “new enemy” problem requires causal ordering of permission and content updates. Correlating authority revisions with resource versions is relevant; importing Zanzibar/Spanner or assuming its performance transfers to this prototype is unwarranted. |

## 3. Audit of the current execution chain

| Equality dimension | Existing control and code | Remaining boundary; evidence |
|---|---|---|
| Same RPC | `adapters/mcp/proxy.go`: canonical JSON, Header/body comparison, tool-parameter allowlist; this change adds exact envelope keys and rebuilds protocol bodies | Top-level case aliases previously bypassed the gate; local `V2`, §4. No full MCP conformance claim. |
| Same identity and executor | `intake/trusted_proxy.go` replaces proposal identity; `verifier/verifier.go:verifyExecutionProof/actionBindingOutcome` compares principal, Agent, workload, delegation, and key thumbprint | Possession does not prove software integrity. The trusted deployment still owns downstream connection identity; no IAM expansion. |
| Same business action | Two compiled profiles normalize arguments; `canonicalaction.Action` binds tool, capability, resource, operation, profile, audience, and argument digest | A workspace logical path lacks inode/object generation; a payment recipient lacks an upstream account-directory revision. External execution-contract gaps, `V1`. |
| Same service and configuration | `cmd/server/main.go` passes `r.SemanticRegistry()` into the proxy; M1 blocks all HTTP redirects | `mcp.New` accepts another registry; `Action` omits `UpstreamURL`/configuration digest. v1 cannot distinguish routes sharing the same audience solely through its digest. Shared default wiring is counterevidence against a claimed deployed remote exploit; code review only, `V1`. |
| Same authorization state | Short-lived signed Permit, registered-claims comparison, atomic in-memory consumption/revocation, expiry checked again at consumption | `policy_version` records issuance, not a live authority epoch. No run-level revocation or durable transaction. There is no current hot reload, and unknown Permits reject after restart; this is not evidence of restart replay. |
| Same execution environment | M1 rejects five obligation classes before consumption when no enforcer exists | No independent runtime, lease/generation, or environment attestation. Agent self-report cannot fill the gap. |
| Same business commit | Consumption precedes forwarding; upstream failure never restores a Permit | One local consumption does not prove exactly-once upstream business execution. Lost responses can hide a committed operation; intent, deduplication, and reconciliation are needed instead of automatic resend. |

Paths above are relative to `internal/`, except explicit `cmd/server/main.go`. Existing identity, argument, replay, obligation, and redirect tests remain regression controls.

## 4. Completed comparison and fix

**Hypothesis and advance acceptance:** exact top-level field matching, followed by forwarding only the classified envelope, must reject alias inputs with HTTP 400 before any upstream call. Valid protocol/Permit calls must continue to work. An invalid envelope must not consume a valid Permit or proof nonce.

**Environment:** local `httptest` receivers only; no external targets, real accounts, or production data. Attack fixtures retain the shipped deny-egress policy and share the same registry between authorizer and proxy, changing only the server-owned route to the local receiver. The receiver uses `map[string]json.RawMessage` to read exact `method` and separately counts requests and tool calls. Attack fixtures supply no Permit, proof, or identity.

| Experiment | Before: `6e4d771` | After |
|---|---|---|
| `method=tools/call` followed by an alias set to `tools/list`: `METHOD`, `MeThOd`, escaped uppercase initial; legacy/modern, 6 combinations | All HTTP 200; request=1 and tool call=1 per case | All HTTP 400; both counters=0 per case |
| Initial probe used alias `ping` | Three legacy cases reached the tool; three modern cases rejected because modern protocol excludes ping | Refined the comparison to `tools/list`, allowed by both versions. Modern ping rejection was not counted as exploit reproduction. |
| Other envelope aliases, reversed fields, unknown extensions: 7 cases | Not independently executed; no retrospective baseline claim | All HTTP 400 / RPC `-32600`, upstream=0 |
| Escaped exact lowercase key, legacy/modern: 2 cases | Not independently executed | Valid `tools/list` reaches upstream once with matching method/id |
| Valid Permit/proof with invalid envelope, followed by a valid call reusing that proof | Not independently executed | First request consumes neither; second consumes successfully with one total upstream call. Positive control explicitly uses an unconstrained synthetic policy. |

Production code changes only `internal/adapters/mcp/proxy.go`. The shared canonicalizer first rejects duplicate keys and lossy JSON. `parseRPCEnvelope` then limits exact top-level keys to `jsonrpc/id/method/params`. After classification, protocol forwarding serializes that same envelope. Tool calls retain existing semantic normalization and the core verifier; there is no additional digest or permit implementation.

**Compatibility:** previously ignored unknown top-level members and case aliases now reject. Top-level extensions require an explicit binding contract. Valid lowercase members, equivalent Unicode escapes, and both business profiles remain supported. Future parameter/schema extensions require separate review; this change does not migrate JSON libraries or token formats.

Repeat with `go test ./internal/adapters/mcp -run 'TestEnvelope|TestExactProtocolEnvelope|TestInvalidEnvelope' -count=1 -v`. Local Windows `go test ./...`, `go vet ./...`, frontend type checking/build, and project-contract validation exited 0. `go test -race ./...` exited 1 because cgo was disabled; `docker build .` exited 1 because the Linux engine named pipe was absent. Final Linux CI evidence belongs to the corresponding PR head. Local `V2` establishes these parsing/dispatch properties, not exploitation of a production upstream or real isolation.

## 5. Iteration order

| Priority / research_id | Disposition / delivery | Design, dependency, migration | Falsifiable acceptance |
|---|---|---|---|
| P0 `BIND-2026-09-15-01` | `implement` / `completed`, `S1/V2` | This envelope fix and regression suite; v1 unchanged | Negative zero-call cases, positive controls, nonce preservation in §4 |
| P1 `BIND-2026-09-15-02` | `experiment` / `planned`, `S1/V1` | Before M2, evaluate server-owned `PreparedExecution`: one immutable result carries action, normalized body, profile revision, route binding, credential binding. Construction must prevent mixing registries; distributed/hot-reload use requires explicit Permit v2 design | Same profile/audience with different route/config/credential mapping rejects before consumption; correct shared configuration succeeds. Legitimate endpoint migrations require reauthorization or a controlled mapping. |
| P1 `BIND-2026-09-15-03` | `experiment` / `planned`, `S1/V1` | Use a mock executor for the existing workspace profile to evaluate stable object ID, workspace namespace, expected generation, and atomic conditional writes at the final writer. Real filesystems later require safe handle/path resolution, not a new adapter | Replacing the named object or generation after authorization yields zero writes; correct object/version writes once. A second Router read alone does not pass. |
| P2 `BIND-2026-09-15-04` | `experiment` / `planned`, `S1/V1` | Continue M2 durability and M4 lifecycle design: current authority epoch, Permit state, nonce, and dispatch intent share one persistent admission transaction. Define the revocation linearization point | Revocation committed first blocks old epoch consumption/dispatch. Consumption first means in-flight work, not a promise of undo. Crashes/lost responses retain unknown without automatic resend. |
| P3 `BIND-2026-09-15-05` | `defer` / `planned`, `S1/V1` | Continue M3: trusted broker validates lease generation, environment policy digest, and executor identity bound to the action; depends on external enforcers | Old lease, wrong executor/scope, or absent controls reject. Actual isolation needs independent target-environment validation; mocks do not promote to V3. |

Aegis maintainers own these experiments. Review on implementation start or introduction of a new semantic profile, configuration hot reload, or external runtime. No full IAM, multitenancy platform, scheduler, or arbitrary tool-plugin system is introduced.

## 6. Target contract and stopping criteria

Candidate next-version flow:

```text
trusted identity + caller proposal
  → strict parse → server-owned PreparedExecution
  → policy decision over the same resolved action
  → versioned Permit binds action + route/profile/credential binding
    + stable resource/version + authority epoch + lease/obligations
  → transactional admission + durable intent
  → dispatch the prepared request through a bound executor
  → upstream conditional commit + receipt (or explicit unknown)
```

This is a design target, not the current ordering. Current policy eligibility precedes semantic resolution. Any reorder must prove semantic resolution cannot weaken an earlier denial and that relevant side-effect/destination/size fields come from the same resolved object.

`PreparedExecution` must be server-created and immutable; a client-supplied digest is not authority. Credential bindings retain only safe identifiers/fingerprints, never secrets. Route hashes do not replace TLS/endpoint authentication. Signed resource versions matter only when checked atomically by the final executor. Missing required v2 fields must reject; v1 cannot silently acquire v2 guarantees. Migration requires an explicit switch and reauthorization.

Promote each next-stage proposal only when its negative experiments pass and valid flows remain intact. Narrow or defer a control that depends on self-report, cannot constrain the actual side effect, or causes excessive false denials. More checked fields alone do not justify a larger security claim.
