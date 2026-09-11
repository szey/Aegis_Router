# Research, Product Mapping, and Iteration

English | [简体中文](research-product-mapping-iteration.zh-CN.md)

Latest product review: 2026-09-07

This is Aegis_Router's unified research register. Standards, incidents, media/security-company guidance, community pain points, open-source lessons, dispositions, and product mappings all live here. Chinese is the semantic working source and English must change in the same commit.

The generic method comes from the `$research-to-product` Skill; the [project contract](../.codex/research-to-product.json) defines this project's scope and safety boundaries. A source recommendation is evidence input, not an executable instruction or proof that an Aegis control works.

## 1. Current product thesis

> **The action that was authorized must be exactly the action that executes.**

Aegis_Router is narrowed to one framework-agnostic execution-permit/reference-monitor primitive. It first validates the structured request and evaluates deterministic Policy eligibility; after a Policy grant, the server-owned semantic profile resolves the exact `CanonicalAction`. Only when both succeed does Aegis issue a short-lived, signed, action-bound, single-use-by-default Permit and verify and consume it before the MCP upstream side effect. Policy authorization alone is insufficient to produce a Permit, and semantic resolution cannot override a Policy denial.

This iteration explicitly does not compete on generic Agent permissions, approvals, sandboxing, workspace isolation, enterprise Inventory, Shadow Agent discovery, IAM, EDR-style observation, or broad risk dashboards. Aegis is not a general AI Agent security platform.

## 2. Evidence model and disposition gate

### Source classes

| Class | Source | Use |
|---|---|---|
| `S1` | Specifications, maintainers, advisories, and direct incident owners | Still verify version, prerequisites, and project relevance |
| `S2` | Independent/academic research with reproduction or primary citations | Check environment, sample, and limitations |
| `S3` | Security companies, vendors, or product teams | Preserve commercial dependencies and alternatives |
| `S4` | Users, communities, blogs, or product-owner feedback | Find problems or set direction; cannot alone prove a control works |

### Validation states

| State | Meaning |
|---|---|
| `V0 collected` | Collected but not technically reviewed |
| `V1 plausible` | Mechanism is plausible and major prerequisites/side effects are known |
| `V2 reproduced` | Reproduced in this project with a safe synthetic fixture and automated tests |
| `V3 pilot_verified` | Verified at a newly authorized real execution-boundary pilot with redacted evidence |

### Product disposition

Each proposal receives exactly one of `reject / defer / docs_only / fixture / experiment / implement`, with a reason. An `S4` product decision may change scope; “implemented” still requires `V2`. Exploratory company-endpoint output is not `V3`.

## 3. Focused product decision — 2026-09-05

| `research_id` | Falsifiable problem | Disposition | Implementation and boundary |
|---|---|---|---|
| `FOCUS-001` | Can an Agent replace amount, resource, tool, or operation after policy evaluation? | `implement` | Authorizer and execution boundary share a canonicalizer and SHA-256 action digest; every bound-field change blocks |
| `FOCUS-002` | Can an in-memory `permit_id` be mistaken for authorization? | `implement` | `permit_id` is correlation only; use an Ed25519-signed, short-lived, action-bound `permit_token` that never enters audit/UI |
| `FOCUS-003` | Can one Permit execute twice, sequentially or concurrently? | `implement` | A concurrency-safe Store atomically verifies and consumes; exactly one concurrent request succeeds |
| `FOCUS-004` | Can an after-the-fact RuntimeEvent block the side effect? | `implement` | Enforcement moves before MCP forwarding; the Event API remains secondary evidence |
| `FOCUS-005` | Would multiple MVP adapters produce multiple inconsistent security semantics? | `implement` | Implement MCP only; other adapters are `reject` for this milestone |
| `FOCUS-006` | Should Aegis itself provide isolation? | `reject` | No sandbox backend; express only an `isolation_required` obligation |
| `FOCUS-007` | Should Discovery/Shadow Agent capability continue expanding? | `reject` (expansion) / `docs_only` (compatibility) | Freeze code, disable by default, hide from normal UI; retain only `--enable-experimental-inventory` and `cmd/discover` |
| `FOCUS-008` | Should numeric Risk define the product or change authorization? | `implement` | Risk/detection enter only `advisory_signals`; they no longer decide status, Permit, obligations, or executor |
| `FOCUS-009` | Can an in-process naked `models.Request` bypass the identity-provenance boundary? | `implement` | Remove normal `AuthorizeAction/Authorize/Process` entry points; Permit issuance requires sealed `intake.Authorization`, while Demo uses only an explicit synthetic entry point |
| `FOCUS-010` | Could a single-use Permit be misrepresented as exactly-once business execution? | `docs_only` | State that only Permit consumption is at-most-once; failure/timeout never restores it, and business retries rely on upstream idempotency |

These product-owner decisions are `S4`. No external sources were added; this pass uses architectural negative tests for the trusted-intake, deterministic-policy, single-consumption, and upstream-not-called boundaries. The corresponding implementation reaches `V2 reproduced` only after canonicalization, signature, expiry/revocation/replay, privacy, and MCP upstream-not-called tests pass.

### Weekly incremental review — 2026-09-07

The review window was 2026-09-05 through 2026-09-07. The latest formal MCP protocol remains `2026-07-28`; the OWASP GenAI LLM Top 10 and Agentic Applications Top 10 baselines remain the 2026 editions; and NIST has not replaced the AI RMF/AI 600-1 baselines listed here. No new distinct incident appeared in the primary incident-owner sources. Media coverage dated 2026-09-01 still traces to the already registered OpenAI, UK AISI, and independent incident accounts, so it was de-duplicated rather than assigned a new incident ID.

| `research_id` | Evidence, mechanism, and state | Source guidance, prerequisites, and side effects | Product disposition |
|---|---|---|---|
| `REV-2026-09-07-001` | [MCP latest](https://modelcontextprotocol.io/specification/latest) still resolves to `2026-07-28`; [Go SDK `a5026ea`](https://github.com/modelcontextprotocol/go-sdk/commit/a5026ea) fixed comparison after decoding the `=?base64?...?=` form of `Mcp-Name` on 2026-09-06 · `S1/V1`. The mechanism affects names/URIs that are not header-safe. Aegis's two compiled-in tool names are ASCII, and its current raw exact-match rejects wrapped values | The maintainer implementation decodes before body comparison and rejects invalid Base64. Supporting it adds another input-decoding path but does not strengthen the Permit security property | `docs_only`: state that Base64-wrapped `Mcp-Name` is outside the focused subset and remains fail closed; do not implement until a supported non-header-safe tool or an explicit conformance target requires it |
| `REV-2026-09-07-002` | [MCP issue #3213](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3213) provides an independent PoC combining `server/discover.instructions` with public caching · `S2/V1`. Server-owned instructions can enter Agent context; Aegis currently forwards discover responses and does not make their text trusted or sanitize it | The source recommends isolating the field as untrusted content, limiting length, avoiding direct system-prompt insertion, and optionally applying detection. A prompt classifier can have false positives/negatives and cannot replace the execution boundary | `docs_only`: explicitly classify discover metadata/instructions as untrusted upstream content; the Host must isolate it, and every real `tools/call` still requires an Execution Permit. Do not add a prompt classifier, caching platform, or generic content filter |
| `REV-2026-09-07-003` | The [OWASP Agent Control Standard v0.1 public preview](https://genai.owasp.org/resource/agent-control-standard-acs/) proposes cross-framework runtime hooks; its [2026-09-06 conformance update](https://github.com/GenAI-Security-Project/agent-control-standard/commit/c1f51df) says v0.1 profile claims are implementer self-declarations with no conformance suite, registry, or arbiter · `S1/V1` | The source tells buyers to verify deployment claims themselves. Adopting ACS would add wire/schema, observability, and governance scope while its conformance claim is not independently verifiable | `defer`: track a stable release and executable conformance; do not call Aegis ACS-compatible or expand it into a Guardian/observability/AgBOM platform |
| `REV-2026-09-07-004` | The [ACLE-MCP preprint](https://arxiv.org/abs/2609.02690) distinguishes OAuth/signed identity binding from execution-time workload appraisal and reports workload substitution, stale appraisal, and undeclared-downstream risks · `S2/V1`. Aegis's `workload_id` is a trusted-intake claim, not live remote-workload proof | The paper proposes sender-constrained leases, point-of-execution consumption, and provider-side attestation. It requires OIDC, trusted appraisal/vTPM, and a resource-side gate; its experiment reports a 25.7% increase in pooled p95 latency for normal allowed calls | `docs_only`: add the limitation that workload binding is not runtime attestation; do not introduce KMS, OIDC, TPM, or remote attestation |
| `REV-2026-09-07-005` | Recent community reports describe [static scope surviving tool-description drift](https://www.reddit.com/r/Information_Security/comments/1w852eb/the_agent_just_needed_read_access_until_one_tool/) and [shared service accounts providing attribution without necessarily providing downstream authorization](https://www.reddit.com/r/mcp/comments/1w4oiiv/how_is_anyone_actually_running_mcp_in_an/) · `S4/V1`. Both are self-reports without independently verifiable deployment records | Suggested responses include reviewing tool-metadata/scope changes, retaining provenance, and using per-user delegation or narrower credentials. Those add IAM, secret lifecycle, approval, and operational cost | `docs_only`: reinforce the untrusted discover/tool-metadata boundary and trusted-intake provenance; do not build IAM, SSO, RBAC, supply-chain scanning, or session-intent tracing from these reports |
| `REV-2026-09-07-006` | ToolHive maintainers addressed authorization-configuration drift, replay/registration boundaries, and Referrer leakage in [canonical inbound grants](https://github.com/stacklok/toolhive/commit/6b40bf3) and [OAuth callback Referer](https://github.com/stacklok/toolhive/commit/7b491f7) · `S1/V1`. Aegis has no OAuth callback, DCR, token exchange, or SPIFFE grant surface | The fixes depend on a full OAuth/IAM and multi-replica storage model. Porting them would broaden the product without a corresponding reachable path | `reject`: do not port them or present unrelated fixes as Aegis capabilities; retain only the existing principles that configuration conflicts fail closed and credentials stay out of audit |

No item reached `V2 reproduced` in this review, so there is no code, fixture, or behavior change. The new conclusions only correct documented boundaries. Any future implementation of a deferred control still requires a safe synthetic fixture, falsifiable hypothesis, and project-local regression first.

## 4. How prior company-endpoint feedback is retained

An exploratory 2026-09-02 trial found stale Server discovery snapshots, permission failures during broad scans, marketplace/cache noise, an unclear approved-list entry point, and confusion between “approved Agent” and “all behavior approved.” The feedback drove local Discovery fixes and the structured AuthorizationEnvelope.

The current disposition is:

- retain the redacted facts and existing regressions so the failures do not recur;
- stop treating Inventory/Shadow discovery as the product center and add no new sensors;
- subsume “an approved Agent still needs per-action authorization” into the more exact action-bound Permit property;
- do not promote the prior trial to `V3`, because it did not validate a real MCP execution boundary, signed Permit, or replay defense.

The repository retains no raw company logs, usernames, hostnames, or absolute paths.

## 5. Standards and framework mapping

| Baseline | Relevance to the focused MVP | Decision |
|---|---|---|
| [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | Excessive Agency, tool I/O, sensitive information, and supply chain provide context for action binding and minimal audit | Implement only execution-permit controls; record other items as external responsibility or non-goal |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | Tool Misuse, Identity/Privilege Abuse, and Goal Hijack support “a plan is not authorization” | Use structured identity + canonical action + Permit; do not expand into a complete Agent security platform |
| [OWASP Agent Control Standard v0.1](https://genai.owasp.org/resource/agent-control-standard-acs/) | Runtime hooks and cross-framework control points are adjacent to Aegis's execution boundary, but v0.1 conformance is still implementer self-declaration | `defer` integration; do not claim ACS compatibility or expand into Guardian, observability, or AgBOM scope |
| [OWASP GenAI Security Industry Framework Crosswalk](https://genai-security-project.github.io/crosswalk/) | Useful for navigating adjacent controls, but the site says every mapping remains `unreviewed` until a named reviewer signs it | Use as navigation only; do not claim compliance, coverage, or a higher validation state from it |
| [NIST AI RMF 1.0 / NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) | Requires clear governance, measurement, limitations, and residual-risk communication | Maintain policy version, tests, receipts, evidence classes, and non-goals; do not claim framework compliance |
| [MITRE ATLAS](https://atlas.mitre.org/) | Supplies taxonomy leads for threats and fixtures | `docs_only/fixture`; not a feature checklist |
| [MCP Security](https://github.com/modelcontextprotocol/modelcontextprotocol/security) | User consent, least privilege, tool boundaries, and isolation responsibility | MCP is the only adapter; Aegis handles action authorization/Permit, not isolation or OAuth |
| [MCP Specification 2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/) | A real proxy must explicitly handle protocol version, header/body consistency, and authorization boundaries | Validate `Mcp-Method`/`Mcp-Name`, reject unbound metadata, strip arbitrary headers/session context, rebuild minimal forwarded headers, and fail closed on unsupported MRTR/`Mcp-Param-*`; do not claim complete MCP/OAuth support |

### OWASP risk families and product boundary

| Risk family | What Aegis directly does | What it does not do |
|---|---|---|
| Excessive Agency / Tool Misuse | Exact-action authorization, short-lived signed Permit, pre-execution verify+consume | Generic Agent permission UI or permanent role management |
| Identity & Privilege Abuse | Bind principal, Agent/workload, and delegation fingerprint | Enterprise IAM, SSO, RBAC, or credential issuance |
| Goal Hijack / Prompt Injection | Do not treat natural-language intent as authorization; argument mutation changes the digest | Prompt classifier or “safe prompt” guarantee |
| Sensitive Disclosure / Improper Output | Minimize audit, bind resource/operation/arguments, express egress/read-only obligations | DLP, content review, network sensor, or output sanitizer |
| Supply Chain | Permit may bind tool identity/schema context | SBOM/AIBOM, registry, or signature supply-chain platform |
| RCE / Unexpected Code Execution | Do not forward an MCP tool call without exact authorization | Endpoint sandbox, EDR, or process control |
| Memory, A2A, Cascading Failures | Retain only future fixtures/research records | No Memory/A2A/session-risk platform in this milestone |

## 6. Incidents and mitigation guidance

| ID | Source and mechanism | Source guidance | Aegis disposition |
|---|---|---|---|
| `INC-2026-001` | [OpenAI 2026-08-26 incident account](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) · `S1/V1`; unapproved coordination/Internet behavior occurred in a specialized cybersecurity evaluation with reduced safeguards and monitoring gaps | Stronger isolation, restricted Internet/weight access, real-time monitoring, incident response, and lifecycle gates | `docs_only`: supports the need for pre-execution Permits, but does not justify expanding isolation, EDR, Kill Switch, or inter-Agent platform scope; an external executor supplies isolation |
| `INC-2026-002` | [UK AISI incident report](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing) · `S1/V1`; unauthorized actions toward real targets occurred in open-Internet evaluation runs | Limit real Internet scope, prohibit real targets, retain human review, supervise in real time, and provide safe exit | `docs_only`: pilots prohibit real targets; if a tool action needs approval, express a Permit obligation rather than implement a generic approval platform |

Both illustrate that after-the-fact detection is not pre-execution control. Their specialized evaluation conditions cannot establish incidence in ordinary enterprise deployment or prove that Aegis works.

## 7. Community pain points, guidance, and product response

| Pain point/guidance | Evidence | Current disposition |
|---|---|---|
| Cannot answer “who authorized this action?” | [MCP identity/delegation discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2404), [enterprise identity context](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2761) · `S4/V1` | `implement`: bind principal, Agent/workload, delegation fingerprint, policy version, and receipt; do not build IAM |
| A “read-only Agent” can still write through a tool | [tool permission/audit discussion](https://www.reddit.com/r/MCPservers/comments/1ska249/how_are_you_handling_permissions_audit_logs_for/) · `S4/V1` | `implement`: operation + security arguments enter the digest and `read_only` is signed; `docs_only`: an arbitrary upstream tool's internal behavior still requires a trusted external control |
| Arguments can change after policy (TOCTOU) | Product-owner failure hypothesis `S4` | `implement`: authorizer/executor share canonicalizer; mismatch blocks and never calls upstream |
| A Permit can be copied or replayed | Product-owner failure hypothesis `S4` | `implement`: short TTL, single-use Store, revocation, and concurrent replay tests |
| Many logs do not prove the execution credential | [MCP audit discussion](https://www.reddit.com/r/mcp/comments/1t0fd3i/what_are_people_using_to_audit_agentmcp/) · `S4/V1` | `implement`: receipt centered on action digest, Permit state, and verification outcome; never log token |
| Poisoned content induces a tool call | [community discussion](https://www.reddit.com/r/MSSP/comments/1vxskpv/mcp_server_security_before_this_touches_prod/) · `S4/V2` (older synthetic fixture) | `fixture`: retain as advanced regression; Aegis does not build a Prompt classifier |
| Safe individual tools can combine into exfiltration | [community discussion](https://www.reddit.com/r/mcp/comments/1s086kb/how_are_you_controlling_mcp_agents_in_practice/) · `S4/V2` (older fixture) | `defer`: do not expand into a session-risk platform; exact per-action Permits and external obligations can narrow each call |
| Isolation can break networking/performance | [ToolHive #5775](https://github.com/stacklok/toolhive/issues/5775), [#5847](https://github.com/stacklok/toolhive/issues/5847) · `S3/V1` | `reject` sandbox implementation; measure only Aegis verifier/proxy overhead, with isolation owned by an external executor |
| Unregistered Agents are hard to govern | [Microsoft Agent Discovery](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-discovery), [community discussion](https://www.reddit.com/r/AskNetsec/comments/1v61h8n/how_do_you_keep_track_of_what_your_ai_agents_can/) · `S1/S4` | `reject` feature expansion; freeze existing Discovery as opt-in experiment that cannot affect a Permit |

## 8. Open-source lessons and competitive boundary

| Project | Useful lesson | Explicit boundary |
|---|---|---|
| [Stacklok ToolHive](https://github.com/stacklok/toolhive) | Real MCP Gateway/Runtime deployment boundaries | Do not copy Registry, Kubernetes, OIDC/OAuth, or sandbox platform; Aegis only supplies Permits |
| [Docker MCP Gateway](https://github.com/docker/mcp-gateway) | Makes proxy, secret, path, and network trust boundaries explicit | Aegis claims no container isolation and may compose with an external executor |
| [Invariant Gateway](https://github.com/invariantlabs-ai/invariant-gateway) / [Guardrails](https://github.com/invariantlabs-ai/invariant) | Interface lessons from transparent proxy and cross-tool rules | Focus on single-action cryptographic binding, not a general guardrail platform |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | Deterministic, testable policy interfaces | OPA migration is `reject` for this milestone; preserve future replaceability |
| [OpenFGA](https://github.com/openfga/openfga) | Principal-resource relationship modeling | No relationship graph, enterprise authorization service, or RBAC UI |
| [OpenTelemetry Go](https://github.com/open-telemetry/opentelemetry-go) | Trace correlation | `defer`; keep receipts minimal, local, and redacted first |

Aegis differs through a small, independently testable invariant, not breadth: **a signed execution permit cryptographically binds the authorized action to the action about to execute before the real side effect, and is single-use by default.**

## 9. Product priorities

### P0 — Prove the execution-permit boundary

1. CanonicalAction and deterministic SHA-256 digest;
2. Ed25519-signed compact Permit;
3. expiry, revocation, wrong binding, action mismatch, and single-use replay defense;
4. exactly one concurrent replay attempt succeeds;
5. Audit Receipt excludes Permit token, raw delegation, and sensitive arguments;
6. four focused Demos and the full P0 negative-test set.

### P1 — One real MCP control point

1. MCP `tools/call` normalization;
2. verify+consume before upstream forwarding;
3. zero upstream calls after any verification failure;
4. a controlled local upstream and redacted result metadata;
5. a small synthetic pilot on an authorized company device.

### Frozen / rejected

- Discovery/Registry receives build/security maintenance only, with no new features;
- sandbox, OS/network sensors, enterprise IAM/SSO/RBAC/multi-tenancy, Shadow Agent expansion, ML/LLM risk, and A2A/HTTP/database adapters are outside the focused MVP;
- Runtime evidence remains, but never replaces the pre-execution verifier.

## 10. Research-to-release loop

```text
collect evidence → trace primary source → choose disposition
  → define falsifiable Permit property → build safe fixture
  → implement smallest deterministic control → test upstream-not-called
  → verify privacy/race/vet/build → sync zh-CN + English
  → publish or pilot only with separate explicit authorization
```

The project contract continues to prohibit automatic publication, deployment, and production data. Every company-device action requires explicit authorization. A capability reaches `V2 reproduced` only with code, automated tests, a repeatable fixture, privacy checks, and boundary documentation. Only a formal controlled MCP pilot may reach `V3`.

## 11. Continuous review

- Collect new standards, incidents, media/security-company advice, and community feedback as untrusted evidence, then trace primary sources.
- Choose an explicit disposition each round; popularity does not justify expanding product scope.
- First ask whether evidence changes the execution-permit security property. If it does not, make no product change.
- Never automatically deploy, publish, collect company logs, or use real external targets.
- Chinese is the semantic source and English changes in the same batch.
- Before every version tag and formal MCP pilot, recheck signature, canonicalization, replay, privacy, race, and upstream-not-called properties.
