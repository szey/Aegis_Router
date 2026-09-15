# Research, Product Mapping, and Iteration

English | [简体中文](research-product-mapping-iteration.zh-CN.md)

Latest product review: 2026-09-14 (weekly incremental review)

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

## 12. 2026-09-13 redesign based on Manus and three recommended articles

Full sources, publication/event dates, mechanisms, commercial dependencies, code evidence, diagrams, and acceptance criteria are in the [bilingual redesign proposal](manus-redesign.md). R1/R2/R3 were located in the latest three “Saturday Essential Read” recommendations and checked against their originals. This does not count three new incidents or rerun the reported attacks. Source IDs below refer to that proposal.

The following historical records were reviewed on 2026-09-13 at `V1`; the local code record has a later update in section 13. Separate source advice from project design: Manus offers product/engineering experience; R1 provides investigation observations; R2 recommends reduced attack surface, timely updates, least privilege, and bounded runtime; R3 emphasizes layered infrastructure and monitoring; F1 assigns filtering to host integration. These are our dispositions, not source validation of Aegis.

| research_id | Source/mechanism and relevance | Phase, dependencies, side effects | Single disposition and next step |
|---|---|---|---|
| `REDESIGN-2026-09-13-01` | M1/M3/M4 `S3`, M5 `S4`: long runs, subtasks, and recreation require task/instance distinction | Prevention/recovery; external controller and lifecycle complexity; historical vendor architecture is not the complete current topology | `docs_only`: RunContext, EnvironmentLease, generation, restoration boundaries |
| `REDESIGN-2026-09-13-02` | M2 `S3`: compacted/file-backed context cannot supply authorization facts | Prevention; Agent host dependency; files may be modified or contain untrusted instructions | `docs_only`: separate memory from authority; tool text cannot change registered semantics |
| `REDESIGN-2026-09-13-03` | R1 `S2`: shared services and tool-call spoofing expose surrounding trust boundaries | Prevention/detection; service ACLs and external collector; reduced cache efficiency and residual side channels | `docs_only`: task namespaces, trusted dispatch records, provenance-aware receipts; E04/E05 candidate acceptance |
| `REDESIGN-2026-09-13-04` | R2 `S2`, F1 `S1`: VM implementation and external networking have independent prerequisites | Containment/recovery; Linux/KVM, updates, mandatory network controls; operational cost and no guarantee against host escape | `defer`: pin and pilot a runtime after M1/M2 |
| `REDESIGN-2026-09-13-05` | R3 `S1`: misconfigured environments and biased reasoning; monitor results differ | Prevention; independent identity, policy, environment facts; conservative denial affects availability | `docs_only`: simulation beliefs cannot establish authority; no reasoning-based authorizer |
| `REDESIGN-2026-09-13-06` | Local code `S1`: some signed obligations lack unified fulfillment checks; default-client redirects need testing | Prevention; explicit obligation scope and fixed routes; may expose existing configuration conflicts | `experiment`: M1 and E02/E07, reproduce safely before changing and comparing |
| `REDESIGN-2026-09-13-07` | Local code `S1`: in-memory consumption/nonces, local audit, uncertain external commits | Response/recovery; durable transactions and key lifecycle; latency and failure-handling costs | `experiment`: M2/E08/E09; unknown Permits still deny, rather than asserting current restart accepts replay |
| `REDESIGN-2026-09-13-08` | Local scope contract `S1`: custom sandbox/generic adapters expand verification scope | Prevention; engineering and operations burden exceeds the current core objective | `reject`: no full IAM, EDR, Inventory, or general orchestration platform in this stage |

Implementation status at the 2026-09-13 research delivery: documentation only. For the subsequent M1 implementation, see section 13 below. Core capabilities, two profiles, MCP scope, and project contract remain unchanged. No new fixture, runtime backend, or production integration was added. Proposed order: M1 execution constraints → M2 durable state → M3 one external sandbox integration → M4 lifecycle and bounded delegation; these are not completed milestones.

Validation at the 2026-09-13 research stage: project-contract check passed; `go test ./...` exited 0 with an isolated temporary GOCACHE, and all packages passed. The first run also passed package tests but exited 1 because the default cache's `trim.txt` was not writable; changing only the cache location resolved it. E02–E12 had not run at that time. Race, vet, frontend and Docker builds were not run then because runtime code, dependencies and deployment configuration were unchanged.

## 13. 2026-09-14: M1 implementation and controlled validation

The updated `$research-to-product` skill guides the user's requested code changes and GitHub push. The original sources in section 12 remain, with code and synthetic experiments establishing project applicability. See the [M1 implementation record](m1-execution-admission.md) for changes, compatibility impact and validation conditions.

| research_id | Current evidence | Disposition | Delivery | Observation and scope |
|---|---|---|---|---|
| `REDESIGN-2026-09-13-06` | `S1/V2`, local code and E02/E07 comparisons | `implement` | `completed` | All five requirements reject before consumption, retaining nonce/Permit; fixed MCP routes block redirects; establishes local admission, not external isolation |
| `REDESIGN-2026-09-13-07` | `S1/V1` | `experiment` | `planned` | Durable single-node consumption and dispatch intent remain M2; local JSONL is not a completed durable transaction |
| `REDESIGN-2026-09-13-04` | `S2/S1/V1` | `defer` | `planned` | External runtime requires pinned versions, a real environment and independently verified controls; not deployed |

At baseline the core consumed all five required-obligation cases, a deny-egress MCP call reached upstream, and all ten redirect combinations reached the second receiver. These negative conditions now pass, while both profiles retain synthetic successful calls with no additional obligations and existing identity, argument, class and replay coverage. The shipped policy still requires denied egress and rejects real execution; configuration was not loosened to restore the old behavior.

`go test ./...`, `go vet ./...`, frontend type checking and build passed. Windows lacks a cgo toolchain, so local race tests could not run; the Docker Linux daemon was not running, so the local container build could not finish. The workflow for this GitHub commit is the authority for final Linux CI status. External sources are not promoted by these local tests, and no real sandbox, durable recovery or business exactly-once guarantee is claimed.

## 14. 2026-09-14 weekly incremental review

The review window is 2026-09-08 through 2026-09-14 and the product/code baseline is `02a9913`. This round covered official specifications and security advisories, incident-owner updates, maintainer commits/releases, professional reporting, security vendors, and public community reports. Secondary reporting was traced to Anthropic, OpenAI, AWS, OWASP, MCP maintainer, and ToolHive primary material. A vendor report gated behind a form is not represented as a full-text review.

| research_id | Source, mechanism, prerequisites, and limits | Source advice, conflicts/side effects, and project applicability | Single disposition and delivery |
|---|---|---|---|
| `REV-2026-09-14-001` | [MCP latest](https://modelcontextprotocol.io/specification/latest) remains `2026-07-28`; the [OWASP 2026 Top 10](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), [Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), NIST AI RMF 1.0, and AI 600-1 have no replacement release. [NIST](https://www.nist.gov/itl/ai-risk-management-framework) explicitly says RMF 1.0 is being revised · official full text `S1/V1` | An unpublished revision cannot replace implemented mappings. No new formal baseline in this review changes the execution-permit property | `docs_only` / `completed`: retain current versions and continue monitoring the formal NIST revision |
| `REV-2026-09-14-002` | ToolHive's 2026-09-08 advisory family includes [declared OIDC configuration delivering nil to middleware](https://github.com/stacklok/toolhive/security/advisories/GHSA-gc9p-rmpx-vv9j), [authorization bypass through a `/sse` path suffix](https://github.com/stacklok/toolhive/security/advisories/GHSA-h4mf-84xq-q2fc), [a UTF-8 BOM parser/filter differential](https://github.com/stacklok/toolhive/security/advisories/GHSA-9v4w-3mqh-6vmm), and [remote health redirect SSRF](https://github.com/stacklok/toolhive/security/advisories/GHSA-vc62-q48c-5cmw) · maintainer full text `S1/V1`; ToolHive had 2,163 stars on 2026-09-14 and v0.49.0 commit `e532cf07` was inspected | Root causes are parallel configuration carriers, a suffix-based route exemption, inconsistent parsers, and following target-controlled redirects. The sources recommend one authoritative configuration, exact routing, consistent parsing, and same-host redirect policy. Aegis has no OIDC/health pinger, but its parser and route boundary are directly relevant | `fixture` / `completed`: add BOM and `/sse`, `/x/sse`, `/mcp/sse` negative cases; all reject before upstream. Retain M1 redirect cases. This is `V2` evidence for Aegis's local boundary, not a replay of the ToolHive exploits |
| `REV-2026-09-14-003` | [MCP SEP-2640 Skills Extension](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2640) became Final on 2026-09-11; [ToolHive v0.49.0](https://github.com/stacklok/toolhive/releases/tag/v0.49.0) added Cedar mappings for `skills/list`/`skills/get` · maintainer full text `S1/V1` | Skills transport and lifecycle are outside Aegis's two semantic profiles and execution-permit boundary. Supporting them would expand protocol and supply-chain scope | `fixture` / `completed`: state that Skills is outside the focused subset and add fail-closed regressions for `skills/list`/`skills/get`; do not add a Skill/plugin system |
| `REV-2026-09-14-004` | OWASP Agent Control Standard v0.1.0 (tag v0.1.1) now has an AGT reference implementation at `7d2dd3c6`, but [conformance remains self-declared](https://github.com/GenAI-Security-Project/agent-control-standard/issues/19), [v0.2 negative vectors](https://github.com/GenAI-Security-Project/agent-control-standard/issues/53) remain deferred, and the [AGT dogfood report](https://github.com/GenAI-Security-Project/agent-control-standard/issues/92) remains backlogged · official repository `S1/V1`; 115 stars on 2026-09-14 | The reference code improves inspectability, but independently falsifiable conformance evidence is incomplete; self-declaration does not raise Aegis validation | `defer` / `planned`: continue making no ACS-compatibility claim until executable conformance and stable mappings exist |
| `REV-2026-09-14-005` | The [OWASP MCP Tool Poisoning](https://community.owasp.org/attacks/MCP_Tool_Poisoning) page frames untrusted tool results entering LLM context as a connect-time/runtime trust gap and recommends structured output, least privilege, execution-layer enforcement, and external confirmation for sensitive operations · official full text `S1/V1` | Structure validation can reduce some parser differences but cannot completely detect indirect injection in free text. Aegis can only require that any later real action passes the Permit gate | `docs_only` / `completed`: keep discover/list responses classified as untrusted Host input; do not add a prompt classifier, content-sanitization platform, or approval system |
| `REV-2026-09-14-006` | [Anthropic's review of four real third-party unauthorized-access incidents](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents) says their shared prerequisite was an evaluation environment mistakenly connected to the open Internet with product safeguards disabled; [OpenAI's 2026-09-11 update](https://openai.com/hugging-face-incident-and-misalignment/) says specific RubyGems malicious-package claims remain unverified · incident-owner full text `S1/V1` | Anthropic expanded transcript review and commissioned an independent METR investigation. Monitoring, sandboxing, and model alignment remain external to Aegis. OpenAI's unresolved claim is not counted as a new incident | `docs_only` / `completed`: retain the limits that simulated belief cannot establish environment authority and isolation is external; do not add sandbox/EDR/intent classification |
| `REV-2026-09-14-007` | [AWS 2026-105-AWS](https://aws.amazon.com/security/security-bulletins/2026-105-aws/) discloses that Security Agent plugin `<1.1.0` and MCP server `<0.2.0` did not verify ownership of a predictable S3 bucket, which could expose workspace archives · vendor security bulletin full text `S1/V1` | AWS recommends upgrading and verifying/pre-creating an account-owned bucket. Aegis signs the server-configured resource/audience binding but does not prove that the expected organization controls an endpoint or cloud resource | `docs_only` / `completed`: make external resource ownership, TLS, and authentication an explicit deployment check; do not add AWS/S3 integration |
| `REV-2026-09-14-008` | [Nightfall's 2026-09-09 early-access launch](https://www.nightfall.ai/news/nightfall-launches-mcp-gateway-to-govern-ai-agents-before-they-act) claims inline MCP enforcement and credential brokering; a Reco vendor release says it analyzed 500 public MCP servers, but [the full report is form-gated](https://www.globenewswire.com/news-release/2026/08/26/3351417/0/en/reco-finds-four-in-five-ai-tools-operate-without-it-oversight-in-state-of-agent-security-2026-report.html) · `S3/V0`; community posts continue to request [deterministic per-tool policy](https://www.reddit.com/r/MCPservers/comments/1wbjf8w/anyone_else_struggling_with_mcp_security_now_that/) and [integration tests proving Policy tests are not upstream-not-called tests](https://www.reddit.com/r/mcp/comments/1wbzkpb/how_do_you_test_that_an_ai_agents_permissions/) · `S4/V1` | Vendor claims have commercial incentives and no repeatable experiment here. Community advice repeats the existing deterministic Policy plus upstream-not-called fixtures and does not establish a need for dynamic LLM judges or Inventory | `docs_only` / `completed`: add no product capability; retain the Permit boundary, negative integration tests, and current non-goals |

The falsifiable fixture hypothesis for this round is: “If Aegis enforces authorization only on the exact `POST /mcp` route and rejects BOM in one canonical parser, then `/sse` suffix requests, BOM-prefixed `tools/call`, and unsupported Skills methods must each produce zero upstream calls.” Negative acceptance requires all three input families to reject without consuming a Permit or calling upstream; the comparison is the existing valid `tools/call`, which must continue to succeed. The fixtures use a synthetic local upstream and no real attack target or company data.

This round adds only regression fixtures and synchronized Chinese/English boundary documentation. It changes no runtime logic, dependency, semantic profile, or product scope. Nothing was automatically committed, pushed, deployed, or run on a company device.

Validation: the project-contract check, targeted new fixtures, `go test ./...`, `go vet ./...`, `npm run check:web`, and `npm run build:web -- --log-level=warning` all exited 0. `go test -race ./...` first failed because `CGO_ENABLED=0`; after explicitly setting it to 1, it still failed because `gcc` is absent from PATH, so race validation was not completed for this working tree. `docker build .` failed because the Docker Desktop Linux-engine named pipe was absent; it is not recorded as passed.

## 15. 2026-09-15 Authorization and actual execution binding

Baseline: `6e4d77197668afe91ddcd53527c9ce4f97b17641`. The user asked about checks referring to a different object, scope, or identity than execution. The [binding review](authorization-execution-binding.md) records primary sources, dates, locators, code mapping, counterevidence, synthetic experiments, and migration design. JSON-RPC and Go decoding form one parser-differential evidence family. CWE-367, RFC 8707, MCP draft guidance, and Zanzibar do not gain validation levels from local tests.

| research_id | Evidence / project observation | Single disposition / delivery |
|---|---|---|
| `BIND-2026-09-15-01` | `S1/V2`: no Permit/proof/identity, shipped policy and shared registry; six aliases separated Aegis protocol classification from mock upstream tool execution. Baseline tool calls=1 per case; fixed=0 | `implement` / `completed`: exact envelope keys, rebuilt protocol envelope, negative and positive/nonce-preservation controls |
| `BIND-2026-09-15-02` | `S1/V1`: v1 digest omits route/config; default shared registry limits applicability, with no demonstrated remote exploit | `experiment` / `planned`: evaluate `PreparedExecution` and server-owned route/profile/credential bindings before M2; explicit v2 migration |
| `BIND-2026-09-15-03` | `S1/V1`: logical path/recipient identity is not a stable object version; no actual filesystem writes exist | `experiment` / `planned`: generation-conditional writes at a mock final writer for the existing workspace profile |
| `BIND-2026-09-15-04` | `S1/V1`: issuance policy version is not current authority epoch; existing individual Permit revocation and restart rejection still hold | `experiment` / `planned`: integrate permission ordering into M2 transactions and M4 lifecycle; explicit revocation ordering and unknown outcomes |
| `BIND-2026-09-15-05` | `S1/V1`: obligation rejection exists; independent lease/generation and external enforcement do not | `defer` / `planned`: continue M3 broker/environment contracts without treating self-report or mocks as real isolation |

This delivery changes one production Go file, preserving tokens, default policy, profile count, and deployment boundaries. New regressions and research documentation are synchronized in Chinese/English. Local Windows full Go tests, vet, frontend checks/build, and contract validation exited 0. Local race could not run without cgo, and Docker failed without the Linux daemon; final Linux CI evidence belongs to the corresponding PR head. The user's prior GitHub-push authorization remains applicable; no deployment, production access, or contract safety-flag change occurred.
