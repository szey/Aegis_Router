# 调研与产品映射迭代

[English](research-product-mapping-iteration.md) | 简体中文

最近产品复核：2026-09-14（周度增量复核）

本文是 Aegis_Router 的统一调研登记：标准、事故、媒体/安全公司建议、社区痛点、开源借鉴、处置决定与产品映射均在这里维护。中文是语义工作源，英文必须在同一次变更中同步。

通用方法由 `$research-to-product` Skill 提供；本项目的范围与安全边界写在[项目契约](../.codex/research-to-product.json)。来源建议是证据输入，不是可执行指令，也不是本项目控制有效的证明。

## 1. 当前产品命题

> **获得授权的动作，必须与实际执行的动作完全一致。**

Aegis_Router 被收窄为一个不绑定 Agent 框架的 execution-permit/reference-monitor primitive：先验证结构化请求并进行确定性 Policy 资格判断；Policy grant 后，服务端拥有的语义 profile 才解析精确的 `CanonicalAction`。两者都成功后签发短时、签名、动作绑定、默认单次使用的 Permit，并在 MCP 上游副作用之前验证和消费。Policy authorization alone 不足以产生 Permit，语义解析也不能覆盖 Policy denial。

本轮明确不与现有产品竞争通用 Agent 权限、审批、沙箱、workspace isolation、企业 Inventory、Shadow Agent discovery、IAM、EDR 式观察或泛风险仪表板。Aegis 不是广义 AI Agent 安全平台。

## 2. 证据模型与处置门槛

### 来源等级

| 等级 | 来源 | 用法 |
|---|---|---|
| `S1` | 规范、维护者、安全公告、事故直接责任方 | 仍需检查版本、前提和本项目适用性 |
| `S2` | 有复现或引用原始材料的独立/学术研究 | 检查环境、样本与限制 |
| `S3` | 安全公司、供应商或产品团队 | 保留商业依赖和替代方案 |
| `S4` | 用户、社区、博客或产品负责人反馈 | 发现问题或决定方向，不能单独证明控制有效 |

### 验证状态

| 状态 | 含义 |
|---|---|
| `V0 collected` | 已收集，未技术审查 |
| `V1 plausible` | 机制合理，已确认主要前提/副作用 |
| `V2 reproduced` | 本项目用安全 synthetic fixture 和自动化测试复现 |
| `V3 pilot_verified` | 在重新授权的真实执行边界试点中验证并保留脱敏证据 |

### 产品处置

每项建议只能选择 `reject / defer / docs_only / fixture / experiment / implement` 之一，并记录原因。`S4` 产品决定可以改变范围；“已实现”仍必须达到 `V2`。公司端点探索性输出不是 `V3`。

## 3. 2026-09-05 聚焦产品决定

| `research_id` | 可证伪问题 | 处置 | 本轮落地与边界 |
|---|---|---|---|
| `FOCUS-001` | Policy 检查后，Agent 可否在执行前替换金额、资源、工具或操作？ | `implement` | 同一 canonicalizer 在授权与执行边界生成 SHA-256 action digest；任一受绑定字段变化必须阻断 |
| `FOCUS-002` | 仅凭内存中的 `permit_id` 是否会被误当授权？ | `implement` | `permit_id` 只关联；使用 Ed25519 签名、短时、动作绑定的 `permit_token`，且不进入审计/UI |
| `FOCUS-003` | 同一 Permit 能否重复或并发执行两次？ | `implement` | 并发安全 Store 原子完成 verify+consume；恰好一个并发请求成功 |
| `FOCUS-004` | 事后 RuntimeEvent 能否在副作用前阻断？ | `implement` | Enforcement 移到 MCP 转发之前；事件 API 只作辅助证据 |
| `FOCUS-005` | 多 Adapter 是否会在 MVP 中产生多套错误安全语义？ | `implement` | 只实现 MCP；其他 Adapter 本里程碑 `reject` |
| `FOCUS-006` | Aegis 是否应自己提供隔离？ | `reject` | 不实现 sandbox backend；仅表达 `isolation_required` obligation |
| `FOCUS-007` | Discovery/Shadow Agent 是否仍应扩展？ | `reject`（扩展）/ `docs_only`（兼容） | 代码冻结、默认关闭、普通 UI 隐藏；仅 `--enable-experimental-inventory` 与 `cmd/discover` 保留 |
| `FOCUS-008` | 数值 Risk 是否应定义产品或改变授权？ | `implement` | Risk/detection 只进入 `advisory_signals`；不再决定状态、Permit、obligations 或 executor |
| `FOCUS-009` | 同进程裸 `models.Request` 是否可能绕过身份来源边界？ | `implement` | 删除普通 `AuthorizeAction/Authorize/Process` 入口；Permit 签发必须接收 sealed `intake.Authorization`，Demo 仅用明确 synthetic 入口 |
| `FOCUS-010` | 单次 Permit 是否会被误写为业务副作用 exactly once？ | `docs_only` | 明确只保证 Permit 至多成功消费一次；失败/timeout 不恢复，业务重试依赖 upstream 幂等机制 |

这批产品负责人决定属于 `S4`。没有新增外部来源；本轮以架构负向测试验证 trusted-intake、deterministic-policy、单次消费与 upstream-not-called 边界。只有 canonicalization、签名、过期/撤销/replay、隐私和 MCP upstream-not-called 测试通过后，相应实现才记为 `V2 reproduced`。

### 2026-09-07 周度增量复核

复核窗口为 2026-09-05 至 2026-09-07。MCP 最新正式协议仍为 `2026-07-28`，OWASP GenAI LLM Top 10 与 Agentic Applications Top 10 的基线版本仍为 2026，NIST AI RMF/AI 600-1 没有替换本项目所列基线。官方事故源没有出现新的独立事件；2026-09-01 的媒体报道继续追溯至已登记的 OpenAI、UK AISI 与独立复盘，因此去重而不新增事故 ID。

| `research_id` | 证据、机制与状态 | 来源建议、前提与副作用 | 产品处置 |
|---|---|---|---|
| `REV-2026-09-07-001` | [MCP latest](https://modelcontextprotocol.io/specification/latest) 仍指向 `2026-07-28`；[Go SDK `a5026ea`](https://github.com/modelcontextprotocol/go-sdk/commit/a5026ea) 在 2026-09-06 修复 `Mcp-Name` 的 `=?base64?...?=` 解码后比对 · `S1/V1`。机制只影响非 Header-safe 的 name/URI；Aegis 两个内置 Tool 名均为 ASCII，当前 raw exact-match 会拒绝包装值 | 维护者实现选择是先解码再与正文比较，并拒绝无效 Base64。支持它会增加一条输入解码路径，但不会增强 Permit security property | `docs_only`：明确 Base64-wrapped `Mcp-Name` 当前不在 focused subset，保持 fail closed；在出现受支持的非 Header-safe Tool 或明确 conformance 目标前不实现 |
| `REV-2026-09-07-002` | [MCP issue #3213](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3213) 提供 `server/discover.instructions` 与 public cache 组合的独立 PoC · `S2/V1`。Server-owned instructions 可进入 Agent context；Aegis 当前转发 discover 响应，不对其文本做可信化或 sanitization | 来源建议隔离为不可信内容、限制长度、避免直接并入 system prompt，并可辅以检测；Prompt classifier 可能误报/漏报，也不能替代执行边界 | `docs_only`：把 discover metadata/instructions 明确列为不可信上游内容；Host 必须隔离处理，所有真实 `tools/call` 仍需 Execution Permit。不增加 Prompt classifier、缓存平台或通用内容过滤器 |
| `REV-2026-09-07-003` | [OWASP Agent Control Standard v0.1 public preview](https://genai.owasp.org/resource/agent-control-standard-acs/) 提议跨框架 runtime hooks；其 [2026-09-06 conformance 更新](https://github.com/GenAI-Security-Project/agent-control-standard/commit/c1f51df) 明确 v0.1 的 profile 声明由实现者自证，尚无 conformance suite、registry 或裁决主体 · `S1/V1` | 来源要求采购方自行验证部署声明。采用 ACS 会引入新 wire/schema、观测与治理范围，且当前一致性承诺不可独立验证 | `defer`：跟踪稳定版和可执行 conformance，不把 Aegis 宣称为 ACS-compatible，也不扩展成 Guardian/observability/AgBOM 平台 |
| `REV-2026-09-07-004` | [ACLE-MCP 预印本](https://arxiv.org/abs/2609.02690) 区分 OAuth/签名身份绑定与执行时 workload appraisal，报告 workload 替换、陈旧证明和未声明下游问题 · `S2/V1`。Aegis 的 `workload_id` 是 trusted-intake claim，不是远程工作负载实时证明 | 论文建议 sender-constrained lease、执行点消费和 provider-side attestation；前提包含 OIDC、可信 appraisal/vTPM 与远程资源侧 gate，实验报告正常允许调用 pooled p95 延迟增加 25.7% | `docs_only`：补充 workload binding 不等于 runtime attestation 的安全限制；不引入 KMS、OIDC、TPM 或远程 attestation |
| `REV-2026-09-07-005` | 新近社区反馈分别描述 [Tool description 漂移后静态 scope 仍放行](https://www.reddit.com/r/Information_Security/comments/1w852eb/the_agent_just_needed_read_access_until_one_tool/) 与 [共享 service account 只能提供 attribution、未必提供 downstream authorization](https://www.reddit.com/r/mcp/comments/1w4oiiv/how_is_anyone_actually_running_mcp_in_an/) · `S4/V1`。两者均为自述，未提供可独立核验的部署记录 | 建议 review Tool metadata/scope 变更、记录来源、使用逐用户委托或更细粒度凭据；会引入 IAM、secret lifecycle、审批与运维成本 | `docs_only`：强化 discover/tool metadata 不可信与 trusted-intake provenance 边界；不据此建设 IAM、SSO、RBAC、供应链扫描或会话意图追踪 |
| `REV-2026-09-07-006` | ToolHive 维护者在 [canonical inbound grants](https://github.com/stacklok/toolhive/commit/6b40bf3) 与 [OAuth callback Referer](https://github.com/stacklok/toolhive/commit/7b491f7) 上修复授权配置漂移、重放/注册边界及 Referrer 泄漏 · `S1/V1`。Aegis 当前没有 OAuth callback、DCR、token exchange 或 SPIFFE grant surface | 这些修复依赖完整 OAuth/IAM 与多实例存储语义；移植会扩大产品面且没有对应可达路径 | `reject`：不移植，也不把无关修复包装成 Aegis 能力；仅保留“配置冲突 fail closed、凭据不进入审计”的现有原则 |

这轮没有条目达到 `V2 reproduced`，因此没有代码、fixture 或行为变更。新增结论只修正文档边界；未来若要实现任一 deferred 控制，仍需先建立安全 synthetic fixture、可证伪假设和项目内回归。

## 4. 先前公司端点反馈的保留方式

2026-09-02 的探索性试用曾发现：Server 启动快照不刷新、过宽扫描遇权限错误、marketplace/cache 噪声、批准清单入口不明显，以及“批准 Agent”容易被误解为“批准所有行为”。这些问题推动了 Discovery 的本地修复和结构化 AuthorizationEnvelope。

当前决定是：

- 保留这些脱敏事实和已有回归，避免未来重复犯错；
- 不再把 Inventory/Shadow discovery 当产品中心，不继续增加传感器；
- “已批准 Agent 仍需逐次授权”的思想由更精确的 action-bound Permit 覆盖；
- 旧公司试用没有验证真实 MCP 执行边界、签名 Permit 或 replay，因此不升级为 `V3`。

仓库不保存原始公司日志、用户名、主机名或绝对路径。

## 5. 标准与框架映射

| 基线 | 与 focused MVP 的关系 | 决定 |
|---|---|---|
| [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | Excessive Agency、工具输入/输出、敏感信息和供应链是 action binding/最小审计的背景 | 只实现 execution-permit 直接相关控制；其他项记录为外部责任或 non-goal |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | Tool Misuse、Identity/Privilege Abuse、Goal Hijack 支持“计划不等于授权” | 用 structured identity + canonical action + Permit；不扩成全套 Agent 安全平台 |
| [OWASP Agent Control Standard v0.1](https://genai.owasp.org/resource/agent-control-standard-acs/) | Runtime hook 与跨框架 control point 邻近 Aegis 的执行边界，但 v0.1 conformance 仍是实现者自证 | `defer` 集成；不声明 ACS compatibility，不扩展 Guardian、observability 或 AgBOM |
| [OWASP GenAI Security Industry Framework Crosswalk](https://genai-security-project.github.io/crosswalk/) | 可用于查找相邻控制，但其站点明确所有 mapping 在具名 reviewer 签署前均为 `unreviewed` | 只作导航，不据此声称合规、覆盖或提升验证状态 |
| [NIST AI RMF 1.0 / NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) | 要求清楚表达治理、测量、限制与剩余风险 | 维护策略版本、测试、receipt、证据等级和非目标；不声称框架合规 |
| [MITRE ATLAS](https://atlas.mitre.org/) | 为威胁和 fixture 提供分类线索 | `docs_only/fixture`；不作为功能清单 |
| [MCP Security](https://github.com/modelcontextprotocol/modelcontextprotocol/security) | 用户同意、最小权限、工具边界和隔离责任 | MCP 为唯一 Adapter；Aegis 只负责动作授权/Permit，不冒充隔离或 OAuth |
| [MCP Specification 2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/) | 真实 Proxy 必须显式处理协议版本、Header/body 一致性和授权边界 | 校验 `Mcp-Method`/`Mcp-Name`，拒绝未绑定元数据，剥离任意 Header/Session 上下文，重建最小转发 Header；不支持的 MRTR/`Mcp-Param-*` fail closed，不声称完整 MCP/OAuth 实现 |

### OWASP 风险到产品边界

| 风险族 | Aegis 直接做什么 | 不做什么 |
|---|---|---|
| Excessive Agency / Tool Misuse | 精确动作授权、短时签名 Permit、执行前 verify+consume | Agent 产品的通用权限 UI 或永久角色管理 |
| Identity & Privilege Abuse | 绑定 principal、Agent/workload 与 delegation fingerprint | 企业 IAM、SSO、RBAC、credential issuance |
| Goal Hijack / Prompt Injection | 不把自然语言意图当授权；参数变化导致 digest mismatch | Prompt 分类器或“安全 Prompt”保证 |
| Sensitive Disclosure / Improper Output | 最小化审计，资源/操作/参数绑定，可表达 egress/read-only obligation | DLP、内容审查、网络 Sensor 或 output sanitizer |
| Supply Chain | Permit 可绑定工具身份/Schema 上下文 | SBOM/AIBOM、Registry、签名供应链平台 |
| RCE / Unexpected Code Execution | 未获精确授权的 MCP tool call 不转发 | endpoint sandbox、EDR、进程阻断 |
| Memory、A2A、Cascading Failures | 仅保留未来 fixture/研究记录 | 本里程碑不实现 Memory/A2A/会话风险平台 |

## 6. 事故与处置建议

| ID | 来源与机制 | 来源建议 | Aegis 处置 |
|---|---|---|---|
| `INC-2026-001` | [OpenAI 2026-08-26 事件说明](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) · `S1/V1`；特殊网络安全评测中出现未批准协作/外联，条件包括降低防护与监控不足 | 更强隔离、限制网络/权重访问、实时监控、事件响应与生命周期门槛 | `docs_only`：支持执行前 Permit 的必要性，但不据此扩展隔离、EDR、Kill Switch 或跨 Agent 平台；外部 executor 负责隔离 |
| `INC-2026-002` | [UK AISI 事件报告](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing) · `S1/V1`；开放互联网评测中出现面向现实对象的未授权动作 | 限制真实互联网、明确禁止现实目标、人工复核、实时监督和安全退出 | `docs_only`：试点禁止真实目标；如工具动作需要人工批准，以 Permit obligation 表达，不实现通用审批平台 |

两项都说明事后发现不等于执行前控制，但发生于特殊评测条件，不能外推普通企业部署的发生率，也不能证明本项目控制有效。

## 7. 社区痛点、处置建议与产品响应

| 痛点/建议 | 证据 | 当前处置 |
|---|---|---|
| 无法回答“谁授权了这次动作” | [MCP identity/delegation 讨论](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2404)、[企业身份上下文](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2761) · `S4/V1` | `implement`：绑定 principal、Agent/workload、delegation fingerprint、policy version 与 receipt；不实现 IAM |
| “只读 Agent”仍可能写入 | [工具权限/审计讨论](https://www.reddit.com/r/MCPservers/comments/1ska249/how_are_you_handling_permissions_audit_logs_for/) · `S4/V1` | `implement`：operation + security arguments 进入 digest，`read_only` 被签名；`docs_only`：任意上游 Tool 的内部行为仍需可信外部控制 |
| Policy 后参数被替换（TOCTOU） | 产品负责人失败假设 `S4` | `implement`：授权与执行复用 canonicalizer；mismatch 阻断且 upstream 不调用 |
| Permit 被复制/重放 | 产品负责人失败假设 `S4` | `implement`：短 TTL、single-use Store、撤销和并发 replay 测试 |
| 日志很多但无法证明执行凭据 | [MCP 审计讨论](https://www.reddit.com/r/mcp/comments/1t0fd3i/what_are_people_using_to_audit_agentmcp/) · `S4/V1` | `implement`：以 action digest、Permit state、verification outcome 为中心的 receipt；绝不记录 token |
| 被污染内容诱导工具调用 | [社区讨论](https://www.reddit.com/r/MSSP/comments/1vxskpv/mcp_server_security_before_this_touches_prod/) · `S4/V2`（旧 synthetic fixture） | `fixture`：历史场景留在 advanced regression；Aegis 不做 Prompt classifier |
| 多工具组合可能外泄 | [社区讨论](https://www.reddit.com/r/mcp/comments/1s086kb/how_are_you_controlling_mcp_agents_in_practice/) · `S4/V2`（旧 fixture） | `defer`：不扩展为会话风险平台；可通过每次精确 Permit 与外部义务缩小单次动作边界 |
| 隔离会破坏网络/性能 | [ToolHive #5775](https://github.com/stacklok/toolhive/issues/5775)、[#5847](https://github.com/stacklok/toolhive/issues/5847) · `S3/V1` | `reject` sandbox implementation；只测 Aegis verifier/Proxy 开销，隔离由外部 executor 负责 |
| 未登记 Agent 难以治理 | [Microsoft Agent Discovery](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-discovery)、[社区讨论](https://www.reddit.com/r/AskNetsec/comments/1v61h8n/how_do_you_keep_track_of_what_your_ai_agents_can/) · `S1/S4` | `reject` feature expansion；旧 Discovery 冻结为 opt-in 实验工具，不能影响 Permit |

## 8. 开源项目借鉴与竞争边界

| 项目 | 可借鉴点 | 明确边界 |
|---|---|---|
| [Stacklok ToolHive](https://github.com/stacklok/toolhive) | MCP Gateway/Runtime 边界与实际部署问题 | 不复制 Registry、Kubernetes、OIDC/OAuth、sandbox 平台；Aegis 只做 Permit |
| [Docker MCP Gateway](https://github.com/docker/mcp-gateway) | 明确 Proxy、秘密、路径和网络信任边界 | Aegis 不声称容器隔离；可以与外部 executor 组合 |
| [Invariant Gateway](https://github.com/invariantlabs-ai/invariant-gateway) / [Guardrails](https://github.com/invariantlabs-ai/invariant) | 透明代理和跨工具策略的接口经验 | 聚焦单动作 cryptographic binding，不扩展为通用 guardrail 平台 |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | 确定性、可测试 Policy 接口 | OPA migration 本里程碑 `reject`；保留未来替换空间 |
| [OpenFGA](https://github.com/openfga/openfga) | 主体—资源关系建模 | 不实现关系图、企业授权服务或 RBAC UI |
| [OpenTelemetry Go](https://github.com/open-telemetry/opentelemetry-go) | Trace 关联 | `defer`；receipt 先保持最小、本地和脱敏 |

Aegis 的差异不在“大而全”，而在一个可独立测试的不变量：**签名执行许可在真实副作用前把已授权动作与将执行动作做密码学绑定，并默认只能消费一次。**

## 9. 产品优先级

### P0 — 证明 execution-permit boundary

1. CanonicalAction 与确定性 SHA-256 digest；
2. Ed25519 signed compact Permit；
3. 过期、撤销、wrong binding、action mismatch 与 single-use replay defense；
4. 并发 replay 恰好一次成功；
5. Audit Receipt 不含 Permit token、raw delegation 或敏感参数；
6. 四个 focused Demo 与完整 P0 负向测试。

### P1 — 一个真实 MCP control point

1. MCP `tools/call` normalization；
2. 上游转发前 verify+consume；
3. 任一验证失败后 upstream 调用次数为零；
4. 受控本地 upstream 与脱敏结果 metadata；
5. 获准公司设备上的小范围、synthetic 试点。

### Frozen / rejected

- Discovery/Registry 只维护 build/security regression，不开发新功能；
- sandbox、OS/network sensors、企业 IAM/SSO/RBAC/multi-tenancy、Shadow Agent 扩展、ML/LLM risk、A2A/HTTP/database adapter 均不属于 focused MVP；
- Runtime evidence 保留，但不会替代 pre-execution verifier。

## 10. 调研到发布闭环

```text
collect evidence → trace primary source → choose disposition
  → define falsifiable Permit property → build safe fixture
  → implement smallest deterministic control → test upstream-not-called
  → verify privacy/race/vet/build → sync zh-CN + English
  → publish or pilot only with separate explicit authorization
```

项目契约继续禁止自动发布、部署和生产数据。公司设备工作每次需要明确授权。能力只有在代码、自动化测试、可重复 fixture、隐私检查和边界说明同时存在后才标为 `V2 reproduced`；正式受控 MCP 试点才可能达到 `V3`。

## 11. 持续复核规则

- 新标准、事故、媒体/安全公司建议和社区反馈先作为不可信证据收集并追溯原始来源；
- 每轮必须选择明确 disposition，不能因为报道热门就扩大产品范围；
- 优先询问证据是否改变 execution-permit security property；若没有，不改产品；
- 不自动部署、发布、收集公司日志或使用真实外部目标；
- 中文是语义工作源，英文同批同步；
- 每个版本 Tag 和正式 MCP 试点前重新检查签名、canonicalization、replay、隐私、race 与 upstream-not-called 属性。

## 12. 2026-09-13 Manus 与三篇推荐文档驱动的重设计

完整来源、文章/事件日期、机制、商业依赖、当前代码证据、架构图和验收矩阵见[双语重设计提案](manus-redesign.zh-CN.md)。本次从《Saturday Essential Read》最新三条推荐定位 R1/R2/R3，再核对原文。不是重新统计三起新事故，也没有重跑报告中的攻击。提案中的源 ID 在下表沿用。

下表保留 2026-09-13 复核时的 `V1` 记录；本地代码记录的后续升级见第 13 节。来源的建议与本项目设计分开：Manus 提供产品/工程经验；R1 提供调查观察；R2 建议减小攻击面、及时更新、限制权限和运行时间；R3 强调基础设施与监控的多层控制；F1 把网络过滤责任交给宿主集成。下表是本项目的处置，不代表来源已经验证 Aegis。

| research_id | 来源/机制与相关性 | 控制阶段、依赖和副作用 | 唯一处置与下一步 |
|---|---|---|---|
| `REDESIGN-2026-09-13-01` | M1/M3/M4 `S3`、M5 `S4`：长任务、子任务与环境重建需要区别任务和实例 | 预防/恢复；依赖外部 controller，增加生命周期复杂度；历史供应商架构不当成当前全貌 | `docs_only`：定义 RunContext、EnvironmentLease、generation 与恢复边界 |
| `REDESIGN-2026-09-13-02` | M2 `S3`：上下文可压缩或写文件，但不能承担授权事实 | 预防；依赖 Agent host；文件可能被修改或带入不可信指令 | `docs_only`：记忆与 authority 分离，工具文本不修改已注册语义 |
| `REDESIGN-2026-09-13-03` | R1 `S2`：共享服务与工具调用伪装暴露外围信任边界 | 预防/检测；依赖服务 ACL、外部 collector；共享缓存效率下降，仍有未覆盖侧信道 | `docs_only`：任务命名空间、可信调度记录和分来源 receipt；E04/E05 作为候选验收 |
| `REDESIGN-2026-09-13-04` | R2 `S2`、F1 `S1`：VM 实现与外部网络边界各有独立前提 | 遏制/恢复；依赖 Linux/KVM、更新与强制网络；额外运维成本，不能保证抗宿主逃逸 | `defer`：真实 runtime 集成等 M1/M2 完成再选固定版本试点 |
| `REDESIGN-2026-09-13-05` | R3 `S1`：环境误配与推理偏差；不同 monitor 的结果不可混同 | 预防；独立身份、policy 与环境事实；保守拒绝影响可用性 | `docs_only`：模型的 simulation 判断不能建立 authority；不增加推理授权器 |
| `REDESIGN-2026-09-13-06` | 本地代码 `S1`：部分 signed obligations 缺统一履行检查；默认 client 的重定向边界待测 | 预防；依赖明确约束 scope 和固定 route；可能暴露既有配置冲突 | `experiment`：下一步 M1，按 E02/E07 先安全复现，再修改并对照 |
| `REDESIGN-2026-09-13-07` | 本地代码 `S1`：消费/nonce 在内存，审计本地写入，外部提交可能结果未知 | 响应/恢复；依赖持久事务和密钥生命周期，增加延迟与故障处理 | `experiment`：M2/E08/E09；未知 Permit 仍拒绝，不声称当前重启直接放行 replay |
| `REDESIGN-2026-09-13-08` | 本地范围契约 `S1`：自研 sandbox/通用 Adapter 会扩大验证面 | 预防；研发与运维负担超过当前核心目标 | `reject`：本阶段不扩成 IAM、EDR、Inventory 或通用编排平台 |

2026-09-13 研究交付时的实现状态：仅文档变更。后续 M1 实现见下文第 13 节。核心能力、两个语义 profile、MCP 范围与项目契约不变；没有新增 fixture、runtime backend 或生产集成。路线为 M1 执行约束 → M2 持久状态 → M3 一个外部沙箱集成 → M4 生命周期与受限委托；这是一条提议路线，不是已通过的里程碑。

2026-09-13 研究阶段验证：项目契约校验通过；`go test ./...` 在独立临时 GOCACHE 下退出码为 0，所有包通过。首次执行各包也通过，但默认缓存目录的 `trim.txt` 无写权限使 Go 命令退出 1，随后仅切换缓存位置重跑成功。当时新增实验 E02–E12 未执行；当时未运行 race、vet、前端构建或 Docker build，因为没有改运行代码、依赖或部署配置。

## 13. 2026-09-14：M1 代码实施与对照验证

本次按新版 `$research-to-product` 落实用户要求的代码改动与 GitHub 推送，沿用第 12 节的原始来源，并以代码和合成实验判断项目适用性。完整变更、兼容影响和验证条件见 [M1 实现记录](m1-execution-admission.zh-CN.md)。

| research_id | 当前证据 | 处置 | 交付状态 | 观察与适用范围 |
|---|---|---|---|---|
| `REDESIGN-2026-09-13-06` | `S1/V2`，本地代码与 E02/E07 合成对照 | `implement` | `completed` | 五类要求在消费前拒绝，nonce/Permit 均保留；固定 MCP 路由禁止重定向；仅证明本地执行准入，不证明外部隔离 |
| `REDESIGN-2026-09-13-07` | `S1/V1` | `experiment` | `planned` | 单节点持久消费与 dispatch intent 仍为 M2；本地 JSONL 不视为已完成持久事务 |
| `REDESIGN-2026-09-13-04` | `S2/S1/V1` | `defer` | `planned` | 外部 runtime 需固定版本、真实环境与独立控制验证，未部署 |

基线中五类要求均在核心被消费，禁网 MCP 调用到达上游；十组重定向组合均到达第二 receiver。修复后这些负向条件通过，同时保留两个 profile 的无附加约束合成成功路径和原有身份、参数、用途、replay 测试。默认示例策略继续要求禁网，真实执行会拒绝；没有为恢复旧行为放宽配置。

`go test ./...`、`go vet ./...`、前端类型检查与构建通过。Windows 缺少 cgo 工具链，本机 race 未运行；Docker Linux daemon 未运行，本机构建未完成。最终 Linux CI 状态以本次 GitHub 提交对应的工作流为准。外部来源未因这些本地测试被升级；没有声称完成真实沙箱、持久恢复或业务 exactly-once。

## 14. 2026-09-14 周度增量复核

复核窗口为 2026-09-08 至 2026-09-14，产品/代码基线是 `02a9913`。本轮查看了官方规范与安全公告、事故方更新、维护者提交/发行、正规媒体、安全供应商与公开社区。二次报道已追溯至 Anthropic、OpenAI、AWS、OWASP、MCP 维护者和 ToolHive 公告；受限于表单的供应商报告不冒充全文审查。

| research_id | 来源、机制、前提与限制 | 来源建议、冲突/副作用与本项目适用性 | 单一处置与交付状态 |
|---|---|---|---|
| `REV-2026-09-14-001` | [MCP latest](https://modelcontextprotocol.io/specification/latest) 仍是 `2026-07-28`；[OWASP 2026 Top 10](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)、[Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)、NIST AI RMF 1.0/AI 600-1 没有发布替代版本。[NIST](https://www.nist.gov/itl/ai-risk-management-framework) 明确 RMF 1.0 正在修订·官方全文 `S1/V1` | 修订未发布，不能用“即将更新”改写已实现映射；本轮没有会改变 execution-permit property 的新正式基线 | `docs_only` / `completed`：保持当前版本，下轮继续监测 NIST 正式修订 |
| `REV-2026-09-14-002` | ToolHive 2026-09-08 公开公告家族：[OIDC 配置已声明但中间件收到 nil](https://github.com/stacklok/toolhive/security/advisories/GHSA-gc9p-rmpx-vv9j)、[`/sse` 后缀绕过授权](https://github.com/stacklok/toolhive/security/advisories/GHSA-h4mf-84xq-q2fc)、[UTF-8 BOM 导致 parser/filter 分歧](https://github.com/stacklok/toolhive/security/advisories/GHSA-9v4w-3mqh-6vmm)、[远程 health redirect SSRF](https://github.com/stacklok/toolhive/security/advisories/GHSA-vc62-q48c-5cmw)·维护者全文 `S1/V1`；ToolHive 于 2026-09-14 检索为 2,163 stars，复核 v0.49.0 commit `e532cf07` | 根因分别是并行配置载体失配、路径后缀豁免、解析器不一致和跟随目标可控重定向；来源建议单一权威配置、精确路由、统一解析和同主机重定向策略。Aegis 无 OIDC/health pinger，但 parser 与路由机制直接相关 | `fixture` / `completed`：新增 BOM 输入及 `/sse`、`/x/sse`、`/mcp/sse` 负向用例；均在 upstream 前拒绝。既有 M1 重定向用例保留。这验证 Aegis 本地边界 `V2`，不是重放 ToolHive 漏洞 |
| `REV-2026-09-14-003` | [MCP SEP-2640 Skills Extension](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2640) 于 2026-09-11 进入 Final；[ToolHive v0.49.0](https://github.com/stacklok/toolhive/releases/tag/v0.49.0) 已对 `skills/list`/`skills/get` 增加 Cedar 映射·维护者全文 `S1/V1` | Skills 传输和生命周期不是 Aegis 两个语义 profile 或 execution-permit 边界；支持它会扩展协议和供应链范围 | `fixture` / `completed`：文档明确 Skills extension 不在 focused subset，`skills/list`/`skills/get` 回归用例证明 fail closed。不增加 Skill/plugin 系统 |
| `REV-2026-09-14-004` | OWASP Agent Control Standard 现有 v0.1.0（tag v0.1.1）在 `7d2dd3c6` 已有 AGT reference implementation，但[conformance 仍为自声明](https://github.com/GenAI-Security-Project/agent-control-standard/issues/19)，[negative vectors v0.2](https://github.com/GenAI-Security-Project/agent-control-standard/issues/53) 仍 deferred，[AGT dogfood report](https://github.com/GenAI-Security-Project/agent-control-standard/issues/92) 仍在 backlog·官方仓库 `S1/V1`；2026-09-14 为 115 stars | 参考实现增加了可读机制，但可独立反证的一致性证据仍未完成；自声明不能提升 Aegis 验证等级 | `defer` / `planned`：保持不声称 ACS-compatible，等可执行 conformance 和稳定映射 |
| `REV-2026-09-14-005` | [OWASP MCP Tool Poisoning](https://community.owasp.org/attacks/MCP_Tool_Poisoning) 页面把不可信 Tool 返回进入 LLM context 定义为连接时/运行时信任缺口，建议结构化输出、最小权限、执行层强制和敏感操作外部确认·官方全文 `S1/V1` | 结构验证可减少部分输入差异，但无法完整识别自由文本中的间接注入；Aegis 只能确保后续真实动作仍经 Permit gate | `docs_only` / `completed`：继续将 discover/list 返回标为不可信 Host 输入；不建 Prompt classifier、内容清洗平台或审批系统 |
| `REV-2026-09-14-006` | [Anthropic 对四起真实第三方未授权访问的复盘](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents) 指出共同前提是测试环境误接开放 Internet、产品 safeguards 关闭；[OpenAI 2026-09-11 更新](https://openai.com/hugging-face-incident-and-misalignment/) 对 RubyGems 恶意包具体指称尚未验证·事故方全文 `S1/V1` | 前者扩大 transcript 复查并委托 METR 独立调查；但监控/沙箱和模型对齐不由 Aegis 提供。后者的未验证说法不计为新事故 | `docs_only` / `completed`：保留“模拟判断不能证明环境权限”和外部隔离责任；不扩展 sandbox/EDR/意图分类 |
| `REV-2026-09-14-007` | [AWS 2026-105-AWS](https://aws.amazon.com/security/security-bulletins/2026-105-aws/) 披露 Security Agent plugin `<1.1.0` 和 MCP server `<0.2.0` 未验证可预测 S3 bucket 的归属，可暴露工作区归档·厂商安全公告全文 `S1/V1` | 建议升级并核对/预创建账户自有 bucket。Aegis 签名绑定服务端配置的 resource/audience，但不证明该网址或云资源真由预期组织控制 | `docs_only` / `completed`：在安全边界明确外部资源归属/TLS/认证需部署方独立验证；不增加 AWS/S3 集成 |
| `REV-2026-09-14-008` | [Nightfall 2026-09-09 早期访问发布](https://www.nightfall.ai/news/nightfall-launches-mcp-gateway-to-govern-ai-agents-before-they-act)宣称 inline MCP 强制/凭据代理；Reco 供应商新闻稿声称分析 500 个公开 MCP server，但[全报告需表单](https://www.globenewswire.com/news-release/2026/08/26/3351417/0/en/reco-finds-four-in-five-ai-tools-operate-without-it-oversight-in-state-of-agent-security-2026-report.html)·`S3/V0`；社区继续要求 [per-tool 确定性策略](https://www.reddit.com/r/MCPservers/comments/1wbjf8w/anyone_else_struggling_with_mcp_security_now_that/) 与[“Policy 测试不等于上游未调用”的集成测试](https://www.reddit.com/r/mcp/comments/1wbzkpb/how_do_you_test_that_an_ai_agents_permissions/)·`S4/V1` | 供应商声称有商业利益且缺少可重复实验；社区建议与既有 deterministic Policy + upstream-not-called fixtures 重复，不证明需要动态 LLM judge 或 Inventory | `docs_only` / `completed`：不新增产品能力；保留当前 Permit 边界、负向集成测试和非目标 |

本轮的可证伪 fixture 假设是：“若 Aegis 只在精确 `POST /mcp` 路由上执行授权，并在单一 canonical parser 中拒绝 BOM，那么 `/sse` 后缀请求、BOM-prefixed `tools/call` 和未支持的 Skills 方法的 upstream 调用次数均必须为 0。”负向验收门槛为三类输入全部拒绝、不消费 Permit、不调用 upstream；对照为现有合法 `tools/call` 测试仍成功。新 fixture 在安全合成 upstream 上运行，不含真实攻击目标或公司数据。

本轮只增加回归 fixture 和中英文边界说明，不改运行时逻辑、依赖、语义 profile 或产品范围。未自动提交、推送、部署或访问公司设备。

验证：项目契约校验、定向新 fixture、`go test ./...`、`go vet ./...`、`npm run check:web` 和 `npm run build:web -- --log-level=warning` 均退出 0。`go test -race ./...` 先因 `CGO_ENABLED=0` 失败；显式设为 1 后仍因 PATH 中没有 `gcc` 失败，因此本工作树没有完成 race 验证。`docker build .` 因 Docker Desktop Linux engine named pipe 不存在而失败；不记为通过。

## 15. 2026-09-15 授权与实际执行的一致性

基线 `6e4d77197668afe91ddcd53527c9ce4f97b17641`；研究问题来自用户对“检查对象、范围或身份与最终执行不同”的观察。一手来源、日期、locator、代码映射、反证、合成实验和迁移设计集中记录在[授权与执行一致性研究](authorization-execution-binding.zh-CN.md)。JSON-RPC 规范与 Go 解码行为作为同一解析差异证据家族；CWE-367、RFC 8707、MCP draft 指导和 Zanzibar 不因本地测试自动升级验证等级。

| research_id | 证据 / 本项目观察 | 单一处置 / 交付状态 |
|---|---|---|
| `BIND-2026-09-15-01` | `S1/V2`：无 Permit/proof/身份、保留默认策略和共享 registry；6 组大小写别名将 Aegis 的协议分类与模拟上游工具动作分离。基线每组工具调用 1 次；修复后 0 次 | `implement` / `completed`：精确顶层 key、重建协议 envelope、负向及成功/nonce 保留对照 |
| `BIND-2026-09-15-02` | `S1/V1`：v1 摘要未绑定 route/config；默认共享 registry 是限制条件，未证明远程利用 | `experiment` / `planned`：M2 前验证 `PreparedExecution` 与服务端 route/profile/credential binding；显式 v2 迁移 |
| `BIND-2026-09-15-03` | `S1/V1`：逻辑路径/recipient 标识不是稳定对象版本；当前没有实际文件写入 | `experiment` / `planned`：已有 workspace profile 的模拟最终写入方执行 generation 条件写入 |
| `BIND-2026-09-15-04` | `S1/V1`：签发 policy version 不等于当前 authority epoch；已有单 Permit 撤销与重启默认拒绝仍有效 | `experiment` / `planned`：把权限时序纳入 M2 持久事务与 M4 生命周期，明确撤销先后和 unknown 状态 |
| `BIND-2026-09-15-05` | `S1/V1`：obligation 拒绝已经实现；独立 lease/generation 与外部实施方尚缺 | `defer` / `planned`：继续 M3 broker/环境契约，不以自报或 mock 宣称真实隔离 |

本轮改变一处生产 Go 文件，保留 token、默认策略、profile 数量和部署边界。新增回归与研究文档同步中英文。Windows 的全量 Go 测试、vet、前端类型检查/构建、项目契约校验退出 0；本机 race 因缺少 cgo、Docker 因 Linux daemon 不可用未通过，Linux CI 状态以对应 PR head 为准。沿用用户此前对 GitHub 推送的授权；没有部署、访问生产或改动契约中的安全标志。

## 16. 2026-09-15 PreparedExecution 实现

基线 `797b9c5c4e3b0d69a36e5d27619c1aace3d2da01`；本节更新第 15 节的历史状态，复用其一手来源，不把引用变成本地运行证据。完整机制、迁移、对照和限制见[实现记录](prepared-execution.zh-CN.md)。

| research_id | 单一处置 / 状态 | 证据与未完成范围 |
|---|---|---|
| `BIND-2026-09-15-02` | `implement` / `completed` | `S1/V2`：两组 route/config 漂移从调用 1 次变为 0；PreparedExecution、匿名身份与 Permit v2 已接 MCP。新增三组字节/副作用低报从签发变为拒绝。 |
| `BIND-2026-09-15-03` | `experiment` / `completed` | 合成最终 writer 的对象 ID/generation/namespace 比较；真实资源接入仍 planned，未证明文件系统隔离。 |
| `BIND-2026-09-15-04` | `implement` / `completed`（仅本地 epoch 子集） | `S1/V2`：禁用、重新启用、旧判断注册及 64 组竞争通过。禁用状态不持久；M2 原子事务和 M4 完整生命周期未完成。 |
| `BIND-2026-09-15-05` | `experiment` / `completed`（仅合成契约） | 八组资源/lease 变更对照：动作检查均写 1 次，最终版本比较均写 0 次；32 竞争写入仅 1 次。真实 controller/环境仍 V1，未部署。 |

验证覆盖完整 Go 测试、vet、frontend 和项目契约；本机 race/Docker 环境缺失及 Linux CI 的最终结果单独记入 PR。保持默认义务、两个 profile、唯一 MCP Adapter 和安全标志；不部署或访问生产数据。
