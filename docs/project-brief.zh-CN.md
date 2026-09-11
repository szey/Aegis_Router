# Aegis Router 项目说明

[English](project-brief.md) | 简体中文

> **AI Agent 动作的执行许可**

## 一句话定位

Aegis Router 是带有 Server-owned 语义动作配置、且不绑定 Agent 框架的 execution-permit 层：它先进行确定性 Policy 资格判断，再把获授权的请求解析为精确的规范动作，签发短时、签名、动作绑定、单次使用的许可，并要求 MCP 执行边界在真实副作用前验证和消费许可。

> **获得授权的动作，必须与实际执行的动作完全一致。**

## 产品边界

Aegis 只聚焦一个 reference-monitor primitive，而不是广义 AI Agent 安全平台。

核心模块按当前授权顺序只有：

1. Structured request validation；
2. Deterministic Policy eligibility；
3. Server-owned semantic action normalization；
4. Execution Permit issuance；
5. Permit verification；
6. Permit consumption / replay prevention；
7. Audit receipt；
8. 一个真实执行边界：MCP。

Aegis 不做通用权限管理、endpoint sandbox、workspace isolation、企业 Agent Inventory、Shadow Agent 治理、完整 IAM、EDR 式观察或泛风险仪表板。它也不实现 HTTP、A2A、数据库、Shell 或云端 Adapter。

实现中恰好有两个编译内置的语义 profile——`payment.send/v1` 与逻辑 `workspace.write/v1`——以及一个不可变的 Server-owned registry 和一个 MCP Adapter。它没有第三个 profile、动态加载、plugin SDK、任意 schema 或由用户选择的 upstream。

## 安全属性与执行顺序

```text
已认证身份 + Agent proposes action
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

确定性 Policy 首先判断结构化请求是否具备所请求 capability、resource、operation 与 tool 的资格。只有 Policy 授权后，Server-owned 语义 profile 才会把精确可执行含义解析为 `CanonicalAction`。任何语义不匹配或 normalization 失败都会在 Permit 签发前把结果转为 `DENIED`。仅有 Policy 授权不足以产生 Execution Permit，语义 profile 解析也绝不会覆盖 Policy 拒绝。

`已认证身份 + 精确语义意图 + 签名单次 Permit = 密码学绑定的执行。`

授权和验证必须使用相同的 canonicalizer。事后收到 RuntimeEvent 不能替代执行前检查；如果 Permit 验证失败，上游工具调用次数必须为零。

## Trusted Authorization Intake

HTTP body/header 中的 principal、Agent、workload 与 delegated authority 不能直接成为授权事实。`TrustedAuthorizationIntake` 必须先从已配置的信任边界解析并覆盖这些字段，再把来源、provider、assurance 与建立时间记录到 `authorization_context_provenance`。未配置 intake 时 HTTP 授权默认拒绝。

独立 Server 只能选择三种模式之一：安全默认的 `RejectAll`、显式 `LoopbackDevelopment`、或 `TrustedProxy`。TrustedProxy 只对已配置 CIDR 内的直接 TCP 对端接受严格的七个 Header 身份与 workload key 契约。`WorkloadBinding{KeyID, PublicKeyThumbprint}` 必须来自已认证基础设施上下文，绝不从授权 JSON body 获取。开发模式同样需要另外配置一个公钥。TrustedProxy 只根据 `request.RemoteAddr` 建立信任，并覆盖全部 body 身份字段。

TrustedProxy provenance 记录 `source=trusted_integration`、配置的 provider ID、`assurance=authenticated_context` 和服务端建立时间。Aegis 自身不认证用户，也不验证 OAuth Token；它只消费另一个可信认证边界建立的身份。这不是 IAM、SSO、OAuth、RBAC 或 bearer-token 验证。签名 `workload_id` 只是对该 intake claim 的绑定，不是对远程 workload 状态或未声明下游组件的实时证明。

`Router.AuthorizeTrustedAction(intake.Authorization)` 是唯一普通 Permit 签发入口。`Router` 不再暴露接受裸 `models.Request` 的 `AuthorizeAction/Authorize/Process`；进程内集成也必须调用 `intake.NewTrustedAuthorization(...)` 或经过 intake 实现来创建 sealed context。同一进程本身不是身份来源。Server-owned fixtures 只能使用名称和 provenance 都明确为 `simulated_demo` 的 synthetic 入口。

仅有 sealed context 仍不足以让废弃 flat request 获得 Permit 资格。执行边界还要求结构化 principal、Agent/workload、delegated authority、tool 与 action context；legacy flat 投影会在执行 Permit 签发前被拒绝，进程内调用方也不能绕过。`allow_legacy_flat_requests` 只保留兼容用途的 Policy 解释，绝不允许带 Agent 派生 workload 或缺失 delegation fingerprint 的可执行 Permit。

## CanonicalAction

规范动作绑定：principal ID、Agent ID、workload ID、delegated-authority fingerprint、tool、capability、resource、operation、profile ID/version、audience 与安全相关 arguments。

Arguments 使用确定性 canonical JSON：空参数变为 `{}`；对象键递归按 Unicode 字典序排列；重复键、畸形 UTF-8 和未配对 surrogate 拒绝；数组保持顺序；字符串按 JSON 规则转义；数字不经浮点转换而精确归一化。完整规范动作以 SHA-256 得到 `sha256:<64 位小写十六进制>` 摘要。

这保证等价 JSON 对象不受键顺序影响，但金额、收款人、资源、工具、操作、身份或其他受绑定字段的改变都会产生不同摘要。审计保留摘要，不保留原始敏感参数。

## AuthorizationEnvelope 与签名 Permit

原有结构化 `AuthorizationEnvelope` 被保留。它继续表达 request、principal、Agent/workload、delegation、tool、resource、operation、policy 和 obligations；同时签发方生成可验证的 `permit_token`。

Permit claims 至少包含：

- `jti/permit_id`、`signing_key_id` 与 `request_id`；
- `issuer`、`principal_id`、`agent_id`、`workload_id`；
- 只对 `execution` 强制的 `executor_key_id` 与 `executor_key_thumbprint`；
- delegated authority digest/fingerprint；
- `tool`、`capability`、`resource`、`operation`；
- `action_digest` 与 `policy_version`；
- `issued_at`、`expires_at`、`single_use=true`。

MVP token 是项目自有的 Ed25519 签名紧凑格式：`base64url(header).base64url(payload).base64url(signature)`，Header 为 `alg=EdDSA`、`typ=AEGIS-PERMIT`、`v=1` 与 `kid`。未验证的 `kid` 仅选择 KeyProvider 公钥，签名验证后必须与 signed claim 的 `signing_key_id` 一致。它借用 JWS 形态，但不声称通用 JWT/JWS 互操作。

TTL 以整秒表示，默认 30 秒，当前最大 15 分钟。

`permit_id` 是审计关联 ID；`permit_token` 是秘密执行凭据。列表、详情、日志和 UI 只能展示前者。

`KeyProvider` 将密钥存储/生命周期从 Permit 逻辑分离：issuer 获取当前签名密钥，verifier 按 `kid` 查找公钥。默认 Server 仍用进程级临时开发密钥；static provider 可接收由嵌入方安全加载的持久本地 Ed25519 密钥。密钥文件格式、自动轮换和 KMS/HSM 不在本里程碑。

## Verifier 与 PermitStore

Verifier 在副作用前检查签名、issuer、时间、Permit ID、主体、Agent/workload、工具、资源、操作和动作摘要。只接受 `VERIFIED`。

并发安全的 PermitStore 维护 `ISSUED / CONSUMED / EXPIRED / REVOKED`。验证成功与消费是一个原子动作；两个并发请求复用同一 Permit 时，只能一个成功，另一个明确返回 replay。状态仅在单进程内时，不提供跨重启/跨副本 replay 保证。

消费发生在上游副作用前，并且是不可逆 commit point。上游失败或 timeout 后 Permit 仍为 `CONSUMED`；重试必须取得一次新授权和新 Permit。不存在 `unconsume`。

这只保证一个 Permit 至多成功消费一次，不保证付款、订单、账户变更、消息发送等上游业务副作用 exactly once。若副作用成功而响应丢失，重试仍需新 Permit，并必须依赖 upstream 自己的业务幂等键/去重机制；Aegis 不实现业务幂等引擎。

## MCP Adapter

MCP 是 focused MVP 唯一的生产形态 Adapter。`tools/call` 在消费 execution Permit 前，先用服务端注册的 workload 公钥验证新鲜 Ed25519 `X-Aegis-Execution-Proof`。Proof 绑定 Permit ID、action digest、`POST /mcp`、签发时间和 nonce；key ID 与公钥 thumbprint 必须匹配受签名 Permit。缺失/无效 Proof、错 workload、过期 Proof 和重复 nonce 都在 Permit 消费和 upstream 之前失败。Proof 不会转发或写入审计。随后 Adapter 才执行原有动作校验、原子 Permit 消费和规范参数转发。

`WRONG_EXECUTOR` 明确区分“有效 Permit 但未证明持有绑定 workload key”与“Permit 签名无效”。Workload key registry 和 Proof nonce 状态目前都是单进程内的；私钥被窃取/共用、跨重启重放、多副本协调、硬件 attestation 和软件完整性测量仍未实现。

`payment.send/v1` 只接受正整数最小货币单位金额、allowlist 币种和 allowlist 收款人，并按币种限制单笔金额。`workspace.write/v1` 只接受 JSON string `path` 与 `content`；path 是逻辑相对 `/` 分隔标识，不允许反斜杠、盘符前缀、空/`.`/`..`/`~` segment、首尾斜杠、控制字符或 normalization。示例限制为 path 1,024 bytes、content 4 KiB。它只转发到 mock/逻辑 upstream，不写主机文件；原始 content 参与摘要，但绝不进入正常审计。

Adapter 不能在验证失败时“先调用、后告警”，也不能仅凭 `permit_id` 转发。上游 MCP 的 TLS、认证、工具副作用和部署绕过仍由部署方独立处理。

当前 Adapter 对 MCP `2026-07-28` 校验 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 与 JSON-RPC 正文的一致性；拒绝重复 JSON key 与未绑定的 Tool `_meta`；剥离任意 Header/Session 上下文后再重建最小传输/路由 Header。它只实现 HTTP `POST` 的 `server/discover`、`tools/list` 与 permit-gated `tools/call` focused subset；Base64-wrapped `Mcp-Name`、MRTR 字段和 Schema 驱动的 `Mcp-Param-*` 暂时 fail closed，不声明完整协议 conformance。Discovery/list 响应由 upstream 转发，因此其中的 description、instructions 和其他 metadata 是不可信 Host 输入，而不是经过 Aegis sanitization 的内容。

## Policy、Risk 与 obligations

Policy 首先对结构化 Request context 进行确定性资格判断。只有 Policy grant 才会进入两个内置语义 profile 之一；grant 与成功的语义解析缺一不可，才能产生 Execution Permit。可执行结果是 `AUTHORIZED / DENIED`。`REQUIRES_APPROVAL` 仍可由模型表达，但没有受支持的审批完成流程，不属于已实现执行能力。

Risk/detection 保留为可选咨询元数据并单独进入 `advisory_signals`；它们不能改变授权状态、产生 grant、签发 Permit 或选择 executor。只有显式确定性 Policy/配置映射可以产生 `human_approval_required`、`isolation_required`、`enhanced_audit_required` 等 obligations。

`isolation_required: true` 由外部 executor 履行。Aegis 不实现 sandbox backend，focused MCP Proxy 在仍需要隔离或人工批准时不会转发。Read-only 与 network-egress obligations 仍需要可信外部 executor/control 落实上游 Tool 的真实行为；兼容字段中的 `RESTRICT/SANDBOX` 只是 execution profile hint。

## Audit Receipt 与 Runtime Evidence

每次动作按 `TRUST CONTEXT → POLICY ELIGIBILITY/OBLIGATIONS → SEMANTIC ACTION → PERMIT → VERIFICATION → EXECUTION` 生成可解释 receipt，并记录 upstream attempted 与 execution outcome。Risk/detection 只出现在 `ADVISORY SIGNALS`。

受支持的可执行 Authorization status 使用 `AUTHORIZED / DENIED`；当前执行 final verdict 包括 `EXECUTED_WITH_VALID_PERMIT`、`PERMIT_ACTION_MISMATCH`、`PERMIT_EXPIRED`、`PERMIT_REPLAY`、`PERMIT_INVALID_SIGNATURE`、`PERMIT_REVOKED` 与 `EXECUTION_OBLIGATION_UNSATISFIED`，receipt 内同时保留 verifier 的精确 outcome 和 execution outcome。

RuntimeEvent 与来源/信任模型继续保留，但属于执行中/执行后的辅助证据。`agent_self_reported`、`instrumented_adapter` 与 `simulated_demo` 不能冒充独立 Sensor；未接入覆盖保持 `UNKNOWN`。

## API 与 UI

主 API 是 `POST /api/actions/authorize`、仅诊断的 `POST /api/permits/verify`、Permit revoke/list/detail、`GET /api/decisions` 与 `GET /api/audits`。MCP Adapter 使用 verifier 唯一的、带 Proof 的 `VerifyExecutionAndConsume` 执行边界。公开 HTTP 检查永不消费 Permit，合法检查返回 `VALID_NOT_CONSUMED` 且 `verified=false`，不能授权执行。所有 HTTP 授权入口都经过 Trusted Intake；未配置时 fail closed，loopback body intake 只用于显式开发模式。旧 `/api/authorize`、`/api/route`、`/api/runtime-events` 暂时兼容并清楚标注。

UI 只保留 `Decisions / Permits / Audit / Demo` 主导航。Permit 详情显示 `permit_id`、`signing_key_id`、state、principal、Agent/workload、tool、capability、resource、operation、action digest、policy version、issued/expires/consumed time 与最近验证结果，永不显示 token、签名密钥、raw delegated credential 或原始敏感参数。

四个主 Demo 是 valid、action mutation/TOCTOU、replay 与 expired Permit；历史场景降为 advanced regression fixtures，并继续标记 `simulated_demo`。

## 实验性 Discovery

现有 Discovery/Registry 代码保持可构建，但冻结开发、默认关闭，并在普通 UI 中隐藏。只有 `--enable-experimental-inventory` 才暴露相关 Server 能力；`cmd/discover` 保持独立实验工具。

不增加进程、OAuth、CI/CD、云端或中央企业 Inventory。发现痕迹不能证明 Agent 正在运行，也不影响某次执行许可。

## 完成定义与限制

Focused MVP 完成时必须能重复证明：精确动作被授权并获签名 Permit；MCP 边界在上游调用前验证和消费；任何受绑定字段变化都阻断；消费后不能 replay；全链路审计不泄漏 token 或敏感 payload。

即使全部本地测试通过，这仍是参考实现。单进程 Store、默认临时开发密钥、本地审计、尚未接入真实认证中间件的部署边界与未完成的独立评审，均不构成生产保证。
