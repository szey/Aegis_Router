# 安全策略

[English](SECURITY.md) | 简体中文

本文适用于 **Aegis Router — AI Agent 动作的执行许可**。仓库名称暂时仍是 `agent-governance-gateway`。

## 报告漏洞

请不要在公开 Issue 中披露疑似漏洞。如果仓库已启用 GitHub Private Vulnerability Reporting，请使用该功能，并提供：受影响版本/Commit、最小安全复现、预期与实际验证结果、上游工具是否被调用、潜在影响和可行缓解措施。

在第一个正式 Tag 发布前，只支持默认分支上的最新 Commit。

## 信任边界

Aegis 是参考实现，不是经独立评审的生产安全边界。它只保护实际经过其 verifier/MCP Adapter 的工具调用；绕过该边界的行为不会因为安装 Aegis 而自动被发现或阻止。

核心控制首先验证可信的结构化请求，并针对其 capability、resource、operation 与 tool 进行确定性 Policy 资格判断。只有 Policy 授权后，服务端拥有的语义配置才会把精确的可执行含义解析为 `CanonicalAction`。Policy 资格判断与语义解析都成功，Aegis 才会签发短时、动作绑定、单次使用的签名 `permit_token`。任何语义冲突或规范化失败都会在 Permit 签发前把结果转为 `DENIED`。仅有 Policy 授权不足以产生 Execution Permit，语义配置解析也绝不会覆盖 Policy 拒绝。

Permit 会在真实工具副作用前被验证和原子消费。`permit_id` 只是关联标识，不能独立授权。验证失败后上游工具必须保持未调用。

`AuthorizationEnvelope` 继续承载结构化 principal、Agent/workload、delegation、tool、capability、resource、operation 和 policy context，但执行凭据还必须包含可验证签名与相同动作摘要。

HTTP 授权请求还必须经过 `TrustedAuthorizationIntake`。独立 Server 有三种模式：默认 fail closed 的 `RejectAll`；显式开启的 `LoopbackDevelopment`，只对 loopback direct peer 信任 body 身份并标记 `development_only`；以及 `TrustedProxy`，只从直接 TCP 对端属于已配置 IPv4/IPv6 CIDR 的另一个已认证代理接收严格身份 Header。TrustedProxy 与开发模式不能共存，不完整的 trusted-proxy 配置会阻止启动。

TrustedProxy 只根据 `request.RemoteAddr` 建立发送方信任，永远不使用 `X-Forwarded-For`、`Forwarded` 或 `X-Real-IP`。必需身份 Header 必须单一、长度受限、无控制字符并符合严格语法。Proxy 还必须断言 `X-Aegis-Workload-Key-Id` 与 `X-Aegis-Workload-Key-Thumbprint`；这一 `WorkloadBinding` 来自已认证基础设施上下文，授权 JSON body 不存在对应输入字段。Delegated scopes 与 delegation fingerprint 仍按严格格式校验，不接受任何原始凭据。

成功的 Proxy intake 会在 `authorization_context_provenance` 中记录 `source=trusted_integration`、配置的 `provider_id`、`assurance=authenticated_context` 和服务端 `established_at`；失败时永不降级使用 body 身份。`Router` 仍然没有接受裸 `models.Request` 的普通 Permit 签发入口，只消费 sealed `intake.Authorization`。Aegis 自身既不认证用户，也不验证 OAuth Token；它只消费另一个可信认证边界已经建立的身份。这不是完整 IAM、SSO、OAuth 或 RBAC 系统。同一进程或网络本身不等于身份认证；认证代理的安全运行、传输保护与网络拓扑约束仍由部署方负责。

每个 execution Permit 都会签名绑定 executor key ID 和 Ed25519 公钥的 SHA-256 thumbprint。MCP `tools/call` 还必须携带 `X-Aegis-Execution-Proof`：对 Permit ID、action digest、`POST /mcp`、签发时间和 nonce 的新鲜 Ed25519 紧凑签名。Aegis 只从本地注册 key 集合解析 Proof `kid`，校验公钥 thumbprint，拒绝过期 Proof 和重复 nonce，并在消费 Permit 或调用 upstream 之前完成全部检查。Permit/Proof 检查与原子消费只通过统一的 `VerifyExecutionAndConsume` 暴露，不再存在公开的无 Proof execution 消费方法。Proof 不会转发或写入审计。有效 Permit 被错 workload 提交时返回 `WRONG_EXECUTOR`，与格式错误/签名无效的 Permit 结果明确区分。保留旧名称的 `POST /api/permits/verify` 仅作诊断检查：不消费 Permit；合法 Permit/action 只返回 `VALID_NOT_CONSUMED` 且 `verified=false`。

该 Proof 只证明某个请求持有已注册私钥，不是硬件 attestation 或软件完整性测量。私钥被窃取、复制或共用会破坏该绑定。Nonce store 和注册 key 集合都是单进程内的；本里程不实现跨重启/多副本防重放。缺失 executor key claims 的旧 execution Permit 必须重新签发；simulation Permit 保持不绑 workload key，且仍不能进入 MCP 执行。

Sealed intake 只是执行签发的必要条件，而不是充分条件：`Router.AuthorizeTrustedAction` 还必须确认请求保留结构化 principal、Agent/workload、delegated authority、tool 和 action 字段。废弃 flat request 会在执行 Permit 的 Policy 授权、审计创建和 Permit 签发前被拒绝。`allow_legacy_flat_requests` 只保留兼容用途的 Policy 解释能力；它不会让 flat request 获得 Execution Permit 资格，也不能让空 delegation fingerprint 或从 Agent ID 推导的 workload 进入签名 claims。

## Token、密钥与 replay

聚焦 MVP 使用项目自有的 Ed25519 签名紧凑格式，形态为 `base64url(header).base64url(payload).base64url(signature)`，不声明通用 JWT/JWS 互操作性。Header 含 `kid`，只用作 KeyProvider 公钥选择器；签名验证后还必须与 claims 的 `signing_key_id` 一致。

Permit TTL 必须是整秒，默认 30 秒，当前最大 15 分钟。

- 私钥只能存在于许可签发方的获准边界，不得进入 UI、审计、错误消息或仓库；
- `KeyProvider` 提供当前签名密钥与按 `kid` 查询验证公钥的边界；默认仍是进程级临时密钥，嵌入方可注入已安全加载的持久本地密钥；
- key 文件格式、自动 rotation、HSM/KMS、跨实例信任和灾难恢复尚不属于 MVP；
- Permit 默认单次使用，并通过并发安全的 Store 原子消费；
- 过期、撤销、已消费或未知 Permit 必须 fail closed；
- 若 Store 仅在单进程内，重启/多副本会形成 replay 状态缺口；在引入共享持久化与密钥生命周期设计前不能声称提供集群级 replay defense。

Permit 在上游副作用前消费。上游失败或 timeout 不会恢复 Permit；重试必须重新授权并获取新 Permit。任何 `unconsume` 语义都会重新打开 replay/双重副作用窗口，因此 Store 接口不提供该操作。

### Exactly-once 边界

Aegis 的保证是：同一个 Execution Permit 至多成功消费一次。它防止授权凭据 replay，但不保证任意业务副作用恰好执行一次。如果付款、订单、账户变更或消息发送已经在上游完成、但响应丢失，原 Permit 仍为 `CONSUMED`。重试必须使用新授权和新 Permit，并依赖上游系统自己的业务幂等键或去重机制。Aegis 不实现业务幂等引擎。

## 动作绑定与 canonicalization

授权方和执行方必须复用同一 canonicalizer。空参数转为 `{}`；对象键递归按 Unicode 字典序排列；重复键、畸形 UTF-8 和未配对 surrogate 拒绝；数组保持原顺序；字符串采用 JSON 转义；数字不经浮点转换而精确归一化，再以 SHA-256 生成 `sha256:<64 位小写十六进制>` 摘要。

Principal、Agent/workload、delegation fingerprint、tool、capability、resource、operation、profile ID/version、audience 或安全相关 arguments 任一改变，都必须导致绑定校验失败。不要依赖 `claimed_intent`、自然语言计划或客户端提供的摘要来替代服务器端规范化。

## MCP 执行边界

MCP 是当前唯一的生产形态 Adapter。Adapter 只接受签名绑定 `permit_class=execution` 的 Permit，并且必须在转发上游 `tools/call` 之前验证和消费。Server-owned Demo 只能签发 `permit_class=simulation`，且只有不具备上游转发能力的独立模拟 verifier 可以接受。用途缺失、未知、不匹配或被篡改时，必须在消费前拒绝且不得调用上游；错误签名、过期、撤销、replay、wrong agent/workload/tool/resource/operation 或 action mismatch 同样不得调用上游。

在 `permit_class` 引入之前签发的 Token 会被刻意视为无效，必须重新授权和签发；不得从缺失 claim 推断为 `execution`。

MCP `2026-07-28` 的 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 与 JSON-RPC 正文必须一致；Proxy 拒绝重复 JSON key 和未绑定的 Tool `_meta`，剥离任意入站 Header/Session 上下文，并只重建最小传输信息与标准路由 Header。Base64-wrapped `Mcp-Name` 当前不会被解码，而是 fail closed。当前 focused subset 不缓存 Tool Schema，因此无法可靠校验 `Mcp-Param-*`，也没有把 MRTR `inputResponses`/`requestState` 纳入动作摘要；这些输入一律在上游前 fail closed。不要把这一子集描述为完整 MCP conformance。

Proxy 会转发已配置 upstream 的 `server/discover` 与 `tools/list` 响应。返回的 description、instructions 和其他 metadata 都是不可信内容，Aegis 不对其进行 sanitization；Host 不得在缺少自身隔离与审查时把它们放入可信 Prompt。该限制不会绕过后续真实 `tools/call` 的独立 Permit gate。

保护只覆盖经过该 Adapter 的调用。Trusted Intake 只让身份来源显式、可拒绝和可审计，并不实现 IAM/SSO/RBAC；真实集成仍必须由已认证的中间件提供上下文。MCP 执行请求里的绑定 Header 只有在与已签名 Permit 完全匹配时才有效，本身不是身份凭据。上游 TLS/认证、transport framing、工具自身副作用、部署绕过和 confused-deputy 风险仍需要独立威胁建模。

当前恰好有两个编译进服务端的语义映射，并通过同一个不可变 registry 分发：`payment.send/v1` 与逻辑 `workspace.write/v1`。重复 profile ID、有歧义的 Tool 映射、未知 Tool、缺失映射及冲突的调用方声明全部 fail closed；调用方不能加载代码、选择 profile 或指定 upstream URL。授权与 MCP 执行使用同一个 registry 和 profile parser，每个已解析 profile 提供自己固定的 upstream target。

`payment.send/v1` 固定 Tool、capability、resource、operation、profile 版本、audience 与 target。严格的三个字段解析器只接受正 `int64` `amount_minor`、精确命中 allowlist 的币种和收款人；每个币种的限额都是独立的最小单位上限，不进行隐式汇率换算。

`workspace.write/v1` 为逻辑 `workspace.write` 固定相同类别的绑定。严格 parser 只接受 JSON string 类型的 `path` 与 `content`。Path 不是 OS 路径：只允许相对的 `/` 分隔 segment，不允许反斜杠、盘符前缀、空/`.`/`..`/`~` segment、首尾斜杠、控制字符，也不进行修复/normalization。示例配置把 path 限制为 1,024 bytes、content 限制为 4 KiB。Content 与 path 都进入动作语义，但不进入 Permit claims 或正常审计。该 profile 只向已配置的逻辑/mock upstream 转发，不写文件，也不提供隔离。

## Policy、Risk 与隔离

Policy 与受支持的两项语义配置保持确定性。Policy 先判断请求资格；只有 Policy 授权的请求才进入服务端语义解析。Policy 授权与语义解析成功两者缺一不可，共同决定 Permit 是否签发及其 signed obligations。当前可执行流程支持 `AUTHORIZED / DENIED`；模型虽能表达 `REQUIRES_APPROVAL`，但没有受支持的审批完成流程，因此不能产生可执行 Permit。Risk score 与 detection findings 只进入 `advisory_signals`，不能覆盖拒绝、创建授权、签发 Permit 或选择 executor。只有显式的确定性 Policy/配置映射才能生成 `human_approval_required`、`isolation_required`、`enhanced_audit_required` 等义务。

Aegis 不实现沙箱。`isolation_required: true` 只要求外部 executor 提供隔离；当仍需要隔离或人工批准时，focused MCP Proxy 会以 `EXECUTION_OBLIGATION_UNSATISFIED` fail closed，而不是转发。`read_only` 与 `network_egress_denied` 仍是已签名要求，必须由另一个独立可信的 executor/control 真正落实。兼容输出中的 `SANDBOX` 也是 profile hint。不要声称 Aegis 提供 Docker、gVisor、Firecracker、文件系统或网络隔离。

## 审计与敏感数据

正常审计按信任上下文、结构化请求验证、确定性 Policy 资格与 obligations、语义动作、Permit、verification、execution 的顺序解释，并可保存 request/decision/permit ID、`signing_key_id`、`permit_class`、规范化身份字段、`authorization_context_provenance`、tool/resource/operation、`action_digest`、policy version、授权决定、Permit 状态、验证结果/拒绝原因、upstream 是否尝试、execution outcome、时间和 evidence source。Risk/detection 单独标为 `advisory_signals`。

调用方必须先对委托凭据做哈希再提交。Aegis 会在 Permit/审计持久化前再次哈希所声明的 64 位十六进制 fingerprint，因此即便输入形状像摘要也不会被原样保存；这层防御不会把授权 API 变成凭据认证器。

永不保存或显示：

- `permit_token` 或签名私钥；
- raw bearer/delegated token、Cookie 或秘密值；
- 原始敏感 action arguments、Prompt、检索文档、文件或工具输出正文；
- 正常运行时审计中的完整个人路径、用户名或未脱敏 URL；
- 未脱敏员工、客户或生产数据。

本地审计文件尚不等于防篡改中央审计仓。错误路径也必须经过脱敏检查，避免 Token 被异常消息或请求 dump 泄漏。

## 运行时证据与实验性 Discovery

`gateway_enforced`、`instrumented_adapter`、`agent_self_reported`、`os_sensor`、`network_sensor` 和 `simulated_demo` 必须保留各自来源/信任等级。事件 API 是辅助证据路径，不是执行前控制。未接入覆盖是 `UNKNOWN / not instrumented`，不是零风险。

Discovery 已冻结、默认关闭，并只在 `--enable-experimental-inventory` 后暴露 Server 能力。配置/依赖/manifest 只能形成启发式发现证据，不能证明运行时行为。不要扩展进程、OAuth、CI/CD、云端或中央企业 Inventory。

## 公司端点与生产禁区

公司试点必须重新获得设备负责人、IT/安全和数据负责人的书面授权，并只使用 synthetic 参数、测试凭据和批准的 MCP 上游。不得捕获其他员工行为、绕过 EDR/DLP/代理/应用白名单，或将公司日志上传到个人 GitHub 或外部 AI 服务。

在完成独立安全评审、受控 MCP 试点、持久化 replay/key 设计和正式运维方案前，不得把 Aegis 作为生产凭据或客户数据前的唯一阻断控制。详见[执行许可试点](docs/experiments/enterprise-agent-pilot.zh-CN.md)。
