# 参与贡献

[English](CONTRIBUTING.md) | 简体中文

感谢你改进 **Aegis_Router — AI Agent 动作的执行许可**。仓库地址为 [`szey/Aegis_Router`](https://github.com/szey/Aegis_Router)。

当前真实 MCP 路径使用 [PreparedExecution 与 Permit v2](docs/prepared-execution.zh-CN.md)，绑定精确路由、profile 配置和匿名上游身份，并从实际参数重算字节数/副作用后检查 Policy。权限 epoch 在注册与消费锁内核对；停用、重新启用或刷新都使旧许可失效。epoch/禁用状态不持久，重启需可信系统重建；资源/lease 只有合成契约实验，真实 broker 尚未接入。

## 先守住一个安全属性

每项核心改动都必须强化这条执行链：

```text
CanonicalAction → deterministic authorization → signed Permit
  → pre-execution verify + atomic consume → MCP upstream → Audit Receipt
```

> 获得授权的动作，必须与实际执行的动作完全一致。

不要把 Aegis 扩展成通用 Agent 权限平台、沙箱、EDR、IAM、Shadow Agent 管理、企业 Inventory 或泛风险仪表板。本里程碑只接受 MCP 执行边界；HTTP、A2A、数据库和 Shell Adapter 不在范围内。

## 安全不变量

每个 Pull Request 都必须保持：

- principal、Agent、workload、delegation fingerprint、tool、capability、resource、operation 和安全参数全部进入规范动作绑定；
- canonical JSON 必须确定性生成；对象键顺序不得改变摘要，重复键必须拒绝，数组顺序必须保留；
- JSON-RPC 顶层成员必须精确匹配大小写；未经契约支持的成员拒绝。包括免 Permit 的协议请求在内，都必须从已分类 envelope 构造上游请求，不能回退转发另一份原始解释；
- 摘要为 SHA-256，原始敏感参数不得进入正常审计；
- `permit_id` 只用于关联，`permit_token` 才是签名执行凭据；ID 本身不能授权；
- HTTP 授权身份必须来自 `TrustedAuthorizationIntake`；未配置时 fail closed，本地 body intake 必须显式开启并标为 `development_only`；
- Permit Header 的 `kid` 必须由 KeyProvider 精确解析，并与签名 claims 中的 `signing_key_id` 一致；
- Permit 必须短时、动作绑定且默认单次使用；验证与消费必须原子完成；
- 验证签名、issuer、时效、Agent/workload、工具、资源、操作或摘要任一失败时，上游工具不得调用；
- MCP `2026-07-28` 的版本、`Mcp-Method`、`Mcp-Name` 与正文必须一致；重复 key、任意 Header/Session 上下文、未绑定 Tool `_meta`、MRTR/`Mcp-Param-*` 输入必须在上游前 fail closed 或被剥离；
- 两个并发消费尝试必须恰好一个成功，另一个明确返回 replay；
- 已撤销或已过期 Permit 不得执行；
- Permit 在上游前消费；上游失败/timeout 不得恢复，重试必须重新授权，禁止增加 `unconsume`；
- `permit_token`、签名私钥、raw bearer/delegated token、秘密值和原始敏感参数不得进入日志、UI 或错误消息；
- authorization 保持确定性；risk/detection 只进入 `advisory_signals`，不能改变状态、签发 Permit 或生成 obligations；
- 五类签名执行要求均在 nonce/Permit 消费前检查；不支持时 Permit 保持 `ISSUED`、上游零调用；不能用开关或 Agent 自报替代可信实施方；
- 运行时证据保留 source/trust；`agent_self_reported` 或 `simulated_demo` 不得冒充独立观察；
- 未接入覆盖保持 `UNKNOWN / not instrumented`。

## 开发流程

1. 写出可证伪的安全属性以及“错误时上游是否会被调用”；
2. 先增加安全 synthetic fixture 和负向测试；
3. 实现最小确定性控制；
4. 检查 replay 并发、过期/撤销、隐私、延迟和失败模式；
5. 同步 API、能力边界、调研登记和中英文文档；
6. 报告真实测试结果，不把本地回归写成生产保证。

至少覆盖：可信 intake 覆盖伪造 HTTP 身份、无 intake 默认拒绝、有效 Permit、`kid`、无效签名、过期、撤销、wrong agent/workload/tool/resource/operation、argument digest mismatch、单次 replay、并发 replay、上游失败/timeout 后仍已消费、审计不含 token，以及任何验证失败后 MCP upstream 调用次数为零。

## API、MCP 与兼容性

新的主要授权入口是 `POST /api/actions/authorize`。Permit 列表/详情只能返回安全元数据。任何返回 `permit_token` 的响应都要避免缓存、日志和 UI 泄漏。

MCP Adapter 必须在转发 `tools/call` 前复用核心 canonicalizer 和 verifier；不要在 Adapter 内实现第二套摘要或许可语义。运行时事件 API 只是辅助证据路径，不能替代执行前验证。

当前 Adapter 只声明 focused HTTP `POST` subset，不声明完整 MCP conformance。增加 MRTR 或 `Mcp-Param-*` 支持前，必须先把相应语义纳入同一动作绑定并增加 Header/body parser-differential 测试。

旧 `/api/authorize`、`/api/route` 和 `/api/runtime-events` 可暂时兼容，但必须明确标注；兼容字段中的 `SANDBOX/RESTRICT` 只表达 obligation/profile hint，不得声称 Aegis 提供真实隔离。

## 实验性 Discovery

Discovery 功能冻结且默认关闭，只能在 `--enable-experimental-inventory` 下暴露相关 Server API/UI。`cmd/discover` 保持可构建的实验工具。不要增加进程、OAuth、CI/CD、云端或中央 Inventory 能力。

## 验证

```bash
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
npm run check:web
npm run build:web
docker build .
```

若环境缺少 race detector 所需工具链，应原样报告限制，不能把未运行写成通过。

## 文档与数据

中文是语义工作源，英文必须在同一 PR 中同步。标识、端点、状态、日期、链接和能力边界必须一致。调研驱动变更使用 `$research-to-product` 与 [项目契约](.codex/research-to-product.json)，不得改变其中的发布、部署、生产数据或公司设备安全标志。

不要提交凭据、签名密钥、Permit token、生产审计、真实公司路径、员工活动、客户数据或公司设备原始日志。公司试点发现只能以脱敏结论或 synthetic fixture 回到公开仓库。

新增或修改编译 profile 时，必须从归一参数计算 PolicyFacts、快照配置摘要，并让授权与派发共用 PreparedExecution。增加路由漂移、低报字节/副作用、过期 epoch 的拒绝测试；不要通过放宽默认策略修复成功用例。
